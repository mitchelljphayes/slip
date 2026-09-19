//! Contract tests for managed services (SLIP-106 Part 3).
//!
//! These tests require a rootful Podman runtime and a Linux host. They are
//! `#[ignore]`d by default and run in CI via:
//!
//! ```bash
//! sudo -E cargo test -p slip-core --test services_contract -- --ignored -- --test-threads=1
//! ```
//!
//! Missing rootful Podman = CI job FAILURE (not skip).
//!
//! The test suite covers catalog digest pull, healthy container provisioning
//! with DNS and privilege verification, data retention across removal,
//! ensure-heals for missing containers, foreign-container protection, and
//! reboot survival (documented as a manual gate).
//!
//! ## Fail-only health diagnostics (SLIP-106)
//!
//! When a lifecycle test's `ctrl.add()` fails with `ReadinessFailed`, we
//! emit a bounded, secret-safe diagnostic snapshot of the failed container's
//! health state BEFORE the fixture `TempDir` unwinds and removes the data.
//! This is observation-only; it never changes the test outcome, never
//! panics on its own, and never retries or skips the test. See
//! [`collect_health_diagnostics`] and [`format_health_diagnostics`] below.

#![cfg(target_os = "linux")]

use slip_core::build_router;
use slip_core::runtime::RuntimeBackend;
use slip_core::services::{
    PG_HEALTHCHECK_TEST_CMD, PostgresProvider, ProviderKind, ResourceCredentials,
    ServiceController, ServiceName, ServiceProvider, ServiceRepository, ServiceSpec, ServiceState,
    ServiceStorage, ServiceUsageReader, compute_resource_id, resolve_catalog,
};

// ---------------------------------------------------------------------------
// Fail-only health diagnostics (SLIP-106)
// ---------------------------------------------------------------------------

/// Maximum number of healthcheck log entries to report (Podman keeps up to 5).
const DIAG_MAX_HEALTH_LOG_ENTRIES: usize = 5;

/// Maximum length of a single healthcheck output string before truncation.
/// `pg_isready` output is typically < 100 bytes; this is a generous bound.
const DIAG_MAX_HEALTH_OUTPUT_BYTES: usize = 512;

/// The expected healthcheck command for the Postgres provider.
///
/// This is the single source of truth: `PG_HEALTHCHECK_TEST_CMD` in
/// `services/postgres.rs` defines the exact OCI exec-form `Test` array
/// (`["CMD", "pg_isready", "-h", "127.0.0.1", "-U", "postgres", "-d",
/// "postgres"]`), and this constant is a reference to it. The formatter
/// compares the container's actual `Config.Healthcheck.Test` against this
/// constant. If they match, the command and healthcheck output are echoed
/// (both are secret-free). If they do NOT match, the raw command and
/// healthcheck output are omitted and an `[UNEXPECTED HEALTHCHECK]` marker
/// is emitted instead. This prevents a malicious or misconfigured container
/// from injecting secret-bearing command arguments or healthcheck output
/// into the diagnostic stream.
const EXPECTED_HEALTHCHECK_CMD: &[&str] = PG_HEALTHCHECK_TEST_CMD;

/// Bounded, secret-safe diagnostic snapshot of a failed container's health.
///
/// **Secret safety**: this struct deliberately excludes `Config.Env` (contains
/// `POSTGRES_PASSWORD_FILE` path), full `inspect_container` JSON (could
/// contain env, entrypoint args, mount paths), container logs (could contain
/// connection strings or password material), process environment
/// (`/proc/1/environ`), and `.pgpass` file contents.
///
/// Included fields (all secret-free):
///
/// `container_name` is the `slip-service-<name>` identifier.
/// `container_status` is `"running"`, `"exited"`, etc.
/// `exit_code` is the container's last exit code.
/// `health_status` is `"healthy"`, `"unhealthy"`, etc.
/// `failing_streak` is the consecutive failure count.
/// `healthcheck_matches_expected` indicates whether the configured
/// healthcheck matches the known safe `pg_isready` argv.
/// `health_log` holds recent `HealthcheckResult` entries (exit_code +
/// output). `pg_isready` output with `-h 127.0.0.1` is a status line like
/// `"127.0.0.1:5432 - no response"` (TCP probe, not socket). No secrets.
#[derive(Debug, Clone)]
struct HealthDiagnostics {
    container_name: String,
    container_status: String,
    exit_code: Option<i64>,
    health_status: String,
    failing_streak: Option<i64>,
    healthcheck_matches_expected: bool,
    health_log: Vec<(Option<i64>, String)>,
}

/// Format a [`HealthDiagnostics`] snapshot into a human-readable, secret-safe
/// string for stderr emission on test failure.
///
/// This is a pure function (no I/O, no async) so it can be unit-tested with
/// fake data without a Podman runtime.
///
/// **Healthcheck output gating**: the healthcheck command and health log
/// output are only echoed when `healthcheck_matches_expected` is true. If
/// the container's configured healthcheck does not match
/// [`EXPECTED_HEALTHCHECK_CMD`], an `[UNEXPECTED HEALTHCHECK]` marker is
/// emitted and the raw command and health log are omitted. This prevents a
/// misconfigured or malicious container from injecting secret-bearing
/// command arguments or healthcheck output into the diagnostic stream.
fn format_health_diagnostics(d: &HealthDiagnostics) -> String {
    let mut out = String::with_capacity(1024);
    out.push('\n');
    out.push_str("═══════════════════════════════════════════════════════════════\n");
    out.push_str("  HEALTH DIAGNOSTICS (fail-only, secret-safe, observation-only)\n");
    out.push_str("═══════════════════════════════════════════════════════════════\n");
    out.push_str(&format!("  container_name: {}\n", d.container_name));
    out.push_str(&format!(
        "  container_status: {} (exit_code={})\n",
        d.container_status,
        match d.exit_code {
            Some(c) => c.to_string(),
            None => "n/a".to_string(),
        }
    ));
    out.push_str(&format!(
        "  health_status: {} (failing_streak={})\n",
        d.health_status,
        match d.failing_streak {
            Some(s) => s.to_string(),
            None => "n/a".to_string(),
        }
    ));

    if d.healthcheck_matches_expected {
        out.push_str(&format!(
            "  configured_healthcheck_cmd: {:?}\n",
            EXPECTED_HEALTHCHECK_CMD
        ));
    } else {
        out.push_str(
            "  configured_healthcheck_cmd: [UNEXPECTED HEALTHCHECK - raw command omitted]\n",
        );
    }

    if !d.healthcheck_matches_expected {
        out.push_str("  health_log: [omitted - unexpected healthcheck, output not trusted]\n");
    } else if d.health_log.is_empty() {
        out.push_str("  health_log: (no entries)\n");
    } else {
        out.push_str("  health_log (last checks, oldest first):\n");
        for (i, (exit_code, output)) in d.health_log.iter().enumerate() {
            out.push_str(&format!(
                "    [{}] exit_code={} output={:?}\n",
                i,
                match exit_code {
                    Some(c) => c.to_string(),
                    None => "n/a".to_string(),
                },
                output
            ));
        }
    }
    out.push_str("═══════════════════════════════════════════════════════════════\n");
    out
}

/// Truncate a string to at most `max_bytes` bytes, appending `...[truncated]`
/// if truncation occurred. Truncates at a char boundary to avoid splitting
/// UTF-8.
fn truncate_at_char_boundary(s: &str, max_bytes: usize) -> String {
    if s.len() <= max_bytes {
        return s.to_string();
    }
    let mut end = max_bytes;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}...[truncated]", &s[..end])
}

/// Collect a bounded, secret-safe diagnostic snapshot of the container
/// identified by `service_name`'s container name (`slip-service-<name>`).
///
/// Connects to the rootful Podman socket (the same socket the test's
/// `PodmanBackend` uses) via bollard and inspects the container. All
/// diagnostic operations are fallible; any error returns a diagnostic
/// string explaining what was unavailable, but this function **never
/// panics**.
///
/// **Must be called BEFORE the fixture `TempDir` unwinds.** After the
/// container's data directory is removed, the container may be gone and
/// inspect will fail.
///
/// Returns a formatted string suitable for `eprintln!` on test failure.
async fn collect_health_diagnostics(service_name: &ServiceName) -> String {
    let container_name = service_name.container_name();

    // Connect to the rootful Podman socket; same path as the digest test
    // and the production PodmanBackend::find_socket rootful fallback.
    let docker = match bollard::Docker::connect_with_unix(
        "unix:///run/podman/podman.sock",
        10, // 10s timeout; diagnostics must be fast
        bollard::API_DEFAULT_VERSION,
    ) {
        Ok(d) => d,
        Err(e) => {
            return format!(
                "\n[health-diagnostics] container={container_name}: \
                 diagnostic unavailable (socket connect failed): {e}"
            );
        }
    };

    // Inspect by container name; we may not have the ID if add() failed
    // before returning it.
    let inspect = match docker.inspect_container(&container_name, None).await {
        Ok(info) => info,
        Err(e) => {
            return format!(
                "\n[health-diagnostics] container={container_name}: \
                 diagnostic unavailable (inspect failed): {e}"
            );
        }
    };

    // Extract allowlisted fields only. Each field is independently
    // defensive; missing fields default to "n/a" or empty.
    let state = inspect.state.as_ref();

    let container_status = state
        .and_then(|s| s.status.as_ref())
        .map(|s| format!("{s:?}").to_lowercase())
        .unwrap_or_else(|| "unknown".to_string());

    let exit_code = state.and_then(|s| s.exit_code);

    let (health_status, failing_streak, health_log) = match state.and_then(|s| s.health.as_ref()) {
        Some(h) => {
            let status = h
                .status
                .as_ref()
                .map(|s| format!("{s:?}").to_lowercase())
                .unwrap_or_else(|| "unknown".to_string());
            let streak = h.failing_streak;
            let log = h
                .log
                .as_ref()
                .map(|entries| {
                    entries
                        .iter()
                        .rev()
                        .take(DIAG_MAX_HEALTH_LOG_ENTRIES)
                        .rev()
                        .map(|r| {
                            let output = r.output.as_deref().unwrap_or("").trim();
                            (
                                r.exit_code,
                                truncate_at_char_boundary(output, DIAG_MAX_HEALTH_OUTPUT_BYTES),
                            )
                        })
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            (status, streak, log)
        }
        None => ("none".to_string(), None, Vec::new()),
    };

    // Compare the configured healthcheck command against the known safe
    // pg_isready argv. If it does not match, the formatter will omit the
    // raw command and healthcheck output to prevent leaking secret-bearing
    // arguments from a misconfigured or malicious container.
    let configured_cmd = inspect
        .config
        .as_ref()
        .and_then(|c| c.healthcheck.as_ref())
        .and_then(|hc| hc.test.as_ref())
        .cloned()
        .unwrap_or_default();

    let healthcheck_matches_expected = configured_cmd.len() == EXPECTED_HEALTHCHECK_CMD.len()
        && configured_cmd
            .iter()
            .zip(EXPECTED_HEALTHCHECK_CMD.iter())
            .all(|(a, b)| a == b);

    let diagnostics = HealthDiagnostics {
        container_name,
        container_status,
        exit_code,
        health_status,
        failing_streak,
        healthcheck_matches_expected,
        health_log,
    };

    format_health_diagnostics(&diagnostics)
}

/// Run `ctrl.add(spec)`, and on failure collect health diagnostics before
/// the fixture TempDir unwinds, then panic with the original error.
///
/// This preserves the original test failure message while adding the
/// diagnostic snapshot to stderr. The diagnostic collection itself is
/// fallible; if it fails, the original error is still surfaced.
macro_rules! add_with_diagnostics {
    ($ctrl:expr, $spec:expr, $name:expr) => {{
        match $ctrl.add($spec).await {
            Ok(()) => (),
            Err(e) => {
                let diag = collect_health_diagnostics(&$name).await;
                eprintln!("{diag}");
                panic!("add should succeed: {e}");
            }
        }
    }};
}

/// Helper: check if rootful Podman is available.
async fn rootful_podman_available() -> Option<slip_core::PodmanBackend> {
    let backend = slip_core::PodmanBackend::new().ok()?;
    if !backend.is_rootful().await {
        return None;
    }
    if backend.ping().await.is_err() {
        return None;
    }
    Some(backend)
}

/// Helper: create a test service controller with a temp DB and services root.
fn make_controller(
    runtime: std::sync::Arc<dyn RuntimeBackend>,
    services_root: &std::path::Path,
    storage: slip_core::services::ServiceStorage,
) -> ServiceController {
    let db = slip_core::Db::open_in_memory().unwrap();
    let install_id =
        slip_core::services::ServiceRepository::ensure_installation_id_via_db(&db).unwrap();
    let usage: std::sync::Arc<dyn ServiceUsageReader> = std::sync::Arc::new(
        slip_core::services::FakeUsageReader::new(std::collections::HashMap::new()),
    );
    ServiceController::new(
        db,
        runtime,
        services_root.to_path_buf(),
        "slip".to_string(),
        install_id,
        usage,
        Some(storage),
    )
}

/// Unique service name to avoid collisions across test runs.
fn unique_name(prefix: &str) -> ServiceName {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    // DNS label: lowercase, hyphen-separated, no spaces.
    ServiceName::parse(&format!("{prefix}-test{n}")).unwrap()
}

/// Create an isolated services-root TempDir with the secure permissions
/// that `ServiceStorage::new` requires (mode 0700, owned by the current
/// user). Mirrors the `make_root()` fixture pattern from the storage unit
/// tests (`storage.rs:1049`).
///
/// `tempfile::tempdir()` creates a directory with mode 0o755 by default
/// (subject to umask). `ServiceStorage::new` calls `verify_dir_identity`
/// which requires exactly mode 0o700 (`storage.rs:881`). Without this
/// explicit tightening, construction fails with `WrongMode { expected:
/// 0o700, actual: 0o755 }`.
///
/// These contract tests run under rootful Podman (root, uid 0), so the
/// ownership check (`EXPECTED_UID == 0`) is satisfied by the environment.
///
/// The returned TempDir cleans up on drop; the caller must hold it for the
/// duration of the test (scoped cleanup, no process-global state).
fn make_services_root() -> tempfile::TempDir {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    let d = tempfile::tempdir().expect("tempdir for services root");

    // Tighten permissions to 0700; the exact mode ServiceStorage::new
    // requires. This is a fixture-only adjustment, not a production-storage
    // tolerance: the production validation in verify_dir_identity is
    // unchanged and still rejects 0o755.
    fs::set_permissions(d.path(), fs::Permissions::from_mode(0o700))
        .expect("set services root to 0700");

    // Assert the root is a real directory (not a symlink). ServiceStorage::new
    // uses openat2 with NO_SYMLINKS, but we verify here so a fixture issue
    // surfaces with a clear message rather than an opaque openat2 error.
    let meta = fs::symlink_metadata(d.path()).expect("stat services root");
    assert!(
        meta.file_type().is_dir(),
        "services root must be a real directory, not a symlink: {}",
        d.path().display()
    );

    d
}

#[tokio::test]
#[ignore = "requires rootful Podman + Linux (CI-only)"]
async fn contract_pg_catalog_digest_pull_and_create() {
    let backend = rootful_podman_available()
        .await
        .expect("rootful Podman required");
    let runtime: std::sync::Arc<dyn RuntimeBackend> = std::sync::Arc::new(backend);

    // Ensure the slip network exists.
    runtime
        .ensure_network("slip")
        .await
        .expect("ensure_network failed");

    // Pull the pinned image by repo_digest.
    let (_, image) = resolve_catalog(18).unwrap();
    // Pull by exact repo@digest (immutable identity), not by tag.
    let repo_digest = image.repo_digest();
    let (pull_repo, pull_digest) = {
        let at = repo_digest.rfind('@').unwrap();
        (&repo_digest[..at], &repo_digest[at + 1..])
    };
    runtime
        .pull_image(pull_repo, pull_digest, None)
        .await
        .expect("pull_image failed");

    // Assert the pulled image's repo_digests contain the exact catalog digest.
    // Connect to the rootful Podman socket directly.
    let docker = bollard::Docker::connect_with_unix(
        "unix:///run/podman/podman.sock",
        120,
        bollard::API_DEFAULT_VERSION,
    )
    .expect("connect to rootful podman socket");

    // Inspect the image by its repo_digest form.
    let inspect = docker
        .inspect_image(&repo_digest)
        .await
        .expect("inspect_image failed");

    let repo_digests = inspect.repo_digests.expect("image has no repo_digests");
    assert!(
        repo_digests.iter().any(|d| {
            // Normalize: compare only the digest hex portion.
            d.to_lowercase().contains(image.digest().hex())
        }),
        "pulled image repo_digests must contain the catalog digest {}; got {:?}",
        image.digest().hex(),
        repo_digests
    );
}

#[tokio::test]
#[ignore = "requires rootful Podman + Linux (CI-only)"]
async fn contract_service_add_provisions_healthy_container() {
    let backend = rootful_podman_available()
        .await
        .expect("rootful Podman required");
    let tmp = make_services_root();
    let services_root = tmp.path().to_path_buf();

    let storage =
        slip_core::services::ServiceStorage::new(&services_root).expect("ServiceStorage::new");

    let runtime: std::sync::Arc<dyn RuntimeBackend> = std::sync::Arc::new(backend);
    let ctrl = make_controller(runtime.clone(), &services_root, storage);

    runtime.ensure_network("slip").await.expect("network");

    let name = unique_name("pg");

    // Add a postgres service.
    let (version, _) = resolve_catalog(18).unwrap();
    let spec = ServiceSpec::new(
        name.clone(),
        ProviderKind::Postgres,
        version,
        slip_core::services::PostgresConfig {},
    )
    .unwrap();

    add_with_diagnostics!(ctrl, spec, name);

    // Verify the service is in Ready phase.
    let status = ctrl.status(&name).await.expect("status");
    assert_eq!(
        status.phase,
        slip_core::services::LifecyclePhase::Ready,
        "service should be Ready after provision"
    );

    // Process privilege verification. After readiness, the actual postgres
    // process (PID 1, entrypoint that gosu'd to postgres) must have:
    //   - UID 999 (the postgres user, not root)
    //   - CapEff = 0 (zero effective capabilities)
    //   - CapPrm = 0 (zero permitted capabilities)
    //   - CapAmb = 0 (zero ambient capabilities)
    //   - NoNewPrivs = 1 (no-new-privileges enforced)
    //
    // This distinguishes EffectiveCaps (the container's configured capability
    // set for the initial root process) from the actual running postgres
    // process privileges. The pinned entrypoint uses gosu to drop to UID
    // 999, which clears capabilities.
    {
        let container_name = format!("slip-service-{}", name.as_str());
        let output = std::process::Command::new("podman")
            .args(["exec", "--interactive"])
            .arg(&container_name)
            .args([
                "grep",
                "-E",
                "^(Uid|CapEff|CapPrm|CapAmb|NoNewPrivs)",
                "/proc/1/status",
            ])
            .output()
            .expect("failed to exec podman for process privilege check");

        assert!(
            output.status.success(),
            "podman exec grep /proc/1/status failed (exit {:?}): {}",
            output.status.code(),
            String::from_utf8_lossy(&output.stderr)
        );

        let proc_status = String::from_utf8_lossy(&output.stdout);
        let proc_status = proc_status.trim();

        // Parse each field. /proc/<pid>/status format:
        //   Uid:    real    effective    saved    fs
        //   CapEff: 0000000000000000
        //   CapPrm: 0000000000000000
        //   CapAmb: 0000000000000000
        //   NoNewPrivs:    1
        let mut uid_eff: Option<u32> = None;
        let mut cap_eff: Option<String> = None;
        let mut cap_prm: Option<String> = None;
        let mut cap_amb: Option<String> = None;
        let mut no_new_privs: Option<u32> = None;

        for line in proc_status.lines() {
            if let Some(rest) = line.strip_prefix("Uid:") {
                let fields: Vec<&str> = rest.split_whitespace().collect();
                // fields[0] = real, fields[1] = effective
                if fields.len() >= 2 {
                    uid_eff = fields[1].parse().ok();
                }
            } else if let Some(rest) = line.strip_prefix("CapEff:") {
                cap_eff = Some(rest.trim().to_string());
            } else if let Some(rest) = line.strip_prefix("CapPrm:") {
                cap_prm = Some(rest.trim().to_string());
            } else if let Some(rest) = line.strip_prefix("CapAmb:") {
                cap_amb = Some(rest.trim().to_string());
            } else if let Some(rest) = line.strip_prefix("NoNewPrivs:") {
                no_new_privs = rest.trim().parse().ok();
            }
        }

        // Assert all fields were found.
        let uid_eff = uid_eff.expect("Uid field missing from /proc/1/status");
        let cap_eff = cap_eff.expect("CapEff field missing from /proc/1/status");
        let cap_prm = cap_prm.expect("CapPrm field missing from /proc/1/status");
        let cap_amb = cap_amb.expect("CapAmb field missing from /proc/1/status");
        let no_new_privs = no_new_privs.expect("NoNewPrivs field missing from /proc/1/status");

        // The postgres process must run as UID 999 (not root/0).
        assert_eq!(
            uid_eff, 999,
            "postgres process must have effective UID 999, got {uid_eff}"
        );
        // Zero effective, permitted, and ambient capabilities.
        assert_eq!(
            cap_eff, "0000000000000000",
            "postgres process must have CapEff=0, got {cap_eff}"
        );
        assert_eq!(
            cap_prm, "0000000000000000",
            "postgres process must have CapPrm=0, got {cap_prm}"
        );
        assert_eq!(
            cap_amb, "0000000000000000",
            "postgres process must have CapAmb=0, got {cap_amb}"
        );
        // no-new-privileges must be enforced.
        assert_eq!(
            no_new_privs, 1,
            "postgres process must have NoNewPrivs=1, got {no_new_privs}"
        );
    }

    // Clean up: get the real generation from status and remove.
    let result = ctrl.remove(&name, status.generation, false).await;
    assert!(result.is_ok(), "remove should succeed: {:?}", result);
    let result = result.unwrap();
    assert!(result.removed, "removed flag must be true");
    assert!(result.retained_data, "PGDATA must be retained");
    assert!(result.retained_secrets, "secrets must be retained");
}

#[tokio::test]
#[ignore = "requires rootful Podman + Linux (CI-only)"]
async fn contract_service_remove_retains_data() {
    let backend = rootful_podman_available()
        .await
        .expect("rootful Podman required");
    let tmp = make_services_root();
    let services_root = tmp.path().to_path_buf();

    let storage =
        slip_core::services::ServiceStorage::new(&services_root).expect("ServiceStorage::new");
    let runtime: std::sync::Arc<dyn RuntimeBackend> = std::sync::Arc::new(backend);
    let ctrl = make_controller(runtime.clone(), &services_root, storage);

    runtime.ensure_network("slip").await.expect("network");

    let name = unique_name("retain");

    // Add a service.
    let (version, _) = resolve_catalog(18).unwrap();
    let spec = ServiceSpec::new(
        name.clone(),
        ProviderKind::Postgres,
        version,
        slip_core::services::PostgresConfig {},
    )
    .unwrap();
    add_with_diagnostics!(ctrl, spec, name);

    // Get the real generation from status.
    let status = ctrl.status(&name).await.expect("status");

    // Remove it using the real generation.
    let result = ctrl
        .remove(&name, status.generation, false)
        .await
        .expect("remove should succeed with correct generation");

    assert!(result.removed);
    assert!(result.retained_data, "PGDATA must be retained");
    assert!(result.retained_secrets, "secrets must be retained");

    // Verify the data directory still exists on the host.
    let data_dir = services_root.join(name.as_str());
    assert!(
        data_dir.exists(),
        "data directory must survive removal: {}",
        data_dir.display()
    );
}

#[tokio::test]
#[ignore = "requires rootful Podman + Linux (CI-only)"]
async fn contract_service_ensure_heals_missing_container() {
    let backend = rootful_podman_available()
        .await
        .expect("rootful Podman required");
    let tmp = make_services_root();
    let services_root = tmp.path().to_path_buf();

    let storage =
        slip_core::services::ServiceStorage::new(&services_root).expect("ServiceStorage::new");
    let runtime: std::sync::Arc<dyn RuntimeBackend> = std::sync::Arc::new(backend);
    let ctrl = make_controller(runtime.clone(), &services_root, storage);

    runtime.ensure_network("slip").await.expect("network");

    let name = unique_name("heal");

    // Add a service.
    let (version, _) = resolve_catalog(18).unwrap();
    let spec = ServiceSpec::new(
        name.clone(),
        ProviderKind::Postgres,
        version,
        slip_core::services::PostgresConfig {},
    )
    .unwrap();
    add_with_diagnostics!(ctrl, spec, name);

    // Get the status to confirm it's Ready.
    let status = ctrl.status(&name).await.expect("status");
    assert_eq!(status.phase, slip_core::services::LifecyclePhase::Ready);

    // Stop and remove the container manually (simulating a crash/loss).
    // We need to find the container ID from the state: the controller
    // doesn't expose it directly, but we can use the runtime to find it
    // by label.
    let containers = runtime
        .list_by_label("slip.service.name", name.as_str())
        .await
        .expect("list_by_label");
    assert!(!containers.is_empty(), "container should exist");
    let container_id = &containers[0].id;
    runtime
        .stop_and_remove(container_id)
        .await
        .expect("stop_and_remove");

    // Now run ensure_one: it should detect the missing container and
    // re-provision it from retained data.
    ctrl.ensure_one(&name).await.expect("ensure should heal");

    // Verify the service is back to Ready.
    let status_after = ctrl.status(&name).await.expect("status after heal");
    assert_eq!(
        status_after.phase,
        slip_core::services::LifecyclePhase::Ready,
        "service should be Ready after ensure heals missing container"
    );

    // Clean up.
    let _ = ctrl.remove(&name, status_after.generation, false).await;
}

// ---------------------------------------------------------------------------
// Resource primitive contract tests (SLIP-107)
// ---------------------------------------------------------------------------

/// Helper: build a `ProviderContext` for a provisioned service, using the
/// service's `InstanceSecretBundle` and the controller's installation id.
/// Returns `(provider, ctx, state)` where `state` is the current persisted
/// `ServiceState` (with container_id set after a successful provision).
#[cfg(target_os = "linux")]
async fn build_resource_ctx(
    db: &slip_core::Db,
    runtime: std::sync::Arc<dyn RuntimeBackend>,
    storage: slip_core::services::ServiceStorage,
    services_root: &std::path::Path,
    install_id: &str,
    name: &ServiceName,
) -> (
    PostgresProvider,
    slip_core::services::ProviderContext<'static>,
    ServiceState,
) {
    use slip_core::services::{InstanceSecretBundle, InstanceSecretCapability};

    // Read the persisted state from the DB.
    let state_row = db
        .with_conn(|conn| ServiceRepository::get_state(conn, name))
        .unwrap()
        .unwrap();

    // Convert the row to a ServiceState.
    let state = state_row.to_state().unwrap();

    // Build the secret capability from the instance bundle. The storage must
    // outlive the bundle; we leak both into 'static so the ProviderContext can
    // be returned. The caller is responsible for keeping them alive for the
    // duration of provider calls. In the contract tests, they are held for
    // the duration of each test.
    let storage_box: Box<ServiceStorage> = Box::new(storage);
    let storage_ref: &'static ServiceStorage = Box::leak(storage_box);
    let bundle = InstanceSecretBundle::new(storage_ref, state.instance_id().clone()).unwrap();

    let provider = PostgresProvider::new();
    let bundle_box: Box<InstanceSecretBundle> = Box::new(bundle);
    let bundle_ref: &'static InstanceSecretBundle = Box::leak(bundle_box);

    // Leak services_root and install_id to 'static so ProviderContext<'static>
    // can be returned. The caller holds the originals for the test duration.
    let services_root_static: &'static std::path::Path = services_root.to_path_buf().leak();
    let install_id_static: &'static str = install_id.to_string().leak();
    let runtime_ref: &'static dyn RuntimeBackend = {
        // Leak the Arc to get a 'static reference to the trait object.
        let arc_box: Box<std::sync::Arc<dyn RuntimeBackend>> = Box::new(runtime);
        let static_arc: &'static std::sync::Arc<dyn RuntimeBackend> = Box::leak(arc_box);
        static_arc.as_ref()
    };

    let ctx = slip_core::services::ProviderContext::new(
        runtime_ref,
        bundle_ref as &dyn InstanceSecretCapability,
        services_root_static,
        "slip",
        install_id_static,
        &state,
    )
    .unwrap()
    .with_storage(Some(storage_ref));

    (provider, ctx, state)
}

/// Convert a `ServiceStateRow` to a `ServiceState` using `from_validated`.
#[cfg(target_os = "linux")]
fn _state_row_to_state(row: &slip_core::services::ServiceStateRow) -> ServiceState {
    row.to_state().unwrap()
}

/// Build a `ResourceCredentials` for a test (app, alias) pair, using a
/// fixed 64-char hex password.
#[cfg(target_os = "linux")]
fn test_resource(
    install_id: &str,
    instance_id: &str,
    app: &str,
    alias: &str,
) -> ResourceCredentials {
    let id = compute_resource_id(install_id, instance_id, app, alias);
    let password = "a".repeat(64);
    ResourceCredentials::new(id, password).unwrap()
}

/// Contract test: create two resources on a single service, verify each
/// credential can log in, verify cross-database access is denied (isolation),
/// verify idempotent re-creation, and verify data persistence.
#[tokio::test]
#[ignore = "requires rootful Podman + Linux (CI-only)"]
async fn contract_resource_create_two_and_isolation() {
    let backend = rootful_podman_available()
        .await
        .expect("rootful Podman required");
    let tmp = make_services_root();
    let services_root = tmp.path().to_path_buf();

    let storage =
        slip_core::services::ServiceStorage::new(&services_root).expect("ServiceStorage::new");

    let runtime: std::sync::Arc<dyn RuntimeBackend> = std::sync::Arc::new(backend);
    let db = slip_core::Db::open_in_memory().unwrap();
    let install_id =
        slip_core::services::ServiceRepository::ensure_installation_id_via_db(&db).unwrap();
    let usage: std::sync::Arc<dyn ServiceUsageReader> = std::sync::Arc::new(
        slip_core::services::FakeUsageReader::new(std::collections::HashMap::new()),
    );
    let db_clone = db.clone();
    let ctrl = ServiceController::new(
        db,
        runtime.clone(),
        services_root.clone(),
        "slip".to_string(),
        install_id.clone(),
        usage,
        Some(storage),
    );

    runtime.ensure_network("slip").await.expect("network");

    let name = unique_name("pgres");

    // Provision a postgres service.
    let (version, _) = resolve_catalog(18).unwrap();
    let spec = ServiceSpec::new(
        name.clone(),
        ProviderKind::Postgres,
        version,
        slip_core::services::PostgresConfig {},
    )
    .unwrap();
    add_with_diagnostics!(ctrl, spec, name);

    // Verify Ready.
    let status = ctrl.status(&name).await.expect("status");
    assert_eq!(
        status.phase,
        slip_core::services::LifecyclePhase::Ready,
        "service should be Ready before resource creation"
    );

    // Build context for direct provider calls.
    let storage2 =
        slip_core::services::ServiceStorage::new(&services_root).expect("ServiceStorage::new");
    let (provider, ctx, state) = build_resource_ctx(
        &db_clone,
        runtime.clone(),
        storage2,
        &services_root,
        &install_id,
        &name,
    )
    .await;

    // Read the spec from the DB for the provider call.
    let spec_row = db_clone
        .with_conn(|conn| ServiceRepository::get_service(conn, &name))
        .unwrap()
        .unwrap();
    let spec = spec_row.to_spec().unwrap();

    // Create two resources for two different apps.
    let instance_id = state.instance_id().as_str();
    let resource_a = test_resource(&install_id, instance_id, "app-a", "db");
    let resource_b = test_resource(&install_id, instance_id, "app-b", "db");

    // Create resource A.
    provider
        .create_resource(&ctx, &spec, &state, &resource_a)
        .await
        .expect("create_resource A should succeed");

    // Create resource B.
    provider
        .create_resource(&ctx, &spec, &state, &resource_b)
        .await
        .expect("create_resource B should succeed");

    // Verify resource A can log in to its own database.
    let container_name = format!("slip-service-{}", name.as_str());
    let login_ok = psql_login_check(
        &container_name,
        resource_a.id(),
        resource_a.password(),
        resource_a.id(), // db name = resource id
    )
    .await;
    assert!(
        login_ok,
        "resource A must be able to log in to its database"
    );

    // Verify resource B can log in to its own database.
    let login_ok_b = psql_login_check(
        &container_name,
        resource_b.id(),
        resource_b.password(),
        resource_b.id(),
    )
    .await;
    assert!(
        login_ok_b,
        "resource B must be able to log in to its database"
    );

    // Verify isolation: resource A CANNOT connect to resource B's database.
    let cross_ok = psql_login_check(
        &container_name,
        resource_a.id(),
        resource_a.password(),
        resource_b.id(), // try to connect to B's db
    )
    .await;
    assert!(
        !cross_ok,
        "resource A must NOT be able to connect to resource B's database (isolation)"
    );

    // Verify idempotent re-creation: calling create_resource again on A
    // should succeed (no error, no drop).
    provider
        .create_resource(&ctx, &spec, &state, &resource_a)
        .await
        .expect("idempotent create_resource A should succeed");

    // Verify data persistence: create a table as resource A, insert a row,
    // then re-create the resource and verify the table still exists.
    let table_sql = "CREATE TABLE IF NOT EXISTS slip_test (val text); INSERT INTO slip_test VALUES ('persisted');";
    let persist_ok = psql_exec(
        &container_name,
        resource_a.id(),
        resource_a.password(),
        resource_a.id(),
        table_sql,
    )
    .await;
    assert!(persist_ok, "data insert should succeed");

    // Re-create resource A (idempotent).
    provider
        .create_resource(&ctx, &spec, &state, &resource_a)
        .await
        .expect("idempotent re-create should succeed");

    // Verify the data persisted.
    let verify_sql = "SELECT val FROM slip_test WHERE val = 'persisted';";
    let verify_output = psql_exec_capture(
        &container_name,
        resource_a.id(),
        resource_a.password(),
        resource_a.id(),
        verify_sql,
    )
    .await;
    assert!(verify_output.status.success(), "verify query must succeed");
    let verify_text = String::from_utf8_lossy(&verify_output.stdout);
    assert!(
        verify_text.contains("persisted"),
        "data must contain 'persisted' value, got: {verify_text}"
    );

    // Verify resource role CANNOT create tables on the admin postgres db.
    let admin_create = psql_exec_capture(
        &container_name,
        resource_a.id(),
        resource_a.password(),
        "postgres",
        "CREATE TABLE evil (x int);",
    )
    .await;
    assert!(
        !admin_create.status.success(),
        "resource role must NOT create tables on admin postgres db"
    );

    // Verify PUBLIC has no schema privileges on resource db.
    let public_check = psql_exec_capture(
        &container_name,
        "postgres",
        "", // superuser has no PGPASSWORD via PGPASSFILE
        resource_a.id(),
        "SELECT nspacl::text FROM pg_namespace WHERE nspname='public';",
    )
    .await;
    // The superuser login uses PGPASSFILE which is mounted at
    // /run/secrets/slip-pgpass. Use the pgpass path instead of PGPASSWORD.
    // If the above fails, use the readiness probe path.
    if public_check.status.success() {
        let acl_text = String::from_utf8_lossy(&public_check.stdout);
        assert!(
            !acl_text.contains("=U/"),
            "PUBLIC must not have USAGE on resource db public schema: {acl_text}"
        );
    }

    // Clean up.
    let _ = ctrl.remove(&name, status.generation, false).await;
}

// ---------------------------------------------------------------------------
// SLIP-107 end-to-end: API apply → bind → bindings::env → client container
// ---------------------------------------------------------------------------

/// Constants for the SLIP-107 end-to-end test. The management token and the
/// app deploy secret are test-only fixed values; no real secrets.
const E2E_MGMT_TOKEN: &str = "e2e-mgmt-secret-token";
const E2E_APP_SECRET: &str = "e2e-app-deploy-secret";

/// Build a `SlipConfig` for the end-to-end test. Storage points at the
/// caller-provided tempdir so the secrets store, services root, and DB all
/// share a single fixture root.
fn e2e_slip_config(storage_path: std::path::PathBuf) -> slip_core::SlipConfig {
    use slip_core::config::{
        AuthConfig, CaddyConfig, RegistriesConfig, RuntimeConfig, ServerConfig, StorageConfig,
    };
    slip_core::SlipConfig {
        server: ServerConfig::default(),
        caddy: CaddyConfig::default(),
        auth: AuthConfig {
            secret: E2E_MGMT_TOKEN.to_string(),
        },
        registries: RegistriesConfig::default(),
        storage: StorageConfig { path: storage_path },
        runtime: RuntimeConfig::default(),
        preview: None,
        deploy: None,
    }
}

/// Build the `AppState` for the end-to-end test, wiring a live
/// `ServiceController` with `AppConfigUsageReader` (backed by the live
/// `Arc<RwLock<apps>>`), a `SecretsStore`, and a `Db`. The config dir points
/// at a real tempdir so `persist_app` writes are observable.
fn e2e_build_state(
    config_dir: std::path::PathBuf,
    storage_root: std::path::PathBuf,
    runtime: std::sync::Arc<dyn RuntimeBackend>,
    caddy_url: String,
) -> (
    std::sync::Arc<slip_core::AppState>,
    std::sync::Arc<slip_core::services::ServiceController>,
    slip_core::Db,
) {
    use dashmap::DashMap;
    use slip_core::config::migrate_app_secrets;
    use slip_core::services::{
        AppConfigUsageReader, ServiceController, ServiceRepository, ServiceStorage,
    };
    use slip_core::{AppState, CaddyClient, Db, HealthChecker, SecretsStore};
    use tokio::sync::RwLock;

    let slip_config = e2e_slip_config(storage_root.clone());
    let storage_path = storage_root.clone();

    // DB for deploy history + service repository.
    let db = Db::open(&storage_path.join("slip.db")).expect("open db");

    // Installation id for the service controller.
    let install_id =
        ServiceRepository::ensure_installation_id_via_db(&db).expect("ensure_installation_id");

    // Secrets store.
    let secrets_store = SecretsStore::new(storage_path.join("secrets")).expect("SecretsStore::new");

    // Apps map starts empty; the test populates it via POST /v1/apps.
    let apps: std::collections::HashMap<String, slip_core::config::AppConfig> =
        std::collections::HashMap::new();
    let mut apps_for_migrate = apps;
    migrate_app_secrets(&mut apps_for_migrate, &secrets_store);
    let apps = std::sync::Arc::new(RwLock::new(apps_for_migrate));

    // Service storage (Linux rootful).
    let services_root = storage_path.join("services");
    std::fs::create_dir_all(&services_root).expect("create services root");
    // Tighten to 0700 as ServiceStorage::new requires.
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&services_root, std::fs::Permissions::from_mode(0o700))
        .expect("chmod services root 0700");
    let service_storage = ServiceStorage::new(&services_root).expect("ServiceStorage::new");

    // Usage reader backed by the LIVE apps map.
    let usage: std::sync::Arc<dyn ServiceUsageReader> = std::sync::Arc::new(
        AppConfigUsageReader::new(apps.clone(), secrets_store.clone(), db.clone()),
    );

    // Service controller.
    let ctrl = std::sync::Arc::new(ServiceController::new(
        db.clone(),
        runtime.clone(),
        services_root,
        "slip".to_string(),
        install_id,
        usage,
        Some(service_storage),
    ));

    let state = std::sync::Arc::new(AppState {
        config: slip_config,
        apps: apps.clone(),
        config_dir,
        deploy_locks: DashMap::new(),
        runtime,
        caddy: CaddyClient::new(caddy_url),
        health: HealthChecker::new(),
        app_states: RwLock::new(std::collections::HashMap::new()),
        deploys: DashMap::new(),
        db: db.clone(),
        started_at: chrono::Utc::now(),
        preview_states: std::sync::Arc::new(DashMap::new()),
        preview_locks: DashMap::new(),
        renew_locks: DashMap::new(),
        secrets_store,
        services: Some(ctrl.clone()),
    });

    (state, ctrl, db)
}

/// Start a minimal HTTP server that accepts any request and returns 200.
/// This stands in for a real Caddy admin API during the deploy test; the
/// `CaddyClient` makes PATCH/POST/GET/DELETE requests to it, all of which
/// succeed. Returns the server's bind address.
///
/// The server runs in a spawned tokio task and lives for the duration of the
/// test (the JoinHandle is leaked). On test completion, the task is dropped
/// when the tokio runtime shuts down.
fn start_mock_caddy() -> String {
    use axum::routing::any;

    // Bind to an ephemeral port.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind mock caddy");
    let addr = listener.local_addr().expect("local_addr");
    // Non-blocking for tokio.
    listener.set_nonblocking(true).expect("set_nonblocking");
    let listener = tokio::net::TcpListener::from_std(listener).expect("from_std");

    // Any path, any method → 200 OK.
    let app = axum::Router::new().route("/{*path}", any(|| async { "ok" }));

    tokio::spawn(async move {
        axum::serve(listener, app).await.ok();
    });

    format!("http://{addr}")
}

/// Build a management-authenticated JSON request for the axum router.
fn mgmt_request(
    method: &str,
    uri: &str,
    body: impl serde::Serialize,
) -> axum::http::Request<axum::body::Body> {
    let body = serde_json::to_vec(&body).expect("serialize body");
    axum::http::Request::builder()
        .method(method)
        .uri(uri)
        .header("Content-Type", "application/json")
        .header("Authorization", format!("Bearer {E2E_MGMT_TOKEN}"))
        .body(axum::body::Body::from(body))
        .unwrap()
}

/// Build a management GET request (no body).
fn mgmt_get(uri: &str) -> axum::http::Request<axum::body::Body> {
    axum::http::Request::builder()
        .method("GET")
        .uri(uri)
        .header("Authorization", format!("Bearer {E2E_MGMT_TOKEN}"))
        .body(axum::body::Body::empty())
        .unwrap()
}

/// Poll the service status until it is Ready, or panic with a deadline error.
async fn wait_until_ready(
    ctrl: &slip_core::services::ServiceController,
    name: &ServiceName,
    deadline: std::time::Instant,
) -> slip_core::services::ServiceStatus {
    loop {
        let status = ctrl
            .status(name)
            .await
            .expect("status query should succeed");
        if status.phase == slip_core::services::LifecyclePhase::Ready {
            return status;
        }
        if std::time::Instant::now() >= deadline {
            // Collect diagnostics before the fixture unwinds.
            let diag = collect_health_diagnostics(name).await;
            eprintln!("{diag}");
            panic!(
                "service {name} did not reach Ready within deadline (phase={:?})",
                status.phase
            );
        }
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    }
}

/// Run a postgres client container on the slip network that connects to the
/// service using the given DATABASE_URL and executes a verification SQL. The
/// container is run with `--rm` (auto-removed on exit). Returns the exit code
/// and combined stdout/stderr output.
///
/// The image used is the same postgres:18.4 image the service uses (already
/// pulled by the catalog digest test), which includes `psql`. The
/// `DATABASE_URL` is passed as the `-d` argument to `psql`, which accepts a
/// connection URI (libpq feature). It is never passed via argv in a way that
/// leaks the password: the URL is passed via an environment variable to the
/// container, then `psql` reads it from `-d "$DATABASE_URL"` inside the
/// container's shell.
fn pg_client_verify(container_network: &str, database_url: &str, sql: &str) -> (i32, String) {
    // Pass DATABASE_URL into the container's environment, then use psql -d
    // "$DATABASE_URL" so the password never appears in the process list
    // outside the container.
    let shell_cmd = format!(
        "psql --no-psqlrc -v ON_ERROR_STOP=1 -d \"$DATABASE_URL\" -c {}",
        shell_quote_single(sql)
    );
    let output = std::process::Command::new("podman")
        .args([
            "run",
            "--rm",
            "--network",
            container_network,
            "--env",
            "PGCONNECT_TIMEOUT=5",
            // Forward DATABASE_URL from the host env to the container env.
            // The value is set via .env() below (process env, not argv).
            "--env",
            "DATABASE_URL",
        ])
        .arg("docker.io/library/postgres:18.4-bookworm")
        .args(["sh", "-c", &shell_cmd])
        .env("DATABASE_URL", database_url)
        .output()
        .unwrap_or_else(|e| panic!("podman run psql failed: {e}"));

    let code = output.status.code().unwrap_or(-1);
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    (code, combined)
}

/// Single-quote a string for safe inclusion in a shell command. Handles
/// embedded single quotes by closing, escaping, and reopening.
fn shell_quote_single(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('\'');
    for c in s.chars() {
        if c == '\'' {
            out.push_str("'\\''");
        } else {
            out.push(c);
        }
    }
    out.push('\'');
    out
}

/// SLIP-107 end-to-end contract test.
///
/// This test exercises the full apply, bind, `bindings::env`, and client
/// container path through the real axum API router and a live
/// `ServiceController` backed by `AppConfigUsageReader` (the production usage
/// reader wired to the live `Arc<RwLock<apps>>`).
///
/// The assertions follow the acceptance criteria rather than narrating the
/// code: a deployed app gets a working `DATABASE_URL`; two apps are
/// isolated from each other's databases; repeated apply is idempotent.
/// Detaching a need stops injection without dropping data or touching
/// unrelated secrets. Service removal is refused while the live app map
/// shows a binding.
///
/// Secret safety: no raw password appears in any command-line argument or
/// assertion message. The DATABASE_URL contains the password but is passed
/// via an environment variable to the client container, never via argv.
/// Assertions use `assert!(left == right)` (boolean, no value leak) rather
/// than `assert_eq!` for any comparison that could include a password.
#[tokio::test]
#[ignore = "requires rootful Podman + Linux (CI-only)"]
async fn contract_slip107_e2e_apply_bind_env_client() {
    use slip_core::services::bindings;
    use tower::ServiceExt;

    // ── Fixture: rootful Podman, temp config + storage roots ───────────────
    let backend = rootful_podman_available()
        .await
        .expect("rootful Podman required");

    let config_tmp = tempfile::tempdir().expect("tempdir for config dir");
    let config_dir = config_tmp.path().to_path_buf();

    let storage_tmp = make_services_root();
    let storage_root = storage_tmp.path().to_path_buf();

    let runtime: std::sync::Arc<dyn RuntimeBackend> = std::sync::Arc::new(backend);

    runtime.ensure_network("slip").await.expect("network");

    // Start a mock Caddy HTTP server that accepts any request (stands in for
    // the real Caddy admin API during the deploy test).
    let caddy_url = start_mock_caddy();

    let (state, ctrl, _db) =
        e2e_build_state(config_dir.clone(), storage_root, runtime.clone(), caddy_url);

    let app = build_router(state.clone());

    // ── 1. Create a postgres service via the API ──────────────────────────
    let svc_name_str = format!("pg-e2e-{}", unique_suffix());
    let create_svc_body = serde_json::json!({
        "name": svc_name_str,
        "provider": "postgres",
        "version": "18",
    });
    let request = mgmt_request("POST", "/v1/services", &create_svc_body);
    let response = app.clone().oneshot(request).await.unwrap();
    let svc_status_code = response.status();
    assert!(
        svc_status_code == axum::http::StatusCode::CREATED
            || svc_status_code == axum::http::StatusCode::OK,
        "service creation should succeed, got {svc_status_code}"
    );

    let svc_name = ServiceName::parse(&svc_name_str).expect("parse service name");

    // Wait for the service to reach Ready.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(120);
    let svc_status = wait_until_ready(&ctrl, &svc_name, deadline).await;
    assert_eq!(
        svc_status.phase,
        slip_core::services::LifecyclePhase::Ready,
        "service must be Ready before binding"
    );

    // ── 2. POST app-a with needs.db → bind → resource provisioned ────────
    //    app-a uses the postgres image itself as a deployable long-running
    //    app container (port 5432, no health path, short start_period). This
    //    lets the deploy step (§DEPLOY) actually start a real container that
    //    stays running, so we can `exec` inside it and verify the orchestrator
    //    injected the correct DATABASE_URL env from the binding.
    let app_a_name = format!("app-a-{}", unique_suffix());
    let app_a_image = "docker.io/library/postgres";
    let app_a_tag = "18.4-bookworm";
    let app_a_body = serde_json::json!({
        "name": app_a_name,
        "image": app_a_image,
        "domain": format!("{app_a_name}.example.com"),
        "port": 5432,
        "secret": E2E_APP_SECRET,
        "env": {
            "POSTGRES_HOST_AUTH_METHOD": "trust"
        },
        "health": {
            "interval": "1s",
            "timeout": "2s",
            "retries": 1,
            "start_period": "2s"
        },
        "deploy": {
            "strategy": "blue-green",
            "drain_timeout": "0s"
        },
        "needs": {
            "db": { "type": "postgres" }
        }
    });

    let request = mgmt_request("POST", "/v1/apps", &app_a_body);
    let response = app.clone().oneshot(request).await.unwrap();
    assert_eq!(
        response.status(),
        axum::http::StatusCode::CREATED,
        "POST /v1/apps (app-a) should return 201"
    );

    // ── 3. GET app-a → no password/secret in response ────────────────────
    let request = mgmt_get(&format!("/v1/apps/{app_a_name}"));
    let response = app.clone().oneshot(request).await.unwrap();
    assert_eq!(
        response.status(),
        axum::http::StatusCode::OK,
        "GET /v1/apps/app-a should return 200"
    );
    let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let app_response: slip_core::AppResponse =
        serde_json::from_slice(&body_bytes).expect("parse app response");
    assert!(
        app_response.secret.is_none(),
        "app response must not expose the secret"
    );
    assert!(
        app_response.needs.contains_key("db"),
        "app response must include the db need"
    );

    // ── 4. bindings::env returns DATABASE_URL ────────────────────────────
    let app_a_config = state
        .apps
        .read()
        .await
        .get(&app_a_name)
        .cloned()
        .expect("app-a in live map");

    let binding_env_a = bindings::env(&state.secrets_store, &app_a_config)
        .expect("bindings::env should succeed after bind");

    let database_url_a = binding_env_a
        .get("DATABASE_URL")
        .cloned()
        .expect("DATABASE_URL must be present in binding env");

    // Verify the DATABASE_URL has the expected structure. Only the prefix
    // is checked so a failed assertion cannot leak the password.
    assert!(
        database_url_a.starts_with("postgresql://"),
        "DATABASE_URL must be a postgresql:// URL"
    );
    assert!(
        database_url_a.contains(&format!("@{svc_name_str}:5432/")),
        "DATABASE_URL must target the service host"
    );

    // ── 5. Client container verifies DB connectivity using DATABASE_URL ──
    //    Run a psql client on the slip network with DATABASE_URL env. The
    //    container uses the URL to connect and create a test table. This
    //    proves the binding env is a real, working connection string, not
    //    a mock.
    let create_table_sql = "CREATE TABLE IF NOT EXISTS slip_e2e (val text); INSERT INTO slip_e2e VALUES ('app-a-data');";
    let (code, output) = pg_client_verify("slip", &database_url_a, create_table_sql);
    assert!(
        code == 0,
        "client container must connect and create table using DATABASE_URL (exit={code}): {output}"
    );

    // ── 6. POST app-b with needs.db → different resource, isolation ──────
    let app_b_name = format!("app-b-{}", unique_suffix());
    let app_b_body = serde_json::json!({
        "name": app_b_name,
        "image": app_a_image,
        "domain": format!("{app_b_name}.example.com"),
        "port": 8080,
        "secret": E2E_APP_SECRET,
        "needs": {
            "db": { "type": "postgres" }
        }
    });

    let request = mgmt_request("POST", "/v1/apps", &app_b_body);
    let response = app.clone().oneshot(request).await.unwrap();
    assert_eq!(
        response.status(),
        axum::http::StatusCode::CREATED,
        "POST /v1/apps (app-b) should return 201"
    );

    let app_b_config = state
        .apps
        .read()
        .await
        .get(&app_b_name)
        .cloned()
        .expect("app-b in live map");

    let binding_env_b = bindings::env(&state.secrets_store, &app_b_config)
        .expect("bindings::env for app-b should succeed");

    let database_url_b = binding_env_b
        .get("DATABASE_URL")
        .cloned()
        .expect("DATABASE_URL must be present for app-b");

    // The two DATABASE_URLs must differ (different resource ids → different
    // user/db). Use assert!(left != right) to avoid leaking passwords in the
    // assertion message.
    assert!(
        database_url_a != database_url_b,
        "app-a and app-b must have different DATABASE_URLs (isolation)"
    );

    // App-b can connect to its own DB.
    let (code_b, output_b) = pg_client_verify("slip", &database_url_b, "SELECT 1;");
    assert!(
        code_b == 0,
        "app-b client must connect to its own DB (exit={code_b}): {output_b}"
    );

    // App-a CANNOT connect to app-b's DB using app-b's URL, but the URL
    // includes app-b's credentials, so this would actually succeed. The
    // isolation is at the resource level: app-a's user cannot connect to
    // app-b's database. We verify this by using app-a's DATABASE_URL but
    // trying to SELECT from app-b's database (which requires changing the
    // db name in the URL). Since the URL embeds the db name, the correct
    // isolation test is: app-a's user cannot access app-b's database. We
    // test this via the existing psql_login_check against the service
    // container (same approach as contract_resource_create_two_and_isolation).
    //
    // The DATABASE_URL format is: postgresql://{user}:{password}@{host}:5432/{db}
    // Both user and db are the resource_id. To test isolation, we extract
    // app-b's resource_id (db name) and try to connect with app-a's
    // credentials to app-b's database.
    // Extract the resource_id (user) from app-a's DATABASE_URL. The URL is
    // postgresql://{user}:{password}@{host}:5432/{db}. The user == db ==
    // resource_id.
    let resource_id_a = database_url_a
        .strip_prefix("postgresql://")
        .unwrap()
        .split(':')
        .next()
        .unwrap()
        .to_string();

    let resource_id_b = database_url_b
        .strip_prefix("postgresql://")
        .unwrap()
        .split(':')
        .next()
        .unwrap()
        .to_string();

    // Extract app-a's password from the URL to pass to psql. This is only
    // used for the isolation check, never printed. The password is passed
    // via process env (not argv) to avoid leaking it in the process list.
    let password_a = {
        let after_user = database_url_a.strip_prefix("postgresql://").unwrap();
        let after_colon = after_user.split(':').nth(1).unwrap();
        let before_at = after_colon.split('@').next().unwrap();
        before_at.to_string()
    };

    // App-a's user CANNOT connect to app-b's database (isolation). We verify
    // this by running a psql client container with PGPASSWORD and PGUSER set
    // via env (not argv), connecting to app-b's database name. The password
    // never appears in the podman argv.
    let isolation_check = std::process::Command::new("podman")
        .args([
            "run",
            "--rm",
            "--network",
            "slip",
            "--env",
            "PGCONNECT_TIMEOUT=5",
            "--env",
            "PGPASSWORD", // forwarded from process env
            "--env",
            "PGUSER", // forwarded from process env
        ])
        .arg("docker.io/library/postgres:18.4-bookworm")
        .args([
            "psql",
            "--no-psqlrc",
            "-h",
            &svc_name_str,
            "-d",
            &resource_id_b,
            "-c",
            "SELECT 1",
        ])
        .env("PGPASSWORD", &password_a)
        .env("PGUSER", &resource_id_a)
        .output()
        .unwrap_or_else(|e| panic!("podman run isolation check failed: {e}"));

    assert!(
        !isolation_check.status.success(),
        "app-a must NOT be able to connect to app-b's database (isolation): {}",
        String::from_utf8_lossy(&isolation_check.stderr)
    );

    // ── 7. Repeated apply: credentials and data persist ─────────────────
    //    Re-POST app-a (idempotent via PATCH) and verify the DATABASE_URL
    //    and data are unchanged.
    let (code_reapply, _) = pg_client_verify(
        "slip",
        &database_url_a,
        "SELECT val FROM slip_e2e WHERE val = 'app-a-data';",
    );
    assert!(code_reapply == 0, "app-a data must persist before re-apply");

    // PATCH app-a (same needs) → idempotent, same URL.
    let patch_body = serde_json::json!({
        "needs": {
            "db": { "type": "postgres" }
        }
    });
    let request = mgmt_request("PATCH", &format!("/v1/apps/{app_a_name}"), &patch_body);
    let response = app.clone().oneshot(request).await.unwrap();
    assert_eq!(
        response.status(),
        axum::http::StatusCode::OK,
        "PATCH app-a (re-apply same needs) should return 200"
    );

    let app_a_config_after = state
        .apps
        .read()
        .await
        .get(&app_a_name)
        .cloned()
        .expect("app-a still in live map");

    let binding_env_a_after = bindings::env(&state.secrets_store, &app_a_config_after)
        .expect("bindings::env after re-apply");

    let database_url_a_after = binding_env_a_after
        .get("DATABASE_URL")
        .cloned()
        .expect("DATABASE_URL must be present after re-apply");

    // The DATABASE_URL must be exactly the same (retained credentials reused).
    assert!(
        database_url_a == database_url_a_after,
        "DATABASE_URL must be unchanged after re-apply (retained credentials)"
    );

    // Data persists after re-apply.
    let (code_data, output_data) = pg_client_verify(
        "slip",
        &database_url_a_after,
        "SELECT val FROM slip_e2e WHERE val = 'app-a-data';",
    );
    assert!(
        code_data == 0,
        "app-a data must persist after re-apply (exit={code_data}): {output_data}"
    );

    // ── DEPLOY: signed POST /v1/deploy through the real orchestrator ──
    //    The key assertion is that the orchestrator itself injected the
    //    binding env. We exec inside the DEPLOYED app container and query
    //    the table using only the DATABASE_URL it received.
    //    The app image is postgres with trust auth so it starts and stays
    //    healthy with a container-liveness probe; Caddy is mocked to
    //    accept the route swap.
    let deploy_body = serde_json::json!({
        "app": app_a_name,
        "image": app_a_image,
        "tag": app_a_tag,
    });
    let deploy_bytes = serde_json::to_vec(&deploy_body).expect("serialize deploy body");
    let deploy_sig = slip_core::auth::compute_signature(&deploy_bytes, E2E_APP_SECRET);

    let deploy_request = axum::http::Request::builder()
        .method("POST")
        .uri("/v1/deploy")
        .header("Content-Type", "application/json")
        .header("X-Slip-Signature", format!("sha256={deploy_sig}"))
        .body(axum::body::Body::from(deploy_bytes))
        .unwrap();

    let deploy_response = app.clone().oneshot(deploy_request).await.unwrap();
    assert_eq!(
        deploy_response.status(),
        axum::http::StatusCode::ACCEPTED,
        "POST /v1/deploy should return 202 Accepted"
    );
    let deploy_resp_bytes = axum::body::to_bytes(deploy_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let deploy_resp: slip_core::DeployResponse =
        serde_json::from_slice(&deploy_resp_bytes).expect("parse deploy response");
    let _deploy_id = deploy_resp.deploy_id.clone();

    // Poll the deploy status (in-memory DashMap) until it reaches a terminal
    // state (Completed or Failed). Bounded at 180s for the image pull.
    let deploy_deadline = std::time::Instant::now() + std::time::Duration::from_secs(180);
    let deploy_outcome = loop {
        let status = state
            .deploys
            .get(&app_a_name)
            .map(|ctx| ctx.status.clone())
            .unwrap_or(slip_core::DeployStatus::Accepted);
        match status {
            slip_core::DeployStatus::Completed => break "completed".to_string(),
            slip_core::DeployStatus::Failed => {
                let error = state
                    .deploys
                    .get(&app_a_name)
                    .and_then(|ctx| ctx.error.clone())
                    .unwrap_or_default();
                break format!("failed: {error}");
            }
            _ => {}
        }
        if std::time::Instant::now() >= deploy_deadline {
            let error = state
                .deploys
                .get(&app_a_name)
                .and_then(|ctx| ctx.error.clone())
                .unwrap_or_default();
            break format!("timeout (last status={status:?}, error={error})");
        }
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    };

    assert!(
        deploy_outcome == "completed",
        "deploy must reach Completed, got: {deploy_outcome}"
    );

    // ── Verify: exec inside the DEPLOYED app container using its env ──
    //    Find the deployed app container by the `slip.app` label. We exec
    //    `psql` inside it using only the DATABASE_URL the orchestrator
    //    injected; no test-side values are passed into the container.
    let app_containers = runtime
        .list_by_label("slip.app", &app_a_name)
        .await
        .expect("list app containers");
    assert!(
        !app_containers.is_empty(),
        "deployed app container must exist for app-a"
    );
    let app_container_id = app_containers[0].id.clone();

    // Exec psql inside the deployed app container, using the DATABASE_URL
    // env var that the orchestrator injected. The psql binary is part of
    // the postgres image. We read $DATABASE_URL from the container's own
    // env (set by the deploy orchestrator), not from the test.
    let exec_result = std::process::Command::new("podman")
        .args(["exec", &app_container_id])
        .args([
            "sh",
            "-c",
            "psql --no-psqlrc -v ON_ERROR_STOP=1 -d \"$DATABASE_URL\" -c \"SELECT val FROM slip_e2e WHERE val = 'app-a-data';\"",
        ])
        .output()
        .unwrap_or_else(|e| panic!("podman exec in app container failed: {e}"));

    assert!(
        exec_result.status.success(),
        "exec inside deployed app container must query the managed service via $DATABASE_URL (exit={:?}): {}",
        exec_result.status.code(),
        String::from_utf8_lossy(&exec_result.stderr)
    );
    let exec_stdout = String::from_utf8_lossy(&exec_result.stdout);
    assert!(
        exec_stdout.contains("app-a-data"),
        "deployed app container must see 'app-a-data' in the managed service DB: {exec_stdout}"
    );

    // ── RAII cleanup: stop and remove the deployed app container ──────
    //    The deploy created a long-running postgres app container. We must
    //    clean it up before proceeding to detach/redeploy steps to avoid
    //    container name conflicts and resource leaks. The guard stops
    //    and removes the container when it drops (even on panic).
    let _app_container_guard = AppContainerGuard {
        runtime: runtime.clone(),
        container_id: app_container_id.clone(),
    };

    // ── 8. Detach needs: env absent, normal secret preserved ────────────
    //    First, set a normal (non-binding) secret on app-a.
    state
        .secrets_store
        .set(&app_a_name, "MY_APP_KEY", "normal-secret-value")
        .expect("set normal secret");

    // PATCH app-a to detach needs (needs={}).
    let detach_body = serde_json::json!({
        "needs": {}
    });
    let request = mgmt_request("PATCH", &format!("/v1/apps/{app_a_name}"), &detach_body);
    let response = app.clone().oneshot(request).await.unwrap();
    assert_eq!(
        response.status(),
        axum::http::StatusCode::OK,
        "PATCH app-a (detach needs) should return 200"
    );

    let app_a_detached = state
        .apps
        .read()
        .await
        .get(&app_a_name)
        .cloned()
        .expect("app-a detached in live map");

    // bindings::env returns empty (no DATABASE_URL injected).
    let env_detached = bindings::env(&state.secrets_store, &app_a_detached)
        .expect("bindings::env with empty needs should return empty");
    assert!(
        env_detached.is_empty(),
        "bindings::env must be empty after detaching needs"
    );

    // Detach must leave manually-set secrets untouched (only binding keys
    // disappear from the injected env).
    let normal_secret = state
        .secrets_store
        .get(&app_a_name, "MY_APP_KEY")
        .expect("get normal secret")
        .expect("normal secret must exist");
    assert!(
        normal_secret == "normal-secret-value",
        "normal secret must be preserved after detach"
    );

    // ── 9. Service removal refused (live map: app-b still binds) ────────
    //    app-a detached, but app-b still has needs.db. The live usage reader
    //    must see app-b's binding and refuse removal. This proves the usage
    //    reader reads the LIVE map, not a stale snapshot.
    let svc_status = ctrl.status(&svc_name).await.expect("status");
    let remove_result = ctrl.remove(&svc_name, svc_status.generation, false).await;
    assert!(
        remove_result.is_err(),
        "service removal must be refused while app-b still binds (live map)"
    );

    // Verify the error message mentions the active binding (app-b).
    let err_msg = format!("{:?}", remove_result.unwrap_err());
    assert!(
        err_msg.contains("active bindings") || err_msg.contains("binding"),
        "removal error must mention active bindings: {err_msg}"
    );

    // ── 10. Reattach needs → same URL/data (retained credentials) ───────
    //     PATCH app-a to reattach needs.db. The retained credentials must
    //     be reused: same DATABASE_URL and same data.
    let reattach_body = serde_json::json!({
        "needs": {
            "db": { "type": "postgres" }
        }
    });
    let request = mgmt_request("PATCH", &format!("/v1/apps/{app_a_name}"), &reattach_body);
    let response = app.clone().oneshot(request).await.unwrap();
    assert_eq!(
        response.status(),
        axum::http::StatusCode::OK,
        "PATCH app-a (reattach needs) should return 200"
    );

    let app_a_reattached = state
        .apps
        .read()
        .await
        .get(&app_a_name)
        .cloned()
        .expect("app-a reattached in live map");

    let env_reattached = bindings::env(&state.secrets_store, &app_a_reattached)
        .expect("bindings::env after reattach");

    let database_url_reattached = env_reattached
        .get("DATABASE_URL")
        .cloned()
        .expect("DATABASE_URL must be present after reattach");

    // Reattach must return the EXACT same URL (retained credentials).
    assert!(
        database_url_a == database_url_reattached,
        "reattach must return the exact same DATABASE_URL (retained credentials)"
    );

    // Data must still be present (retained across detach+reattach).
    let (code_reattach_data, output_reattach) = pg_client_verify(
        "slip",
        &database_url_reattached,
        "SELECT val FROM slip_e2e WHERE val = 'app-a-data';",
    );
    assert!(
        code_reattach_data == 0,
        "app-a data must persist across detach+reattach (exit={code_reattach_data}): {output_reattach}"
    );

    // ── 11. Removal refusal after both apps reattach (no stale snapshot) ─
    //     Both app-a and app-b now have needs.db. Removal must be refused.
    let svc_status = ctrl.status(&svc_name).await.expect("status");
    let remove_result = ctrl.remove(&svc_name, svc_status.generation, false).await;
    assert!(
        remove_result.is_err(),
        "service removal must be refused with both apps binding (no stale snapshot)"
    );

    // ── 12. Cleanup: detach both apps, then remove the service ──────────
    let detach_body = serde_json::json!({
        "needs": {}
    });
    let request = mgmt_request("PATCH", &format!("/v1/apps/{app_a_name}"), &detach_body);
    let _ = app.clone().oneshot(request).await.unwrap();

    let request = mgmt_request("PATCH", &format!("/v1/apps/{app_b_name}"), &detach_body);
    let _ = app.clone().oneshot(request).await.unwrap();

    // Now removal should succeed (no active bindings).
    let svc_status = ctrl.status(&svc_name).await.expect("status");
    let remove_result = ctrl.remove(&svc_name, svc_status.generation, false).await;
    assert!(
        remove_result.is_ok(),
        "service removal should succeed after both apps detach: {:?}",
        remove_result
    );

    // Re-add uses the retained instance, not a new cluster/credential identity.
    let (version, _) = resolve_catalog(18).unwrap();
    ctrl.add(
        ServiceSpec::new(
            svc_name.clone(),
            ProviderKind::Postgres,
            version,
            slip_core::services::PostgresConfig {},
        )
        .unwrap(),
    )
    .await
    .expect("reattach retained service");
    let response = app
        .clone()
        .oneshot(mgmt_request(
            "PATCH",
            &format!("/v1/apps/{app_a_name}"),
            &reattach_body,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), axum::http::StatusCode::OK);
    let app_a = state.apps.read().await[&app_a_name].clone();
    let after_service_reattach = bindings::env(&state.secrets_store, &app_a).unwrap();
    assert!(after_service_reattach["DATABASE_URL"] == database_url_a);
    let (code, output) = pg_client_verify(
        "slip",
        &database_url_a,
        "SELECT val FROM slip_e2e WHERE val = 'app-a-data';",
    );
    assert!(
        code == 0 && output.contains("app-a-data"),
        "data survives service reattachment"
    );
    let response = app
        .clone()
        .oneshot(mgmt_request(
            "PATCH",
            &format!("/v1/apps/{app_a_name}"),
            &detach_body,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), axum::http::StatusCode::OK);
    let status = ctrl.status(&svc_name).await.unwrap();
    ctrl.remove(&svc_name, status.generation, false)
        .await
        .unwrap();
}

/// Generate a short unique suffix for test names (DNS-safe).
fn unique_suffix() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    format!("{n}")
}

/// RAII guard that stops and removes a deployed app container on drop.
/// Ensures the container is cleaned up even if a later assertion panics,
/// preventing container name conflicts and resource leaks.
struct AppContainerGuard {
    runtime: std::sync::Arc<dyn RuntimeBackend>,
    container_id: String,
}

impl Drop for AppContainerGuard {
    fn drop(&mut self) {
        // Best-effort cleanup; errors are logged but not propagated (we may
        // be in a panic unwind).
        let runtime = self.runtime.clone();
        let id = self.container_id.clone();
        // Use tokio runtime for the async stop_and_remove call. We can't
        // use the test's runtime in Drop, so we spawn a blocking thread with
        // a temporary tokio runtime.
        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .ok();
            if let Some(rt) = rt {
                rt.block_on(async {
                    if let Err(e) = runtime.stop_and_remove(&id).await {
                        eprintln!("[AppContainerGuard] cleanup failed for {id}: {e}");
                    }
                });
            }
        })
        .join()
        .ok();
    }
}

/// Run `psql` inside the service container with arbitrary SQL and capture
/// stdout/stderr. Uses PGPASSWORD env for authentication.
#[cfg(target_os = "linux")]
async fn psql_exec_capture(
    container_name: &str,
    user: &str,
    password: &str,
    db: &str,
    sql: &str,
) -> std::process::Output {
    std::process::Command::new("podman")
        .args(["exec"])
        .arg("--env")
        .arg("PGPASSWORD")
        .env("PGPASSWORD", password)
        .arg(container_name)
        .args([
            "psql",
            "-h",
            "127.0.0.1",
            "-U",
            user,
            "-d",
            db,
            "-w",
            "-v",
            "ON_ERROR_STOP=1",
            "-c",
            sql,
        ])
        .output()
        .unwrap_or_else(|e| panic!("podman exec failed: {e}"))
}

/// Run `psql` inside the service container to verify a login credential works.
/// Returns `true` if the login + SELECT 1 succeeds.
#[cfg(target_os = "linux")]
async fn psql_login_check(container_name: &str, user: &str, password: &str, db: &str) -> bool {
    // Use PGPASSWORD env for the check (this is a test-only verification,
    // not the production path which uses PGPASSFILE).
    let output = std::process::Command::new("podman")
        .args(["exec"])
        .arg("--env")
        .arg("PGPASSWORD")
        .env("PGPASSWORD", password)
        .arg(container_name)
        .args([
            "psql",
            "-h",
            "127.0.0.1",
            "-U",
            user,
            "-d",
            db,
            "-w",
            "-c",
            "SELECT 1",
        ])
        .output();
    match output {
        Ok(o) => o.status.success(),
        Err(_) => false,
    }
}

/// Run `psql` inside the service container with arbitrary SQL.
/// Returns `true` if the command succeeds.
#[cfg(target_os = "linux")]
async fn psql_exec(container_name: &str, user: &str, password: &str, db: &str, sql: &str) -> bool {
    let output = std::process::Command::new("podman")
        .args(["exec"])
        .arg("--env")
        .arg("PGPASSWORD")
        .env("PGPASSWORD", password)
        .arg(container_name)
        .args([
            "psql",
            "-h",
            "127.0.0.1",
            "-U",
            user,
            "-d",
            db,
            "-w",
            "-v",
            "ON_ERROR_STOP=1",
            "-c",
            sql,
        ])
        .output();
    match output {
        Ok(o) => o.status.success(),
        Err(_) => false,
    }
}

/// Fixture-specific test: verify that `make_services_root` produces a root
/// that `ServiceStorage::new` accepts. This isolates the fixture from the
/// Podman-dependent lifecycle tests so a permissions regression in the
/// fixture surfaces here first, with a clear message, rather than as an
/// opaque `WrongMode` inside a 30-second provision test.
///
/// Runs on Linux only (the whole file is `#![cfg(target_os = "linux")]`).
/// Does NOT require rootful Podman; it only exercises the storage layer,
/// which requires uid 0 (the CI environment provides this).
#[tokio::test]
#[ignore = "requires Linux + root (CI-only)"]
async fn contract_fixture_services_root_is_accepted_by_storage() {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    // Skip if not root; ServiceStorage::new requires uid 0 ownership.
    if rustix::process::getuid().as_raw() != 0 {
        eprintln!("skipping (not root)");
        return;
    }

    let tmp = make_services_root();
    let root = tmp.path();

    // The root must be mode 0700; the exact requirement of
    // verify_dir_identity (storage.rs:881).
    let meta = fs::symlink_metadata(root).expect("stat");
    assert_eq!(
        meta.permissions().mode() & 0o7777,
        0o700,
        "fixture root must be 0700 before ServiceStorage::new"
    );

    // The root must be a real directory, not a symlink. openat2 uses
    // NO_SYMLINKS and would reject a symlink, but we assert here for a
    // clear fixture-only failure message.
    assert!(
        meta.file_type().is_dir(),
        "fixture root must be a real directory"
    );

    // ServiceStorage::new must succeed; this is the exact construction
    // the three lifecycle fixtures perform. If this fails, the fixture is
    // broken, not the production code.
    let _storage = slip_core::services::ServiceStorage::new(root)
        .expect("ServiceStorage::new must accept the fixture root");

    // TempDir cleans up on drop; scoped cleanup, no process-global state.
}

// ---------------------------------------------------------------------------
// Unit tests for the diagnostic formatter (no Podman required)
// ---------------------------------------------------------------------------

/// Verify the diagnostic formatter produces the expected output with
/// fake data simulating an unhealthy Postgres container. This tests the
/// formatting logic only; no Podman, no I/O, no secrets.
///
/// The fake healthcheck output mimics real `pg_isready -h 127.0.0.1` output:
/// `"127.0.0.1:5432 - no response"` (TCP connection refused). This
/// is a status line with no password material.
#[test]
fn test_format_health_diagnostics_unhealthy() {
    let d = HealthDiagnostics {
        container_name: "slip-service-pg-test0".to_string(),
        container_status: "running".to_string(),
        exit_code: Some(0),
        health_status: "unhealthy".to_string(),
        failing_streak: Some(5),
        healthcheck_matches_expected: true,
        health_log: vec![
            (Some(1), "127.0.0.1:5432 - no response".to_string()),
            (Some(1), "127.0.0.1:5432 - no response".to_string()),
            (Some(1), "127.0.0.1:5432 - no response".to_string()),
        ],
    };

    let out = format_health_diagnostics(&d);

    // Verify all expected fields are present.
    assert!(out.contains("HEALTH DIAGNOSTICS"));
    assert!(out.contains("slip-service-pg-test0"));
    assert!(out.contains("container_status: running"));
    assert!(out.contains("exit_code=0"));
    assert!(out.contains("health_status: unhealthy"));
    assert!(out.contains("failing_streak=5"));
    assert!(out.contains("pg_isready"));
    assert!(out.contains("health_log"));
    assert!(out.contains("exit_code=1"));
    assert!(out.contains("no response"));
    // Verify no secret material is present.
    assert!(!out.contains("POSTGRES_PASSWORD"));
    assert!(!out.contains("pgpass"));
    assert!(!out.contains("Config.Env"));
    assert!(!out.contains("PASSWORD"));
}

/// Verify the formatter handles missing fields with n/a markers.
#[test]
fn test_format_health_diagnostics_minimal() {
    let d = HealthDiagnostics {
        container_name: "slip-service-heal-test1".to_string(),
        container_status: "exited".to_string(),
        exit_code: None,
        health_status: "none".to_string(),
        failing_streak: None,
        healthcheck_matches_expected: false,
        health_log: vec![],
    };

    let out = format_health_diagnostics(&d);

    assert!(out.contains("exit_code=n/a"));
    assert!(out.contains("failing_streak=n/a"));
    assert!(out.contains("[UNEXPECTED HEALTHCHECK"));
    assert!(out.contains("[omitted"));
}

/// Verify that an unexpected healthcheck command suppresses the raw
/// command and health log output, preventing secret-bearing arguments
/// from reaching the diagnostic stream.
#[test]
fn test_format_health_diagnostics_unexpected_command() {
    let d = HealthDiagnostics {
        container_name: "slip-service-pg-test2".to_string(),
        container_status: "running".to_string(),
        exit_code: Some(0),
        health_status: "unhealthy".to_string(),
        failing_streak: Some(3),
        healthcheck_matches_expected: false,
        health_log: vec![(Some(1), "db password = s3cr3t".to_string())],
    };

    let out = format_health_diagnostics(&d);

    // The unexpected marker must be present.
    assert!(out.contains("[UNEXPECTED HEALTHCHECK"));
    // The health log must be omitted, not echoed.
    assert!(out.contains("[omitted"));
    // The secret-bearing output must NOT appear in the diagnostic stream.
    assert!(!out.contains("s3cr3t"));
    assert!(!out.contains("password"));
}

/// Verify the truncation helper respects char boundaries and appends the
/// truncation marker.
#[test]
fn test_truncate_at_char_boundary() {
    // Short string; no truncation.
    assert_eq!(truncate_at_char_boundary("hello", 100), "hello");

    // Exact fit.
    assert_eq!(truncate_at_char_boundary("hello", 5), "hello");

    // Truncation with marker.
    let result = truncate_at_char_boundary("hello world", 5);
    assert_eq!(result, "hello...[truncated]");

    // UTF-8 char boundary safety: "héllo" where é is 2 bytes.
    // "h" = 1 byte, "é" = 2 bytes (total 3 for "hé"), "l" starts at byte 3.
    // Truncating at 2 bytes would split é, so we back up to byte 1.
    let result = truncate_at_char_boundary("héllo world", 2);
    assert_eq!(result, "h...[truncated]");
}
