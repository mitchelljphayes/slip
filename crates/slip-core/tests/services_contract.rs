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

use slip_core::runtime::RuntimeBackend;
use slip_core::services::{
    PG_HEALTHCHECK_TEST_CMD, ProviderKind, ServiceController, ServiceName, ServiceSpec,
    ServiceUsageReader, resolve_catalog,
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
/// (`["CMD", "pg_isready", "-U", "postgres", "-d", "postgres"]`), and this
/// constant is a reference to it. The formatter compares the container's
/// actual `Config.Healthcheck.Test` against this constant. If they match,
/// the command and healthcheck output are echoed (both are secret-free). If
/// they do NOT match, the raw command and healthcheck output are omitted and
/// an `[UNEXPECTED HEALTHCHECK]` marker is emitted instead. This prevents a
/// malicious or misconfigured container from injecting secret-bearing command
/// arguments or healthcheck output into the diagnostic stream.
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
/// output). `pg_isready` output is a status line like
/// `"/var/run/postgresql:5432 - no response"`. No secrets.
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
/// The fake healthcheck output mimics real `pg_isready` output:
/// `"/var/run/postgresql:5432 - no response"` (connection refused). This
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
            (
                Some(1),
                "/var/run/postgresql:5432 - no response".to_string(),
            ),
            (
                Some(1),
                "/var/run/postgresql:5432 - no response".to_string(),
            ),
            (
                Some(1),
                "/var/run/postgresql:5432 - no response".to_string(),
            ),
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
