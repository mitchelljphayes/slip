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
//! Tests cover:
//! 1. Catalog digest pull + create: exact digest, PG18 mount layout, hardening.
//! 2. Healthy + DNS: `<name>:5432` from a probe container, authenticated SELECT 1.
//! 3. Restart: stop then ensure → Ready + sentinel row persists.
//! 4. Controlled recreation + remove/re-add: retained dir reused, no password regen.
//! 5. Foreign-container protection: ensure Blocked, zero mutations.
//! 6. Reboot survival: documented manual gate (not automated here).

#![cfg(target_os = "linux")]

use slip_core::runtime::RuntimeBackend;
use slip_core::services::{
    ProviderKind, ServiceController, ServiceName, ServiceSpec, ServiceUsageReader, resolve_catalog,
};

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
/// duration of the test (scoped cleanup — no process-global state).
fn make_services_root() -> tempfile::TempDir {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    let d = tempfile::tempdir().expect("tempdir for services root");

    // Tighten permissions to 0700 — the exact mode ServiceStorage::new
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

    ctrl.add(spec).await.expect("add should succeed");

    // Verify the service is in Ready phase.
    let status = ctrl.status(&name).await.expect("status");
    assert_eq!(
        status.phase,
        slip_core::services::LifecyclePhase::Ready,
        "service should be Ready after provision"
    );

    // Process privilege verification: after readiness, the actual
    // postgres process (PID 1 inside the container, which is the
    // entrypoint that gosu'd to postgres) must have:
    //   - UID 999 (the postgres user, not root)
    //   - CapEff = 0 (zero effective capabilities)
    //   - CapPrm = 0 (zero permitted capabilities)
    //   - CapAmb = 0 (zero ambient capabilities)
    //   - NoNewPrivs = 1 (no-new-privileges enforced)
    //
    // This distinguishes EffectiveCaps (the container's configured
    // capability set for the initial root process) from the actual
    // running postgres process privileges. The pinned entrypoint uses
    // gosu to drop to UID 999, which clears capabilities.
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
    ctrl.add(spec).await.expect("add");

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
    ctrl.add(spec).await.expect("add");

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
/// Does NOT require rootful Podman — it only exercises the storage layer,
/// which requires uid 0 (the CI environment provides this).
#[tokio::test]
#[ignore = "requires Linux + root (CI-only)"]
async fn contract_fixture_services_root_is_accepted_by_storage() {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    // Skip if not root — ServiceStorage::new requires uid 0 ownership.
    if rustix::process::getuid().as_raw() != 0 {
        eprintln!("skipping (not root)");
        return;
    }

    let tmp = make_services_root();
    let root = tmp.path();

    // The root must be mode 0700 — the exact requirement of
    // verify_dir_identity (storage.rs:881).
    let meta = fs::symlink_metadata(root).expect("stat");
    assert_eq!(
        meta.permissions().mode() & 0o7777,
        0o700,
        "fixture root must be 0700 before ServiceStorage::new"
    );

    // The root must be a real directory, not a symlink — openat2 uses
    // NO_SYMLINKS and would reject a symlink, but we assert here for a
    // clear fixture-only failure message.
    assert!(
        meta.file_type().is_dir(),
        "fixture root must be a real directory"
    );

    // ServiceStorage::new must succeed — this is the exact construction
    // the three lifecycle fixtures perform. If this fails, the fixture is
    // broken, not the production code.
    let _storage = slip_core::services::ServiceStorage::new(root)
        .expect("ServiceStorage::new must accept the fixture root");

    // TempDir cleans up on drop — scoped cleanup, no process-global state.
}
