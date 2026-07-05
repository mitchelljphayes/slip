//! Integration tests for config fixture files.
//!
//! Parses each fixture from `tests/fixtures/` using the public API
//! (`slip_core::SlipConfig` / `slip_core::AppConfig`) and asserts key fields.

use std::fs;

/// Parse the full daemon config fixture.
#[test]
fn slip_config_fixture_parses() {
    let raw =
        fs::read_to_string("tests/fixtures/slip.toml").expect("slip.toml fixture should exist");
    let config: slip_core::SlipConfig =
        toml::from_str(&raw).expect("slip.toml should parse as SlipConfig");

    assert_eq!(config.server.listen.to_string(), "127.0.0.1:7890");
    assert_eq!(config.caddy.admin_api, "http://localhost:2019");
    assert_eq!(config.storage.path.to_string_lossy(), "/var/lib/slip");
    // `${SLIP_SECRET}` deserializes as a literal string — no env var needed.
    assert_eq!(config.auth.secret, "${SLIP_SECRET}");
}

/// Parse the single-container app fixture.
#[test]
fn app_container_fixture_parses() {
    let raw = fs::read_to_string("tests/fixtures/app-container.toml")
        .expect("app-container.toml fixture should exist");
    let app: slip_core::AppConfig =
        toml::from_str(&raw).expect("app-container.toml should parse as AppConfig");

    assert_eq!(app.app.name, "my-app");
    assert_eq!(app.app.image, "ghcr.io/youruser/my-app");
    assert_eq!(app.deploy.strategy, "blue-green");
    assert_eq!(app.routing.domain.as_deref(), Some("myapp.yourdomain.com"));
    assert_eq!(app.routing.port, Some(8080));
    assert!(app.volumes.is_empty());
}

/// Parse the worker app fixture (no `[routing]` table).
#[test]
fn app_worker_fixture_parses() {
    let raw = fs::read_to_string("tests/fixtures/app-worker.toml")
        .expect("app-worker.toml fixture should exist");
    let app: slip_core::AppConfig =
        toml::from_str(&raw).expect("app-worker.toml should parse as AppConfig");

    assert_eq!(app.app.name, "pipeline");
    assert_eq!(app.deploy.strategy, "recreate");
    assert_eq!(app.volumes.len(), 1);
    assert_eq!(
        app.volumes[0].host_path,
        "/var/lib/slip/volumes/pipeline/dlt-state"
    );
    assert_eq!(app.volumes[0].mount_path, "/app/data");
    assert!(!app.volumes[0].read_only);
}

/// Parse the pod app fixture.
#[test]
fn app_pod_fixture_parses() {
    let raw = fs::read_to_string("tests/fixtures/app-pod.toml")
        .expect("app-pod.toml fixture should exist");
    let app: slip_core::AppConfig =
        toml::from_str(&raw).expect("app-pod.toml should parse as AppConfig");

    assert_eq!(app.app.name, "statstream");
    assert_eq!(app.deploy.strategy, "recreate");
    // Two routes (the `container` field is repo-config-only and silently ignored
    // by serde when parsing as AppConfig).
    assert_eq!(app.routing.routes.len(), 2);
    assert_eq!(app.routing.routes[0].hostname, "statstream.yourdomain.com");
    assert_eq!(app.routing.routes[1].hostname, "dagster.yourdomain.com");
    // Two volumes.
    assert_eq!(app.volumes.len(), 2);
    assert_eq!(
        app.volumes[0].host_path,
        "/var/lib/slip/volumes/statstream/dagster-home"
    );
    assert_eq!(
        app.volumes[1].host_path,
        "/var/lib/slip/volumes/statstream/catalog"
    );
}
