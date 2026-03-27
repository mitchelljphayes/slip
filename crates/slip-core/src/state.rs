//! Persistent state for deployed apps — JSON file-based storage and startup reconciliation.

use std::collections::HashMap;
use std::path::Path;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::caddy::{CaddyClient, RouteInfo};
use crate::config::AppConfig;
use crate::deploy::{AppRuntimeState, AppStatus};
use crate::docker::DockerClient;
use crate::error::CaddyError;

// ─── Persisted state shape ────────────────────────────────────────────────────

/// Subset of [`AppRuntimeState`] that gets persisted to JSON.
///
/// We deliberately omit fields that are not meaningful across restarts
/// (e.g. `previous_container_id`, `deploy_id`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistedAppState {
    pub current_tag: Option<String>,
    pub previous_tag: Option<String>,
    pub current_container_id: Option<String>,
    pub current_port: Option<u16>,
    pub deployed_at: Option<DateTime<Utc>>,
}

impl From<&AppRuntimeState> for PersistedAppState {
    fn from(s: &AppRuntimeState) -> Self {
        Self {
            current_tag: s.current_tag.clone(),
            previous_tag: s.previous_tag.clone(),
            current_container_id: s.current_container_id.clone(),
            current_port: s.current_port,
            deployed_at: s.deployed_at,
        }
    }
}

impl From<PersistedAppState> for AppRuntimeState {
    fn from(p: PersistedAppState) -> Self {
        // Assume Running if we have a container ID; otherwise NotDeployed.
        let status = if p.current_container_id.is_some() {
            AppStatus::Running
        } else {
            AppStatus::NotDeployed
        };
        Self {
            status,
            current_tag: p.current_tag,
            previous_tag: p.previous_tag,
            current_container_id: p.current_container_id,
            previous_container_id: None,
            current_port: p.current_port,
            deployed_at: p.deployed_at,
            deploy_id: None,
        }
    }
}

// ─── Save ─────────────────────────────────────────────────────────────────────

/// Save an app's runtime state to `{state_dir}/{app_name}.json`.
///
/// Creates `state_dir` if it does not yet exist.
pub fn save_app_state(
    state_dir: &Path,
    app_name: &str,
    state: &AppRuntimeState,
) -> Result<(), std::io::Error> {
    std::fs::create_dir_all(state_dir)?;

    let persisted = PersistedAppState::from(state);
    let json = serde_json::to_string_pretty(&persisted)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

    let path = state_dir.join(format!("{app_name}.json"));
    std::fs::write(path, json)
}

// ─── Load ─────────────────────────────────────────────────────────────────────

/// Load all app states from `{state_dir}/*.json`.
///
/// Each file's stem (without `.json`) becomes the app name key.
/// If `state_dir` does not exist, returns an empty map.
/// Files that cannot be parsed are silently skipped with a warning.
pub fn load_app_states(
    state_dir: &Path,
) -> Result<HashMap<String, AppRuntimeState>, std::io::Error> {
    if !state_dir.exists() {
        return Ok(HashMap::new());
    }

    let mut states = HashMap::new();

    for entry in std::fs::read_dir(state_dir)? {
        let entry = entry?;
        let path = entry.path();

        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }

        let app_name = match path.file_stem().and_then(|s| s.to_str()) {
            Some(name) => name.to_owned(),
            None => continue,
        };

        let content = match std::fs::read_to_string(&path) {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(path = %path.display(), error = %e, "failed to read state file, skipping");
                continue;
            }
        };

        let persisted: PersistedAppState = match serde_json::from_str(&content) {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!(path = %path.display(), error = %e, "failed to parse state file, skipping");
                continue;
            }
        };

        states.insert(app_name, AppRuntimeState::from(persisted));
    }

    Ok(states)
}

// ─── Verify containers ────────────────────────────────────────────────────────

/// Verify that persisted containers still exist in Docker.
///
/// For each app state that has a `current_container_id`, calls
/// [`DockerClient::container_exists`]. If the container is gone, the state is
/// cleaned up and the status set to [`AppStatus::NotDeployed`].
pub async fn verify_containers(
    docker: &DockerClient,
    states: HashMap<String, AppRuntimeState>,
) -> HashMap<String, AppRuntimeState> {
    let mut verified = HashMap::with_capacity(states.len());

    for (app_name, mut state) in states {
        match &state.current_container_id {
            None => {
                // Nothing to verify — keep as-is.
                verified.insert(app_name, state);
            }
            Some(container_id) => {
                match docker.container_exists(container_id).await {
                    Ok(true) => {
                        tracing::info!(app = %app_name, container_id, "container verified running");
                        verified.insert(app_name, state);
                    }
                    Ok(false) => {
                        tracing::warn!(
                            app = %app_name,
                            container_id,
                            "container no longer exists, clearing state"
                        );
                        state.current_container_id = None;
                        state.current_port = None;
                        state.status = AppStatus::NotDeployed;
                        verified.insert(app_name, state);
                    }
                    Err(e) => {
                        // Docker error — don't clear state, it might be transient
                        tracing::warn!(
                            app = %app_name,
                            container_id,
                            error = %e,
                            "failed to verify container, keeping state"
                        );
                        verified.insert(app_name, state);
                    }
                }
            }
        }
    }

    verified
}

// ─── Reconcile Caddy ──────────────────────────────────────────────────────────

/// Reconcile Caddy routes for all apps that are currently running.
///
/// Looks up each app's domain from `app_configs`. Apps without a config entry
/// are skipped with a warning.
pub async fn reconcile_routes(
    caddy: &CaddyClient,
    states: &HashMap<String, AppRuntimeState>,
    app_configs: &HashMap<String, AppConfig>,
) -> Result<(), CaddyError> {
    let routes: Vec<RouteInfo> = states
        .iter()
        .filter_map(|(app_name, state)| {
            if state.status != AppStatus::Running {
                return None;
            }
            let port = state.current_port?;
            let config = match app_configs.get(app_name) {
                Some(c) => c,
                None => {
                    tracing::warn!(app = %app_name, "no config found for running app, skipping route reconciliation");
                    return None;
                }
            };
            Some(RouteInfo {
                app_name: app_name.clone(),
                domain: config.routing.domain.clone(),
                port,
            })
        })
        .collect();

    if routes.is_empty() {
        tracing::debug!("no running apps to reconcile");
        return Ok(());
    }

    tracing::info!(route_count = routes.len(), "reconciling caddy routes");
    caddy.reconcile(&routes).await
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::io::Write;

    use chrono::Utc;
    use tempfile::TempDir;

    use super::*;
    use crate::deploy::{AppRuntimeState, AppStatus};

    fn sample_state() -> AppRuntimeState {
        AppRuntimeState {
            status: AppStatus::Running,
            current_tag: Some("v1.2.3".to_string()),
            previous_tag: Some("v1.2.2".to_string()),
            current_container_id: Some("abc123def456".to_string()),
            previous_container_id: Some("oldcontainer".to_string()),
            current_port: Some(54321),
            deployed_at: Some(Utc::now()),
            deploy_id: Some("dep_01abc".to_string()),
        }
    }

    // ── Round-trip ────────────────────────────────────────────────────────────

    #[test]
    fn test_save_and_load_round_trip() {
        let dir = TempDir::new().unwrap();
        let state_dir = dir.path();
        let app_name = "myapp";
        let original = sample_state();

        save_app_state(state_dir, app_name, &original).expect("save should succeed");

        let loaded = load_app_states(state_dir).expect("load should succeed");
        assert!(
            loaded.contains_key(app_name),
            "app should be present after load"
        );

        let restored = &loaded[app_name];

        // Fields that are persisted
        assert_eq!(restored.current_tag, original.current_tag);
        assert_eq!(restored.previous_tag, original.previous_tag);
        assert_eq!(restored.current_container_id, original.current_container_id);
        assert_eq!(restored.current_port, original.current_port);

        // deployed_at: compare truncated to seconds due to sub-second precision differences.
        let orig_secs = original.deployed_at.map(|dt| dt.timestamp());
        let rest_secs = restored.deployed_at.map(|dt| dt.timestamp());
        assert_eq!(rest_secs, orig_secs);

        // Fields that are NOT persisted should be cleared/defaulted
        assert!(restored.previous_container_id.is_none());
        assert!(restored.deploy_id.is_none());

        // Status should be inferred from container_id presence
        assert_eq!(restored.status, AppStatus::Running);
    }

    // ── Nonexistent directory ─────────────────────────────────────────────────

    #[test]
    fn test_load_nonexistent_dir_returns_empty() {
        let dir = TempDir::new().unwrap();
        // Use a path that doesn't exist
        let state_dir = dir.path().join("nonexistent");

        let result = load_app_states(&state_dir).expect("should succeed even if dir missing");
        assert!(
            result.is_empty(),
            "should return empty map for nonexistent dir"
        );
    }

    // ── Invalid JSON skipped ──────────────────────────────────────────────────

    #[test]
    fn test_load_ignores_invalid_json() {
        let dir = TempDir::new().unwrap();
        let state_dir = dir.path();

        // Write a valid state file
        let good_state = sample_state();
        save_app_state(state_dir, "goodapp", &good_state).expect("save should succeed");

        // Write an invalid JSON file
        let bad_path = state_dir.join("badapp.json");
        let mut f = std::fs::File::create(&bad_path).unwrap();
        f.write_all(b"this is not valid json {{{").unwrap();

        let loaded = load_app_states(state_dir).expect("load should succeed despite bad file");

        // Good app should be present
        assert!(loaded.contains_key("goodapp"), "goodapp should be loaded");
        // Bad app should be absent (silently skipped)
        assert!(!loaded.contains_key("badapp"), "badapp should be skipped");
        assert_eq!(loaded.len(), 1, "only one app should be loaded");
    }

    // ── Save creates directory ────────────────────────────────────────────────

    #[test]
    fn test_save_creates_state_dir() {
        let dir = TempDir::new().unwrap();
        let state_dir = dir.path().join("state").join("sub");
        assert!(!state_dir.exists(), "dir should not exist yet");

        let state = sample_state();
        save_app_state(&state_dir, "app1", &state).expect("save should create dirs");

        assert!(state_dir.exists(), "save should have created the directory");
        assert!(
            state_dir.join("app1.json").exists(),
            "json file should exist"
        );
    }

    // ── Not-deployed state round-trip ─────────────────────────────────────────

    #[test]
    fn test_save_and_load_not_deployed_state() {
        let dir = TempDir::new().unwrap();
        let state_dir = dir.path();
        let app_name = "freshapp";
        let state = AppRuntimeState::default(); // NotDeployed, all None

        save_app_state(state_dir, app_name, &state).expect("save should succeed");

        let loaded = load_app_states(state_dir).expect("load should succeed");
        let restored = &loaded[app_name];

        assert_eq!(restored.status, AppStatus::NotDeployed);
        assert!(restored.current_tag.is_none());
        assert!(restored.current_container_id.is_none());
        assert!(restored.current_port.is_none());
    }

    // ── Reconcile routes tests ──────────────────────────────────────────────────

    /// Helper to start a mock Caddy server for testing reconcile_routes.
    /// Returns (port, mock_state) where mock_state tracks the routes.
    async fn start_mock_caddy_for_reconcile() -> (
        u16,
        std::sync::Arc<tokio::sync::Mutex<HashMap<String, serde_json::Value>>>,
    ) {
        use axum::{
            Router,
            extract::State,
            http::StatusCode,
            routing::{get, post},
        };

        type MockState = std::sync::Arc<tokio::sync::Mutex<HashMap<String, serde_json::Value>>>;

        async fn mock_get_server(State(s): State<MockState>) -> StatusCode {
            let map = s.lock().await;
            if map.contains_key("__server__") {
                StatusCode::OK
            } else {
                StatusCode::NOT_FOUND
            }
        }

        async fn mock_create_server(
            State(s): State<MockState>,
            axum::Json(body): axum::Json<serde_json::Value>,
        ) -> StatusCode {
            let mut map = s.lock().await;
            map.insert("__server__".to_string(), body);
            StatusCode::OK
        }

        async fn mock_add_route(
            State(s): State<MockState>,
            axum::Json(body): axum::Json<serde_json::Value>,
        ) -> StatusCode {
            let id = body
                .get("@id")
                .and_then(|v| v.as_str())
                .unwrap_or("__unknown__")
                .to_string();
            let mut map = s.lock().await;
            map.insert(id, body);
            StatusCode::OK
        }

        let state: MockState = std::sync::Arc::new(tokio::sync::Mutex::new(HashMap::new()));
        let app = Router::new()
            .route(
                "/config/apps/http/servers/slip",
                get(mock_get_server).post(mock_create_server),
            )
            .route(
                "/config/apps/http/servers/slip/routes",
                post(mock_add_route),
            )
            .route("/config/", get(|| async { StatusCode::OK }))
            .with_state(state.clone());

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (port, state)
    }

    #[tokio::test]
    async fn test_reconcile_routes_skips_non_running_apps() {
        let (port, state) = start_mock_caddy_for_reconcile().await;
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

        let caddy = CaddyClient::new(format!("http://127.0.0.1:{port}"));
        caddy.bootstrap().await.unwrap();

        // Create app configs
        let mut app_configs = HashMap::new();
        app_configs.insert(
            "app1".to_string(),
            AppConfig {
                app: crate::config::AppInfo {
                    name: "app1".to_string(),
                    image: "nginx".to_string(),
                    secret: None,
                },
                routing: crate::config::RoutingConfig {
                    domain: "app1.example.com".to_string(),
                    port: 80,
                },
                health: crate::config::HealthConfig::default(),
                deploy: crate::config::DeployConfig::default(),
                network: crate::config::NetworkConfig::default(),
                resources: crate::config::ResourceConfig::default(),
                env: HashMap::new(),
                env_file: None,
            },
        );

        // Create states with mixed statuses
        let mut states = HashMap::new();
        states.insert(
            "app1".to_string(),
            AppRuntimeState {
                status: AppStatus::Running,
                current_tag: Some("v1".to_string()),
                current_port: Some(8080),
                ..Default::default()
            },
        );
        states.insert(
            "app2".to_string(),
            AppRuntimeState {
                status: AppStatus::Failed,
                current_tag: Some("v1".to_string()),
                current_port: Some(8081),
                ..Default::default()
            },
        );
        states.insert(
            "app3".to_string(),
            AppRuntimeState {
                status: AppStatus::Deploying,
                current_tag: Some("v1".to_string()),
                current_port: Some(8082),
                ..Default::default()
            },
        );

        // Reconcile
        reconcile_routes(&caddy, &states, &app_configs)
            .await
            .unwrap();

        // Verify only app1 route was created
        let map = state.lock().await;
        assert!(map.contains_key("slip-app1"), "app1 route should exist");
        assert!(
            !map.contains_key("slip-app2"),
            "app2 (Failed) should not have route"
        );
        assert!(
            !map.contains_key("slip-app3"),
            "app3 (Deploying) should not have route"
        );
    }

    #[tokio::test]
    async fn test_reconcile_routes_handles_missing_app_config() {
        let (port, state) = start_mock_caddy_for_reconcile().await;
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

        let caddy = CaddyClient::new(format!("http://127.0.0.1:{port}"));
        caddy.bootstrap().await.unwrap();

        // App configs only has app1
        let mut app_configs = HashMap::new();
        app_configs.insert(
            "app1".to_string(),
            AppConfig {
                app: crate::config::AppInfo {
                    name: "app1".to_string(),
                    image: "nginx".to_string(),
                    secret: None,
                },
                routing: crate::config::RoutingConfig {
                    domain: "app1.example.com".to_string(),
                    port: 80,
                },
                health: crate::config::HealthConfig::default(),
                deploy: crate::config::DeployConfig::default(),
                network: crate::config::NetworkConfig::default(),
                resources: crate::config::ResourceConfig::default(),
                env: HashMap::new(),
                env_file: None,
            },
        );

        // States have both app1 and app2 (app2 has no config)
        let mut states = HashMap::new();
        states.insert(
            "app1".to_string(),
            AppRuntimeState {
                status: AppStatus::Running,
                current_tag: Some("v1".to_string()),
                current_port: Some(8080),
                ..Default::default()
            },
        );
        states.insert(
            "app2".to_string(),
            AppRuntimeState {
                status: AppStatus::Running,
                current_tag: Some("v1".to_string()),
                current_port: Some(8081),
                ..Default::default()
            },
        );

        // Reconcile should succeed, skipping app2
        reconcile_routes(&caddy, &states, &app_configs)
            .await
            .unwrap();

        // Verify only app1 route was created
        let map = state.lock().await;
        assert!(map.contains_key("slip-app1"), "app1 route should exist");
        assert!(
            !map.contains_key("slip-app2"),
            "app2 (no config) should not have route"
        );
    }
}
