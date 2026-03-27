//! HTTP API types, router, and handlers for slipd.

use std::collections::HashMap;
use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::{Json, body::Bytes};
use chrono::{DateTime, Utc};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, RwLock};
use tracing::{info, warn};

use crate::auth::{resolve_secret, verify_signature};
use crate::caddy::CaddyClient;
use crate::config::{AppConfig, SlipConfig};
use crate::deploy::{AppRuntimeState, DeployContext, TriggerSource, execute_deploy};
use crate::docker::DockerClient;
use crate::health::HealthChecker;

// ─── Request / Response types ─────────────────────────────────────────────────

/// Payload sent to `POST /v1/deploy`.
#[derive(Debug, Deserialize)]
pub struct DeployRequest {
    pub app: String,
    pub image: String,
    pub tag: String,
}

/// Successful deploy response (202 Accepted).
#[derive(Debug, Serialize, Deserialize)]
pub struct DeployResponse {
    pub deploy_id: String,
    pub app: String,
    pub tag: String,
    pub status: String,
}

/// Error response body.
#[derive(Debug, Serialize, Deserialize)]
pub struct ErrorResponse {
    pub error: String,
}

/// Response for `GET /v1/status`.
#[derive(Debug, Serialize)]
pub struct StatusResponse {
    pub daemon: String,
    pub uptime_seconds: i64,
    pub apps: HashMap<String, AppStatusResponse>,
}

/// Per-app status within a `StatusResponse`.
#[derive(Debug, Serialize)]
pub struct AppStatusResponse {
    pub status: String,
    pub tag: Option<String>,
    pub deployed_at: Option<DateTime<Utc>>,
    pub container_id: Option<String>,
    pub port: Option<u16>,
}

/// Response for `GET /v1/deploys/:deploy_id`.
#[derive(Debug, Serialize)]
pub struct DeployStatusResponse {
    pub deploy_id: String,
    pub app: String,
    pub tag: String,
    pub status: String,
    pub started_at: DateTime<Utc>,
    pub finished_at: Option<DateTime<Utc>>,
    pub error: Option<String>,
}

// ─── App error ────────────────────────────────────────────────────────────────

/// Typed errors returned from handlers; each variant maps to an HTTP status.
#[derive(Debug)]
pub enum AppError {
    BadRequest(String),
    Unauthorized(String),
    NotFound(String),
    Conflict(String),
    Internal(String),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            AppError::BadRequest(msg) => (StatusCode::BAD_REQUEST, msg),
            AppError::Unauthorized(msg) => (StatusCode::UNAUTHORIZED, msg),
            AppError::NotFound(msg) => (StatusCode::NOT_FOUND, msg),
            AppError::Conflict(msg) => (StatusCode::CONFLICT, msg),
            AppError::Internal(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg),
        };
        (status, Json(ErrorResponse { error: message })).into_response()
    }
}

// ─── Shared application state ─────────────────────────────────────────────────

/// Shared state injected into every request handler via `axum::extract::State`.
pub struct AppState {
    /// Daemon-level configuration (auth secret, Caddy URL, etc.).
    pub config: SlipConfig,
    /// Per-application configurations keyed by app name.
    pub apps: HashMap<String, AppConfig>,
    /// Per-app deploy locks; prevents concurrent deploys for the same app.
    pub deploy_locks: DashMap<String, Arc<Mutex<()>>>,
    /// Docker daemon client.
    pub docker: DockerClient,
    /// Caddy admin API client.
    pub caddy: CaddyClient,
    /// HTTP health checker.
    pub health: HealthChecker,
    /// Runtime state for each app (current container, port, tag, etc.).
    pub app_states: RwLock<HashMap<String, AppRuntimeState>>,
    /// Recent deploy contexts keyed by deploy_id (capped at 100).
    pub deploys: DashMap<String, DeployContext>,
    /// Timestamp when the daemon was started (used for uptime calculation).
    pub started_at: DateTime<Utc>,
}

impl AppState {
    /// Record (insert/update) a deploy context, evicting the oldest entry if
    /// the map exceeds 100 entries.
    pub fn record_deploy(&self, ctx: &DeployContext) {
        self.deploys.insert(ctx.id.clone(), ctx.clone());
        // Cap at 100 entries — evict one approximate-oldest entry.
        if self.deploys.len() > 100
            && let Some(oldest) = self.deploys.iter().next().map(|e| e.key().clone())
        {
            self.deploys.remove(&oldest);
        }
    }

    /// Build Docker registry credentials from the configured GHCR token, if any.
    pub fn docker_credentials(&self) -> Option<bollard::auth::DockerCredentials> {
        self.config
            .registry
            .ghcr_token
            .as_ref()
            .map(|token| bollard::auth::DockerCredentials {
                username: Some("slip".to_string()),
                password: Some(token.clone()),
                ..Default::default()
            })
    }
}

// ─── Router ───────────────────────────────────────────────────────────────────

/// Build the axum router with all API routes and shared state.
pub fn build_router(state: Arc<AppState>) -> axum::Router {
    axum::Router::new()
        .route("/v1/deploy", axum::routing::post(handle_deploy))
        .route("/v1/status", axum::routing::get(handle_status))
        .route(
            "/v1/deploys/{deploy_id}",
            axum::routing::get(handle_deploy_status),
        )
        .with_state(state)
}

// ─── Deploy handler ───────────────────────────────────────────────────────────

/// `POST /v1/deploy`
///
/// Flow:
/// 1. Read raw body bytes
/// 2. Require `X-Slip-Signature` header (401 if missing)
/// 3. Parse JSON body → get app name
/// 4. Look up app config (404 if unknown)
/// 5. Resolve HMAC secret (per-app or global)
/// 6. Verify HMAC (401 if invalid)
/// 7. Validate image matches config (400 if mismatch)
/// 8. Validate tag is non-empty (400)
/// 9. Acquire per-app deploy lock (409 if locked)
/// 10. Generate deploy_id and respond 202
/// 11. Spawn placeholder task that logs and releases the lock
async fn handle_deploy(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    body: Bytes,
) -> Result<(StatusCode, Json<DeployResponse>), AppError> {
    // 2. Require X-Slip-Signature header.
    let sig_header = headers
        .get("X-Slip-Signature")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| AppError::Unauthorized("missing X-Slip-Signature header".to_string()))?;

    // 3. Parse JSON body to obtain the app name (we still need raw bytes for HMAC).
    let request: DeployRequest = serde_json::from_slice(&body)
        .map_err(|e| AppError::BadRequest(format!("invalid JSON: {e}")))?;

    // 4. Look up app config.
    let app_cfg = state
        .apps
        .get(&request.app)
        .ok_or_else(|| AppError::NotFound(format!("unknown app: {}", request.app)))?;

    // 5. Resolve HMAC secret.
    let secret = resolve_secret(app_cfg.app.secret.as_deref(), &state.config.auth.secret);

    // 6. Verify HMAC signature.
    if !verify_signature(sig_header, &body, secret) {
        warn!(app = %request.app, "deploy rejected: invalid signature");
        return Err(AppError::Unauthorized("invalid signature".to_string()));
    }

    // 7. Validate image matches config.
    if request.image != app_cfg.app.image {
        return Err(AppError::BadRequest(format!(
            "image mismatch: expected '{}', got '{}'",
            app_cfg.app.image, request.image
        )));
    }

    // 8. Validate tag is non-empty.
    if request.tag.is_empty() {
        return Err(AppError::BadRequest("tag must not be empty".to_string()));
    }

    // 9. Try to acquire per-app deploy lock (non-blocking).
    let lock = {
        let lock_entry = state
            .deploy_locks
            .entry(request.app.clone())
            .or_insert_with(|| Arc::new(Mutex::new(())));
        lock_entry.clone()
        // lock_entry (DashMap RefMut) is dropped here, before the await
    };

    let guard = lock.try_lock_owned().map_err(|_| {
        AppError::Conflict(format!("deploy already in progress for '{}'", request.app))
    })?;

    // 10. Generate deploy_id.
    let deploy_id = format!("dep_{}", ulid::Ulid::new().to_string().to_lowercase());

    info!(
        deploy_id = %deploy_id,
        app = %request.app,
        tag = %request.tag,
        "deploy accepted"
    );

    let response = DeployResponse {
        deploy_id: deploy_id.clone(),
        app: request.app.clone(),
        tag: request.tag.clone(),
        status: "accepted".to_string(),
    };

    // 11. Spawn deploy orchestrator.
    let deploy_ctx = DeployContext::new(
        deploy_id.clone(),
        request.app.clone(),
        request.image.clone(),
        request.tag.clone(),
        TriggerSource::Webhook,
    );
    state.record_deploy(&deploy_ctx);

    let state_clone = state.clone();
    tokio::spawn(async move {
        // Lock guard is moved into the task — released when the task ends.
        let _guard = guard;
        execute_deploy(state_clone, deploy_ctx).await;
    });

    Ok((StatusCode::ACCEPTED, Json(response)))
}

// ─── Status handler ───────────────────────────────────────────────────────────

/// `GET /v1/status`
///
/// Returns daemon uptime and the runtime status of every configured app.
async fn handle_status(State(state): State<Arc<AppState>>) -> (StatusCode, Json<StatusResponse>) {
    let uptime_seconds = (Utc::now() - state.started_at).num_seconds();

    let app_states = state.app_states.read().await;

    let apps = state
        .apps
        .keys()
        .map(|app_name| {
            let app_status = match app_states.get(app_name) {
                None => AppStatusResponse {
                    status: "not_deployed".to_string(),
                    tag: None,
                    deployed_at: None,
                    container_id: None,
                    port: None,
                },
                Some(runtime) => {
                    let status_str = match runtime.status {
                        crate::deploy::AppStatus::Running => "running",
                        crate::deploy::AppStatus::Deploying => "deploying",
                        crate::deploy::AppStatus::Failed => "failed",
                        crate::deploy::AppStatus::NotDeployed => "not_deployed",
                    };
                    AppStatusResponse {
                        status: status_str.to_string(),
                        tag: runtime.current_tag.clone(),
                        deployed_at: runtime.deployed_at,
                        container_id: runtime.current_container_id.clone(),
                        port: runtime.current_port,
                    }
                }
            };
            (app_name.clone(), app_status)
        })
        .collect();

    (
        StatusCode::OK,
        Json(StatusResponse {
            daemon: "slipd".to_string(),
            uptime_seconds,
            apps,
        }),
    )
}

// ─── Deploy status handler ────────────────────────────────────────────────────

/// `GET /v1/deploys/:deploy_id`
///
/// Returns the current state of a specific deploy by ID, or 404 if not found.
async fn handle_deploy_status(
    State(state): State<Arc<AppState>>,
    Path(deploy_id): Path<String>,
) -> Result<(StatusCode, Json<DeployStatusResponse>), AppError> {
    let ctx = state
        .deploys
        .get(&deploy_id)
        .ok_or_else(|| AppError::NotFound("deploy not found".to_string()))?;

    let status_str = match ctx.status {
        crate::deploy::DeployStatus::Accepted => "accepted",
        crate::deploy::DeployStatus::Pulling => "pulling",
        crate::deploy::DeployStatus::Starting => "starting",
        crate::deploy::DeployStatus::HealthChecking => "health_checking",
        crate::deploy::DeployStatus::Switching => "switching",
        crate::deploy::DeployStatus::Completed => "completed",
        crate::deploy::DeployStatus::Failed => "failed",
    };

    let response = DeployStatusResponse {
        deploy_id: ctx.id.clone(),
        app: ctx.app.clone(),
        tag: ctx.tag.clone(),
        status: status_str.to_string(),
        started_at: ctx.started_at,
        finished_at: ctx.finished_at,
        error: ctx.error.clone(),
    };

    Ok((StatusCode::OK, Json(response)))
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Arc;

    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use dashmap::DashMap;
    use tokio::sync::RwLock;
    use tower::ServiceExt;

    use chrono::Utc;

    use crate::api::{AppState, DeployResponse, ErrorResponse, build_router};
    use crate::auth::compute_signature;
    use crate::caddy::CaddyClient;
    use crate::config::{
        AppConfig, AppInfo, AuthConfig, CaddyConfig, DeployConfig, HealthConfig, NetworkConfig,
        RegistryConfig, ResourceConfig, RoutingConfig, ServerConfig, SlipConfig, StorageConfig,
    };
    use crate::deploy::{AppRuntimeState, AppStatus, DeployContext, DeployStatus, TriggerSource};
    use crate::docker::DockerClient;
    use crate::health::HealthChecker;

    const GLOBAL_SECRET: &str = "global-secret";
    const APP_SECRET: &str = "app-secret";
    const APP_NAME: &str = "testapp";
    const APP_IMAGE: &str = "ghcr.io/org/testapp";

    /// Build a minimal `SlipConfig` for tests.
    fn test_slip_config() -> SlipConfig {
        SlipConfig {
            server: ServerConfig::default(),
            caddy: CaddyConfig::default(),
            auth: AuthConfig {
                secret: GLOBAL_SECRET.to_string(),
            },
            registry: RegistryConfig { ghcr_token: None },
            storage: StorageConfig::default(),
        }
    }

    /// Build a minimal `AppConfig` for tests.
    fn test_app_config(secret: Option<&str>) -> AppConfig {
        AppConfig {
            app: AppInfo {
                name: APP_NAME.to_string(),
                image: APP_IMAGE.to_string(),
                secret: secret.map(|s| s.to_string()),
            },
            routing: RoutingConfig {
                domain: "testapp.example.com".to_string(),
                port: 3000,
            },
            health: HealthConfig::default(),
            deploy: DeployConfig::default(),
            env: HashMap::new(),
            env_file: None,
            resources: ResourceConfig::default(),
            network: NetworkConfig::default(),
        }
    }

    /// Build an `Arc<AppState>` for tests. Uses per-app secret when `use_app_secret` is true.
    fn create_test_state() -> Arc<AppState> {
        let mut apps = HashMap::new();
        apps.insert(APP_NAME.to_string(), test_app_config(Some(APP_SECRET)));

        Arc::new(AppState {
            config: test_slip_config(),
            apps,
            deploy_locks: DashMap::new(),
            docker: DockerClient::new_with_url("http://127.0.0.1:19998").expect("DockerClient::new"),
            caddy: CaddyClient::new("http://127.0.0.1:19999".to_string()),
            health: HealthChecker::new(),
            app_states: RwLock::new(HashMap::new()),
            deploys: DashMap::new(),
            started_at: Utc::now(),
        })
    }

    /// Build a valid deploy request body.
    fn deploy_body(app: &str, image: &str, tag: &str) -> Vec<u8> {
        serde_json::json!({
            "app": app,
            "image": image,
            "tag": tag,
        })
        .to_string()
        .into_bytes()
    }

    /// Build a signature header for the given body + secret.
    fn sig_header(body: &[u8], secret: &str) -> String {
        format!("sha256={}", compute_signature(body, secret))
    }

    // ── 202 Accepted ──────────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_deploy_valid_signature() {
        let state = create_test_state();
        let app = build_router(state);

        let body = deploy_body(APP_NAME, APP_IMAGE, "v1.2.3");
        let sig = sig_header(&body, APP_SECRET);

        let request = Request::builder()
            .method("POST")
            .uri("/v1/deploy")
            .header("Content-Type", "application/json")
            .header("X-Slip-Signature", sig)
            .body(Body::from(body))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::ACCEPTED);

        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let payload: DeployResponse = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(payload.app, APP_NAME);
        assert_eq!(payload.tag, "v1.2.3");
        assert_eq!(payload.status, "accepted");
        assert!(payload.deploy_id.starts_with("dep_"));
    }

    // ── 401 Missing signature ──────────────────────────────────────────────────

    #[tokio::test]
    async fn test_deploy_missing_signature() {
        let state = create_test_state();
        let app = build_router(state);

        let body = deploy_body(APP_NAME, APP_IMAGE, "v1.0.0");

        let request = Request::builder()
            .method("POST")
            .uri("/v1/deploy")
            .header("Content-Type", "application/json")
            .body(Body::from(body))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let payload: ErrorResponse = serde_json::from_slice(&bytes).unwrap();
        assert!(payload.error.contains("X-Slip-Signature"));
    }

    // ── 401 Invalid signature ─────────────────────────────────────────────────

    #[tokio::test]
    async fn test_deploy_invalid_signature() {
        let state = create_test_state();
        let app = build_router(state);

        let body = deploy_body(APP_NAME, APP_IMAGE, "v1.0.0");

        let request = Request::builder()
            .method("POST")
            .uri("/v1/deploy")
            .header("Content-Type", "application/json")
            .header("X-Slip-Signature", "sha256=deadbeefdeadbeefdeadbeef")
            .body(Body::from(body))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let payload: ErrorResponse = serde_json::from_slice(&bytes).unwrap();
        assert!(payload.error.contains("invalid signature"));
    }

    // ── 404 Unknown app ───────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_deploy_unknown_app() {
        let state = create_test_state();
        let app = build_router(state);

        let body = deploy_body("nonexistent", APP_IMAGE, "v1.0.0");
        // We sign with global secret because app doesn't exist (any secret won't matter —
        // 404 is returned before signature check, but we need valid sig to reach the right
        // error path.  Actually per the flow, lookup happens BEFORE signature check, so
        // we'll get 404 regardless of the signature.)
        let sig = sig_header(&body, GLOBAL_SECRET);

        let request = Request::builder()
            .method("POST")
            .uri("/v1/deploy")
            .header("Content-Type", "application/json")
            .header("X-Slip-Signature", sig)
            .body(Body::from(body))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let payload: ErrorResponse = serde_json::from_slice(&bytes).unwrap();
        assert!(payload.error.contains("nonexistent"));
    }

    // ── 400 Image mismatch ────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_deploy_image_mismatch() {
        let state = create_test_state();
        let app = build_router(state);

        let body = deploy_body(APP_NAME, "ghcr.io/org/wrong-image", "v1.0.0");
        let sig = sig_header(&body, APP_SECRET);

        let request = Request::builder()
            .method("POST")
            .uri("/v1/deploy")
            .header("Content-Type", "application/json")
            .header("X-Slip-Signature", sig)
            .body(Body::from(body))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let payload: ErrorResponse = serde_json::from_slice(&bytes).unwrap();
        assert!(payload.error.contains("image mismatch"));
    }

    // ── 400 Empty tag ─────────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_deploy_empty_tag() {
        let state = create_test_state();
        let app = build_router(state);

        let body = deploy_body(APP_NAME, APP_IMAGE, "");
        let sig = sig_header(&body, APP_SECRET);

        let request = Request::builder()
            .method("POST")
            .uri("/v1/deploy")
            .header("Content-Type", "application/json")
            .header("X-Slip-Signature", sig)
            .body(Body::from(body))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let payload: ErrorResponse = serde_json::from_slice(&bytes).unwrap();
        assert!(payload.error.contains("tag"));
    }

    // ── 409 Concurrent deploy ─────────────────────────────────────────────────

    #[tokio::test]
    async fn test_deploy_concurrent_lock() {
        use dashmap::DashMap;
        use tokio::sync::Mutex;

        let mut apps = HashMap::new();
        apps.insert(APP_NAME.to_string(), test_app_config(Some(APP_SECRET)));

        let deploy_locks: DashMap<String, Arc<Mutex<()>>> = DashMap::new();
        // Pre-insert a locked mutex so the handler cannot acquire it.
        let locked = Arc::new(Mutex::new(()));
        // Acquire an owned guard — this keeps the lock held for the lifetime of `_guard`.
        let _guard = locked.clone().try_lock_owned().unwrap();

        // Insert it so the handler sees the lock as taken.
        deploy_locks.insert(APP_NAME.to_string(), locked);

        let state_inner = Arc::new(AppState {
            config: test_slip_config(),
            apps,
            deploy_locks,
            docker: DockerClient::new_with_url("http://127.0.0.1:19998").expect("DockerClient::new"),
            caddy: CaddyClient::new("http://127.0.0.1:19999".to_string()),
            health: HealthChecker::new(),
            app_states: RwLock::new(HashMap::new()),
            deploys: DashMap::new(),
            started_at: Utc::now(),
        });

        let app = build_router(state_inner);

        let body = deploy_body(APP_NAME, APP_IMAGE, "v1.0.0");
        let sig = sig_header(&body, APP_SECRET);

        let request = Request::builder()
            .method("POST")
            .uri("/v1/deploy")
            .header("Content-Type", "application/json")
            .header("X-Slip-Signature", sig)
            .body(Body::from(body))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::CONFLICT);

        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let payload: ErrorResponse = serde_json::from_slice(&bytes).unwrap();
        assert!(payload.error.contains("in progress"));
    }

    // ── Global secret fallback ────────────────────────────────────────────────

    #[tokio::test]
    async fn test_deploy_global_secret_fallback() {
        // App has no per-app secret — should fall back to global secret.
        let mut apps = HashMap::new();
        apps.insert(APP_NAME.to_string(), test_app_config(None));

        let state = Arc::new(AppState {
            config: test_slip_config(),
            apps,
            deploy_locks: DashMap::new(),
            docker: DockerClient::new_with_url("http://127.0.0.1:19998").expect("DockerClient::new"),
            caddy: CaddyClient::new("http://127.0.0.1:19999".to_string()),
            health: HealthChecker::new(),
            app_states: RwLock::new(HashMap::new()),
            deploys: DashMap::new(),
            started_at: Utc::now(),
        });

        let app = build_router(state);

        let body = deploy_body(APP_NAME, APP_IMAGE, "v2.0.0");
        let sig = sig_header(&body, GLOBAL_SECRET); // sign with global secret

        let request = Request::builder()
            .method("POST")
            .uri("/v1/deploy")
            .header("Content-Type", "application/json")
            .header("X-Slip-Signature", sig)
            .body(Body::from(body))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::ACCEPTED);
    }

    // ── GET /v1/status — no deploys ───────────────────────────────────────────

    #[tokio::test]
    async fn test_status_no_deploys() {
        let state = create_test_state();
        let app = build_router(state);

        let request = Request::builder()
            .method("GET")
            .uri("/v1/status")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let payload: serde_json::Value = serde_json::from_slice(&bytes).unwrap();

        assert_eq!(payload["daemon"], "slipd");
        assert!(payload["uptime_seconds"].as_i64().unwrap() >= 0);

        let apps = &payload["apps"];
        let testapp = &apps[APP_NAME];
        assert_eq!(testapp["status"], "not_deployed");
        assert!(testapp["tag"].is_null());
        assert!(testapp["container_id"].is_null());
        assert!(testapp["port"].is_null());
    }

    // ── GET /v1/status — app with running status ──────────────────────────────

    #[tokio::test]
    async fn test_status_with_running_app() {
        let state = create_test_state();

        // Pre-populate runtime state with a Running app.
        {
            let mut app_states = state.app_states.write().await;
            app_states.insert(
                APP_NAME.to_string(),
                AppRuntimeState {
                    status: AppStatus::Running,
                    current_tag: Some("v1.2.3".to_string()),
                    current_container_id: Some("abc123".to_string()),
                    current_port: Some(8080),
                    deployed_at: Some(Utc::now()),
                    deploy_id: Some("dep_test".to_string()),
                    ..Default::default()
                },
            );
        }

        let app = build_router(state);

        let request = Request::builder()
            .method("GET")
            .uri("/v1/status")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let payload: serde_json::Value = serde_json::from_slice(&bytes).unwrap();

        let testapp = &payload["apps"][APP_NAME];
        assert_eq!(testapp["status"], "running");
        assert_eq!(testapp["tag"], "v1.2.3");
        assert_eq!(testapp["container_id"], "abc123");
        assert_eq!(testapp["port"], 8080);
    }

    // ── GET /v1/deploys/:deploy_id — found ────────────────────────────────────

    #[tokio::test]
    async fn test_deploy_status_found() {
        let state = create_test_state();

        let ctx = DeployContext {
            id: "dep_testid123".to_string(),
            app: APP_NAME.to_string(),
            image: APP_IMAGE.to_string(),
            tag: "v2.0.0".to_string(),
            status: DeployStatus::Completed,
            started_at: Utc::now(),
            finished_at: Some(Utc::now()),
            error: None,
            triggered_by: TriggerSource::Webhook,
            new_container_id: Some("ctr456".to_string()),
            new_port: Some(9000),
        };
        state.deploys.insert(ctx.id.clone(), ctx);

        let app = build_router(state);

        let request = Request::builder()
            .method("GET")
            .uri("/v1/deploys/dep_testid123")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let payload: serde_json::Value = serde_json::from_slice(&bytes).unwrap();

        assert_eq!(payload["deploy_id"], "dep_testid123");
        assert_eq!(payload["app"], APP_NAME);
        assert_eq!(payload["tag"], "v2.0.0");
        assert_eq!(payload["status"], "completed");
        assert!(payload["finished_at"].is_string());
        assert!(payload["error"].is_null());
    }

    // ── GET /v1/deploys/:deploy_id — not found ────────────────────────────────

    #[tokio::test]
    async fn test_deploy_status_not_found() {
        let state = create_test_state();
        let app = build_router(state);

        let request = Request::builder()
            .method("GET")
            .uri("/v1/deploys/dep_doesnotexist")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let payload: ErrorResponse = serde_json::from_slice(&bytes).unwrap();
        assert!(payload.error.contains("deploy not found"));
    }
}
