//! HTTP API types, router, and handlers for slipd.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use axum::extract::{DefaultBodyLimit, Path, State};
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
use crate::health::HealthChecker;
use crate::preview::{
    PreviewDeployContext, PreviewState, execute_preview_deploy, resolve_preview_domain,
    teardown_preview,
};
use crate::runtime::{RegistryCredentials, RuntimeBackend};

// ─── Request / Response types ─────────────────────────────────────────────────

/// Preview-specific fields sent alongside a deploy request.
///
/// When present, the deploy creates an ephemeral preview environment instead
/// of updating the production deployment.
#[derive(Debug, Deserialize)]
pub struct PreviewRequestInfo {
    /// Unique preview identifier (e.g. "pr-42", "feature-foo").
    pub id: String,
    /// Git commit SHA for metadata / display purposes.
    pub sha: String,
}

/// Payload sent to `POST /v1/deploy`.
#[derive(Debug, Deserialize)]
pub struct DeployRequest {
    pub app: String,
    pub image: String,
    pub tag: String,
    /// If present, this is a preview deploy rather than a production deploy.
    #[serde(default)]
    pub preview: Option<PreviewRequestInfo>,
}

/// Successful deploy response (202 Accepted).
#[derive(Debug, Serialize, Deserialize)]
pub struct DeployResponse {
    pub deploy_id: String,
    pub app: String,
    pub tag: String,
    pub status: String,
    /// Expected preview URL for preview deploys. `None` for production deploys.
    ///
    /// This is computed from config at request time as a hint. The actual URL
    /// becomes live after the background deploy task completes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preview_url: Option<String>,
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
    pub caddy: String,
    pub runtime: String,
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

/// Response for preview status endpoints.
#[derive(Debug, Serialize)]
pub struct PreviewStatusResponse {
    pub preview_id: String,
    pub app: String,
    pub sha: String,
    pub status: String,
    pub tag: Option<String>,
    pub domain: String,
    pub port: Option<u16>,
    pub deployed_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
}

// ─── Management API request/response types ─────────────────────────────────────

/// Request body for `POST /v1/apps`.
#[derive(Debug, Deserialize)]
pub struct CreateAppRequest {
    pub name: String,
    pub image: String,
    pub domain: String,
    #[serde(default = "default_app_port")]
    pub port: u16,
    pub secret: Option<String>,
    #[serde(default)]
    pub env: HashMap<String, String>,
    pub resources: Option<crate::config::ResourceConfig>,
    pub network: Option<crate::config::NetworkConfig>,
    pub health: Option<crate::config::HealthConfig>,
    pub deploy: Option<crate::config::DeployConfig>,
    pub preview: Option<crate::config::AppPreviewConfig>,
}

fn default_app_port() -> u16 {
    8080
}

/// Request body for `PATCH /v1/apps/{name}`.
#[derive(Debug, Deserialize)]
pub struct UpdateAppRequest {
    pub image: Option<String>,
    pub domain: Option<String>,
    pub port: Option<u16>,
    pub secret: Option<String>,
    pub env: Option<HashMap<String, String>>,
    pub resources: Option<crate::config::ResourceConfig>,
    pub network: Option<crate::config::NetworkConfig>,
    pub health: Option<crate::config::HealthConfig>,
    pub deploy: Option<crate::config::DeployConfig>,
    pub preview: Option<crate::config::AppPreviewConfig>,
}

/// Request body for `POST /v1/apps/{name}/rollback`.
#[derive(Debug, Deserialize)]
pub struct RollbackRequest {
    /// Target tag to roll back to. If omitted, uses `previous_tag` from runtime state.
    #[serde(default)]
    pub to: Option<String>,
}

/// Validate tag format (non-empty, valid charset for Docker container names).
fn validate_tag(tag: &str) -> Result<(), AppError> {
    if tag.is_empty() {
        return Err(AppError::BadRequest("tag must not be empty".to_string()));
    }
    // Docker container names must match [a-zA-Z0-9][a-zA-Z0-9_.-]*
    // We use the tag in the container name, so validate it here.
    if !tag
        .chars()
        .all(|c| c.is_alphanumeric() || c == '-' || c == '_' || c == '.')
    {
        return Err(AppError::BadRequest(
            "tag contains invalid characters (allowed: alphanumeric, -, _, .)".to_string(),
        ));
    }
    Ok(())
}

/// Response for `GET /v1/apps` and `GET /v1/apps/{name}`.
#[derive(Debug, Serialize, Deserialize)]
pub struct AppResponse {
    pub name: String,
    pub image: String,
    pub domain: String,
    pub port: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret: Option<String>,
    pub env: HashMap<String, String>,
    pub resources: crate::config::ResourceConfig,
    pub network: crate::config::NetworkConfig,
    pub health: crate::config::HealthConfig,
    pub deploy: crate::config::DeployConfig,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preview: Option<crate::config::AppPreviewConfig>,
}

impl From<&AppConfig> for AppResponse {
    fn from(cfg: &AppConfig) -> Self {
        Self {
            name: cfg.app.name.clone(),
            image: cfg.app.image.clone(),
            domain: cfg.routing.domain.clone(),
            port: cfg.routing.port,
            // Don't expose the secret in responses
            secret: None,
            env: cfg.env.clone(),
            resources: cfg.resources.clone(),
            network: cfg.network.clone(),
            health: cfg.health.clone(),
            deploy: cfg.deploy.clone(),
            preview: cfg.preview.clone(),
        }
    }
}

/// Response for `GET /v1/apps` (list).
#[derive(Debug, Serialize, Deserialize)]
pub struct AppListResponse {
    pub apps: Vec<AppResponse>,
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
    pub apps: RwLock<HashMap<String, AppConfig>>,
    /// Path to the configuration directory (for writing app configs).
    pub config_dir: PathBuf,
    /// Per-app deploy locks; prevents concurrent deploys for the same app.
    ///
    /// Entries are created on first deploy and never removed. This is bounded by
    /// the number of registered apps in the config. If hot-reload is added in
    /// Phase 2, we'll need to clean up locks for removed apps.
    ///
    /// TODO(Phase 2): Add cleanup when apps are removed during hot-reload.
    pub deploy_locks: DashMap<String, Arc<Mutex<()>>>,
    /// Container runtime backend (Docker, Podman, etc.).
    pub runtime: Arc<dyn RuntimeBackend>,
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
    /// Active preview deployment states keyed by `"{app}:{preview_id}"`.
    pub preview_states: Arc<DashMap<String, PreviewState>>,
    /// Per-preview deploy locks; prevents concurrent deploys for the same preview.
    ///
    /// Keyed by `"{app}:{preview_id}"`. Allows preview deploys to run concurrently
    /// with production deploys and other previews.
    pub preview_locks: DashMap<String, Arc<Mutex<()>>>,
}

impl AppState {
    /// Record (insert/update) a deploy context, evicting an entry if the map exceeds 100.
    pub fn record_deploy(&self, ctx: &DeployContext) {
        crate::deploy::record_deploy(&self.deploys, ctx);
    }

    /// Build registry credentials from the configured GHCR token, if any.
    pub fn registry_credentials(&self) -> Option<RegistryCredentials> {
        self.config
            .registry
            .ghcr_token
            .as_ref()
            .map(|token| RegistryCredentials {
                username: "slip".to_string(),
                password: token.clone(),
            })
    }
}

// ─── Router ───────────────────────────────────────────────────────────────────

/// Build the axum router with all API routes and shared state.
pub fn build_router(state: Arc<AppState>) -> axum::Router {
    // Management routes (require Bearer token auth)
    let management_routes = axum::Router::new()
        .route(
            "/v1/apps",
            axum::routing::post(handle_create_app).get(handle_list_apps),
        )
        .route(
            "/v1/apps/{name}",
            axum::routing::get(handle_get_app)
                .patch(handle_update_app)
                .delete(handle_delete_app),
        )
        .route(
            "/v1/apps/{name}/rollback",
            axum::routing::post(handle_rollback),
        )
        .route_layer(axum::middleware::from_fn_with_state(
            state.clone(),
            management_auth,
        ));

    // Public routes (HMAC auth per-endpoint)
    axum::Router::new()
        .route("/v1/deploy", axum::routing::post(handle_deploy))
        .route("/v1/status", axum::routing::get(handle_status))
        .route(
            "/v1/deploys/{deploy_id}",
            axum::routing::get(handle_deploy_status),
        )
        .route(
            "/v1/previews/{app}",
            axum::routing::get(handle_list_previews),
        )
        .route(
            "/v1/previews/{app}/{preview_id}",
            axum::routing::get(handle_preview_status).delete(handle_preview_teardown),
        )
        .merge(management_routes)
        .layer(DefaultBodyLimit::max(64 * 1024)) // 64 KiB limit
        .with_state(state)
}

// ─── Management auth middleware ────────────────────────────────────────────────

use axum::middleware::Next;

/// Middleware that validates Bearer token against the auth secret.
async fn management_auth(
    State(state): State<Arc<AppState>>,
    request: axum::extract::Request,
    next: Next,
) -> Result<Response, AppError> {
    let auth_header = request
        .headers()
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| AppError::Unauthorized("missing Authorization header".to_string()))?;

    let token = auth_header
        .strip_prefix("Bearer ")
        .ok_or_else(|| AppError::Unauthorized("invalid Authorization header format".to_string()))?;

    // Constant-time comparison to prevent timing attacks
    let expected = &state.config.auth.secret;
    if !constant_time_eq(token, expected) {
        return Err(AppError::Unauthorized("invalid token".to_string()));
    }

    Ok(next.run(request).await)
}

/// Constant-time string comparison.
fn constant_time_eq(a: &str, b: &str) -> bool {
    use subtle::ConstantTimeEq;
    if a.len() != b.len() {
        return false;
    }
    a.as_bytes().ct_eq(b.as_bytes()).into()
}

// ─── Management API handlers ───────────────────────────────────────────────────

/// Validate app name format.
///
/// Rules:
/// - Lowercase alphanumeric and hyphens only
/// - No leading or trailing hyphen
/// - 1-63 characters (DNS label limit)
fn validate_app_name(name: &str) -> Result<(), AppError> {
    if name.is_empty() {
        return Err(AppError::BadRequest("app name cannot be empty".to_string()));
    }
    if name.len() > 63 {
        return Err(AppError::BadRequest(
            "app name must be 63 characters or less".to_string(),
        ));
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    {
        return Err(AppError::BadRequest(
            "app name must contain only lowercase letters, digits, and hyphens".to_string(),
        ));
    }
    if name.starts_with('-') || name.ends_with('-') {
        return Err(AppError::BadRequest(
            "app name cannot start or end with a hyphen".to_string(),
        ));
    }
    Ok(())
}

/// `POST /v1/apps` — Create a new app.
async fn handle_create_app(
    State(state): State<Arc<AppState>>,
    Json(req): Json<CreateAppRequest>,
) -> Result<(StatusCode, Json<AppResponse>), AppError> {
    // Validate name format
    validate_app_name(&req.name)?;

    // Build AppConfig from request
    let app_config = AppConfig {
        app: crate::config::AppInfo {
            name: req.name.clone(),
            image: req.image.clone(),
            secret: req.secret,
        },
        routing: crate::config::RoutingConfig {
            domain: req.domain,
            port: req.port,
        },
        health: req.health.unwrap_or_default(),
        deploy: req.deploy.unwrap_or_default(),
        env: req.env,
        env_file: None,
        resources: req.resources.unwrap_or_default(),
        network: req.network.unwrap_or_default(),
        preview: req.preview,
    };

    // Check for conflicts and insert atomically (TOCTOU fix)
    {
        let mut apps = state.apps.write().await;
        if apps.contains_key(&req.name) {
            return Err(AppError::Conflict(format!(
                "app '{}' already exists",
                req.name
            )));
        }
        apps.insert(req.name.clone(), app_config.clone());
    }

    // Write config to disk (non-blocking)
    let config_dir = state.config_dir.clone();
    let app_config_clone = app_config.clone();
    tokio::task::spawn_blocking(move || {
        if let Err(e) = crate::config::write_app_config(&config_dir, &app_config_clone) {
            warn!(error = %e, "failed to write app config");
        }
    });

    info!(app = %req.name, "app created");

    Ok((StatusCode::CREATED, Json(AppResponse::from(&app_config))))
}

/// `GET /v1/apps` — List all apps.
async fn handle_list_apps(
    State(state): State<Arc<AppState>>,
) -> Result<(StatusCode, Json<AppListResponse>), AppError> {
    let apps = state.apps.read().await;
    let app_list: Vec<AppResponse> = apps.values().map(AppResponse::from).collect();
    Ok((StatusCode::OK, Json(AppListResponse { apps: app_list })))
}

/// `GET /v1/apps/{name}` — Get a specific app.
async fn handle_get_app(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
) -> Result<(StatusCode, Json<AppResponse>), AppError> {
    let apps = state.apps.read().await;
    let app_config = apps
        .get(&name)
        .ok_or_else(|| AppError::NotFound(format!("app '{}' not found", name)))?;
    Ok((StatusCode::OK, Json(AppResponse::from(app_config))))
}

/// `PATCH /v1/apps/{name}` — Update an app.
async fn handle_update_app(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
    Json(req): Json<UpdateAppRequest>,
) -> Result<(StatusCode, Json<AppResponse>), AppError> {
    // Get existing config and merge updates
    let updated_config = {
        let mut apps = state.apps.write().await;
        let existing = apps
            .get(&name)
            .ok_or_else(|| AppError::NotFound(format!("app '{}' not found", name)))?
            .clone();

        let mut updated = existing.clone();

        // Merge updates (only update fields that are Some)
        if let Some(image) = req.image {
            updated.app.image = image;
        }
        if let Some(domain) = req.domain {
            updated.routing.domain = domain;
        }
        if let Some(port) = req.port {
            updated.routing.port = port;
        }
        if let Some(secret) = req.secret {
            updated.app.secret = Some(secret);
        }
        if let Some(env) = req.env {
            updated.env = env;
        }
        if let Some(resources) = req.resources {
            updated.resources = resources;
        }
        if let Some(network) = req.network {
            updated.network = network;
        }
        if let Some(health) = req.health {
            updated.health = health;
        }
        if let Some(deploy) = req.deploy {
            updated.deploy = deploy;
        }
        if let Some(preview) = req.preview {
            updated.preview = Some(preview);
        }

        apps.insert(name.clone(), updated.clone());
        updated
    };

    // Write config to disk
    let config_dir = state.config_dir.clone();
    let app_config_clone = updated_config.clone();
    tokio::task::spawn_blocking(move || {
        if let Err(e) = crate::config::write_app_config(&config_dir, &app_config_clone) {
            warn!(error = %e, "failed to write app config");
        }
    });

    info!(app = %name, "app updated");

    Ok((StatusCode::OK, Json(AppResponse::from(&updated_config))))
}

/// `DELETE /v1/apps/{name}` — Delete an app.
async fn handle_delete_app(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
) -> Result<(StatusCode, Json<serde_json::Value>), AppError> {
    // Remove from apps map
    {
        let mut apps = state.apps.write().await;
        if apps.remove(&name).is_none() {
            return Err(AppError::NotFound(format!("app '{}' not found", name)));
        }
    }

    // Full teardown: stop container, remove Caddy route, clean up state
    // Get runtime state if exists
    if let Some(app_state) = state.app_states.read().await.get(&name).cloned() {
        // Stop container if running
        if let Some(ref container_id) = app_state.current_container_id
            && let Err(e) = state.runtime.stop_and_remove(container_id).await
        {
            warn!(app = %name, container_id = %container_id, error = %e, "failed to stop container during app deletion");
        }
        // Stop pod if running
        if let (Some(ref _pod_name), Some(manifest)) =
            (app_state.current_pod_name, &app_state.current_manifest_path)
            && let Err(e) = state.runtime.teardown_pod(manifest).await
        {
            warn!(app = %name, error = %e, "failed to teardown pod during app deletion");
        }
    }

    // Remove Caddy route
    if let Err(e) = state.caddy.remove_route(&name).await {
        warn!(app = %name, error = %e, "failed to remove Caddy route during app deletion");
    }

    // Remove deploy lock
    state.deploy_locks.remove(&name);

    // Remove app state
    state.app_states.write().await.remove(&name);

    // Delete config file
    let config_dir = state.config_dir.clone();
    let name_clone = name.clone();
    tokio::task::spawn_blocking(move || {
        if let Err(e) = crate::config::delete_app_config(&config_dir, &name_clone) {
            warn!(app = %name_clone, error = %e, "failed to delete app config file");
        }
    });

    info!(app = %name, "app deleted");

    Ok((StatusCode::OK, Json(serde_json::json!({"status": "ok"}))))
}

/// `POST /v1/apps/{name}/rollback` — Roll back to the previous version.
async fn handle_rollback(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
    Json(req): Json<RollbackRequest>,
) -> Result<(StatusCode, Json<DeployResponse>), AppError> {
    // Look up app config.
    let app_cfg = state
        .apps
        .read()
        .await
        .get(&name)
        .cloned()
        .ok_or_else(|| AppError::NotFound(format!("app '{}' not found", name)))?;

    // Resolve target tag.
    let target_tag = match req.to {
        Some(ref tag) => {
            validate_tag(tag)?;
            tag.clone()
        }
        None => {
            let app_states = state.app_states.read().await;
            let previous_tag = app_states.get(&name).and_then(|s| s.previous_tag.clone());
            drop(app_states);
            match previous_tag {
                Some(tag) => tag,
                None => {
                    return Err(AppError::Conflict(
                        "no previous tag to roll back to".to_string(),
                    ));
                }
            }
        }
    };

    // Acquire per-app deploy lock (non-blocking).
    let lock = {
        let lock_entry = state
            .deploy_locks
            .entry(name.clone())
            .or_insert_with(|| Arc::new(Mutex::new(())));
        lock_entry.clone()
    };

    let guard = lock
        .try_lock_owned()
        .map_err(|_| AppError::Conflict(format!("deploy already in progress for '{}'", name)))?;

    // Generate deploy_id.
    let deploy_id = format!("dep_{}", ulid::Ulid::new().to_string().to_lowercase());

    info!(
        deploy_id = %deploy_id,
        app = %name,
        tag = %target_tag,
        "rollback accepted"
    );

    let response = DeployResponse {
        deploy_id: deploy_id.clone(),
        app: name.clone(),
        tag: target_tag.clone(),
        status: "accepted".to_string(),
        preview_url: None,
    };

    // Build deploy context and record it.
    let deploy_ctx = DeployContext::new(
        deploy_id.clone(),
        name.clone(),
        app_cfg.app.image.clone(),
        target_tag.clone(),
        TriggerSource::Rollback,
    );
    state.record_deploy(&deploy_ctx);

    // Spawn deploy orchestrator.
    let state_clone = state.clone();
    tokio::spawn(async move {
        let _guard = guard;
        execute_deploy(state_clone, deploy_ctx).await;
    });

    Ok((StatusCode::ACCEPTED, Json(response)))
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
        .read()
        .await
        .get(&request.app)
        .cloned()
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

    // 8. Validate tag format.
    validate_tag(&request.tag)?;

    // ── Preview deploy path ──────────────────────────────────────────────────
    if let Some(ref preview_info) = request.preview {
        // Validate preview ID format (same charset as tags).
        if preview_info.id.is_empty() {
            return Err(AppError::BadRequest(
                "preview.id must not be empty".to_string(),
            ));
        }
        if !preview_info
            .id
            .chars()
            .all(|c| c.is_alphanumeric() || c == '-' || c == '_' || c == '.')
        {
            return Err(AppError::BadRequest(
                "preview.id contains invalid characters (allowed: alphanumeric, -, _, .)"
                    .to_string(),
            ));
        }

        // Pre-flight: verify preview domain is configured (server or app level).
        // This gives a fast 400 before spawning any background task.
        let preview_url = match resolve_preview_domain(
            &preview_info.id,
            &request.app,
            &state.config.preview,
            &app_cfg.preview,
        ) {
            Ok(domain) => Some(format!("https://{domain}")),
            Err(_) => {
                return Err(AppError::BadRequest(
                        "preview deployments not configured for this server: set [preview].domain in slip.toml".to_string(),
                    ));
            }
        };

        // Acquire per-preview deploy lock (allows concurrent preview deploys).
        let preview_lock_key = format!("{}:{}", request.app, preview_info.id);
        let lock = {
            let lock_entry = state
                .preview_locks
                .entry(preview_lock_key.clone())
                .or_insert_with(|| Arc::new(Mutex::new(())));
            lock_entry.clone()
        };

        let guard = lock.try_lock_owned().map_err(|_| {
            AppError::Conflict(format!(
                "preview deploy already in progress for '{}/{}'",
                request.app, preview_info.id
            ))
        })?;

        // Generate deploy_id.
        let deploy_id = format!("dep_{}", ulid::Ulid::new().to_string().to_lowercase());

        info!(
            deploy_id = %deploy_id,
            app = %request.app,
            tag = %request.tag,
            preview_id = %preview_info.id,
            "preview deploy accepted"
        );

        let response = DeployResponse {
            deploy_id: deploy_id.clone(),
            app: request.app.clone(),
            tag: request.tag.clone(),
            status: "accepted".to_string(),
            preview_url,
        };

        let preview_ctx = PreviewDeployContext {
            deploy_id,
            app_name: request.app.clone(),
            image: request.image.clone(),
            tag: request.tag.clone(),
            preview_id: preview_info.id.clone(),
            sha: preview_info.sha.clone(),
        };

        let state_clone = state.clone();
        tokio::spawn(async move {
            let _guard = guard;
            execute_preview_deploy(state_clone, preview_ctx).await;
        });

        return Ok((StatusCode::ACCEPTED, Json(response)));
    }

    // ── Production deploy path (unchanged) ────────────────────────────────────

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
        preview_url: None,
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

    // Check Caddy and runtime health
    let caddy_health = if state.caddy.ping().await.is_ok() {
        "ok"
    } else {
        "error"
    };
    let runtime_health = if state.runtime.ping().await.is_ok() {
        "ok"
    } else {
        "error"
    };

    let app_states = state.app_states.read().await;

    let apps_keys: Vec<String> = state.apps.read().await.keys().cloned().collect();
    let apps = apps_keys
        .into_iter()
        .map(|app_name| {
            let app_status = match app_states.get(&app_name) {
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
            caddy: caddy_health.to_string(),
            runtime: runtime_health.to_string(),
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
        crate::deploy::DeployStatus::Configuring => "configuring",
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

// ─── Preview handlers ─────────────────────────────────────────────────────────

/// Helper: convert `AppStatus` to a string for JSON responses.
fn preview_status_str(status: &crate::deploy::AppStatus) -> &'static str {
    match status {
        crate::deploy::AppStatus::Running => "running",
        crate::deploy::AppStatus::Deploying => "deploying",
        crate::deploy::AppStatus::Failed => "failed",
        crate::deploy::AppStatus::NotDeployed => "not_deployed",
    }
}

/// Helper: build a `PreviewStatusResponse` from a `PreviewState`.
fn to_preview_response(state: &PreviewState) -> PreviewStatusResponse {
    PreviewStatusResponse {
        preview_id: state.preview_id.clone(),
        app: state.app.clone(),
        sha: state.sha.clone(),
        status: preview_status_str(&state.status).to_string(),
        tag: state.tag.clone(),
        domain: state.domain.clone(),
        port: state.port,
        deployed_at: state.deployed_at,
        expires_at: state.expires_at,
    }
}

/// `DELETE /v1/previews/:app/:preview_id`
///
/// Tears down a preview deployment: stops container/pod, removes Caddy route,
/// clears state. Requires HMAC authentication (same as deploy endpoint).
async fn handle_preview_teardown(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Path((app, preview_id)): Path<(String, String)>,
) -> Result<(StatusCode, Json<serde_json::Value>), AppError> {
    // Validate HMAC signature.
    let sig_header = headers
        .get("X-Slip-Signature")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| AppError::Unauthorized("missing X-Slip-Signature header".to_string()))?;

    let app_cfg = state
        .apps
        .read()
        .await
        .get(&app)
        .cloned()
        .ok_or_else(|| AppError::NotFound(format!("unknown app: {app}")))?;

    let secret = resolve_secret(app_cfg.app.secret.as_deref(), &state.config.auth.secret);

    // Sign over the path params (app + preview_id concatenated as the "body").
    let body = format!("{app}:{preview_id}");
    if !verify_signature(sig_header, body.as_bytes(), secret) {
        warn!(app = %app, preview_id = %preview_id, "preview teardown rejected: invalid signature");
        return Err(AppError::Unauthorized("invalid signature".to_string()));
    }

    teardown_preview(
        state.runtime.as_ref(),
        &state.caddy,
        &state.preview_states,
        &state.config.storage.path,
        &app,
        &preview_id,
    )
    .await
    .map_err(|e| AppError::Internal(format!("teardown failed: {e}")))?;

    Ok((StatusCode::OK, Json(serde_json::json!({"status": "ok"}))))
}

/// `GET /v1/previews/:app`
///
/// Returns a list of all active previews for an app. No auth required (read-only).
async fn handle_list_previews(
    State(state): State<Arc<AppState>>,
    Path(app): Path<String>,
) -> (StatusCode, Json<Vec<PreviewStatusResponse>>) {
    let prefix = format!("{app}:");
    let previews: Vec<PreviewStatusResponse> = state
        .preview_states
        .iter()
        .filter(|entry| entry.key().starts_with(&prefix))
        .map(|entry| to_preview_response(entry.value()))
        .collect();

    (StatusCode::OK, Json(previews))
}

/// `GET /v1/previews/:app/:preview_id`
///
/// Returns the status of a single preview. No auth required (read-only).
async fn handle_preview_status(
    State(state): State<Arc<AppState>>,
    Path((app, preview_id)): Path<(String, String)>,
) -> Result<(StatusCode, Json<PreviewStatusResponse>), AppError> {
    let key = format!("{app}:{preview_id}");
    let entry = state.preview_states.get(&key).ok_or_else(|| {
        AppError::NotFound(format!("preview '{preview_id}' not found for app '{app}'"))
    })?;

    Ok((StatusCode::OK, Json(to_preview_response(&entry))))
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::path::PathBuf;
    use std::sync::Arc;

    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use dashmap::DashMap;
    use tokio::sync::RwLock;
    use tower::ServiceExt;

    use chrono::Utc;

    use crate::api::{
        AppListResponse, AppResponse, AppState, DeployResponse, ErrorResponse, build_router,
    };
    use crate::auth::compute_signature;
    use crate::caddy::CaddyClient;
    use crate::config::{
        AppConfig, AppInfo, AuthConfig, CaddyConfig, DeployConfig, HealthConfig, NetworkConfig,
        RegistryConfig, ResourceConfig, RoutingConfig, RuntimeConfig, ServerConfig, SlipConfig,
        StorageConfig,
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
            runtime: RuntimeConfig::default(),
            preview: None,
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
            preview: None,
        }
    }

    /// Build an `Arc<AppState>` for tests. Uses per-app secret when `use_app_secret` is true.
    fn create_test_state() -> Arc<AppState> {
        let mut apps = HashMap::new();
        apps.insert(APP_NAME.to_string(), test_app_config(Some(APP_SECRET)));

        Arc::new(AppState {
            config: test_slip_config(),
            apps: RwLock::new(apps),
            config_dir: PathBuf::from("/tmp/slip-test"),
            deploy_locks: DashMap::new(),
            runtime: Arc::new(
                DockerClient::new_with_url("http://127.0.0.1:19998").expect("DockerClient::new"),
            ),
            caddy: CaddyClient::new("http://127.0.0.1:19999".to_string()),
            health: HealthChecker::new(),
            app_states: RwLock::new(HashMap::new()),
            deploys: DashMap::new(),
            started_at: Utc::now(),
            preview_states: Arc::new(DashMap::new()),
            preview_locks: DashMap::new(),
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

    // ── DeployRequest backward compatibility ──────────────────────────────────

    #[test]
    fn test_deploy_request_no_preview_field_deserializes() {
        // Old clients that don't send `preview` should still parse fine.
        let json = r#"{"app":"myapp","image":"ghcr.io/org/myapp","tag":"v1.0.0"}"#;
        let req: crate::api::DeployRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.app, "myapp");
        assert_eq!(req.tag, "v1.0.0");
        assert!(
            req.preview.is_none(),
            "preview must be None when field is absent"
        );
    }

    #[test]
    fn test_deploy_request_with_preview_field_deserializes() {
        let json = r#"{
            "app": "myapp",
            "image": "ghcr.io/org/myapp",
            "tag": "sha-abc123",
            "preview": {"id": "pr-42", "sha": "abc123def456"}
        }"#;
        let req: crate::api::DeployRequest = serde_json::from_str(json).unwrap();
        let preview = req.preview.expect("preview should be Some");
        assert_eq!(preview.id, "pr-42");
        assert_eq!(preview.sha, "abc123def456");
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
            apps: RwLock::new(apps),
            config_dir: PathBuf::from("/tmp/slip-test"),
            deploy_locks,
            runtime: Arc::new(
                DockerClient::new_with_url("http://127.0.0.1:19998").expect("DockerClient::new"),
            ),
            caddy: CaddyClient::new("http://127.0.0.1:19999".to_string()),
            health: HealthChecker::new(),
            app_states: RwLock::new(HashMap::new()),
            deploys: DashMap::new(),
            started_at: Utc::now(),
            preview_states: Arc::new(DashMap::new()),
            preview_locks: DashMap::new(),
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
            apps: RwLock::new(apps),
            config_dir: PathBuf::from("/tmp/slip-test"),
            deploy_locks: DashMap::new(),
            runtime: Arc::new(
                DockerClient::new_with_url("http://127.0.0.1:19998").expect("DockerClient::new"),
            ),
            caddy: CaddyClient::new("http://127.0.0.1:19999".to_string()),
            health: HealthChecker::new(),
            app_states: RwLock::new(HashMap::new()),
            deploys: DashMap::new(),
            started_at: Utc::now(),
            preview_states: Arc::new(DashMap::new()),
            preview_locks: DashMap::new(),
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
            new_pod_name: None,
            new_manifest_path: None,
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

    // ── POST /v1/deploy with preview field → 202 ──────────────────────────────

    #[tokio::test]
    async fn test_deploy_with_preview_field_returns_202() {
        use crate::config::ServerPreviewConfig;

        let mut apps = HashMap::new();
        apps.insert(APP_NAME.to_string(), test_app_config(Some(APP_SECRET)));

        let mut config = test_slip_config();
        config.preview = Some(ServerPreviewConfig {
            domain: "preview.example.com".to_string(),
            max_per_app: None,
            default_ttl: None,
            max_memory: None,
            max_cpus: None,
        });

        let state = Arc::new(AppState {
            config,
            apps: RwLock::new(apps),
            config_dir: PathBuf::from("/tmp/slip-test"),
            deploy_locks: DashMap::new(),
            runtime: Arc::new(
                DockerClient::new_with_url("http://127.0.0.1:19998").expect("DockerClient::new"),
            ),
            caddy: CaddyClient::new("http://127.0.0.1:19999".to_string()),
            health: HealthChecker::new(),
            app_states: RwLock::new(HashMap::new()),
            deploys: DashMap::new(),
            started_at: Utc::now(),
            preview_states: Arc::new(DashMap::new()),
            preview_locks: DashMap::new(),
        });

        let app = build_router(state);

        let body_json = serde_json::json!({
            "app": APP_NAME,
            "image": APP_IMAGE,
            "tag": "sha-abc123",
            "preview": {
                "id": "pr-42",
                "sha": "abc123def456"
            }
        })
        .to_string();
        let body_bytes = body_json.as_bytes().to_vec();
        let sig = sig_header(&body_bytes, APP_SECRET);

        let request = Request::builder()
            .method("POST")
            .uri("/v1/deploy")
            .header("Content-Type", "application/json")
            .header("X-Slip-Signature", sig)
            .body(Body::from(body_bytes))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::ACCEPTED);

        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let payload: DeployResponse = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(payload.app, APP_NAME);
        assert_eq!(payload.tag, "sha-abc123");
        assert_eq!(payload.status, "accepted");
        assert!(payload.deploy_id.starts_with("dep_"));
    }

    // ── POST /v1/deploy preview: invalid preview_id → 400 ────────────────────

    #[tokio::test]
    async fn test_deploy_preview_invalid_id() {
        let state = create_test_state();
        let app = build_router(state);

        let body_json = serde_json::json!({
            "app": APP_NAME,
            "image": APP_IMAGE,
            "tag": "sha-abc123",
            "preview": {
                "id": "pr/42", // invalid: contains slash
                "sha": "abc123"
            }
        })
        .to_string();
        let body_bytes = body_json.as_bytes().to_vec();
        let sig = sig_header(&body_bytes, APP_SECRET);

        let request = Request::builder()
            .method("POST")
            .uri("/v1/deploy")
            .header("Content-Type", "application/json")
            .header("X-Slip-Signature", sig)
            .body(Body::from(body_bytes))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let payload: ErrorResponse = serde_json::from_slice(&bytes).unwrap();
        assert!(payload.error.contains("invalid characters"));
    }

    // ── GET /v1/previews/:app — empty list ────────────────────────────────────

    #[tokio::test]
    async fn test_list_previews_empty() {
        let state = create_test_state();
        let app = build_router(state);

        let request = Request::builder()
            .method("GET")
            .uri(format!("/v1/previews/{APP_NAME}"))
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let payload: Vec<serde_json::Value> = serde_json::from_slice(&bytes).unwrap();
        assert!(payload.is_empty(), "should return empty list");
    }

    // ── GET /v1/previews/:app — with previews ─────────────────────────────────

    #[tokio::test]
    async fn test_list_previews_with_entries() {
        use crate::deploy::AppStatus;
        use crate::preview::PreviewState;
        use chrono::Utc;

        let state = create_test_state();

        // Insert two previews for testapp and one for another app.
        state.preview_states.insert(
            format!("{APP_NAME}:pr-1"),
            PreviewState {
                preview_id: "pr-1".to_string(),
                app: APP_NAME.to_string(),
                sha: "abc".to_string(),
                status: AppStatus::Running,
                container_id: Some("ctr-1".to_string()),
                pod_name: None,
                port: Some(54001),
                tag: Some("v1".to_string()),
                deployed_at: Utc::now(),
                expires_at: None,
                domain: "pr-1.preview.example.com".to_string(),
                manifest_path: None,
                deploy_id: None,
            },
        );
        state.preview_states.insert(
            format!("{APP_NAME}:pr-2"),
            PreviewState {
                preview_id: "pr-2".to_string(),
                app: APP_NAME.to_string(),
                sha: "def".to_string(),
                status: AppStatus::Running,
                container_id: Some("ctr-2".to_string()),
                pod_name: None,
                port: Some(54002),
                tag: Some("v2".to_string()),
                deployed_at: Utc::now(),
                expires_at: None,
                domain: "pr-2.preview.example.com".to_string(),
                manifest_path: None,
                deploy_id: None,
            },
        );
        // Different app — should not appear in the list for APP_NAME.
        state.preview_states.insert(
            "otherapp:pr-1".to_string(),
            PreviewState {
                preview_id: "pr-1".to_string(),
                app: "otherapp".to_string(),
                sha: "ghi".to_string(),
                status: AppStatus::Running,
                container_id: Some("ctr-other".to_string()),
                pod_name: None,
                port: Some(54003),
                tag: Some("v1".to_string()),
                deployed_at: Utc::now(),
                expires_at: None,
                domain: "pr-1.other.example.com".to_string(),
                manifest_path: None,
                deploy_id: None,
            },
        );

        let app = build_router(state);

        let request = Request::builder()
            .method("GET")
            .uri(format!("/v1/previews/{APP_NAME}"))
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let payload: Vec<serde_json::Value> = serde_json::from_slice(&bytes).unwrap();

        assert_eq!(payload.len(), 2, "should return 2 previews for testapp");
        let ids: Vec<&str> = payload
            .iter()
            .map(|p| p["preview_id"].as_str().unwrap())
            .collect();
        assert!(ids.contains(&"pr-1"), "should contain pr-1");
        assert!(ids.contains(&"pr-2"), "should contain pr-2");
    }

    // ── GET /v1/previews/:app/:preview_id — found ─────────────────────────────

    #[tokio::test]
    async fn test_preview_status_found() {
        use crate::deploy::AppStatus;
        use crate::preview::PreviewState;
        use chrono::Utc;

        let state = create_test_state();

        state.preview_states.insert(
            format!("{APP_NAME}:pr-99"),
            PreviewState {
                preview_id: "pr-99".to_string(),
                app: APP_NAME.to_string(),
                sha: "sha999".to_string(),
                status: AppStatus::Running,
                container_id: Some("ctr-99".to_string()),
                pod_name: None,
                port: Some(55999),
                tag: Some("sha-abc999".to_string()),
                deployed_at: Utc::now(),
                expires_at: None,
                domain: "pr-99.preview.example.com".to_string(),
                manifest_path: None,
                deploy_id: None,
            },
        );

        let app = build_router(state);

        let request = Request::builder()
            .method("GET")
            .uri(format!("/v1/previews/{APP_NAME}/pr-99"))
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let payload: serde_json::Value = serde_json::from_slice(&bytes).unwrap();

        assert_eq!(payload["preview_id"], "pr-99");
        assert_eq!(payload["app"], APP_NAME);
        assert_eq!(payload["status"], "running");
        assert_eq!(payload["tag"], "sha-abc999");
        assert_eq!(payload["port"], 55999);
    }

    // ── GET /v1/previews/:app/:preview_id — not found ─────────────────────────

    #[tokio::test]
    async fn test_preview_status_not_found() {
        let state = create_test_state();
        let app = build_router(state);

        let request = Request::builder()
            .method("GET")
            .uri(format!("/v1/previews/{APP_NAME}/nonexistent"))
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let payload: ErrorResponse = serde_json::from_slice(&bytes).unwrap();
        assert!(payload.error.contains("not found"));
    }

    // ── DELETE /v1/previews/:app/:preview_id — missing signature → 401 ────────

    #[tokio::test]
    async fn test_preview_teardown_missing_signature() {
        let state = create_test_state();
        let app = build_router(state);

        let request = Request::builder()
            .method("DELETE")
            .uri(format!("/v1/previews/{APP_NAME}/pr-1"))
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    // ── DELETE /v1/previews/:app/:preview_id — invalid signature → 401 ────────

    #[tokio::test]
    async fn test_preview_teardown_invalid_signature() {
        let state = create_test_state();
        let app = build_router(state);

        let request = Request::builder()
            .method("DELETE")
            .uri(format!("/v1/previews/{APP_NAME}/pr-1"))
            .header("X-Slip-Signature", "sha256=deadbeef")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    // ── POST /v1/deploy with preview but no server preview config → 400 ────────

    #[tokio::test]
    async fn test_deploy_preview_no_domain_config_returns_400() {
        // State has no server preview config (preview: None in SlipConfig).
        let state = create_test_state(); // uses test_slip_config() which has preview: None
        let app = build_router(state);

        let body_json = serde_json::json!({
            "app": APP_NAME,
            "image": APP_IMAGE,
            "tag": "sha-abc123",
            "preview": {
                "id": "pr-42",
                "sha": "abc123def456"
            }
        })
        .to_string();
        let body_bytes = body_json.as_bytes().to_vec();
        let sig = sig_header(&body_bytes, APP_SECRET);

        let request = Request::builder()
            .method("POST")
            .uri("/v1/deploy")
            .header("Content-Type", "application/json")
            .header("X-Slip-Signature", sig)
            .body(Body::from(body_bytes))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(
            response.status(),
            StatusCode::BAD_REQUEST,
            "should reject preview deploy when no domain is configured"
        );

        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let payload: ErrorResponse = serde_json::from_slice(&bytes).unwrap();
        assert!(
            payload.error.contains("not configured") || payload.error.contains("domain"),
            "error should mention preview not configured: {}",
            payload.error
        );
    }

    // ── POST /v1/deploy with preview + server config → 202 with preview_url ──

    #[tokio::test]
    async fn test_deploy_preview_with_server_config_returns_preview_url() {
        use crate::config::ServerPreviewConfig;

        let mut apps = HashMap::new();
        apps.insert(APP_NAME.to_string(), test_app_config(Some(APP_SECRET)));

        let mut config = test_slip_config();
        config.preview = Some(ServerPreviewConfig {
            domain: "preview.example.com".to_string(),
            max_per_app: None,
            default_ttl: None,
            max_memory: None,
            max_cpus: None,
        });

        let state = Arc::new(AppState {
            config,
            apps: RwLock::new(apps),
            config_dir: PathBuf::from("/tmp/slip-test"),
            deploy_locks: DashMap::new(),
            runtime: Arc::new(
                DockerClient::new_with_url("http://127.0.0.1:19998").expect("DockerClient::new"),
            ),
            caddy: CaddyClient::new("http://127.0.0.1:19999".to_string()),
            health: HealthChecker::new(),
            app_states: RwLock::new(HashMap::new()),
            deploys: DashMap::new(),
            started_at: Utc::now(),
            preview_states: Arc::new(DashMap::new()),
            preview_locks: DashMap::new(),
        });

        let app = build_router(state);

        let body_json = serde_json::json!({
            "app": APP_NAME,
            "image": APP_IMAGE,
            "tag": "sha-abc123",
            "preview": {
                "id": "pr-42",
                "sha": "abc123def456"
            }
        })
        .to_string();
        let body_bytes = body_json.as_bytes().to_vec();
        let sig = sig_header(&body_bytes, APP_SECRET);

        let request = Request::builder()
            .method("POST")
            .uri("/v1/deploy")
            .header("Content-Type", "application/json")
            .header("X-Slip-Signature", sig)
            .body(Body::from(body_bytes))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::ACCEPTED);

        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let payload: serde_json::Value = serde_json::from_slice(&bytes).unwrap();

        assert_eq!(payload["app"], APP_NAME);
        assert_eq!(payload["status"], "accepted");
        // preview_url should be included and point to the expected subdomain.
        let preview_url = payload["preview_url"]
            .as_str()
            .expect("preview_url should be present");
        assert!(
            preview_url.contains("pr-42.preview.example.com"),
            "preview_url should contain subdomain: {preview_url}"
        );
    }

    // ── POST /v1/deploy (production) → no preview_url in response ─────────────

    #[tokio::test]
    async fn test_deploy_production_response_has_no_preview_url() {
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
        let payload: serde_json::Value = serde_json::from_slice(&bytes).unwrap();

        // preview_url should be absent from the JSON (skip_serializing_if = None).
        assert!(
            payload["preview_url"].is_null(),
            "preview_url should not be present in production deploy response"
        );
    }

    // ── DELETE /v1/previews/:app/:preview_id — valid, no preview → 200 ────────

    #[tokio::test]
    async fn test_preview_teardown_valid_nonexistent_returns_ok() {
        // teardown_preview is idempotent — deleting a non-existent preview → 200.
        let state = create_test_state();
        let app = build_router(state);

        // Sign over "testapp:pr-99" (the body format used by teardown).
        let body = format!("{APP_NAME}:pr-99");
        let sig = sig_header(body.as_bytes(), APP_SECRET);

        let request = Request::builder()
            .method("DELETE")
            .uri(format!("/v1/previews/{APP_NAME}/pr-99"))
            .header("X-Slip-Signature", sig)
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let payload: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(payload["status"], "ok");
    }

    // ── Management API tests ─────────────────────────────────────────────────────

    fn auth_header(token: &str) -> String {
        format!("Bearer {token}")
    }

    #[tokio::test]
    async fn test_management_auth_missing_header() {
        let state = create_test_state();
        let app = build_router(state);

        let request = Request::builder()
            .method("GET")
            .uri("/v1/apps")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_management_auth_invalid_token() {
        let state = create_test_state();
        let app = build_router(state);

        let request = Request::builder()
            .method("GET")
            .uri("/v1/apps")
            .header("Authorization", "Bearer wrong-token")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_list_apps_empty() {
        let config = test_slip_config();
        let state = Arc::new(AppState {
            config,
            apps: RwLock::new(HashMap::new()),
            config_dir: PathBuf::from("/tmp/slip-test"),
            deploy_locks: DashMap::new(),
            runtime: Arc::new(
                DockerClient::new_with_url("http://127.0.0.1:19998").expect("DockerClient::new"),
            ),
            caddy: CaddyClient::new("http://127.0.0.1:19999".to_string()),
            health: HealthChecker::new(),
            app_states: RwLock::new(HashMap::new()),
            deploys: DashMap::new(),
            started_at: Utc::now(),
            preview_states: Arc::new(DashMap::new()),
            preview_locks: DashMap::new(),
        });
        let app = build_router(state);

        let request = Request::builder()
            .method("GET")
            .uri("/v1/apps")
            .header("Authorization", auth_header(GLOBAL_SECRET))
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let payload: AppListResponse = serde_json::from_slice(&bytes).unwrap();
        assert!(payload.apps.is_empty());
    }

    #[tokio::test]
    async fn test_list_apps_with_apps() {
        let state = create_test_state();
        let app = build_router(state);

        let request = Request::builder()
            .method("GET")
            .uri("/v1/apps")
            .header("Authorization", auth_header(GLOBAL_SECRET))
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let payload: AppListResponse = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(payload.apps.len(), 1);
        assert_eq!(payload.apps[0].name, APP_NAME);
    }

    #[tokio::test]
    async fn test_get_app_found() {
        let state = create_test_state();
        let app = build_router(state);

        let request = Request::builder()
            .method("GET")
            .uri(format!("/v1/apps/{APP_NAME}"))
            .header("Authorization", auth_header(GLOBAL_SECRET))
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let payload: AppResponse = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(payload.name, APP_NAME);
        assert_eq!(payload.image, APP_IMAGE);
    }

    #[tokio::test]
    async fn test_get_app_not_found() {
        let state = create_test_state();
        let app = build_router(state);

        let request = Request::builder()
            .method("GET")
            .uri("/v1/apps/nonexistent")
            .header("Authorization", auth_header(GLOBAL_SECRET))
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_create_app_success() {
        let config = test_slip_config();
        let state = Arc::new(AppState {
            config,
            apps: RwLock::new(HashMap::new()),
            config_dir: PathBuf::from("/tmp/slip-test"),
            deploy_locks: DashMap::new(),
            runtime: Arc::new(
                DockerClient::new_with_url("http://127.0.0.1:19998").expect("DockerClient::new"),
            ),
            caddy: CaddyClient::new("http://127.0.0.1:19999".to_string()),
            health: HealthChecker::new(),
            app_states: RwLock::new(HashMap::new()),
            deploys: DashMap::new(),
            started_at: Utc::now(),
            preview_states: Arc::new(DashMap::new()),
            preview_locks: DashMap::new(),
        });
        let app = build_router(state.clone());

        let body = serde_json::json!({
            "name": "newapp",
            "image": "ghcr.io/org/newapp:latest",
            "domain": "newapp.example.com",
            "port": 3000
        });

        let request = Request::builder()
            .method("POST")
            .uri("/v1/apps")
            .header("Authorization", auth_header(GLOBAL_SECRET))
            .header("Content-Type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);

        // Verify app was added
        let apps = state.apps.read().await;
        assert!(apps.contains_key("newapp"));
    }

    #[tokio::test]
    async fn test_create_app_conflict() {
        let state = create_test_state();
        let app = build_router(state);

        let body = serde_json::json!({
            "name": APP_NAME,
            "image": "ghcr.io/org/testapp:latest",
            "domain": "testapp.example.com",
            "port": 3000
        });

        let request = Request::builder()
            .method("POST")
            .uri("/v1/apps")
            .header("Authorization", auth_header(GLOBAL_SECRET))
            .header("Content-Type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn test_create_app_invalid_name() {
        let state = create_test_state();
        let app = build_router(state);

        let body = serde_json::json!({
            "name": "Invalid-Name",
            "image": "ghcr.io/org/testapp:latest",
            "domain": "testapp.example.com",
            "port": 3000
        });

        let request = Request::builder()
            .method("POST")
            .uri("/v1/apps")
            .header("Authorization", auth_header(GLOBAL_SECRET))
            .header("Content-Type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_update_app_partial() {
        let state = create_test_state();
        let app = build_router(state.clone());

        let body = serde_json::json!({
            "port": 9000
        });

        let request = Request::builder()
            .method("PATCH")
            .uri(format!("/v1/apps/{APP_NAME}"))
            .header("Authorization", auth_header(GLOBAL_SECRET))
            .header("Content-Type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        // Verify port was updated
        let apps = state.apps.read().await;
        let app_config = apps.get(APP_NAME).unwrap();
        assert_eq!(app_config.routing.port, 9000);
    }

    #[tokio::test]
    async fn test_delete_app() {
        let state = create_test_state();
        let app = build_router(state.clone());

        let request = Request::builder()
            .method("DELETE")
            .uri(format!("/v1/apps/{APP_NAME}"))
            .header("Authorization", auth_header(GLOBAL_SECRET))
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        // Verify app was removed
        let apps = state.apps.read().await;
        assert!(!apps.contains_key(APP_NAME));
    }

    // ── Rollback API tests ──────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_rollback_no_previous_tag_returns_409() {
        let state = create_test_state();
        let app = build_router(state);

        let body = serde_json::json!({});
        let request = Request::builder()
            .method("POST")
            .uri(format!("/v1/apps/{APP_NAME}/rollback"))
            .header("Authorization", auth_header(GLOBAL_SECRET))
            .header("Content-Type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::CONFLICT);

        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let payload: ErrorResponse = serde_json::from_slice(&bytes).unwrap();
        assert!(payload.error.contains("no previous tag"));
    }

    #[tokio::test]
    async fn test_rollback_with_previous_tag_returns_202() {
        let state = create_test_state();

        // Pre-populate app_states with previous_tag.
        {
            let mut app_states = state.app_states.write().await;
            app_states.insert(
                APP_NAME.to_string(),
                AppRuntimeState {
                    status: AppStatus::Running,
                    current_tag: Some("v2.0".to_string()),
                    previous_tag: Some("v1.0".to_string()),
                    ..Default::default()
                },
            );
        }

        let app = build_router(state);

        let body = serde_json::json!({});
        let request = Request::builder()
            .method("POST")
            .uri(format!("/v1/apps/{APP_NAME}/rollback"))
            .header("Authorization", auth_header(GLOBAL_SECRET))
            .header("Content-Type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::ACCEPTED);

        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let payload: DeployResponse = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(payload.tag, "v1.0");
        assert_eq!(payload.app, APP_NAME);
        assert_eq!(payload.status, "accepted");
        assert!(payload.deploy_id.starts_with("dep_"));
    }

    #[tokio::test]
    async fn test_rollback_with_explicit_to_tag_returns_202() {
        let state = create_test_state();
        let app = build_router(state);

        let body = serde_json::json!({"to": "v0.9"});
        let request = Request::builder()
            .method("POST")
            .uri(format!("/v1/apps/{APP_NAME}/rollback"))
            .header("Authorization", auth_header(GLOBAL_SECRET))
            .header("Content-Type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::ACCEPTED);

        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let payload: DeployResponse = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(payload.tag, "v0.9");
    }

    #[tokio::test]
    async fn test_rollback_unknown_app_returns_404() {
        let state = create_test_state();
        let app = build_router(state);

        let body = serde_json::json!({});
        let request = Request::builder()
            .method("POST")
            .uri("/v1/apps/nonexistent/rollback")
            .header("Authorization", auth_header(GLOBAL_SECRET))
            .header("Content-Type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_rollback_requires_auth() {
        let state = create_test_state();
        let app = build_router(state);

        let body = serde_json::json!({});
        let request = Request::builder()
            .method("POST")
            .uri(format!("/v1/apps/{APP_NAME}/rollback"))
            .header("Content-Type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_rollback_empty_to_tag_returns_400() {
        let state = create_test_state();
        let app = build_router(state);

        let body = serde_json::json!({"to": ""});
        let request = Request::builder()
            .method("POST")
            .uri(format!("/v1/apps/{APP_NAME}/rollback"))
            .header("Authorization", auth_header(GLOBAL_SECRET))
            .header("Content-Type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let payload: ErrorResponse = serde_json::from_slice(&bytes).unwrap();
        assert!(payload.error.contains("tag"));
    }

    #[tokio::test]
    async fn test_rollback_concurrent_returns_409() {
        use tokio::sync::Mutex;

        let mut apps = HashMap::new();
        apps.insert(APP_NAME.to_string(), test_app_config(Some(APP_SECRET)));

        let deploy_locks: DashMap<String, Arc<Mutex<()>>> = DashMap::new();
        // Pre-insert a locked mutex so the handler cannot acquire it.
        let locked = Arc::new(Mutex::new(()));
        let _guard = locked.clone().try_lock_owned().unwrap();
        deploy_locks.insert(APP_NAME.to_string(), locked);

        let state = Arc::new(AppState {
            config: test_slip_config(),
            apps: RwLock::new(apps),
            config_dir: PathBuf::from("/tmp/slip-test"),
            deploy_locks,
            runtime: Arc::new(
                DockerClient::new_with_url("http://127.0.0.1:19998").expect("DockerClient::new"),
            ),
            caddy: CaddyClient::new("http://127.0.0.1:19999".to_string()),
            health: HealthChecker::new(),
            app_states: RwLock::new(HashMap::new()),
            deploys: DashMap::new(),
            started_at: Utc::now(),
            preview_states: Arc::new(DashMap::new()),
            preview_locks: DashMap::new(),
        });

        let app = build_router(state);

        let body = serde_json::json!({"to": "v1.0"});
        let request = Request::builder()
            .method("POST")
            .uri(format!("/v1/apps/{APP_NAME}/rollback"))
            .header("Authorization", auth_header(GLOBAL_SECRET))
            .header("Content-Type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::CONFLICT);

        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let payload: ErrorResponse = serde_json::from_slice(&bytes).unwrap();
        assert!(payload.error.contains("in progress"));
    }

    #[tokio::test]
    async fn test_rollback_then_rollback_again() {
        let state = create_test_state();

        // Pre-populate app_states with current=v2.0, previous=v1.0.
        {
            let mut app_states = state.app_states.write().await;
            app_states.insert(
                APP_NAME.to_string(),
                AppRuntimeState {
                    status: AppStatus::Running,
                    current_tag: Some("v2.0".to_string()),
                    previous_tag: Some("v1.0".to_string()),
                    ..Default::default()
                },
            );
        }

        let app = build_router(state);

        // POST /v1/apps/testapp/rollback with empty body → 202, tag should be "v1.0"
        let body = serde_json::json!({});
        let request = Request::builder()
            .method("POST")
            .uri(format!("/v1/apps/{APP_NAME}/rollback"))
            .header("Authorization", auth_header(GLOBAL_SECRET))
            .header("Content-Type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::ACCEPTED);

        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let payload: DeployResponse = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            payload.tag, "v1.0",
            "rollback should target previous_tag v1.0"
        );
    }
}
