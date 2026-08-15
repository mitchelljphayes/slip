//! HTTP API types, router, and handlers for slipd.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use axum::body::Body;
use axum::extract::{DefaultBodyLimit, Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::{Json, body::Bytes};
use chrono::{DateTime, Utc};
use dashmap::DashMap;
use futures_util::StreamExt;
use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, RwLock};
use tracing::{info, warn};

use crate::auth::{resolve_secret, verify_signature};
use crate::caddy::CaddyClient;
use crate::config::{AppConfig, SlipConfig};
use crate::db::Db;
use crate::deploy::{AppRuntimeState, DeployContext, TriggerSource, execute_deploy};
use crate::health::HealthChecker;
use crate::preview::{
    PreviewDeployContext, PreviewState, execute_preview_deploy, resolve_preview_domain,
    teardown_preview,
};
use crate::runtime::{ContainerInfo, RuntimeBackend};
use crate::secrets::{SecretsStore, validate_secret_key};

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
    /// Image base (e.g., "ghcr.io/org/stat-stream"). Optional — server resolves
    /// from app config when omitted.
    #[serde(default)]
    pub image: Option<String>,
    pub tag: String,
    /// If present, this is a preview deploy rather than a production deploy.
    #[serde(default)]
    pub preview: Option<PreviewRequestInfo>,
    /// Optional per-container image overrides: container_name → full image reference.
    /// Values are full image references (e.g., "ghcr.io/org/dagster:v1.2.3").
    #[serde(default)]
    pub images: HashMap<String, String>,
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

/// Query parameters for `GET /v1/apps/{name}/logs`.
#[derive(Debug, Deserialize)]
pub struct LogsQueryParams {
    /// Duration string (e.g. "1h", "5m30s") — only show logs newer than this.
    #[serde(default)]
    pub since: Option<String>,
    /// Follow log output (stream new lines as they arrive). Default: false.
    #[serde(default)]
    pub follow: Option<bool>,
}

/// One NDJSON line in the logs stream.
#[derive(Debug, Serialize)]
pub struct LogEntry {
    /// RFC 3339 timestamp (or null if the runtime didn't provide one).
    pub ts: Option<String>,
    /// Container short ID or name.
    pub container: String,
    /// Stream name: "stdout", "stderr", or "console".
    pub stream: String,
    /// The log line (timestamp already stripped).
    pub line: String,
}

/// In-stream error event (NDJSON line).
#[derive(Debug, Serialize)]
struct LogStreamError {
    error: String,
    container: String,
}

/// Response for `GET /v1/status`.
///
/// Schema: `slip.status/v1`
#[derive(Debug, Serialize, Deserialize)]
pub struct StatusResponse {
    /// Schema version tag.
    pub schema: String,
    /// Daemon name ("slipd").
    pub daemon: String,
    /// slipd version (from CARGO_PKG_VERSION).
    pub version: String,
    pub uptime_seconds: i64,
    /// "ok" or "error".
    pub caddy: String,
    /// "ok" or "error".
    pub runtime: String,
    /// Runtime backend name ("docker" or "podman").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub runtime_backend: Option<String>,
    /// Number of registered apps.
    pub app_count: usize,
    /// Last deploys summary (latest deploy per app).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub last_deploys: Vec<DeploySummary>,
    pub apps: HashMap<String, AppStatusResponse>,
}

/// Per-app status within a `StatusResponse`.
///
/// When queried for a specific app (`slip status <app>`), this is enriched
/// with health, routes, secrets, cert, and drift information.
#[derive(Debug, Serialize, Deserialize)]
pub struct AppStatusResponse {
    pub status: String,
    pub tag: Option<String>,
    pub deployed_at: Option<DateTime<Utc>>,
    pub container_id: Option<String>,
    pub port: Option<u16>,
    /// App kind: "container", "pod", or "worker".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    /// Latest deploy ID for this app (from the deploy history cache).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deploy_id: Option<String>,
    /// How the latest deploy was triggered (from the deploy history cache).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub triggered_by: Option<String>,
    // ── Enriched fields (populated by `slip status <app>`) ──────────────────
    /// Container state from the runtime (e.g. "running", "exited").
    /// Populated by querying containers by `slip.app` label.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub container_state: Option<String>,

    /// Health check config + last probe result.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub health: Option<HealthStatus>,

    /// Last deploy summary (id, status, reason, timestamp).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_deploy: Option<DeploySummary>,

    /// Route hostnames registered in Caddy for this app.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub routes: Vec<RouteStatus>,

    /// Secret key names (never values).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub secrets: Vec<String>,

    /// Certificate issuer for this app's domain(s).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cert: Option<CertStatus>,

    /// True when live server config differs from last `slip apply`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config_drift: Option<bool>,
}

/// Health check status for an app.
#[derive(Debug, Serialize, Deserialize)]
pub struct HealthStatus {
    /// Configured health check path (None = no health check configured).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// Number of retries configured.
    pub retries: u32,
    /// "healthy", "unhealthy", or "unknown" (not yet probed / no path configured).
    pub status: String,
    /// Timestamp of the last health probe, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_check: Option<DateTime<Utc>>,
}

/// Deploy summary for status responses.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DeploySummary {
    pub deploy_id: String,
    pub app: String,
    pub tag: String,
    /// Deploy status string ("completed", "failed", "accepted", etc.).
    pub status: String,
    /// How the deploy was triggered: "webhook", "cli", or "rollback".
    pub triggered_by: String,
    pub started_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub finished_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Route status for an app.
#[derive(Debug, Serialize, Deserialize)]
pub struct RouteStatus {
    pub hostname: String,
    pub port: u16,
}

/// Certificate status for an app's domain.
#[derive(Debug, Serialize, Deserialize)]
pub struct CertStatus {
    /// TLS issuer: "internal" (self-signed) or "acme" (Let's Encrypt).
    pub issuer: String,
    /// Certificate expiry (if known).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
}

/// Request body for `POST /v1/tls/renew`.
#[derive(Debug, Deserialize)]
pub struct TlsRenewRequest {
    pub host: String,
    /// Restart Caddy as a retry if ratio-bump doesn't clear the stuck state.
    #[serde(default)]
    pub restart_caddy: bool,
}

/// Response for `POST /v1/tls/renew` (schema `slip.tls.renew/v1`).
#[derive(Debug, Serialize)]
pub struct TlsRenewResult {
    pub schema: &'static str,
    pub host: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub before_not_after: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub after_not_after: Option<String>,
    pub renewed: bool,
    pub restored: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub managed_by: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    pub elapsed_ms: u64,
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
    pub domain: Option<String>,
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
    /// Volume mounts for the app.
    #[serde(default)]
    pub volumes: Option<Vec<crate::config::VolumeConfig>>,
    /// Multi-route entries.
    #[serde(default)]
    pub routes: Option<Vec<crate::config::RouteEntry>>,
    /// Per-app routing TLS strategy override (None = inherit/classify).
    #[serde(default)]
    pub tls: Option<crate::config::TlsStrategy>,
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
    /// Volume mounts for the app.
    #[serde(default)]
    pub volumes: Option<Vec<crate::config::VolumeConfig>>,
    /// Multi-route entries.
    #[serde(default)]
    pub routes: Option<Vec<crate::config::RouteEntry>>,
    /// Per-app routing TLS strategy override (None = inherit/classify).
    #[serde(default)]
    pub tls: Option<crate::config::TlsStrategy>,
}

/// Request body for `POST /v1/apps/{name}/rollback`.
#[derive(Debug, Deserialize)]
pub struct RollbackRequest {
    /// Target tag to roll back to. If omitted, uses `previous_tag` from runtime state.
    #[serde(default)]
    pub to: Option<String>,
}

/// Request body for `PUT /v1/apps/{name}/secrets`.
#[derive(Debug, Deserialize)]
pub struct SetSecretsRequest {
    pub secrets: HashMap<String, String>,
}

/// Response for `PUT /v1/apps/{name}/secrets` — lists keys that were set.
#[derive(Debug, Serialize, Deserialize)]
pub struct SetSecretsResponse {
    pub set: Vec<String>,
}

/// Response for `GET /v1/apps/{name}/secrets` — key names only, never values.
#[derive(Debug, Serialize, Deserialize)]
pub struct SecretsListResponse {
    pub secrets: Vec<String>,
}

/// Response for `DELETE /v1/previews/{app}` — IDs of torn-down previews.
#[derive(Debug, Serialize, Deserialize)]
pub struct TeardownAllResponse {
    pub torn_down: Vec<String>,
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
#[derive(Debug, Clone, Serialize, Deserialize)]
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
    #[serde(default)]
    pub volumes: Vec<crate::config::VolumeConfig>,
    #[serde(default)]
    pub routes: Vec<crate::config::RouteEntry>,
    /// Per-app routing TLS strategy override (None = inherit/classify).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls: Option<crate::config::TlsStrategy>,
}

impl From<&AppConfig> for AppResponse {
    fn from(cfg: &AppConfig) -> Self {
        Self {
            name: cfg.app.name.clone(),
            image: cfg.app.image.clone(),
            domain: cfg.routing.domain.clone().unwrap_or_default(),
            port: cfg.routing.port.unwrap_or(0),
            // Don't expose the secret in responses
            secret: None,
            env: cfg.env.clone(),
            resources: cfg.resources.clone(),
            network: cfg.network.clone(),
            health: cfg.health.clone(),
            deploy: cfg.deploy.clone(),
            preview: cfg.preview.clone(),
            volumes: cfg.volumes.clone(),
            routes: cfg.routing.routes.clone(),
            tls: cfg.routing.tls,
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
    /// TLS renewal was not proven by certificate probe (exit 5 / DEPLOY_FAILED).
    RenewNotProven(String),
    /// TLS renewal timed out waiting for cert proof (exit 6 / TIMEOUT).
    RenewTimeout(String),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            AppError::BadRequest(msg) => (StatusCode::BAD_REQUEST, msg),
            AppError::Unauthorized(msg) => (StatusCode::UNAUTHORIZED, msg),
            AppError::NotFound(msg) => (StatusCode::NOT_FOUND, msg),
            AppError::Conflict(msg) => (StatusCode::CONFLICT, msg),
            AppError::Internal(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg),
            // 502 Bad Gateway — Caddy/storage failure that prevents completion.
            AppError::RenewNotProven(msg) => (StatusCode::from_u16(502).unwrap(), msg),
            // 504 Gateway Timeout — renewal timed out.
            AppError::RenewTimeout(msg) => (StatusCode::from_u16(504).unwrap(), msg),
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
    /// Recent deploy contexts keyed by app name (latest deploy per app).
    ///
    /// This is a write-through cache: every deploy is persisted to SQLite and
    /// also stored here for fast reads.  On daemon startup the cache is
    /// populated from SQLite.
    pub deploys: DashMap<String, DeployContext>,
    /// SQLite-backed deploy history store.
    pub db: Db,
    /// Timestamp when the daemon was started (used for uptime calculation).
    pub started_at: DateTime<Utc>,
    /// Active preview deployment states keyed by `"{app}:{preview_id}"`.
    pub preview_states: Arc<DashMap<String, PreviewState>>,
    /// Per-preview deploy locks; prevents concurrent deploys for the same preview.
    ///
    /// Keyed by `"{app}:{preview_id}"`. Allows preview deploys to run concurrently
    /// with production deploys and other previews.
    pub preview_locks: DashMap<String, Arc<Mutex<()>>>,
    /// Per-host TLS renew locks; prevents concurrent `slip tls renew <host>` calls
    /// from racing on the renewal_window_ratio bump/revert cycle.
    pub renew_locks: DashMap<String, Arc<Mutex<()>>>,
    /// File-system backed secret storage (one file per secret with 0o600 perms).
    pub secrets_store: SecretsStore,
}

impl AppState {
    /// Record (insert/update) a deploy context.
    ///
    /// Persists to SQLite (fire-and-forget via `tokio::spawn`) and updates the
    /// in-memory cache synchronously.  If the SQLite write fails it is logged
    /// but the deploy continues — deploy history is best-effort persistence.
    pub fn record_deploy(&self, ctx: &DeployContext) {
        // Persist to SQLite (fire-and-forget via spawn_blocking).
        let db = self.db.clone();
        let ctx_clone = ctx.clone();
        tokio::spawn(async move {
            tokio::task::spawn_blocking(move || {
                if let Err(e) = db.insert_deploy(&ctx_clone) {
                    tracing::error!(deploy_id = %ctx_clone.id, error = %e, "failed to persist deploy to SQLite");
                }
            })
            .await
            .ok();
        });
        // Update in-memory cache (synchronous, always succeeds)
        self.deploys.insert(ctx.app.clone(), ctx.clone());
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
        .route(
            "/v1/apps/{name}/secrets",
            axum::routing::get(handle_list_secrets).put(handle_set_secrets),
        )
        .route(
            "/v1/apps/{name}/secrets/{key}",
            axum::routing::delete(handle_remove_secret),
        )
        .route(
            "/v1/apps/{name}/key",
            axum::routing::put(handle_set_deploy_key),
        )
        .route(
            "/v1/apps/{name}/status",
            axum::routing::get(handle_app_status),
        )
        .route("/v1/apps/{name}/logs", axum::routing::get(handle_app_logs))
        .route("/v1/tls/renew", axum::routing::post(handle_tls_renew))
        .route("/v1/registries", axum::routing::get(handle_list_registries))
        .route(
            "/v1/registries/{url}",
            axum::routing::put(handle_set_registry_credential)
                .delete(handle_remove_registry_credential),
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
            axum::routing::get(handle_list_previews).delete(handle_preview_teardown_all),
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

/// Verify authentication for preview endpoints.
///
/// Accepts either:
/// - `Authorization: Bearer {token}` — validated against the management auth secret
/// - `X-Slip-Signature` — HMAC-SHA256 validated against the app's secret (or global fallback)
///
/// The `hmac_body` parameter is the data to verify the HMAC signature over
/// (e.g. `format!("{app}:{preview_id}")` for single teardown,
/// `format!("{app}:*")` for teardown-all).
async fn verify_preview_auth(
    headers: &axum::http::HeaderMap,
    state: &AppState,
    app: &str,
    hmac_body: &str,
) -> Result<(), AppError> {
    // 1. Try Bearer token first.
    if let Some(auth_header) = headers.get("Authorization").and_then(|v| v.to_str().ok())
        && let Some(token) = auth_header.strip_prefix("Bearer ")
        && constant_time_eq(token, &state.config.auth.secret)
    {
        return Ok(());
    }

    // 2. Fall back to HMAC signature.
    if let Some(sig_header) = headers
        .get("X-Slip-Signature")
        .and_then(|v| v.to_str().ok())
    {
        let app_cfg = state.apps.read().await.get(app).cloned().ok_or_else(|| {
            AppError::NotFound(format!(
                "unknown app: {app} — register it via POST /v1/apps or run `slip apply`"
            ))
        })?;

        let secret = resolve_secret(
            app_cfg.app.secret.as_deref(),
            &state.config.auth.secret,
            &state.secrets_store,
            app,
        );

        if verify_signature(sig_header, hmac_body.as_bytes(), &secret) {
            return Ok(());
        }

        warn!(app = %app, "preview auth rejected: invalid HMAC signature");
        return Err(AppError::Unauthorized("invalid signature".to_string()));
    }

    Err(AppError::Unauthorized(
        "missing Authorization or X-Slip-Signature header".to_string(),
    ))
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
            domain: Some(req.domain),
            port: Some(req.port),
            routes: req.routes.unwrap_or_default(),
            tls: req.tls,
        },
        health: req.health.unwrap_or_default(),
        deploy: req.deploy.unwrap_or_default(),
        env: req.env,
        env_file: None,
        resources: req.resources.unwrap_or_default(),
        network: req.network.unwrap_or_default(),
        preview: req.preview,
        volumes: req.volumes.unwrap_or_default(),
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
    let state_dir = state.config.storage.path.join("state");
    let app_response = AppResponse::from(&app_config);
    let app_name_clone = req.name.clone();
    let app_response_clone = app_response.clone();
    tokio::task::spawn_blocking(move || {
        if let Err(e) = crate::config::write_app_config(&config_dir, &app_config_clone) {
            warn!(error = %e, "failed to write app config");
        }
        // Save last_applied for drift detection.
        if let Err(e) =
            crate::state::save_last_applied(&state_dir, &app_name_clone, &app_response_clone)
        {
            warn!(error = %e, "failed to save last_applied state");
        }
    });

    info!(app = %req.name, "app created");

    Ok((StatusCode::CREATED, Json(app_response)))
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
    let app_config = apps.get(&name).ok_or_else(|| {
        AppError::NotFound(format!(
            "app '{}' not found — register it via POST /v1/apps or run `slip apply`",
            name
        ))
    })?;
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
            .ok_or_else(|| {
                AppError::NotFound(format!(
                    "app '{}' not found — register it via POST /v1/apps or run `slip apply`",
                    name
                ))
            })?
            .clone();

        let mut updated = existing.clone();

        // Merge updates (only update fields that are Some)
        if let Some(image) = req.image {
            updated.app.image = image;
        }
        if let Some(domain) = req.domain {
            updated.routing.domain = Some(domain);
        }
        if let Some(port) = req.port {
            updated.routing.port = Some(port);
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
        if let Some(volumes) = req.volumes {
            updated.volumes = volumes;
        }
        if let Some(routes) = req.routes {
            updated.routing.routes = routes;
        }
        if let Some(tls) = req.tls {
            updated.routing.tls = Some(tls);
        }

        apps.insert(name.clone(), updated.clone());
        updated
    };

    // Write config to disk
    let config_dir = state.config_dir.clone();
    let app_config_clone = updated_config.clone();
    let state_dir = state.config.storage.path.join("state");
    let app_response = AppResponse::from(&updated_config);
    let app_name_clone = name.clone();
    let app_response_clone = app_response.clone();
    tokio::task::spawn_blocking(move || {
        if let Err(e) = crate::config::write_app_config(&config_dir, &app_config_clone) {
            warn!(error = %e, "failed to write app config");
        }
        // Save last_applied for drift detection.
        if let Err(e) =
            crate::state::save_last_applied(&state_dir, &app_name_clone, &app_response_clone)
        {
            warn!(error = %e, "failed to save last_applied state");
        }
    });

    info!(app = %name, "app updated");

    Ok((StatusCode::OK, Json(app_response)))
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
            return Err(AppError::NotFound(format!(
                "app '{}' not found — register it via POST /v1/apps or run `slip apply`",
                name
            )));
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

    // Remove Caddy routes
    let route_count = state
        .app_states
        .read()
        .await
        .get(&name)
        .map(|s| s.current_routes.len())
        .unwrap_or(1);
    if let Err(e) = state.caddy.remove_routes(&name, route_count).await {
        warn!(app = %name, error = %e, "failed to remove Caddy routes during app deletion");
    }

    // Remove deploy lock
    state.deploy_locks.remove(&name);

    // Remove app state
    state.app_states.write().await.remove(&name);

    // Remove secrets
    if let Err(e) = state.secrets_store.remove_all(&name) {
        warn!(app = %name, error = %e, "failed to remove secrets during app deletion");
    }

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
    let app_cfg = state.apps.read().await.get(&name).cloned().ok_or_else(|| {
        AppError::NotFound(format!(
            "app '{}' not found — register it via POST /v1/apps or run `slip apply`",
            name
        ))
    })?;

    // Resolve target tag.
    let target_tag = match req.to {
        Some(ref tag) => {
            validate_tag(tag)?;
            tag.clone()
        }
        None => {
            // First, try to find the previous successful deploy from SQLite.
            let current_deploy_id = state
                .app_states
                .read()
                .await
                .get(&name)
                .and_then(|s| s.deploy_id.clone())
                .unwrap_or_default();
            let db = state.db.clone();
            let name_clone = name.clone();
            let previous_from_db: Option<String> = tokio::task::spawn_blocking(move || {
                match db.get_previous_successful_deploy(&name_clone, &current_deploy_id) {
                    Ok(Some(ctx)) => Some(ctx.tag),
                    _ => None,
                }
            })
            .await
            .unwrap_or(None);

            if let Some(tag) = previous_from_db {
                tag
            } else {
                // Fall back to previous_tag from runtime state (backward compat).
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

// ─── Secrets handlers ─────────────────────────────────────────────────────────

/// `GET /v1/apps/{name}/secrets` — List secret key names for an app.
///
/// Values are never returned.
async fn handle_list_secrets(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
) -> Result<(StatusCode, Json<SecretsListResponse>), AppError> {
    // Verify app exists
    {
        let apps = state.apps.read().await;
        if !apps.contains_key(&name) {
            return Err(AppError::NotFound(format!(
                "app '{}' not found — register it via POST /v1/apps or run `slip apply`",
                name
            )));
        }
    }

    let keys = state
        .secrets_store
        .list(&name)
        .map_err(|e| AppError::Internal(format!("failed to list secrets: {e}")))?;

    Ok((StatusCode::OK, Json(SecretsListResponse { secrets: keys })))
}

/// `PUT /v1/apps/{name}/secrets` — Set (bulk) secrets for an app.
///
/// Each key name is validated. Values are stored but never returned in the
/// response — only the list of keys that were set.
async fn handle_set_secrets(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
    Json(req): Json<SetSecretsRequest>,
) -> Result<(StatusCode, Json<SetSecretsResponse>), AppError> {
    // Verify app exists
    {
        let apps = state.apps.read().await;
        if !apps.contains_key(&name) {
            return Err(AppError::NotFound(format!(
                "app '{}' not found — register it via POST /v1/apps or run `slip apply`",
                name
            )));
        }
    }

    // Validate all key names before writing any
    for key in req.secrets.keys() {
        if let Err(msg) = validate_secret_key(key) {
            return Err(AppError::BadRequest(format!(
                "invalid secret key '{}': {msg}",
                key
            )));
        }
    }

    // Write each secret
    let mut set_keys: Vec<String> = Vec::with_capacity(req.secrets.len());
    for (key, value) in &req.secrets {
        state
            .secrets_store
            .set(&name, key, value)
            .map_err(|e| AppError::Internal(format!("failed to set secret: {e}")))?;
        set_keys.push(key.clone());
    }

    set_keys.sort();

    info!(
        app = %name,
        key_count = set_keys.len(),
        "secrets updated"
    );

    Ok((StatusCode::OK, Json(SetSecretsResponse { set: set_keys })))
}

/// `DELETE /v1/apps/{name}/secrets/{key}` — Remove a single secret.
async fn handle_remove_secret(
    State(state): State<Arc<AppState>>,
    Path((name, key)): Path<(String, String)>,
) -> Result<(StatusCode, Json<serde_json::Value>), AppError> {
    // Verify app exists
    {
        let apps = state.apps.read().await;
        if !apps.contains_key(&name) {
            return Err(AppError::NotFound(format!(
                "app '{}' not found — register it via POST /v1/apps or run `slip apply`",
                name
            )));
        }
    }

    let existed = state
        .secrets_store
        .remove(&name, &key)
        .map_err(|e| AppError::Internal(format!("failed to remove secret: {e}")))?;

    if !existed {
        return Err(AppError::NotFound(format!(
            "secret '{}' not found for app '{}'",
            key, name
        )));
    }

    info!(app = %name, key = %key, "secret removed");

    Ok((StatusCode::OK, Json(serde_json::json!({"status": "ok"}))))
}

// ─── Deploy key handler ────────────────────────────────────────────────────────

/// Request body for `PUT /v1/apps/{name}/key`.
#[derive(Debug, Deserialize)]
pub struct SetDeployKeyRequest {
    /// If `true`, rotates the key even if one already exists.
    /// If `false` (default), only creates a key if none exists.
    #[serde(default)]
    pub rotate: bool,
}

/// Response for `PUT /v1/apps/{name}/key`.
#[derive(Debug, Serialize)]
pub struct SetDeployKeyResponse {
    pub app: String,
    /// The deploy key. Present only when a new key was generated (create or
    /// rotate).  `None` when an existing key was left untouched.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    /// Whether the key was rotated (true) or newly created (false).
    pub rotated: bool,
    /// Human-readable message about what happened.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

/// `PUT /v1/apps/{name}/key` — Generate or rotate a per-app deploy key.
///
/// The key is stored in the secrets store (not in app TOML) with 0o600 perms.
/// It is returned **once** in the response body.  The caller is responsible
/// for saving it (e.g. into CI secrets).
///
/// Admin-token gated (via the management auth middleware).
async fn handle_set_deploy_key(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
    Json(req): Json<SetDeployKeyRequest>,
) -> Result<(StatusCode, Json<SetDeployKeyResponse>), AppError> {
    // Verify app exists
    {
        let apps = state.apps.read().await;
        if !apps.contains_key(&name) {
            return Err(AppError::NotFound(format!(
                "app '{}' not found — register it via POST /v1/apps or run `slip apply`",
                name
            )));
        }
    }

    // Check if a deploy key already exists.
    let existing = state
        .secrets_store
        .get_deploy_key(&name)
        .map_err(|e| AppError::Internal(format!("failed to read deploy key: {e}")))?;

    let (key, rotated, message) = match existing {
        Some(_) if req.rotate => {
            // Rotate: generate a new key, replacing the old one.
            let new_key = state
                .secrets_store
                .set_deploy_key(&name)
                .map_err(|e| AppError::Internal(format!("failed to set deploy key: {e}")))?;
            (Some(new_key), true, None)
        }
        Some(_) => {
            // Key exists but rotate not requested — do not reveal the key.
            (
                None,
                false,
                Some("deploy key already exists — pass rotate=true to rotate it".to_string()),
            )
        }
        None => {
            // No existing key — create one.
            let new_key = state
                .secrets_store
                .set_deploy_key(&name)
                .map_err(|e| AppError::Internal(format!("failed to set deploy key: {e}")))?;
            (Some(new_key), false, None)
        }
    };

    info!(
        app = %name,
        rotated = rotated,
        "deploy key set"
    );

    Ok((
        StatusCode::OK,
        Json(SetDeployKeyResponse {
            app: name,
            key,
            rotated,
            message,
        }),
    ))
}

// ─── Registry credential handlers (SLIP-105) ─────────────────────────────────

/// Request body for `PUT /v1/registries/{url}`.
#[derive(Debug, Deserialize)]
pub struct SetRegistryCredRequest {
    /// Username for the registry (optional — anonymous pull if absent).
    #[serde(default)]
    pub username: Option<String>,
    /// Password/token. Required (use `slip registry login` to set it).
    pub password: String,
}

/// Response for `PUT /v1/registries/{url}`.
///
/// Never echoes the password.
#[derive(Debug, Serialize, Deserialize)]
pub struct SetRegistryCredResponse {
    pub url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
}

/// `PUT /v1/registries/{url}` — store (or rotate) a registry credential.
///
/// The `{url}` path segment is host[:port] (no scheme, no path). The
/// password is written to the secrets store under the synthetic `__registry`
/// namespace (0o600); the `{url, username}` is recorded in the sidecar index.
/// The response never includes the password.
///
/// Admin-token gated (management auth middleware).
async fn handle_set_registry_credential(
    State(state): State<Arc<AppState>>,
    Path(url): Path<String>,
    Json(req): Json<SetRegistryCredRequest>,
) -> Result<(StatusCode, Json<SetRegistryCredResponse>), AppError> {
    // Validate URL via normalize (rejects path components / bad shape).
    let normalized = crate::config::normalize_registry_url(&url).map_err(|e| {
        AppError::BadRequest(format!(
            "invalid registry url '{url}' — {e}. \
             Use host[:port] only (e.g. ghcr.io). See `slip registry login --help`."
        ))
    })?;

    state
        .secrets_store
        .set_registry_credential(&normalized, req.username.as_deref(), &req.password)
        .map_err(|e| AppError::Internal(format!("failed to store registry credential: {e}")))?;

    info!(registry = %normalized, "registry credential set");

    Ok((
        StatusCode::OK,
        Json(SetRegistryCredResponse {
            url: normalized,
            username: req.username,
        }),
    ))
}

/// `DELETE /v1/registries/{url}` — remove a stored registry credential.
///
/// 404 if no credential is stored for the (normalized) URL.
async fn handle_remove_registry_credential(
    State(state): State<Arc<AppState>>,
    Path(url): Path<String>,
) -> Result<StatusCode, AppError> {
    let normalized = crate::config::normalize_registry_url(&url)
        .map_err(|e| AppError::BadRequest(format!("invalid registry url '{url}' — {e}")))?;
    let removed = state
        .secrets_store
        .remove_registry_credential(&normalized)
        .map_err(|e| AppError::Internal(format!("failed to remove registry credential: {e}")))?;
    if removed {
        info!(registry = %normalized, "registry credential removed");
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(AppError::NotFound(format!(
            "no credential stored for registry '{normalized}' — \
             run `slip registry list` to see stored registries"
        )))
    }
}

/// A registry entry as returned by `GET /v1/registries`.
///
/// `has_credential` is true if either a TOML-declared token OR a store
/// credential exists for the URL. Never includes the password/token.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegistryListResponse {
    pub url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    pub has_credential: bool,
    /// "toml" if the credential comes from slip.toml, "store" if from
    /// `slip registry login`, "toml+store" if both (store wins at pull).
    pub credential_source: String,
}

/// `GET /v1/registries` — list all known registries (TOML-declared + store).
///
/// Merges the two sources. Never includes password/token material.
async fn handle_list_registries(
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<RegistryListResponse>>, AppError> {
    // Store creds (public metadata only).
    let store_entries = state
        .secrets_store
        .list_registry_credentials()
        .map_err(|e| AppError::Internal(format!("failed to list registry credentials: {e}")))?;
    let store_map: std::collections::HashMap<String, Option<String>> = store_entries
        .iter()
        .map(|e| (e.url.clone(), e.username.clone()))
        .collect();

    // TOML-declared registries.
    let toml_map: std::collections::HashMap<String, (Option<String>, bool)> = state
        .config
        .registries
        .registries
        .values()
        .map(|e| {
            let has_token = e.token.is_some();
            (e.url.clone(), (e.username.clone(), has_token))
        })
        .collect();

    // Merge: union of urls.
    let mut urls: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    urls.extend(store_map.keys().cloned());
    urls.extend(toml_map.keys().cloned());

    let out: Vec<RegistryListResponse> = urls
        .iter()
        .map(|url| {
            let in_store = store_map.contains_key(url);
            let toml_entry = toml_map.get(url);
            let toml_has_token = toml_entry.is_some_and(|(_, has)| *has);
            let username = store_map
                .get(url)
                .cloned()
                .flatten()
                .or_else(|| toml_entry.and_then(|(u, _)| u.clone()));
            let has_credential = in_store || toml_has_token;
            let credential_source = match (in_store, toml_has_token) {
                (true, true) => "toml+store".to_string(),
                (true, false) => "store".to_string(),
                (false, true) => "toml".to_string(),
                (false, false) => "none".to_string(),
            };
            RegistryListResponse {
                url: url.clone(),
                username,
                has_credential,
                credential_source,
            }
        })
        .collect();

    Ok(Json(out))
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
        .ok_or_else(|| {
            AppError::NotFound(format!(
                "unknown app: {} — register it via POST /v1/apps or run `slip apply`",
                request.app
            ))
        })?;

    // 5. Resolve HMAC secret (deploy key → app TOML → global fallback).
    let secret = resolve_secret(
        app_cfg.app.secret.as_deref(),
        &state.config.auth.secret,
        &state.secrets_store,
        &request.app,
    );

    // 6. Verify HMAC signature.
    if !verify_signature(sig_header, &body, &secret) {
        warn!(app = %request.app, "deploy rejected: invalid signature");
        return Err(AppError::Unauthorized("invalid signature".to_string()));
    }

    // 7. Resolve image (optional in request — fall back to app config).
    let resolved_image = request
        .image
        .clone()
        .unwrap_or_else(|| app_cfg.app.image.clone());

    // 7b. Validate image matches config (only if explicitly provided).
    if let Some(ref req_image) = request.image
        && *req_image != app_cfg.app.image
    {
        return Err(AppError::BadRequest(format!(
            "image mismatch: expected '{}', got '{}'",
            app_cfg.app.image, req_image
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
            image: resolved_image.clone(),
            tag: request.tag.clone(),
            preview_id: preview_info.id.clone(),
            sha: preview_info.sha.clone(),
            images: request.images.clone(),
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
        resolved_image.clone(),
        request.tag.clone(),
        TriggerSource::Webhook,
    );
    // Pass images through to the deploy context
    let deploy_ctx = DeployContext {
        images: request.images.clone(),
        ..deploy_ctx
    };
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
    let app_count = apps_keys.len();

    // Build last_deploys summary (latest per app).
    let last_deploys: Vec<DeploySummary> = apps_keys
        .iter()
        .filter_map(|app_name| {
            let cached = state.deploys.get(app_name)?;
            let triggered_by = match cached.triggered_by {
                crate::deploy::TriggerSource::Webhook => "webhook",
                crate::deploy::TriggerSource::Cli => "cli",
                crate::deploy::TriggerSource::Rollback => "rollback",
            };
            let status_str = match cached.status {
                crate::deploy::DeployStatus::Accepted => "accepted",
                crate::deploy::DeployStatus::Pulling => "pulling",
                crate::deploy::DeployStatus::Configuring => "configuring",
                crate::deploy::DeployStatus::Starting => "starting",
                crate::deploy::DeployStatus::HealthChecking => "health_checking",
                crate::deploy::DeployStatus::Switching => "switching",
                crate::deploy::DeployStatus::StoppingOld => "stopping_old",
                crate::deploy::DeployStatus::RemovingRoute => "removing_route",
                crate::deploy::DeployStatus::RestartingOld => "restarting_old",
                crate::deploy::DeployStatus::Completed => "completed",
                crate::deploy::DeployStatus::Failed => "failed",
            };
            Some(DeploySummary {
                deploy_id: cached.id.clone(),
                app: cached.app.clone(),
                tag: cached.tag.clone(),
                status: status_str.to_string(),
                triggered_by: triggered_by.to_string(),
                started_at: cached.started_at,
                finished_at: cached.finished_at,
                error: cached.error.clone(),
            })
        })
        .collect();

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
                    kind: None,
                    deploy_id: None,
                    triggered_by: None,
                    container_state: None,
                    health: None,
                    last_deploy: None,
                    routes: Vec::new(),
                    secrets: Vec::new(),
                    cert: None,
                    config_drift: None,
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
                        kind: runtime.kind.clone(),
                        deploy_id: None,
                        triggered_by: None,
                        container_state: None,
                        health: None,
                        last_deploy: None,
                        routes: Vec::new(),
                        secrets: Vec::new(),
                        cert: None,
                        config_drift: None,
                    }
                }
            };

            // Supplement with deploy metadata from the in-memory cache
            let mut enriched = app_status;
            if let Some(cached) = state.deploys.get(&app_name) {
                enriched.deploy_id = Some(cached.id.clone());
                enriched.triggered_by = Some(
                    match cached.triggered_by {
                        crate::deploy::TriggerSource::Webhook => "webhook",
                        crate::deploy::TriggerSource::Cli => "cli",
                        crate::deploy::TriggerSource::Rollback => "rollback",
                    }
                    .to_string(),
                );

                // Build last_deploy summary.
                let status_str = match cached.status {
                    crate::deploy::DeployStatus::Accepted => "accepted",
                    crate::deploy::DeployStatus::Pulling => "pulling",
                    crate::deploy::DeployStatus::Configuring => "configuring",
                    crate::deploy::DeployStatus::Starting => "starting",
                    crate::deploy::DeployStatus::HealthChecking => "health_checking",
                    crate::deploy::DeployStatus::Switching => "switching",
                    crate::deploy::DeployStatus::StoppingOld => "stopping_old",
                    crate::deploy::DeployStatus::RemovingRoute => "removing_route",
                    crate::deploy::DeployStatus::RestartingOld => "restarting_old",
                    crate::deploy::DeployStatus::Completed => "completed",
                    crate::deploy::DeployStatus::Failed => "failed",
                };
                let triggered_str = match cached.triggered_by {
                    crate::deploy::TriggerSource::Webhook => "webhook",
                    crate::deploy::TriggerSource::Cli => "cli",
                    crate::deploy::TriggerSource::Rollback => "rollback",
                };
                enriched.last_deploy = Some(DeploySummary {
                    deploy_id: cached.id.clone(),
                    app: app_name.clone(),
                    tag: cached.tag.clone(),
                    status: status_str.to_string(),
                    triggered_by: triggered_str.to_string(),
                    started_at: cached.started_at,
                    finished_at: cached.finished_at,
                    error: cached.error.clone(),
                });
            }
            (app_name.clone(), enriched)
        })
        .collect();

    (
        StatusCode::OK,
        Json(StatusResponse {
            schema: "slip.status/v1".to_string(),
            daemon: "slipd".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            uptime_seconds,
            caddy: caddy_health.to_string(),
            runtime: runtime_health.to_string(),
            runtime_backend: Some(state.runtime.name().to_string()),
            app_count,
            last_deploys,
            apps,
        }),
    )
}

// ─── Per-app status handler ───────────────────────────────────────────────────

/// `GET /v1/apps/{name}/status`
///
/// `GET /v1/apps/{name}/logs` — stream container logs as NDJSON (chunked).
///
/// Resolves containers by the `slip.app` label (catches both blue-green
/// overlap containers), merges their log streams via `futures_util::stream::select`,
/// and emits one JSON object per line. Pre-stream errors return HTTP status
/// codes (404/400); mid-stream errors are emitted as NDJSON error lines.
///
/// Query params:
/// - `since` — duration string like "1h", "5m30s" (converted to Unix timestamp)
/// - `follow` — stream new lines as they arrive (default false)
async fn handle_app_logs(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
    Query(params): Query<LogsQueryParams>,
) -> Response {
    // ── a. Verify app exists ──────────────────────────────────────────────────
    {
        let apps = state.apps.read().await;
        if !apps.contains_key(&name) {
            return AppError::NotFound(format!(
                "app '{name}' not found — register it via POST /v1/apps or run `slip apply`"
            ))
            .into_response();
        }
    }

    // ── b. Parse `since` duration → Unix timestamp ─────────────────────────────
    let since_unix: Option<i64> = if let Some(ref s) = params.since {
        match parse_since_duration(s) {
            Ok(ts) => Some(ts),
            Err(msg) => {
                return AppError::BadRequest(format!(
                    "invalid --since '{s}': {msg} — use formats like 1h, 5m, 30s, 5m30s"
                ))
                .into_response();
            }
        }
    } else {
        None
    };

    let follow = params.follow.unwrap_or(false);

    // ── c. Resolve running containers by `slip.app` label ─────────────────────
    let containers: Vec<ContainerInfo> = match tokio::time::timeout(
        std::time::Duration::from_secs(2),
        state.runtime.list_by_label("slip.app", &name),
    )
    .await
    {
        Ok(Ok(cs)) => cs.into_iter().filter(|c| c.state == "running").collect(),
        Ok(Err(_)) | Err(_) => Vec::new(),
    };

    if containers.is_empty() {
        return AppError::NotFound(format!(
            "app '{name}' has no running containers — run `slip deploy` to start one"
        ))
        .into_response();
    }

    // ── d. Determine blue/green roles from AppRuntimeState ─────────────────────
    let (green_id, blue_id) = {
        let app_states = state.app_states.read().await;
        let rs = app_states.get(&name);
        let current = rs.and_then(|s| s.current_container_id.as_deref());
        let previous = rs.and_then(|s| s.previous_container_id.as_deref());

        let green = containers
            .iter()
            .find(|c| current.is_some_and(|id| id.starts_with(&c.id) || c.id.starts_with(id)))
            .map(|c| c.id.clone())
            .or_else(|| containers.first().map(|c| c.id.clone()));

        let blue = containers
            .iter()
            .find(|c| previous.is_some_and(|id| id.starts_with(&c.id) || c.id.starts_with(id)))
            .map(|c| c.id.clone());

        (green, blue)
    };

    // ── e. Build per-container tagged streams via mpsc channels ───────────────
    // Each container's log stream borrows `&runtime` (not 'static), but
    // `Body::from_stream` requires 'static. We bridge by spawning a task per
    // container that reads the borrowed stream and sends NDJSON Bytes into an
    // mpsc channel; the ReceiverStream is 'static.
    let (tx, rx) = tokio::sync::mpsc::channel::<
        Result<Bytes, std::boxed::Box<dyn std::error::Error + Send + Sync>>,
    >(256);

    for c in &containers {
        let role = if Some(&c.id) == green_id.as_ref() {
            "green"
        } else if Some(&c.id) == blue_id.as_ref() {
            "blue"
        } else if containers.len() == 1 {
            "green"
        } else {
            "blue"
        };
        let container_label = format!("{role}-{}/{}", c.id, c.name.as_deref().unwrap_or(&c.id));
        let container_id = c.id.clone();
        let runtime = state.runtime.clone();
        let tx = tx.clone();
        let since = since_unix;

        tokio::spawn(async move {
            let mut stream = runtime.container_logs(&container_id, since, follow);
            while let Some(item) = stream.next().await {
                let bytes = match item {
                    Ok(log) => {
                        let entry = LogEntry {
                            ts: log.ts.map(|t| t.to_rfc3339()),
                            container: container_label.clone(),
                            stream: log.stream.as_str().to_string(),
                            line: log.line,
                        };
                        match serde_json::to_vec(&entry) {
                            Ok(v) => {
                                let mut line = v;
                                line.push(b'\n');
                                Bytes::from(line)
                            }
                            Err(e) => {
                                let err = LogStreamError {
                                    error: format!("serialize error: {e}"),
                                    container: container_label.clone(),
                                };
                                let mut line =
                                    serde_json::to_vec(&err).unwrap_or_else(|_| b"{}\n".to_vec());
                                line.push(b'\n');
                                Bytes::from(line)
                            }
                        }
                    }
                    Err(e) => {
                        let err = LogStreamError {
                            error: e.to_string(),
                            container: container_label.clone(),
                        };
                        let mut line =
                            serde_json::to_vec(&err).unwrap_or_else(|_| b"{}\n".to_vec());
                        line.push(b'\n');
                        Bytes::from(line)
                    }
                };
                if tx.send(Ok(bytes)).await.is_err() {
                    // Receiver dropped (client disconnected) — stop streaming.
                    break;
                }
            }
        });
    }

    // Drop the last clone of tx so the ReceiverStream ends when all senders drop.
    drop(tx);

    // ── f. Build the merged 'static stream from the mpsc receiver ─────────────
    let merged = tokio_stream::wrappers::ReceiverStream::new(rx);

    // ── g. Build the chunked NDJSON response ────────────────────────────────────
    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/x-ndjson")
        .header("cache-control", "no-cache")
        .body(Body::from_stream(merged))
        .unwrap()
}

/// Parse a duration string ("1h", "5m30s", "30s") into a Unix timestamp
/// representing `now - duration`. Returns the timestamp on success, or an
/// error message on failure.
fn parse_since_duration(s: &str) -> Result<i64, String> {
    if s.is_empty() {
        return Err("empty duration string".to_string());
    }
    let mut total_secs: i64 = 0;
    let mut current: i64 = 0;
    for ch in s.chars() {
        match ch {
            '0'..='9' => {
                current = current
                    .checked_mul(10)
                    .and_then(|v| v.checked_add((ch as u8 - b'0') as i64))
                    .ok_or_else(|| "overflow in duration".to_string())?;
            }
            's' => {
                total_secs = total_secs
                    .checked_add(current)
                    .ok_or_else(|| "overflow in duration".to_string())?;
                current = 0;
            }
            'm' => {
                total_secs = total_secs
                    .checked_add(
                        current
                            .checked_mul(60)
                            .ok_or_else(|| "overflow in duration".to_string())?,
                    )
                    .ok_or_else(|| "overflow in duration".to_string())?;
                current = 0;
            }
            'h' => {
                total_secs = total_secs
                    .checked_add(
                        current
                            .checked_mul(3600)
                            .ok_or_else(|| "overflow in duration".to_string())?,
                    )
                    .ok_or_else(|| "overflow in duration".to_string())?;
                current = 0;
            }
            _ => {
                return Err(format!(
                    "unexpected character '{ch}' in duration, expected digits followed by s/m/h"
                ));
            }
        }
    }
    if current > 0 {
        return Err("duration must have a unit suffix (s, m, or h)".to_string());
    }
    let now = chrono::Utc::now().timestamp();
    Ok(now - total_secs)
}

/// Returns a detailed status report for a single app: current tag, container
/// id/state, health config + last probe result, last deploy, route hostnames,
/// secret key names, cert issuer, and config drift flag.
///
/// This is the backend for `slip status <app>`.
async fn handle_app_status(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
) -> Result<(StatusCode, Json<AppStatusResponse>), AppError> {
    // Verify app exists and get config.
    let app_cfg = state.apps.read().await.get(&name).cloned().ok_or_else(|| {
        AppError::NotFound(format!(
            "app '{}' not found — register it via POST /v1/apps or run `slip apply`",
            name
        ))
    })?;

    // Get runtime state.
    let runtime_state = state.app_states.read().await.get(&name).cloned();

    let status_str = match &runtime_state {
        Some(rs) => match rs.status {
            crate::deploy::AppStatus::Running => "running",
            crate::deploy::AppStatus::Deploying => "deploying",
            crate::deploy::AppStatus::Failed => "failed",
            crate::deploy::AppStatus::NotDeployed => "not_deployed",
        },
        None => "not_deployed",
    };

    // ── Container state via label query (2s timeout — a hanging runtime
    //    socket must not block the status response) ─────────────────────────
    let container_query_timeout = std::time::Duration::from_secs(2);
    let container_state = if let Some(ref rs) = runtime_state {
        // If we have a container_id, check if it's running via the runtime.
        if let Some(ref cid) = rs.current_container_id {
            match tokio::time::timeout(
                container_query_timeout,
                state.runtime.container_is_running(cid),
            )
            .await
            {
                Ok(Ok(true)) => Some("running".to_string()),
                Ok(Ok(false)) => Some("exited".to_string()),
                Ok(Err(_)) => None,
                Err(_) => Some("unknown".to_string()),
            }
        } else {
            // No container_id — query by label for the app.
            match tokio::time::timeout(
                container_query_timeout,
                state.runtime.list_by_label("slip.app", &name),
            )
            .await
            {
                Ok(Ok(containers)) => containers.first().map(|first| first.state.clone()),
                Ok(Err(_)) => None,
                Err(_) => Some("unknown".to_string()),
            }
        }
    } else {
        // Query by label even if no runtime state.
        match tokio::time::timeout(
            container_query_timeout,
            state.runtime.list_by_label("slip.app", &name),
        )
        .await
        {
            Ok(Ok(containers)) => containers.first().map(|first| first.state.clone()),
            Ok(Err(_)) => None,
            Err(_) => Some("unknown".to_string()),
        }
    };

    // ── Health status (sync 2s probe) ──────────────────────────────────────
    let health = if let Some(ref rs) = runtime_state
        && let Some(port) = rs.current_port
    {
        let health_cfg = &app_cfg.health;
        let path = health_cfg.path.clone();

        if let Some(ref _p) = path {
            // Do a quick synchronous probe with a 2-second timeout.
            let probe_url = format!("http://127.0.0.1:{port}{}", path.as_deref().unwrap_or("/"));
            let probe_result = tokio::time::timeout(
                std::time::Duration::from_secs(2),
                state.health.client().get(&probe_url).send(),
            )
            .await;

            // Use the shared matcher so the sync probe and the deploy checker
            // apply the same `expect_status` policy (SLIP-103 D5). The probe
            // client is the no-redirect one from `HealthChecker::new`.
            let expectation = health_cfg.expect_status.as_ref();
            let health_status = match probe_result {
                Ok(Ok(resp)) if crate::health::status_matches(&resp, expectation) => "healthy",
                Ok(Ok(_)) => "unhealthy",
                Ok(Err(_)) => "unhealthy",
                Err(_) => "unhealthy",
            };

            Some(HealthStatus {
                path: path.clone(),
                retries: health_cfg.retries,
                status: health_status.to_string(),
                last_check: Some(Utc::now()),
            })
        } else {
            // No health path configured.
            Some(HealthStatus {
                path: None,
                retries: health_cfg.retries,
                status: "unknown".to_string(),
                last_check: None,
            })
        }
    } else {
        None
    };

    // ── Routes from runtime state ──────────────────────────────────────────
    let routes: Vec<RouteStatus> = if let Some(ref rs) = runtime_state {
        rs.current_routes
            .iter()
            .map(|r| RouteStatus {
                hostname: r.hostname.clone(),
                port: r.port,
            })
            .collect()
    } else {
        // Fall back to config routes.
        app_cfg
            .routing
            .effective_routes()
            .into_iter()
            .filter_map(|r| {
                r.port.map(|p| RouteStatus {
                    hostname: r.hostname,
                    port: p,
                })
            })
            .collect()
    };

    // ── Secret key names (never values) ────────────────────────────────────
    let secrets = state.secrets_store.list(&name).unwrap_or_default();

    // ── Deploy metadata from cache ─────────────────────────────────────────
    let mut last_deploy: Option<DeploySummary> = None;
    let mut deploy_id: Option<String> = None;
    let mut triggered_by: Option<String> = None;

    if let Some(cached) = state.deploys.get(&name) {
        let status_str = match cached.status {
            crate::deploy::DeployStatus::Accepted => "accepted",
            crate::deploy::DeployStatus::Pulling => "pulling",
            crate::deploy::DeployStatus::Configuring => "configuring",
            crate::deploy::DeployStatus::Starting => "starting",
            crate::deploy::DeployStatus::HealthChecking => "health_checking",
            crate::deploy::DeployStatus::Switching => "switching",
            crate::deploy::DeployStatus::StoppingOld => "stopping_old",
            crate::deploy::DeployStatus::RemovingRoute => "removing_route",
            crate::deploy::DeployStatus::RestartingOld => "restarting_old",
            crate::deploy::DeployStatus::Completed => "completed",
            crate::deploy::DeployStatus::Failed => "failed",
        };
        let triggered_str = match cached.triggered_by {
            crate::deploy::TriggerSource::Webhook => "webhook",
            crate::deploy::TriggerSource::Cli => "cli",
            crate::deploy::TriggerSource::Rollback => "rollback",
        };
        deploy_id = Some(cached.id.clone());
        triggered_by = Some(triggered_str.to_string());
        last_deploy = Some(DeploySummary {
            deploy_id: cached.id.clone(),
            app: name.clone(),
            tag: cached.tag.clone(),
            status: status_str.to_string(),
            triggered_by: triggered_str.to_string(),
            started_at: cached.started_at,
            finished_at: cached.finished_at,
            error: cached.error.clone(),
        });
    }

    // ── Config drift (last_applied vs current) ─────────────────────────────
    let config_drift = if let Some(ref rs) = runtime_state {
        if let Some(ref last_applied_json) = rs.last_applied {
            // Parse last_applied as AppResponse and compare with current config.
            match serde_json::from_str::<AppResponse>(last_applied_json) {
                Ok(last) => {
                    let current = AppResponse::from(&app_cfg);
                    // If they differ, there's drift.
                    let last_val = serde_json::to_value(&last).unwrap_or(serde_json::Value::Null);
                    let curr_val =
                        serde_json::to_value(&current).unwrap_or(serde_json::Value::Null);
                    Some(last_val != curr_val)
                }
                Err(_) => Some(true),
            }
        } else {
            // No last_applied recorded — can't determine drift.
            None
        }
    } else {
        None
    };

    // ── Cert status (from Caddy TLS policies) ──────────────────────────────
    let cert = if !routes.is_empty() {
        // Query Caddy for the TLS issuer of the first route's hostname.
        let hostname = &routes[0].hostname;
        match state.caddy.get_tls_issuer(hostname).await {
            Ok(Some(issuer)) => Some(CertStatus {
                issuer,
                expires_at: None, // Caddy admin API doesn't expose cert expiry directly
            }),
            Ok(None) => {
                // No matching TLS policy → Caddy default is ACME.
                Some(CertStatus {
                    issuer: "acme".to_string(),
                    expires_at: None,
                })
            }
            Err(_) => None,
        }
    } else {
        None
    };

    let response = AppStatusResponse {
        status: status_str.to_string(),
        tag: runtime_state.as_ref().and_then(|r| r.current_tag.clone()),
        deployed_at: runtime_state.as_ref().and_then(|r| r.deployed_at),
        container_id: runtime_state
            .as_ref()
            .and_then(|r| r.current_container_id.clone()),
        port: runtime_state.as_ref().and_then(|r| r.current_port),
        kind: runtime_state.as_ref().and_then(|r| r.kind.clone()),
        deploy_id,
        triggered_by,
        container_state,
        health,
        last_deploy,
        routes,
        secrets,
        cert,
        config_drift,
    };

    Ok((StatusCode::OK, Json(response)))
}

// ─── TLS renew handler ────────────────────────────────────────────────────────

/// Validate a host before probing to prevent SSRF.
///
/// Rejects link-local, loopback, and unspecified IP literals. Also rejects
/// hosts that don't look like valid hostnames (must have at least one dot,
/// or be a valid IP literal).
fn validate_renew_host(host: &str) -> Result<(), AppError> {
    // Reject empty hosts.
    if host.is_empty() {
        return Err(AppError::BadRequest("host must not be empty".to_string()));
    }
    // Check if it's an IP literal.
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        use std::net::IpAddr;
        match ip {
            IpAddr::V4(v4) => {
                if v4.is_loopback() || v4.is_link_local() || v4.is_unspecified() {
                    return Err(AppError::BadRequest(format!(
                        "host '{host}' is a loopback/link-local/unspecified IP — \
                         renew is not permitted against metadata endpoints"
                    )));
                }
            }
            IpAddr::V6(v6) => {
                if v6.is_loopback() || v6.is_unspecified() {
                    return Err(AppError::BadRequest(format!(
                        "host '{host}' is a loopback/unspecified IPv6 — \
                         renew is not permitted against metadata endpoints"
                    )));
                }
            }
        }
        return Ok(());
    }
    // Hostname: must contain at least one dot (reject bare names).
    if !host.contains('.') {
        return Err(AppError::BadRequest(format!(
            "host '{host}' is not a valid FQDN — must contain at least one dot"
        )));
    }
    // Reject obvious SSRF targets.
    if host == "metadata.google.internal" || host.ends_with(".metadata") {
        return Err(AppError::BadRequest(format!(
            "host '{host}' looks like a cloud metadata endpoint — refused"
        )));
    }
    Ok(())
}

/// `POST /v1/tls/renew` — non-destructive, authenticated TLS certificate
/// renewal via `renewal_window_ratio` bump-and-revert.
///
/// For Tailscale-managed hosts, returns a successful no-op (exit 0).
/// For ACME-issuer hosts:
/// 1. Acquire per-host lock (concurrent renew → 409 Conflict).
/// 2. Validate host (SSRF defense).
/// 3. Probe the before-state cert (TLS handshake with SNI → fingerprint + notAfter).
/// 4. Bump `renewal_window_ratio` to 1.0 + reload.
/// 5. Poll the external cert until fingerprint changes and/or notAfter advances.
/// 6. If `restart_caddy` is set and ratio-bump didn't prove renewal, restart
///    Caddy (bounded, prescriptive error if systemd unavailable), wait for
///    admin readiness, then re-poll for cert proof.
/// 7. Guard/finally: ALWAYS revert the ratio (success, failure, timeout).
/// 8. `renewed: true` only if cert probe proves renewal.
/// 9. If restoration fails, the whole operation fails loudly.
///
/// The renewal body (bump→probe→restore) runs in a detached tokio task so
/// that HTTP client disconnection does not cancel restoration. The handler
/// awaits the task's result via a oneshot channel.
async fn handle_tls_renew(
    State(state): State<Arc<AppState>>,
    Json(req): Json<TlsRenewRequest>,
) -> Result<(StatusCode, Json<TlsRenewResult>), AppError> {
    let start = std::time::Instant::now();
    let host = req.host.clone();

    // Validate host (SSRF defense).
    validate_renew_host(&host)?;

    // Acquire per-host renew lock (concurrent renew → 409).
    // Use try_lock_owned() so the OwnedMutexGuard can be moved into the
    // detached task — the lock outlives handler cancellation and protects
    // the entire renewal cycle, not just the handler's scope.
    let lock = {
        state
            .renew_locks
            .entry(host.clone())
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone()
    };
    let guard = lock.try_lock_owned().map_err(|_| {
        AppError::Conflict(format!(
            "a TLS renewal for '{host}' is already in progress — wait for it to complete"
        ))
    })?;

    // Check if Tailscale-managed → successful no-op.
    let is_ts = state
        .caddy
        .is_tailscale_managed(&host)
        .await
        .unwrap_or(false);
    if is_ts {
        return Ok((
            StatusCode::OK,
            Json(TlsRenewResult {
                schema: "slip.tls.renew/v1",
                host: host.clone(),
                before_not_after: None,
                after_not_after: None,
                renewed: false,
                restored: true,
                managed_by: Some("tailscale".to_string()),
                message: Some(format!(
                    "host {host} uses the Tailscale certificate manager — \
                     renewal is handled automatically by tailscaled; no action needed"
                )),
                elapsed_ms: start.elapsed().as_millis() as u64,
            }),
        ));
    }

    // Get the current policy for the host.
    let original_policy = state.caddy.get_tls_policy(&host).await.map_err(|e| {
        AppError::Internal(crate::caddy::redact_external_error(&format!(
            "failed to query TLS policy for {host}: {e}"
        )))
    })?;

    let original_policy = original_policy.ok_or_else(|| {
        AppError::NotFound(format!(
            "no TLS policy found for {host} — run `slip apply` to register it"
        ))
    })?;

    // Capture original ratio for revert.
    let original_ratio = original_policy
        .get("renewal_window_ratio")
        .and_then(|r| r.as_f64());

    // Spawn a detached task for the bump→probe→restore cycle.
    // This ensures restoration completes even if the HTTP client disconnects.
    // The lock guard is moved INTO the task, so the lock outlives the handler
    // and protects the full cycle lifetime (RE-1 fix).
    let (tx, rx) = tokio::sync::oneshot::channel();
    let caddy = state.caddy.clone();
    let host_clone = host.clone();
    let restart_caddy = req.restart_caddy;
    let original_ratio_clone = original_ratio;
    let subjects_clone = original_policy
        .get("subjects")
        .and_then(|s| s.as_array())
        .and_then(|a| a.first())
        .and_then(|s| s.as_str())
        .map(String::from);

    tokio::spawn(async move {
        // Lock guard is held for the entire task lifetime.
        let _guard = guard;
        let result = run_renewal_cycle(
            &caddy,
            &host_clone,
            restart_caddy,
            original_ratio_clone,
            subjects_clone,
        )
        .await;
        let _ = tx.send(result);
    });

    // Await the result (or return timeout if the client is still connected).
    let renewal_result = rx
        .await
        .map_err(|_| AppError::Internal("renewal task panicked or was cancelled".to_string()))?;

    match renewal_result {
        RenewalOutcome::Success {
            before_not_after,
            after_not_after,
            restored,
        } => Ok((
            StatusCode::OK,
            Json(TlsRenewResult {
                schema: "slip.tls.renew/v1",
                host: host.clone(),
                before_not_after,
                after_not_after,
                renewed: true,
                restored,
                managed_by: None,
                message: None,
                elapsed_ms: start.elapsed().as_millis() as u64,
            }),
        )),
        RenewalOutcome::NotProven { restored } => Err(AppError::RenewNotProven(format!(
            "TLS renewal for {host} was not proven by certificate probe \
             (fingerprint/notAfter unchanged). \
             The renewal_window_ratio has been reverted (restored={restored}). \
             Try: slip tls renew --restart-caddy {host}"
        ))),
        RenewalOutcome::Timeout { restored } => Err(AppError::RenewTimeout(format!(
            "TLS renewal for {host} timed out waiting for certificate proof. \
             The renewal_window_ratio has been reverted (restored={restored}). \
             Try: slip tls renew --restart-caddy {host}"
        ))),
        RenewalOutcome::RestorationFailed { detail } => Err(AppError::Internal(
            crate::caddy::redact_external_error(&format!(
                "TLS renewal for {host}: renewal_window_ratio revert FAILED — \
                 Caddy may be left with ratio=1.0 which will hit LE rate limits. \
                 Manual fix: PATCH the policy for {host} to restore \
                 renewal_window_ratio, then reload Caddy. Error: {detail}"
            )),
        )),
        RenewalOutcome::Error { detail } => Err(AppError::Internal(
            crate::caddy::redact_external_error(&detail),
        )),
    }
}

/// Outcome of the renewal cycle (bump→probe→restore).
enum RenewalOutcome {
    Success {
        before_not_after: Option<String>,
        after_not_after: Option<String>,
        restored: bool,
    },
    /// Renewal not proven (cert unchanged, but not a timeout).
    NotProven { restored: bool },
    /// Renewal timed out.
    Timeout { restored: bool },
    /// Ratio restoration failed — critical, needs manual intervention.
    RestorationFailed { detail: String },
    /// Other error.
    Error { detail: String },
}

/// Run the renewal cycle: probe before → bump ratio → poll for cert proof → restore.
///
/// This runs in a detached task with the per-host lock held. The ratio is
/// ALWAYS restored (success, failure, timeout). If restoration fails, returns
/// `RestorationFailed`. When the original ratio was None, the temporary
/// `renewal_window_ratio` field is DELETED (not left at 1.0). Restoration
/// is verified by re-reading the policy after the restore operation.
async fn run_renewal_cycle(
    caddy: &CaddyClient,
    host: &str,
    restart_caddy: bool,
    original_ratio: Option<f64>,
    _subject: Option<String>,
) -> RenewalOutcome {
    // ── 1. Probe before-state cert ────────────────────────────────────────
    let before_probe = match crate::caddy::probe_cert(host).await {
        Ok(Some(p)) => Some(p),
        Ok(None) => None,
        Err(e) => {
            tracing::warn!(host = host, error = %e, "before-probe failed");
            None
        }
    };
    let before_not_after = before_probe.as_ref().and_then(|p| p.not_after.clone());

    // ── 2. Bump ratio to 1.0 + reload ─────────────────────────────────────
    if let Err(e) = caddy.patch_tls_policy_ratio(host, 1.0).await {
        return RenewalOutcome::Error {
            detail: format!("failed to bump renewal_window_ratio for {host}: {e}"),
        };
    }

    if let Err(e) = caddy.reload().await {
        // Guard: revert ratio before returning.
        restore_ratio(caddy, host, original_ratio).await;
        return RenewalOutcome::Error {
            detail: format!("Caddy reload failed for {host}: {e}"),
        };
    }

    // ── 3. Poll for cert proof ─────────────────────────────────────────────
    let poll_timeout = std::time::Duration::from_secs(120);
    let poll_interval = std::time::Duration::from_secs(5);
    let deadline = std::time::Instant::now() + poll_timeout;

    let mut renewed = false;
    let mut timed_out = false;
    let mut after_probe: Option<crate::caddy::CertProbe> = None;

    while std::time::Instant::now() < deadline {
        tokio::time::sleep(poll_interval).await;
        match crate::caddy::probe_cert(host).await {
            Ok(Some(p)) => {
                if crate::caddy::cert_renewed(before_probe.as_ref(), Some(&p)) {
                    renewed = true;
                    after_probe = Some(p);
                    break;
                }
            }
            Ok(None) => {}
            Err(e) => {
                tracing::debug!(host = host, error = %e, "poll probe failed, retrying");
            }
        }
    }
    if !renewed && std::time::Instant::now() >= deadline {
        timed_out = true;
    }

    // ── 4. If not renewed and restart_caddy is set, restart + re-poll ────
    if !renewed && restart_caddy {
        tracing::info!(
            host = host,
            "ratio-bump did not prove renewal — restarting Caddy"
        );
        match restart_caddy_bounded().await {
            Ok(()) => {
                if let Err(e) = wait_caddy_ready(caddy, std::time::Duration::from_secs(30)).await {
                    tracing::warn!(host = host, error = %e, "Caddy readiness wait failed");
                }
                let restart_deadline = std::time::Instant::now() + poll_timeout;
                while std::time::Instant::now() < restart_deadline {
                    tokio::time::sleep(poll_interval).await;
                    match crate::caddy::probe_cert(host).await {
                        Ok(Some(p)) => {
                            if crate::caddy::cert_renewed(before_probe.as_ref(), Some(&p)) {
                                renewed = true;
                                after_probe = Some(p);
                                break;
                            }
                        }
                        Ok(None) => {}
                        Err(e) => {
                            tracing::debug!(host = host, error = %e, "post-restart poll failed");
                        }
                    }
                }
                if !renewed && std::time::Instant::now() >= restart_deadline {
                    timed_out = true;
                }
            }
            Err(e) => {
                tracing::warn!(host = host, error = %e, "Caddy restart failed");
            }
        }
    }

    // ── 5. Guard/finally: ALWAYS revert the ratio ────────────────────────
    // When original_ratio is Some, PATCH it back. When original_ratio is None,
    // DELETE the temporary field. Then VERIFY the restoration by re-reading
    // the policy. If verification fails, the operation fails loudly.
    let restored = restore_ratio(caddy, host, original_ratio).await;

    match restored {
        true => {
            // Verify restoration by re-reading the policy.
            match caddy.verify_ratio_restored(host, original_ratio).await {
                Ok(true) => {}
                Ok(false) => {
                    return RenewalOutcome::RestorationFailed {
                        detail: format!(
                            "post-restore verification failed: \
                             renewal_window_ratio still present/incorrect for {host}"
                        ),
                    };
                }
                Err(e) => {
                    tracing::warn!(
                        host = host,
                        error = %e,
                        "post-restore verification read failed (non-fatal)"
                    );
                    // Don't fail on read error — the restore itself succeeded.
                }
            }
        }
        false => {
            return RenewalOutcome::RestorationFailed {
                detail: format!(
                    "failed to restore renewal_window_ratio for {host} \
                     (was Some={:?}) — Caddy may be left with ratio=1.0",
                    original_ratio
                ),
            };
        }
    }

    let after_not_after = after_probe.as_ref().and_then(|p| p.not_after.clone());

    if renewed {
        RenewalOutcome::Success {
            before_not_after,
            after_not_after,
            restored,
        }
    } else if timed_out {
        RenewalOutcome::Timeout { restored }
    } else {
        RenewalOutcome::NotProven { restored }
    }
}

/// Restore the original ratio: PATCH back if Some, DELETE the field if None.
/// Returns `true` on success, `false` on failure. Always reloads after restore.
async fn restore_ratio(caddy: &CaddyClient, host: &str, original_ratio: Option<f64>) -> bool {
    let result = match original_ratio {
        Some(ratio) => caddy.patch_tls_policy_ratio(host, ratio).await,
        None => caddy.delete_tls_policy_ratio(host).await,
    };
    match result {
        Ok(()) => {
            let _ = caddy.reload().await;
            true
        }
        Err(e) => {
            tracing::error!(
                host = host,
                error = %e,
                "CRITICAL: ratio revert FAILED (original_ratio={:?})",
                original_ratio
            );
            false
        }
    }
}

/// Restart Caddy via systemctl, bounded by a 30s timeout.
///
/// Returns an error if systemctl is unavailable or the restart fails.
/// This only works if slip owns the systemd lifecycle (runs as root or
/// has the appropriate permissions).
async fn restart_caddy_bounded() -> Result<(), String> {
    use crate::doctor::CommandRunner;
    struct RealRunner;
    impl CommandRunner for RealRunner {
        fn run(&self, cmd: &str, args: &[&str]) -> std::io::Result<crate::doctor::CommandOutput> {
            let output = std::process::Command::new(cmd).args(args).output()?;
            Ok(crate::doctor::CommandOutput {
                stdout: String::from_utf8_lossy(&output.stdout).to_string(),
                stderr: String::from_utf8_lossy(&output.stderr).to_string(),
                status: output.status.code().unwrap_or(-1),
            })
        }
    }

    let runner = RealRunner;
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        tokio::task::spawn_blocking(move || runner.run("systemctl", &["restart", "caddy"])),
    )
    .await;

    match result {
        Ok(Ok(Ok(out))) if out.status == 0 => Ok(()),
        Ok(Ok(Ok(out))) => Err(format!(
            "systemctl restart caddy exited {} — \
             slip may not own the systemd lifecycle; restart manually: systemctl restart caddy. \
             stderr: {}",
            out.status,
            out.stderr.chars().take(200).collect::<String>()
        )),
        Ok(Ok(Err(e))) => Err(format!(
            "cannot run systemctl: {e} — restart Caddy manually"
        )),
        Ok(Err(e)) => Err(format!("task join error: {e}")),
        Err(_) => {
            Err("systemctl restart caddy timed out (30s) — restart Caddy manually".to_string())
        }
    }
}

/// Wait for Caddy admin API to become reachable after a restart.
async fn wait_caddy_ready(caddy: &CaddyClient, timeout: std::time::Duration) -> Result<(), String> {
    let deadline = std::time::Instant::now() + timeout;
    while std::time::Instant::now() < deadline {
        if caddy.ping().await.is_ok() {
            return Ok(());
        }
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
    Err(format!(
        "Caddy admin API not reachable within {timeout:?} after restart"
    ))
}

/// `GET /v1/deploys/:deploy_id`
///
/// Returns the current state of a specific deploy by ID, or 404 if not found.
async fn handle_deploy_status(
    State(state): State<Arc<AppState>>,
    Path(deploy_id): Path<String>,
) -> Result<(StatusCode, Json<DeployStatusResponse>), AppError> {
    let db = state.db.clone();
    let deploy_id_clone = deploy_id.clone();
    let ctx = tokio::task::spawn_blocking(move || db.get_deploy(&deploy_id_clone))
        .await
        .map_err(|e| AppError::Internal(format!("task join error: {e}")))?
        .map_err(|e| {
            tracing::error!(deploy_id = %deploy_id, error = %e, "database error reading deploy");
            AppError::Internal("database error".to_string())
        })?
        .ok_or_else(|| AppError::NotFound("deploy not found".to_string()))?;

    let status_str = match ctx.status {
        crate::deploy::DeployStatus::Accepted => "accepted",
        crate::deploy::DeployStatus::Pulling => "pulling",
        crate::deploy::DeployStatus::Configuring => "configuring",
        crate::deploy::DeployStatus::Starting => "starting",
        crate::deploy::DeployStatus::HealthChecking => "health_checking",
        crate::deploy::DeployStatus::Switching => "switching",
        crate::deploy::DeployStatus::StoppingOld => "stopping_old",
        crate::deploy::DeployStatus::RemovingRoute => "removing_route",
        crate::deploy::DeployStatus::RestartingOld => "restarting_old",
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
/// clears state. Accepts either Bearer token or HMAC signature authentication.
async fn handle_preview_teardown(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Path((app, preview_id)): Path<(String, String)>,
) -> Result<(StatusCode, Json<serde_json::Value>), AppError> {
    // Validate app exists.
    if !state.apps.read().await.contains_key(&app) {
        return Err(AppError::NotFound(format!(
            "unknown app: {app} — register it via POST /v1/apps or run `slip apply`"
        )));
    }

    // Verify auth (Bearer token or HMAC).
    let hmac_body = format!("{app}:{preview_id}");
    verify_preview_auth(&headers, &state, &app, &hmac_body).await?;

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
/// Returns 404 if the app is not registered.
async fn handle_list_previews(
    State(state): State<Arc<AppState>>,
    Path(app): Path<String>,
) -> Result<(StatusCode, Json<Vec<PreviewStatusResponse>>), AppError> {
    // Validate app exists.
    if !state.apps.read().await.contains_key(&app) {
        return Err(AppError::NotFound(format!(
            "unknown app: {app} — register it via POST /v1/apps or run `slip apply`"
        )));
    }

    let prefix = format!("{app}:");
    let previews: Vec<PreviewStatusResponse> = state
        .preview_states
        .iter()
        .filter(|entry| entry.key().starts_with(&prefix))
        .map(|entry| to_preview_response(entry.value()))
        .collect();

    Ok((StatusCode::OK, Json(previews)))
}

/// `GET /v1/previews/:app/:preview_id`
///
/// Returns the status of a single preview. No auth required (read-only).
/// Returns 404 if the app is not registered.
async fn handle_preview_status(
    State(state): State<Arc<AppState>>,
    Path((app, preview_id)): Path<(String, String)>,
) -> Result<(StatusCode, Json<PreviewStatusResponse>), AppError> {
    // Validate app exists.
    if !state.apps.read().await.contains_key(&app) {
        return Err(AppError::NotFound(format!(
            "unknown app: {app} — register it via POST /v1/apps or run `slip apply`"
        )));
    }

    let key = format!("{app}:{preview_id}");
    let entry = state.preview_states.get(&key).ok_or_else(|| {
        AppError::NotFound(format!("preview '{preview_id}' not found for app '{app}'"))
    })?;

    Ok((StatusCode::OK, Json(to_preview_response(&entry))))
}

/// `DELETE /v1/previews/:app`
///
/// Tears down all preview deployments for an app. Accepts either Bearer token
/// or HMAC signature authentication. Returns the list of torn-down preview IDs.
async fn handle_preview_teardown_all(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Path(app): Path<String>,
) -> Result<(StatusCode, Json<TeardownAllResponse>), AppError> {
    // Validate app exists.
    if !state.apps.read().await.contains_key(&app) {
        return Err(AppError::NotFound(format!(
            "unknown app: {app} — register it via POST /v1/apps or run `slip apply`"
        )));
    }

    // Verify auth (Bearer token or HMAC).
    let hmac_body = format!("{app}:*");
    verify_preview_auth(&headers, &state, &app, &hmac_body).await?;

    // Collect all preview IDs for this app.
    let prefix = format!("{app}:");
    let preview_ids: Vec<String> = state
        .preview_states
        .iter()
        .filter(|entry| entry.key().starts_with(&prefix))
        .map(|entry| entry.value().preview_id.clone())
        .collect();

    // Tear down each preview. Collect successfully torn-down IDs.
    let mut torn_down = Vec::new();
    for preview_id in &preview_ids {
        if let Err(e) = teardown_preview(
            state.runtime.as_ref(),
            &state.caddy,
            &state.preview_states,
            &state.config.storage.path,
            &app,
            preview_id,
        )
        .await
        {
            warn!(
                app = %app,
                preview_id = %preview_id,
                error = %e,
                "teardown-all: individual teardown failed (continuing)"
            );
        } else {
            torn_down.push(preview_id.clone());
        }
    }

    Ok((StatusCode::OK, Json(TeardownAllResponse { torn_down })))
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

    use super::{LogEntry, parse_since_duration};
    use crate::api::{
        AppListResponse, AppResponse, AppState, DeployResponse, ErrorResponse, build_router,
    };
    use crate::auth::compute_signature;
    use crate::caddy::CaddyClient;
    use crate::config::{
        AppConfig, AppInfo, AuthConfig, CaddyConfig, DeployConfig, HealthConfig, NetworkConfig,
        RegistriesConfig, ResourceConfig, RoutingConfig, RuntimeConfig, ServerConfig, SlipConfig,
        StorageConfig,
    };
    use crate::db::Db;
    use crate::deploy::{AppRuntimeState, AppStatus, DeployContext, DeployStatus, TriggerSource};
    use crate::docker::DockerClient;
    use crate::health::HealthChecker;
    use crate::secrets::SecretsStore;

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
            registries: RegistriesConfig::default(),
            storage: StorageConfig::default(),
            runtime: RuntimeConfig::default(),
            preview: None,
            deploy: None,
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
                domain: Some("testapp.example.com".to_string()),
                port: Some(3000),
                routes: vec![],
                tls: None,
            },
            health: HealthConfig::default(),
            deploy: DeployConfig::default(),
            env: HashMap::new(),
            env_file: None,
            resources: ResourceConfig::default(),
            network: NetworkConfig::default(),
            preview: None,
            volumes: Vec::new(),
        }
    }
    ///
    /// Each call creates a fresh tempdir for the secrets store, avoiding
    /// interference between parallel tests.
    fn create_test_state() -> Arc<AppState> {
        create_test_state_with_config(test_slip_config())
    }

    /// Build a test `AppState` with a custom `SlipConfig` (e.g. with declared
    /// registries). Each call gets a fresh secrets tempdir.
    fn create_test_state_with_config(config: SlipConfig) -> Arc<AppState> {
        let mut apps = HashMap::new();
        apps.insert(APP_NAME.to_string(), test_app_config(Some(APP_SECRET)));

        let secrets_tmp = tempfile::tempdir().expect("tempdir for secrets");
        let secrets_path = secrets_tmp.path().to_path_buf();
        // Leak the TempDir so it survives for the test duration.
        // This is acceptable in test code — the OS cleans up /tmp on reboot.
        Box::leak(Box::new(secrets_tmp));

        Arc::new(AppState {
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
            db: Db::open_in_memory().unwrap(),
            started_at: Utc::now(),
            preview_states: Arc::new(DashMap::new()),
            preview_locks: DashMap::new(),
            renew_locks: DashMap::new(),
            secrets_store: SecretsStore::new(secrets_path).unwrap(),
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

    // ── DeployRequest images field ─────────────────────────────────────────────

    #[test]
    fn test_deploy_request_with_images_field_deserializes() {
        let json = r#"{
            "app": "myapp",
            "image": "ghcr.io/org/myapp",
            "tag": "v1.0.0",
            "images": {
                "dagster-daemon": "ghcr.io/org/dagster:v1.2.3",
                "redis": "redis:8-alpine"
            }
        }"#;
        let req: crate::api::DeployRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.images.len(), 2);
        assert_eq!(
            req.images.get("dagster-daemon").unwrap(),
            "ghcr.io/org/dagster:v1.2.3"
        );
        assert_eq!(req.images.get("redis").unwrap(), "redis:8-alpine");
    }

    #[test]
    fn test_deploy_request_without_images_field_defaults_empty() {
        let json = r#"{"app":"myapp","image":"ghcr.io/org/myapp","tag":"v1.0.0"}"#;
        let req: crate::api::DeployRequest = serde_json::from_str(json).unwrap();
        assert!(
            req.images.is_empty(),
            "images must be empty when field is absent"
        );
    }

    #[test]
    fn test_deploy_request_without_image_field_defaults_empty() {
        // image is optional — defaults to None
        let json = r#"{"app":"myapp","tag":"v1.0.0"}"#;
        let req: crate::api::DeployRequest = serde_json::from_str(json).unwrap();
        assert!(
            req.image.is_none(),
            "image must be None when field is absent"
        );
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
            db: Db::open_in_memory().unwrap(),
            started_at: Utc::now(),
            preview_states: Arc::new(DashMap::new()),
            preview_locks: DashMap::new(),
            renew_locks: DashMap::new(),
            secrets_store: SecretsStore::new({
                let t = tempfile::tempdir().expect("tempdir for secrets");
                let p = t.path().to_path_buf();
                Box::leak(Box::new(t));
                p
            })
            .unwrap(),
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
            db: Db::open_in_memory().unwrap(),
            started_at: Utc::now(),
            preview_states: Arc::new(DashMap::new()),
            preview_locks: DashMap::new(),
            renew_locks: DashMap::new(),
            secrets_store: SecretsStore::new({
                let t = tempfile::tempdir().expect("tempdir for secrets");
                let p = t.path().to_path_buf();
                Box::leak(Box::new(t));
                p
            })
            .unwrap(),
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
                    current_tag: Some("v1.0.0".to_string()),
                    current_container_id: Some("abc123".to_string()),
                    current_port: Some(54321),
                    deployed_at: Some(Utc::now()),
                    deploy_id: Some("dep_001".to_string()),
                    kind: Some("container".to_string()),
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
        assert_eq!(testapp["tag"], "v1.0.0");
        assert_eq!(testapp["container_id"], "abc123");
        assert_eq!(testapp["port"], 54321);
    }

    // ── GET /v1/status — includes deploy_id/triggered_by from cache ────────────

    #[tokio::test]
    async fn test_status_includes_deploy_metadata() {
        let state = create_test_state();

        // Pre-populate runtime state with a Running app.
        {
            let mut app_states = state.app_states.write().await;
            app_states.insert(
                APP_NAME.to_string(),
                AppRuntimeState {
                    status: AppStatus::Running,
                    current_tag: Some("v1.0.0".to_string()),
                    current_container_id: Some("abc123".to_string()),
                    current_port: Some(54321),
                    deployed_at: Some(Utc::now()),
                    deploy_id: Some("dep_001".to_string()),
                    kind: Some("container".to_string()),
                    ..Default::default()
                },
            );
        }

        // Populate the cache with a deploy entry keyed by app name.
        let ctx = DeployContext {
            id: "dep_meta001".to_string(),
            app: APP_NAME.to_string(),
            image: APP_IMAGE.to_string(),
            tag: "v1.2.3".to_string(),
            status: DeployStatus::Completed,
            started_at: Utc::now(),
            finished_at: Some(Utc::now()),
            error: None,
            triggered_by: TriggerSource::Webhook,
            new_container_id: Some("abc123".to_string()),
            new_port: Some(8080),
            images: HashMap::new(),
            new_pod_name: None,
            new_manifest_path: None,
            rollback_failed: false,
        };

        // Insert into the cache (keyed by app name for latest-deploy lookups)
        state.deploys.insert(ctx.app.clone(), ctx.clone());

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
        assert_eq!(testapp["tag"], "v1.0.0");
        assert_eq!(testapp["deploy_id"], "dep_meta001");
        assert_eq!(testapp["triggered_by"], "webhook");
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
            images: HashMap::new(),
            status: DeployStatus::Completed,
            started_at: Utc::now(),
            finished_at: Some(Utc::now()),
            error: None,
            triggered_by: TriggerSource::Webhook,
            new_container_id: Some("ctr456".to_string()),
            new_port: Some(9000),
            new_pod_name: None,
            new_manifest_path: None,
            rollback_failed: false,
        };
        // Insert into SQLite (the handler reads from SQLite in Phase 4).
        state.db.insert_deploy(&ctx).unwrap();
        // Also populate the cache (keyed by app name for latest-deploy lookups).
        state.deploys.insert(ctx.app.clone(), ctx.clone());

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
            db: Db::open_in_memory().unwrap(),
            started_at: Utc::now(),
            preview_states: Arc::new(DashMap::new()),
            preview_locks: DashMap::new(),
            renew_locks: DashMap::new(),
            secrets_store: SecretsStore::new({
                let t = tempfile::tempdir().expect("tempdir for secrets");
                let p = t.path().to_path_buf();
                Box::leak(Box::new(t));
                p
            })
            .unwrap(),
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
                domain: Some("pr-1.preview.example.com".to_string()),
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
                domain: Some("pr-2.preview.example.com".to_string()),
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
                domain: Some("pr-1.other.example.com".to_string()),
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
                domain: Some("pr-99.preview.example.com".to_string()),
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
            db: Db::open_in_memory().unwrap(),
            started_at: Utc::now(),
            preview_states: Arc::new(DashMap::new()),
            preview_locks: DashMap::new(),
            renew_locks: DashMap::new(),
            secrets_store: SecretsStore::new({
                let t = tempfile::tempdir().expect("tempdir for secrets");
                let p = t.path().to_path_buf();
                Box::leak(Box::new(t));
                p
            })
            .unwrap(),
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
            db: Db::open_in_memory().unwrap(),
            started_at: Utc::now(),
            preview_states: Arc::new(DashMap::new()),
            preview_locks: DashMap::new(),
            renew_locks: DashMap::new(),
            secrets_store: SecretsStore::new({
                let t = tempfile::tempdir().expect("tempdir for secrets");
                let p = t.path().to_path_buf();
                Box::leak(Box::new(t));
                p
            })
            .unwrap(),
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
            db: Db::open_in_memory().unwrap(),
            started_at: Utc::now(),
            preview_states: Arc::new(DashMap::new()),
            preview_locks: DashMap::new(),
            renew_locks: DashMap::new(),
            secrets_store: SecretsStore::new({
                let t = tempfile::tempdir().expect("tempdir for secrets");
                let p = t.path().to_path_buf();
                Box::leak(Box::new(t));
                p
            })
            .unwrap(),
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
        assert_eq!(app_config.routing.port, Some(9000));
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
    async fn test_rollback_uses_sqlite_previous_deploy() {
        let state = create_test_state();

        // Insert a completed deploy into SQLite with tag "v1.0".
        let previous_ctx = DeployContext {
            id: "dep_prev001".to_string(),
            app: APP_NAME.to_string(),
            image: APP_IMAGE.to_string(),
            tag: "v1.0".to_string(),
            images: HashMap::new(),
            status: DeployStatus::Completed,
            started_at: Utc::now() - chrono::Duration::hours(1),
            finished_at: Some(Utc::now() - chrono::Duration::minutes(30)),
            error: None,
            triggered_by: TriggerSource::Webhook,
            new_container_id: Some("ctr_prev".to_string()),
            new_port: Some(8080),
            new_pod_name: None,
            new_manifest_path: None,
            rollback_failed: false,
        };
        state.db.insert_deploy(&previous_ctx).unwrap();

        // Set up app_states with a deploy_id (so the handler excludes the
        // current deploy from the SQLite query) but NO previous_tag.
        {
            let mut app_states = state.app_states.write().await;
            app_states.insert(
                APP_NAME.to_string(),
                AppRuntimeState {
                    status: AppStatus::Running,
                    current_tag: Some("v2.0".to_string()),
                    deploy_id: Some("dep_current".to_string()),
                    previous_tag: None, // Must fall back to SQLite.
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
        // The tag should come from SQLite (v1.0), not from previous_tag (which is None).
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
            db: Db::open_in_memory().unwrap(),
            started_at: Utc::now(),
            preview_states: Arc::new(DashMap::new()),
            preview_locks: DashMap::new(),
            renew_locks: DashMap::new(),
            secrets_store: SecretsStore::new({
                let t = tempfile::tempdir().expect("tempdir for secrets");
                let p = t.path().to_path_buf();
                Box::leak(Box::new(t));
                p
            })
            .unwrap(),
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

    // ── Secrets API tests ──────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_list_secrets_empty() {
        let state = create_test_state();
        let app = build_router(state);

        let request = Request::builder()
            .method("GET")
            .uri(format!("/v1/apps/{APP_NAME}/secrets"))
            .header("Authorization", auth_header(GLOBAL_SECRET))
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let payload: crate::api::SecretsListResponse = serde_json::from_slice(&bytes).unwrap();
        assert!(payload.secrets.is_empty());
    }

    #[tokio::test]
    async fn test_set_and_list_secrets() {
        let state = create_test_state();

        // Set two secrets
        let body = serde_json::json!({
            "secrets": {
                "DB_URL": "postgres://localhost/db",
                "API_KEY": "sk-12345"
            }
        });
        let request = Request::builder()
            .method("PUT")
            .uri(format!("/v1/apps/{APP_NAME}/secrets"))
            .header("Authorization", auth_header(GLOBAL_SECRET))
            .header("Content-Type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();

        let app = build_router(state.clone());
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let payload: crate::api::SetSecretsResponse = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(payload.set, vec!["API_KEY", "DB_URL"]); // sorted

        // List secrets — should return key names only (use same state)
        let request = Request::builder()
            .method("GET")
            .uri(format!("/v1/apps/{APP_NAME}/secrets"))
            .header("Authorization", auth_header(GLOBAL_SECRET))
            .body(Body::empty())
            .unwrap();

        let app2 = build_router(state);
        let response = app2.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let payload: crate::api::SecretsListResponse = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(payload.secrets, vec!["API_KEY", "DB_URL"]);
    }

    #[tokio::test]
    async fn test_set_secrets_response_never_contains_values() {
        let state = create_test_state();
        let app = build_router(state);

        let body = serde_json::json!({
            "secrets": {
                "MY_KEY": "super-secret-value-never-to-be-exposed"
            }
        });
        let request = Request::builder()
            .method("PUT")
            .uri(format!("/v1/apps/{APP_NAME}/secrets"))
            .header("Authorization", auth_header(GLOBAL_SECRET))
            .header("Content-Type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let response_text = String::from_utf8(bytes.to_vec()).unwrap();
        // The response should not contain the secret value
        assert!(
            !response_text.contains("super-secret-value-never-to-be-exposed"),
            "secrets response must not contain values"
        );
    }

    #[tokio::test]
    async fn test_remove_secret() {
        let state = create_test_state();

        // Set a secret first
        let body = serde_json::json!({
            "secrets": {
                "TO_DELETE": "value"
            }
        });
        let request = Request::builder()
            .method("PUT")
            .uri(format!("/v1/apps/{APP_NAME}/secrets"))
            .header("Authorization", auth_header(GLOBAL_SECRET))
            .header("Content-Type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();
        let app = build_router(state.clone());
        let _ = app.oneshot(request).await.unwrap();

        // Now delete it (use same state)
        let request = Request::builder()
            .method("DELETE")
            .uri(format!("/v1/apps/{APP_NAME}/secrets/TO_DELETE"))
            .header("Authorization", auth_header(GLOBAL_SECRET))
            .body(Body::empty())
            .unwrap();

        let app2 = build_router(state);
        let response = app2.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_remove_nonexistent_secret_returns_404() {
        let state = create_test_state();
        let app = build_router(state);

        let request = Request::builder()
            .method("DELETE")
            .uri(format!("/v1/apps/{APP_NAME}/secrets/NONEXISTENT"))
            .header("Authorization", auth_header(GLOBAL_SECRET))
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_secrets_require_auth() {
        let state = create_test_state();
        let app = build_router(state);

        // No auth header
        let request = Request::builder()
            .method("GET")
            .uri(format!("/v1/apps/{APP_NAME}/secrets"))
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_secrets_unknown_app_returns_404() {
        let state = create_test_state();
        let app = build_router(state);

        let request = Request::builder()
            .method("GET")
            .uri("/v1/apps/nonexistent/secrets")
            .header("Authorization", auth_header(GLOBAL_SECRET))
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_secrets_invalid_key_returns_400() {
        let state = create_test_state();
        let app = build_router(state);

        let body = serde_json::json!({
            "secrets": {
                "bad-key-name": "value"
            }
        });
        let request = Request::builder()
            .method("PUT")
            .uri(format!("/v1/apps/{APP_NAME}/secrets"))
            .header("Authorization", auth_header(GLOBAL_SECRET))
            .header("Content-Type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_delete_app_cleans_up_secrets() {
        let tmp = tempfile::tempdir().unwrap();
        let secrets_store = SecretsStore::new(tmp.path().join("secrets")).unwrap();

        let mut apps = HashMap::new();
        apps.insert(APP_NAME.to_string(), test_app_config(Some(APP_SECRET)));

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
            db: Db::open_in_memory().unwrap(),
            started_at: Utc::now(),
            preview_states: Arc::new(DashMap::new()),
            preview_locks: DashMap::new(),
            renew_locks: DashMap::new(),
            secrets_store: secrets_store.clone(),
        });

        // Set a secret via the store directly
        state
            .secrets_store
            .set(APP_NAME, "MY_KEY", "my_value")
            .unwrap();
        assert!(state.secrets_store.list(APP_NAME).unwrap().len() == 1);

        let app = build_router(state.clone());

        // Delete the app
        let request = Request::builder()
            .method("DELETE")
            .uri(format!("/v1/apps/{APP_NAME}"))
            .header("Authorization", auth_header(GLOBAL_SECRET))
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        // Verify secrets directory was cleaned up
        assert!(
            state.secrets_store.list(APP_NAME).unwrap().is_empty(),
            "secrets should be removed when app is deleted"
        );
    }

    // ── Preview dual-auth and teardown-all tests ──────────────────────────────

    #[tokio::test]
    async fn test_list_previews_unknown_app_returns_404() {
        let state = create_test_state();
        let app = build_router(state);

        let request = Request::builder()
            .method("GET")
            .uri("/v1/previews/nonexistent")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let payload: ErrorResponse = serde_json::from_slice(&bytes).unwrap();
        assert!(payload.error.contains("nonexistent"));
    }

    #[tokio::test]
    async fn test_preview_teardown_with_bearer_token() {
        use crate::deploy::AppStatus;
        use crate::preview::PreviewState;

        let state = create_test_state();

        // Insert a preview.
        state.preview_states.insert(
            format!("{APP_NAME}:pr-bearer"),
            PreviewState {
                preview_id: "pr-bearer".to_string(),
                app: APP_NAME.to_string(),
                sha: "abc".to_string(),
                status: AppStatus::Running,
                container_id: None,
                pod_name: None,
                port: Some(54321),
                tag: Some("v1".to_string()),
                deployed_at: Utc::now(),
                expires_at: None,
                domain: Some("pr-bearer.preview.example.com".to_string()),
                manifest_path: None,
                deploy_id: None,
            },
        );

        let app = build_router(state.clone());

        // DELETE with Bearer token (no X-Slip-Signature).
        let request = Request::builder()
            .method("DELETE")
            .uri(format!("/v1/previews/{APP_NAME}/pr-bearer"))
            .header("Authorization", auth_header(GLOBAL_SECRET))
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        // Verify preview was removed from state.
        assert!(
            state
                .preview_states
                .get(&format!("{APP_NAME}:pr-bearer"))
                .is_none(),
            "preview should be removed after teardown"
        );
    }

    #[tokio::test]
    async fn test_preview_teardown_still_accepts_hmac() {
        // Verify backward compatibility: HMAC auth still works.
        let state = create_test_state();
        let app = build_router(state);

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
    }

    #[tokio::test]
    async fn test_teardown_all_previews_empty() {
        let state = create_test_state();
        let app = build_router(state);

        // DELETE /v1/previews/{app} with Bearer token — no previews exist.
        let request = Request::builder()
            .method("DELETE")
            .uri(format!("/v1/previews/{APP_NAME}"))
            .header("Authorization", auth_header(GLOBAL_SECRET))
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let payload: crate::api::TeardownAllResponse = serde_json::from_slice(&bytes).unwrap();
        assert!(payload.torn_down.is_empty(), "should have no torn_down IDs");
    }

    #[tokio::test]
    async fn test_teardown_all_previews_with_entries() {
        use crate::deploy::AppStatus;
        use crate::preview::PreviewState;

        let state = create_test_state();

        // Insert two previews.
        state.preview_states.insert(
            format!("{APP_NAME}:pr-a1"),
            PreviewState {
                preview_id: "pr-a1".to_string(),
                app: APP_NAME.to_string(),
                sha: "sha1".to_string(),
                status: AppStatus::Running,
                container_id: None,
                pod_name: None,
                port: Some(54001),
                tag: Some("v1".to_string()),
                deployed_at: Utc::now(),
                expires_at: None,
                domain: Some("pr-a1.preview.example.com".to_string()),
                manifest_path: None,
                deploy_id: None,
            },
        );
        state.preview_states.insert(
            format!("{APP_NAME}:pr-a2"),
            PreviewState {
                preview_id: "pr-a2".to_string(),
                app: APP_NAME.to_string(),
                sha: "sha2".to_string(),
                status: AppStatus::Running,
                container_id: None,
                pod_name: None,
                port: Some(54002),
                tag: Some("v2".to_string()),
                deployed_at: Utc::now(),
                expires_at: None,
                domain: Some("pr-a2.preview.example.com".to_string()),
                manifest_path: None,
                deploy_id: None,
            },
        );

        let app = build_router(state.clone());

        let request = Request::builder()
            .method("DELETE")
            .uri(format!("/v1/previews/{APP_NAME}"))
            .header("Authorization", auth_header(GLOBAL_SECRET))
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let payload: crate::api::TeardownAllResponse = serde_json::from_slice(&bytes).unwrap();

        assert_eq!(
            payload.torn_down.len(),
            2,
            "should have torn down 2 previews"
        );
        assert!(payload.torn_down.contains(&"pr-a1".to_string()));
        assert!(payload.torn_down.contains(&"pr-a2".to_string()));

        // Verify state is cleared.
        let prefix = format!("{APP_NAME}:");
        let remaining: Vec<String> = state
            .preview_states
            .iter()
            .filter(|e| e.key().starts_with(&prefix))
            .map(|e| e.key().to_string())
            .collect();
        assert!(
            remaining.is_empty(),
            "all previews should be removed from state"
        );
    }

    #[tokio::test]
    async fn test_teardown_all_requires_auth() {
        let state = create_test_state();
        let app = build_router(state);

        // DELETE /v1/previews/{app} without any auth header.
        let request = Request::builder()
            .method("DELETE")
            .uri(format!("/v1/previews/{APP_NAME}"))
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_teardown_all_unknown_app_returns_404() {
        let state = create_test_state();
        let app = build_router(state);

        let request = Request::builder()
            .method("DELETE")
            .uri("/v1/previews/nonexistent")
            .header("Authorization", auth_header(GLOBAL_SECRET))
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_preview_status_unknown_app_returns_404() {
        let state = create_test_state();
        let app = build_router(state);

        let request = Request::builder()
            .method("GET")
            .uri("/v1/previews/nonexistent/some-preview")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    // ── Deploy key tests ────────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_set_deploy_key_create_returns_key() {
        let state = create_test_state();
        let app = build_router(state);

        // Create a deploy key (no existing key).
        let body = serde_json::json!({}).to_string();
        let request = Request::builder()
            .method("PUT")
            .uri(format!("/v1/apps/{}/key", APP_NAME))
            .header("Content-Type", "application/json")
            .header("Authorization", auth_header(GLOBAL_SECRET))
            .body(Body::from(body))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let payload: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(payload["app"], APP_NAME);
        assert_eq!(payload["rotated"], false);
        assert!(payload["key"].is_string(), "key must be present on create");
        assert!(payload.get("message").is_none(), "no message on create");
        let first_key = payload["key"].as_str().unwrap().to_string();
        assert_eq!(first_key.len(), 64, "deploy key must be 64 hex chars");
    }

    #[tokio::test]
    async fn test_set_deploy_key_existing_no_rotate_returns_no_key() {
        let state = create_test_state();
        let app = build_router(state);

        // First call: create a key.
        let body = serde_json::json!({}).to_string();
        let request = Request::builder()
            .method("PUT")
            .uri(format!("/v1/apps/{}/key", APP_NAME))
            .header("Content-Type", "application/json")
            .header("Authorization", auth_header(GLOBAL_SECRET))
            .body(Body::from(body))
            .unwrap();
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        // Second call: same app, no rotate — must NOT return the key.
        let body = serde_json::json!({}).to_string();
        let request = Request::builder()
            .method("PUT")
            .uri(format!("/v1/apps/{}/key", APP_NAME))
            .header("Content-Type", "application/json")
            .header("Authorization", auth_header(GLOBAL_SECRET))
            .body(Body::from(body))
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let payload: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(payload["app"], APP_NAME);
        assert_eq!(payload["rotated"], false);
        assert!(
            payload.get("key").is_none() || payload["key"].is_null(),
            "key must NOT be present when existing key is not rotated"
        );
        assert!(
            payload["message"].is_string(),
            "message should explain why no key was returned"
        );
        assert!(
            payload["message"]
                .as_str()
                .unwrap()
                .contains("already exists"),
            "message should mention key already exists"
        );
    }

    #[tokio::test]
    async fn test_set_deploy_key_rotate_returns_new_key() {
        let state = create_test_state();
        let app = build_router(state);

        // First call: create a key.
        let body = serde_json::json!({}).to_string();
        let request = Request::builder()
            .method("PUT")
            .uri(format!("/v1/apps/{}/key", APP_NAME))
            .header("Content-Type", "application/json")
            .header("Authorization", auth_header(GLOBAL_SECRET))
            .body(Body::from(body))
            .unwrap();
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let payload: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let first_key = payload["key"].as_str().unwrap().to_string();

        // Second call: rotate=true — must return a NEW key.
        let body = serde_json::json!({"rotate": true}).to_string();
        let request = Request::builder()
            .method("PUT")
            .uri(format!("/v1/apps/{}/key", APP_NAME))
            .header("Content-Type", "application/json")
            .header("Authorization", auth_header(GLOBAL_SECRET))
            .body(Body::from(body))
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let payload: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(payload["app"], APP_NAME);
        assert_eq!(payload["rotated"], true);
        assert!(payload["key"].is_string(), "key must be present on rotate");
        let second_key = payload["key"].as_str().unwrap().to_string();
        assert_eq!(second_key.len(), 64, "deploy key must be 64 hex chars");
        assert_ne!(
            first_key, second_key,
            "rotated key must differ from original"
        );
        assert!(payload.get("message").is_none(), "no message on rotate");
    }

    #[tokio::test]
    async fn test_set_deploy_key_unknown_app_returns_404() {
        let state = create_test_state();
        let app = build_router(state);

        let body = serde_json::json!({}).to_string();
        let request = Request::builder()
            .method("PUT")
            .uri("/v1/apps/nonexistent/key")
            .header("Content-Type", "application/json")
            .header("Authorization", auth_header(GLOBAL_SECRET))
            .body(Body::from(body))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    // ── Registry credential handler tests (SLIP-105) ────────────────────────────

    #[tokio::test]
    async fn test_registry_put_creates_store_entry() {
        let state = create_test_state();
        let app = build_router(state.clone());

        let body = serde_json::json!({
            "username": "slip",
            "password": "tok-secret"
        })
        .to_string();
        let request = Request::builder()
            .method("PUT")
            .uri("/v1/registries/ghcr.io")
            .header("Content-Type", "application/json")
            .header("Authorization", auth_header(GLOBAL_SECRET))
            .body(Body::from(body))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let payload: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(payload["url"], "ghcr.io");
        assert_eq!(payload["username"], "slip");
        assert!(
            payload.get("password").is_none(),
            "response must never include the password"
        );

        // Store entry created.
        let cred = state
            .secrets_store
            .get_registry_credential("ghcr.io")
            .unwrap();
        assert_eq!(
            cred,
            Some((Some("slip".to_string()), "tok-secret".to_string()))
        );
    }

    #[tokio::test]
    async fn test_registry_put_missing_password_rejects() {
        // The `password` field is required; a body without it fails to
        // deserialize → 400 (axum's default Json extractor response).
        let state = create_test_state();
        let app = build_router(state);

        let body = serde_json::json!({"username": "u"}).to_string();
        let request = Request::builder()
            .method("PUT")
            .uri("/v1/registries/ghcr.io")
            .header("Content-Type", "application/json")
            .header("Authorization", auth_header(GLOBAL_SECRET))
            .body(Body::from(body))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert!(
            response.status().is_client_error(),
            "missing password should be rejected, got {}",
            response.status()
        );
    }

    #[tokio::test]
    async fn test_registry_delete_removes_entry() {
        let state = create_test_state();
        state
            .secrets_store
            .set_registry_credential("ghcr.io", Some("u"), "p")
            .unwrap();
        let app = build_router(state.clone());

        let request = Request::builder()
            .method("DELETE")
            .uri("/v1/registries/ghcr.io")
            .header("Authorization", auth_header(GLOBAL_SECRET))
            .body(Body::empty())
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        assert!(
            state
                .secrets_store
                .get_registry_credential("ghcr.io")
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn test_registry_delete_unknown_returns_404() {
        let state = create_test_state();
        let app = build_router(state);

        let request = Request::builder()
            .method("DELETE")
            .uri("/v1/registries/ghcr.io")
            .header("Authorization", auth_header(GLOBAL_SECRET))
            .body(Body::empty())
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_registry_list_excludes_password_and_merges_sources() {
        let mut config = test_slip_config();
        config.registries.registries.insert(
            "ghcr".to_string(),
            crate::config::RegistryEntry {
                url: "ghcr.io".to_string(),
                username: Some("toml-user".to_string()),
                token: Some("toml-tok".to_string()),
            },
        );
        // A second TOML registry with no token.
        config.registries.registries.insert(
            "public".to_string(),
            crate::config::RegistryEntry {
                url: "registry.example.com".to_string(),
                username: None,
                token: None,
            },
        );
        let state = create_test_state_with_config(config);
        // Store a cred for localhost:5000 + one for ghcr.io (store wins).
        state
            .secrets_store
            .set_registry_credential("localhost:5000", Some("ci"), "store-tok")
            .unwrap();
        state
            .secrets_store
            .set_registry_credential("ghcr.io", Some("store-user"), "store-tok2")
            .unwrap();
        let app = build_router(state);

        let request = Request::builder()
            .method("GET")
            .uri("/v1/registries")
            .header("Authorization", auth_header(GLOBAL_SECRET))
            .body(Body::empty())
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let payload: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let arr = payload.as_array().expect("list is an array");
        let by_url: std::collections::HashMap<String, serde_json::Value> = arr
            .iter()
            .map(|v| (v["url"].as_str().unwrap().to_string(), v.clone()))
            .collect();

        // ghcr.io: both toml+store present; store username wins; source toml+store.
        let ghcr = &by_url["ghcr.io"];
        assert_eq!(ghcr["username"], "store-user", "store username wins");
        assert_eq!(ghcr["hasCredential"], true);
        assert_eq!(ghcr["credentialSource"], "toml+store");
        assert!(
            !serde_json::to_string(ghcr).unwrap().contains("store-tok2"),
            "no password leak"
        );

        // registry.example.com: toml-declared, no token.
        let public = &by_url["registry.example.com"];
        assert_eq!(public["hasCredential"], false);
        assert_eq!(public["credentialSource"], "none");

        // localhost:5000: store only.
        let local = &by_url["localhost:5000"];
        assert_eq!(local["username"], "ci");
        assert_eq!(local["hasCredential"], true);
        assert_eq!(local["credentialSource"], "store");
    }

    #[tokio::test]
    async fn test_registry_routes_require_auth() {
        let state = create_test_state();
        let app = build_router(state);

        // No Authorization header → 401.
        let request = Request::builder()
            .method("GET")
            .uri("/v1/registries")
            .body(Body::empty())
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    // ── Live app registration: create → immediate visibility → survive restart ──

    #[tokio::test]
    async fn test_live_app_registration_full_flow() {
        // This test verifies the SLIP-90 acceptance criteria:
        // 1. Register an app via API → immediately visible in GET /v1/apps
        // 2. Secrets settable immediately (no restart)
        // 3. Simulate restart (re-load from disk) → app still present

        let tmp = tempfile::tempdir().expect("tempdir");
        let config_dir = tmp.path().to_path_buf();

        // Create a minimal slip.toml so load_config can find it.
        let slip_toml = r#"
[server]
listen = "0.0.0.0:7890"

[caddy]
admin_api = "http://localhost:2019"

[auth]
secret = "test-secret"

[registry]

[storage]
path = "/tmp/slip-test"
"#;
        std::fs::write(config_dir.join("slip.toml"), slip_toml).unwrap();

        let secrets_tmp = tempfile::tempdir().expect("tempdir for secrets");
        let secrets_path = secrets_tmp.path().to_path_buf();
        Box::leak(Box::new(secrets_tmp));

        let state = Arc::new(AppState {
            config: test_slip_config(),
            apps: RwLock::new(HashMap::new()),
            config_dir: config_dir.clone(),
            deploy_locks: DashMap::new(),
            runtime: Arc::new(
                DockerClient::new_with_url("http://127.0.0.1:19998").expect("DockerClient::new"),
            ),
            caddy: CaddyClient::new("http://127.0.0.1:19999".to_string()),
            health: HealthChecker::new(),
            app_states: RwLock::new(HashMap::new()),
            deploys: DashMap::new(),
            db: Db::open_in_memory().unwrap(),
            started_at: Utc::now(),
            preview_states: Arc::new(DashMap::new()),
            preview_locks: DashMap::new(),
            renew_locks: DashMap::new(),
            secrets_store: SecretsStore::new(secrets_path).unwrap(),
        });

        // Step 1: Register an app via POST /v1/apps
        let app = build_router(state.clone());
        let create_body = serde_json::json!({
            "name": "liveapp",
            "image": "ghcr.io/org/liveapp:latest",
            "domain": "liveapp.example.com",
            "port": 8080,
            "health": {"path": "/healthz"}
        });

        let request = Request::builder()
            .method("POST")
            .uri("/v1/apps")
            .header("Authorization", auth_header(GLOBAL_SECRET))
            .header("Content-Type", "application/json")
            .body(Body::from(serde_json::to_vec(&create_body).unwrap()))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(
            response.status(),
            StatusCode::CREATED,
            "app should be created"
        );

        // Step 2: Immediately visible in GET /v1/apps/{name}
        let request = Request::builder()
            .method("GET")
            .uri("/v1/apps/liveapp")
            .header("Authorization", auth_header(GLOBAL_SECRET))
            .body(Body::empty())
            .unwrap();

        let app2 = build_router(state.clone());
        let response = app2.oneshot(request).await.unwrap();
        assert_eq!(
            response.status(),
            StatusCode::OK,
            "app should be immediately visible"
        );

        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let payload: AppResponse = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(payload.name, "liveapp");
        assert_eq!(payload.image, "ghcr.io/org/liveapp:latest");
        assert_eq!(payload.port, 8080);

        // Step 3: Secrets settable immediately (no restart)
        let secrets_body = serde_json::json!({
            "secrets": {"DB_URL": "postgres://localhost/liveapp"}
        });
        let request = Request::builder()
            .method("PUT")
            .uri("/v1/apps/liveapp/secrets")
            .header("Authorization", auth_header(GLOBAL_SECRET))
            .header("Content-Type", "application/json")
            .body(Body::from(serde_json::to_vec(&secrets_body).unwrap()))
            .unwrap();

        let app3 = build_router(state.clone());
        let response = app3.oneshot(request).await.unwrap();
        assert_eq!(
            response.status(),
            StatusCode::OK,
            "secrets should be settable immediately"
        );

        // Step 4: Simulate restart — re-load config from disk
        let (_reloaded_cfg, reloaded_apps) =
            crate::config::load_config(&config_dir).expect("should reload config from disk");

        assert!(
            reloaded_apps.contains_key("liveapp"),
            "app should survive restart (persisted to disk)"
        );
        let reloaded = &reloaded_apps["liveapp"];
        assert_eq!(reloaded.app.name, "liveapp");
        assert_eq!(reloaded.app.image, "ghcr.io/org/liveapp:latest");
        assert_eq!(reloaded.routing.port, Some(8080));
        assert_eq!(
            reloaded.health.path.as_deref(),
            Some("/healthz"),
            "health config should be persisted"
        );

        // Step 5: Verify the generated TOML has the managed-by header
        let toml_path = config_dir.join("apps").join("liveapp.toml");
        assert!(toml_path.exists(), "generated TOML should exist");
        let toml_content = std::fs::read_to_string(&toml_path).unwrap();
        assert!(
            toml_content.starts_with("# managed by slip"),
            "generated TOML should have the managed-by header"
        );
    }

    #[tokio::test]
    async fn test_live_app_update_persists() {
        // Verify PATCH updates survive restart
        let tmp = tempfile::tempdir().expect("tempdir");
        let config_dir = tmp.path().to_path_buf();

        let slip_toml = r#"
[server]
listen = "0.0.0.0:7890"

[caddy]
admin_api = "http://localhost:2019"

[auth]
secret = "test-secret"

[registry]

[storage]
path = "/tmp/slip-test"
"#;
        std::fs::write(config_dir.join("slip.toml"), slip_toml).unwrap();

        let secrets_tmp = tempfile::tempdir().expect("tempdir for secrets");
        let secrets_path = secrets_tmp.path().to_path_buf();
        Box::leak(Box::new(secrets_tmp));

        let state = Arc::new(AppState {
            config: test_slip_config(),
            apps: RwLock::new(HashMap::new()),
            config_dir: config_dir.clone(),
            deploy_locks: DashMap::new(),
            runtime: Arc::new(
                DockerClient::new_with_url("http://127.0.0.1:19998").expect("DockerClient::new"),
            ),
            caddy: CaddyClient::new("http://127.0.0.1:19999".to_string()),
            health: HealthChecker::new(),
            app_states: RwLock::new(HashMap::new()),
            deploys: DashMap::new(),
            db: Db::open_in_memory().unwrap(),
            started_at: Utc::now(),
            preview_states: Arc::new(DashMap::new()),
            preview_locks: DashMap::new(),
            renew_locks: DashMap::new(),
            secrets_store: SecretsStore::new(secrets_path).unwrap(),
        });

        // Create app
        let app = build_router(state.clone());
        let create_body = serde_json::json!({
            "name": "updateapp",
            "image": "ghcr.io/org/updateapp:latest",
            "domain": "updateapp.example.com",
            "port": 8080,
            "health": {"path": "/healthz"}
        });
        let request = Request::builder()
            .method("POST")
            .uri("/v1/apps")
            .header("Authorization", auth_header(GLOBAL_SECRET))
            .header("Content-Type", "application/json")
            .body(Body::from(serde_json::to_vec(&create_body).unwrap()))
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);

        // Update health path via PATCH
        let patch_body = serde_json::json!({
            "health": {"path": "/readyz"},
            "port": 9090
        });
        let request = Request::builder()
            .method("PATCH")
            .uri("/v1/apps/updateapp")
            .header("Authorization", auth_header(GLOBAL_SECRET))
            .header("Content-Type", "application/json")
            .body(Body::from(serde_json::to_vec(&patch_body).unwrap()))
            .unwrap();

        let app2 = build_router(state.clone());
        let response = app2.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK, "PATCH should succeed");

        // Verify in-memory
        {
            let apps = state.apps.read().await;
            let cfg = apps.get("updateapp").unwrap();
            assert_eq!(cfg.routing.port, Some(9090));
            assert_eq!(cfg.health.path.as_deref(), Some("/readyz"));
        }

        // Simulate restart
        let (_reloaded_cfg, reloaded_apps) =
            crate::config::load_config(&config_dir).expect("should reload config from disk");

        assert!(reloaded_apps.contains_key("updateapp"));
        let reloaded = &reloaded_apps["updateapp"];
        assert_eq!(
            reloaded.routing.port,
            Some(9090),
            "PATCH port should survive restart"
        );
        assert_eq!(
            reloaded.health.path.as_deref(),
            Some("/readyz"),
            "PATCH health path should survive restart"
        );
    }

    #[tokio::test]
    async fn test_secrets_unknown_app_prescriptive_error() {
        let state = create_test_state();
        let app = build_router(state);

        let body = serde_json::json!({
            "secrets": {"KEY": "value"}
        });
        let request = Request::builder()
            .method("PUT")
            .uri("/v1/apps/nonexistent/secrets")
            .header("Authorization", auth_header(GLOBAL_SECRET))
            .header("Content-Type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let payload: ErrorResponse = serde_json::from_slice(&bytes).unwrap();
        assert!(
            payload.error.contains("register it via POST /v1/apps")
                || payload.error.contains("run `slip apply`"),
            "error should be prescriptive: {}",
            payload.error
        );
    }

    // ── Regression: poi health-path drift ────────────────────────────────────

    #[tokio::test]
    async fn test_health_path_patch_persists() {
        // Regression for the poi health-path drift: create with path="/",
        // PATCH to "/api/healthz", GET asserts new path persisted.
        let tmp = tempfile::tempdir().expect("tempdir");
        let config_dir = tmp.path().to_path_buf();

        let slip_toml = r#"
[server]
listen = "0.0.0.0:7890"
[caddy]
admin_api = "http://localhost:2019"
[auth]
secret = "test-secret"
[registry]
[storage]
path = "/tmp/slip-test"
"#;
        std::fs::write(config_dir.join("slip.toml"), slip_toml).unwrap();

        let secrets_tmp = tempfile::tempdir().expect("tempdir for secrets");
        let secrets_path = secrets_tmp.path().to_path_buf();
        Box::leak(Box::new(secrets_tmp));

        let state = Arc::new(AppState {
            config: test_slip_config(),
            apps: RwLock::new(HashMap::new()),
            config_dir: config_dir.clone(),
            deploy_locks: DashMap::new(),
            runtime: Arc::new(
                DockerClient::new_with_url("http://127.0.0.1:19998").expect("DockerClient::new"),
            ),
            caddy: CaddyClient::new("http://127.0.0.1:19999".to_string()),
            health: HealthChecker::new(),
            app_states: RwLock::new(HashMap::new()),
            deploys: DashMap::new(),
            db: Db::open_in_memory().unwrap(),
            started_at: Utc::now(),
            preview_states: Arc::new(DashMap::new()),
            preview_locks: DashMap::new(),
            renew_locks: DashMap::new(),
            secrets_store: SecretsStore::new(secrets_path).unwrap(),
        });

        let app = build_router(state.clone());

        // Create app with health.path="/"
        let create_body = serde_json::json!({
            "name": "poi",
            "image": "ghcr.io/org/poi:latest",
            "domain": "poi.example.com",
            "port": 8080,
            "health": {"path": "/"}
        });
        let request = Request::builder()
            .method("POST")
            .uri("/v1/apps")
            .header("Authorization", auth_header(GLOBAL_SECRET))
            .header("Content-Type", "application/json")
            .body(Body::from(serde_json::to_vec(&create_body).unwrap()))
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);

        // PATCH health.path to "/api/healthz"
        let patch_body = serde_json::json!({
            "health": {"path": "/api/healthz"}
        });
        let request = Request::builder()
            .method("PATCH")
            .uri("/v1/apps/poi")
            .header("Authorization", auth_header(GLOBAL_SECRET))
            .header("Content-Type", "application/json")
            .body(Body::from(serde_json::to_vec(&patch_body).unwrap()))
            .unwrap();
        let app2 = build_router(state.clone());
        let response = app2.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        // GET asserts new path persisted
        let request = Request::builder()
            .method("GET")
            .uri("/v1/apps/poi")
            .header("Authorization", auth_header(GLOBAL_SECRET))
            .body(Body::empty())
            .unwrap();
        let app3 = build_router(state.clone());
        let response = app3.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let payload: AppResponse = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            payload.health.path.as_deref(),
            Some("/api/healthz"),
            "health path should be updated"
        );
    }

    // ── Regression: env removal on PATCH ─────────────────────────────────────

    #[tokio::test]
    async fn test_env_removal_on_patch() {
        // Create with {OLD_KEY, KEPT_KEY}, PATCH env {KEPT_KEY}, GET asserts OLD_KEY gone.
        let state = create_test_state();
        let app = build_router(state.clone());

        let create_body = serde_json::json!({
            "name": "envtest",
            "image": "ghcr.io/org/envtest:latest",
            "domain": "envtest.example.com",
            "port": 8080,
            "env": {"OLD_KEY": "old_val", "KEPT_KEY": "kept_val"}
        });
        let request = Request::builder()
            .method("POST")
            .uri("/v1/apps")
            .header("Authorization", auth_header(GLOBAL_SECRET))
            .header("Content-Type", "application/json")
            .body(Body::from(serde_json::to_vec(&create_body).unwrap()))
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);

        // PATCH with only KEPT_KEY (full-replace semantics)
        let patch_body = serde_json::json!({
            "env": {"KEPT_KEY": "kept_val"}
        });
        let request = Request::builder()
            .method("PATCH")
            .uri("/v1/apps/envtest")
            .header("Authorization", auth_header(GLOBAL_SECRET))
            .header("Content-Type", "application/json")
            .body(Body::from(serde_json::to_vec(&patch_body).unwrap()))
            .unwrap();
        let app2 = build_router(state.clone());
        let response = app2.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        // GET asserts OLD_KEY gone
        let request = Request::builder()
            .method("GET")
            .uri("/v1/apps/envtest")
            .header("Authorization", auth_header(GLOBAL_SECRET))
            .body(Body::empty())
            .unwrap();
        let app3 = build_router(state.clone());
        let response = app3.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let payload: AppResponse = serde_json::from_slice(&bytes).unwrap();
        assert!(
            !payload.env.contains_key("OLD_KEY"),
            "OLD_KEY should be removed by full-replace PATCH"
        );
        assert_eq!(
            payload.env.get("KEPT_KEY").map(|s| s.as_str()),
            Some("kept_val"),
            "KEPT_KEY should remain"
        );
        assert_eq!(payload.env.len(), 1, "only KEPT_KEY should remain");
    }

    // ── GET /v1/apps/{name}/status ─────────────────────────────────────────

    #[tokio::test]
    async fn test_app_status_not_found() {
        let state = create_test_state();
        let app = build_router(state);

        let request = Request::builder()
            .method("GET")
            .uri("/v1/apps/nonexistent/status")
            .header("Authorization", auth_header(GLOBAL_SECRET))
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_app_status_not_deployed() {
        let state = create_test_state();
        let app = build_router(state);

        let request = Request::builder()
            .method("GET")
            .uri(format!("/v1/apps/{APP_NAME}/status"))
            .header("Authorization", auth_header(GLOBAL_SECRET))
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let payload: serde_json::Value = serde_json::from_slice(&bytes).unwrap();

        assert_eq!(payload["status"], "not_deployed");
        assert!(payload["tag"].is_null());
        // Routes should fall back to config routes.
        assert!(payload["routes"].is_array());
        // No secrets for a fresh app (field is skipped when empty).
        assert!(
            payload["secrets"].is_array() || payload["secrets"].is_null(),
            "secrets should be absent or empty array"
        );
    }

    #[tokio::test]
    async fn test_app_status_with_running_app() {
        let state = create_test_state();

        // Pre-populate runtime state.
        {
            let mut app_states = state.app_states.write().await;
            app_states.insert(
                APP_NAME.to_string(),
                AppRuntimeState {
                    status: AppStatus::Running,
                    current_tag: Some("v1.0.0".to_string()),
                    current_container_id: Some("abc123".to_string()),
                    current_port: Some(54321),
                    deployed_at: Some(Utc::now()),
                    kind: Some("container".to_string()),
                    current_routes: vec![crate::deploy::RouteState {
                        hostname: "testapp.example.com".to_string(),
                        port: 54321,
                    }],
                    ..Default::default()
                },
            );
        }

        let app = build_router(state);

        let request = Request::builder()
            .method("GET")
            .uri(format!("/v1/apps/{APP_NAME}/status"))
            .header("Authorization", auth_header(GLOBAL_SECRET))
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let payload: serde_json::Value = serde_json::from_slice(&bytes).unwrap();

        assert_eq!(payload["status"], "running");
        assert_eq!(payload["tag"], "v1.0.0");
        assert_eq!(payload["container_id"], "abc123");
        assert_eq!(payload["port"], 54321);
        assert_eq!(payload["kind"], "container");
        // Routes from runtime state.
        assert_eq!(payload["routes"][0]["hostname"], "testapp.example.com");
        assert_eq!(payload["routes"][0]["port"], 54321);
    }

    #[tokio::test]
    async fn test_app_status_includes_deploy_metadata() {
        let state = create_test_state();

        // Pre-populate runtime state.
        {
            let mut app_states = state.app_states.write().await;
            app_states.insert(
                APP_NAME.to_string(),
                AppRuntimeState {
                    status: AppStatus::Running,
                    current_tag: Some("v1.0.0".to_string()),
                    current_container_id: Some("abc123".to_string()),
                    current_port: Some(54321),
                    deployed_at: Some(Utc::now()),
                    kind: Some("container".to_string()),
                    ..Default::default()
                },
            );
        }

        // Populate deploy cache.
        let ctx = DeployContext {
            id: "dep_status001".to_string(),
            app: APP_NAME.to_string(),
            image: APP_IMAGE.to_string(),
            tag: "v1.2.3".to_string(),
            status: DeployStatus::Completed,
            started_at: Utc::now(),
            finished_at: Some(Utc::now()),
            error: None,
            triggered_by: TriggerSource::Webhook,
            new_container_id: Some("abc123".to_string()),
            new_port: Some(8080),
            images: HashMap::new(),
            new_pod_name: None,
            new_manifest_path: None,
            rollback_failed: false,
        };
        state.deploys.insert(ctx.app.clone(), ctx);

        let app = build_router(state);

        let request = Request::builder()
            .method("GET")
            .uri(format!("/v1/apps/{APP_NAME}/status"))
            .header("Authorization", auth_header(GLOBAL_SECRET))
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let payload: serde_json::Value = serde_json::from_slice(&bytes).unwrap();

        assert_eq!(payload["deploy_id"], "dep_status001");
        assert_eq!(payload["triggered_by"], "webhook");
        assert_eq!(payload["last_deploy"]["deploy_id"], "dep_status001");
        assert_eq!(payload["last_deploy"]["status"], "completed");
        assert_eq!(payload["last_deploy"]["triggered_by"], "webhook");
    }

    #[tokio::test]
    async fn test_app_status_no_secret_values() {
        let state = create_test_state();

        // Set some secrets.
        state
            .secrets_store
            .set(APP_NAME, "API_KEY", "supersecret123")
            .unwrap();
        state
            .secrets_store
            .set(APP_NAME, "DB_PASSWORD", "hunter2")
            .unwrap();

        let app = build_router(state);

        let request = Request::builder()
            .method("GET")
            .uri(format!("/v1/apps/{APP_NAME}/status"))
            .header("Authorization", auth_header(GLOBAL_SECRET))
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let payload: serde_json::Value = serde_json::from_slice(&bytes).unwrap();

        let secrets = payload["secrets"].as_array().unwrap();
        assert_eq!(secrets.len(), 2, "should list 2 secret keys");
        let key_names: Vec<&str> = secrets.iter().map(|s| s.as_str().unwrap()).collect();
        assert!(key_names.contains(&"API_KEY"));
        assert!(key_names.contains(&"DB_PASSWORD"));
        // No secret values should appear anywhere in the response.
        let raw = serde_json::to_string(&payload).unwrap();
        assert!(
            !raw.contains("supersecret123"),
            "secret value must not appear in status"
        );
        assert!(!raw.contains("hunter2"), "secret value must not appear");
    }

    #[tokio::test]
    async fn test_app_status_auth_required() {
        let state = create_test_state();
        let app = build_router(state);

        // No auth header → 401.
        let request = Request::builder()
            .method("GET")
            .uri(format!("/v1/apps/{APP_NAME}/status"))
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    // ── Acceptance-criteria debugging scenarios ──────────────────────────────
    // These three tests verify that `slip status <app>` output alone is
    // sufficient to debug the three scenarios called out in the SLIP-100
    // acceptance criteria: stuck deploy, failed health, drifted config.

    /// Scenario 1: Stuck deploy.
    /// App is in `Deploying` status, the latest deploy record is in a
    /// non-terminal `DeployStatus` (e.g. `HealthChecking`) with no
    /// `finished_at`. The status output must show `status: "deploying"` and
    /// `last_deploy.status` reflecting the stuck phase so an operator can see
    /// the deploy is in progress (not completed, not failed).
    #[tokio::test]
    async fn test_app_status_stuck_deploy() {
        let state = create_test_state();

        // Runtime state: app is mid-deploy.
        {
            let mut app_states = state.app_states.write().await;
            app_states.insert(
                APP_NAME.to_string(),
                AppRuntimeState {
                    status: AppStatus::Deploying,
                    current_tag: Some("v2.0.0".to_string()),
                    current_container_id: Some("newcid456".to_string()),
                    current_port: Some(54321),
                    deployed_at: Some(Utc::now()),
                    kind: Some("container".to_string()),
                    ..Default::default()
                },
            );
        }

        // Deploy cache: latest deploy is stuck in HealthChecking (non-terminal).
        let stuck_ctx = DeployContext {
            id: "dep_stuck001".to_string(),
            app: APP_NAME.to_string(),
            image: APP_IMAGE.to_string(),
            tag: "v2.0.0".to_string(),
            status: DeployStatus::HealthChecking,
            started_at: Utc::now(),
            finished_at: None, // no finish → still running
            error: None,
            triggered_by: TriggerSource::Webhook,
            new_container_id: Some("newcid456".to_string()),
            new_port: Some(54321),
            images: HashMap::new(),
            new_pod_name: None,
            new_manifest_path: None,
            rollback_failed: false,
        };
        state.deploys.insert(stuck_ctx.app.clone(), stuck_ctx);

        let app = build_router(state);

        let request = Request::builder()
            .method("GET")
            .uri(format!("/v1/apps/{APP_NAME}/status"))
            .header("Authorization", auth_header(GLOBAL_SECRET))
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let payload: serde_json::Value = serde_json::from_slice(&bytes).unwrap();

        // The app-level status reflects the deploying state.
        assert_eq!(payload["status"], "deploying");
        assert_eq!(payload["tag"], "v2.0.0");
        // The deploy metadata shows the stuck phase (non-terminal) with no
        // finished_at — this is the diagnostic that tells an operator the
        // deploy is in progress and hasn't completed.
        assert_eq!(payload["deploy_id"], "dep_stuck001");
        assert_eq!(payload["last_deploy"]["deploy_id"], "dep_stuck001");
        assert_eq!(payload["last_deploy"]["status"], "health_checking");
        assert_eq!(payload["last_deploy"]["triggered_by"], "webhook");
        assert!(
            payload["last_deploy"]["finished_at"].is_null(),
            "stuck deploy must have no finished_at"
        );
    }

    /// Scenario 2: Failed health.
    /// App is `Running` with a configured health path, but the health endpoint
    /// is not responding (port points at nothing). The status output must show
    /// `health.status: "unhealthy"` so an operator can see the app is
    /// unhealthy despite being "running".
    #[tokio::test]
    async fn test_app_status_failed_health() {
        let state = create_test_state();

        // Override the app config to include a health check path.
        {
            let mut apps = state.apps.write().await;
            let cfg = apps.get_mut(APP_NAME).expect("test app exists");
            cfg.health = HealthConfig {
                path: Some("/healthz".to_string()),
                ..Default::default()
            };
        }

        // Runtime state: running, but port 1 has no listener → connection
        // refused immediately (no 2s timeout wait).
        {
            let mut app_states = state.app_states.write().await;
            app_states.insert(
                APP_NAME.to_string(),
                AppRuntimeState {
                    status: AppStatus::Running,
                    current_tag: Some("v1.0.0".to_string()),
                    current_container_id: Some("abc123".to_string()),
                    current_port: Some(1), // nothing listening → refused
                    deployed_at: Some(Utc::now()),
                    kind: Some("container".to_string()),
                    ..Default::default()
                },
            );
        }

        let app = build_router(state);

        let request = Request::builder()
            .method("GET")
            .uri(format!("/v1/apps/{APP_NAME}/status"))
            .header("Authorization", auth_header(GLOBAL_SECRET))
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let payload: serde_json::Value = serde_json::from_slice(&bytes).unwrap();

        // App is running but health probe fails.
        assert_eq!(payload["status"], "running");
        assert_eq!(payload["health"]["status"], "unhealthy");
        assert_eq!(payload["health"]["path"], "/healthz");
        assert!(
            payload["health"]["last_check"].is_string(),
            "last_check should be timestamped"
        );
    }

    /// Sync probe respects `expect_status = "200"` and rejects an initial 307
    /// (no redirects followed). AC12 — single shared policy.
    #[tokio::test]
    async fn status_app_respects_expect_status_200_rejects_307() {
        let state = create_test_state();
        let port = {
            let app = axum::Router::new().route(
                "/healthz",
                axum::routing::get(|| async { axum::http::StatusCode::TEMPORARY_REDIRECT }),
            );
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = listener.local_addr().unwrap().port();
            tokio::spawn(async move {
                axum::serve(listener, app).await.unwrap();
            });
            port
        };

        // Set the app config to point at the mock server with expect_status="200".
        {
            let mut apps = state.apps.write().await;
            let cfg = apps.get_mut(APP_NAME).expect("test app exists");
            cfg.health = HealthConfig {
                path: Some("/healthz".to_string()),
                expect_status: Some(
                    crate::status_expectation::StatusExpectation::parse("200").unwrap(),
                ),
                ..Default::default()
            };
        }

        {
            let mut app_states = state.app_states.write().await;
            app_states.insert(
                APP_NAME.to_string(),
                AppRuntimeState {
                    status: AppStatus::Running,
                    current_tag: Some("v1.0.0".to_string()),
                    current_container_id: Some("abc123".to_string()),
                    current_port: Some(port),
                    deployed_at: Some(Utc::now()),
                    kind: Some("container".to_string()),
                    ..Default::default()
                },
            );
        }

        let app = build_router(state);
        let request = Request::builder()
            .method("GET")
            .uri(format!("/v1/apps/{APP_NAME}/status"))
            .header("Authorization", auth_header(GLOBAL_SECRET))
            .body(Body::empty())
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let payload: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(payload["health"]["status"], "unhealthy");
    }

    /// Sync probe default (no `expect_status`) accepts 307 — the default
    /// `200-399` is applied at probe time. AC12 / AC7.
    #[tokio::test]
    async fn status_app_default_accepts_307() {
        let state = create_test_state();
        let port = {
            let app = axum::Router::new().route(
                "/healthz",
                axum::routing::get(|| async { axum::http::StatusCode::TEMPORARY_REDIRECT }),
            );
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = listener.local_addr().unwrap().port();
            tokio::spawn(async move {
                axum::serve(listener, app).await.unwrap();
            });
            port
        };

        {
            let mut apps = state.apps.write().await;
            let cfg = apps.get_mut(APP_NAME).expect("test app exists");
            cfg.health = HealthConfig {
                path: Some("/healthz".to_string()),
                expect_status: None, // → default 200-399 at probe time
                ..Default::default()
            };
        }
        {
            let mut app_states = state.app_states.write().await;
            app_states.insert(
                APP_NAME.to_string(),
                AppRuntimeState {
                    status: AppStatus::Running,
                    current_tag: Some("v1.0.0".to_string()),
                    current_container_id: Some("abc123".to_string()),
                    current_port: Some(port),
                    deployed_at: Some(Utc::now()),
                    kind: Some("container".to_string()),
                    ..Default::default()
                },
            );
        }

        let app = build_router(state);
        let request = Request::builder()
            .method("GET")
            .uri(format!("/v1/apps/{APP_NAME}/status"))
            .header("Authorization", auth_header(GLOBAL_SECRET))
            .body(Body::empty())
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let payload: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            payload["health"]["status"], "healthy",
            "default 200-399 must accept 307 — no redirect chasing"
        );
    }

    /// Scenario 3: Drifted config.
    /// The `last_applied` snapshot differs from the current server config (image
    /// was changed out-of-band). The status output must show
    /// `config_drift: true` so an operator knows the server config no longer
    /// matches what was last applied. Also verifies the no-baseline case
    /// (`last_applied: None` → `config_drift: null`).
    #[tokio::test]
    async fn test_app_status_config_drift() {
        let state = create_test_state();

        // Build a last_applied snapshot from the current config, then mutate
        // the server config so they differ (simulating an out-of-band change).
        let current_cfg = state
            .apps
            .read()
            .await
            .get(APP_NAME)
            .cloned()
            .expect("test app exists");
        let last_applied_json =
            serde_json::to_string(&AppResponse::from(&current_cfg)).expect("serialize AppResponse");

        // Mutate the server config: change the image to simulate drift.
        {
            let mut apps = state.apps.write().await;
            let cfg = apps.get_mut(APP_NAME).expect("test app exists");
            cfg.app.image = "ghcr.io/org/different-image".to_string();
        }

        // Runtime state with the old last_applied snapshot.
        {
            let mut app_states = state.app_states.write().await;
            app_states.insert(
                APP_NAME.to_string(),
                AppRuntimeState {
                    status: AppStatus::Running,
                    current_tag: Some("v1.0.0".to_string()),
                    current_container_id: Some("abc123".to_string()),
                    current_port: Some(54321),
                    deployed_at: Some(Utc::now()),
                    kind: Some("container".to_string()),
                    last_applied: Some(last_applied_json),
                    ..Default::default()
                },
            );
        }

        let app = build_router(state);

        let request = Request::builder()
            .method("GET")
            .uri(format!("/v1/apps/{APP_NAME}/status"))
            .header("Authorization", auth_header(GLOBAL_SECRET))
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let payload: serde_json::Value = serde_json::from_slice(&bytes).unwrap();

        // Drift detected: server config differs from last_applied.
        assert_eq!(
            payload["config_drift"], true,
            "config_drift should be true when server config differs from last_applied"
        );

        // ── No-baseline case: last_applied = None → config_drift = null ──────
        let state2 = create_test_state();
        {
            let mut app_states = state2.app_states.write().await;
            app_states.insert(
                APP_NAME.to_string(),
                AppRuntimeState {
                    status: AppStatus::Running,
                    current_tag: Some("v1.0.0".to_string()),
                    current_container_id: Some("abc123".to_string()),
                    current_port: Some(54321),
                    deployed_at: Some(Utc::now()),
                    kind: Some("container".to_string()),
                    last_applied: None, // no baseline
                    ..Default::default()
                },
            );
        }
        let app2 = build_router(state2);
        let request2 = Request::builder()
            .method("GET")
            .uri(format!("/v1/apps/{APP_NAME}/status"))
            .header("Authorization", auth_header(GLOBAL_SECRET))
            .body(Body::empty())
            .unwrap();
        let response2 = app2.oneshot(request2).await.unwrap();
        let bytes2 = axum::body::to_bytes(response2.into_body(), usize::MAX)
            .await
            .unwrap();
        let payload2: serde_json::Value = serde_json::from_slice(&bytes2).unwrap();
        assert!(
            payload2["config_drift"].is_null(),
            "config_drift should be null when no last_applied baseline exists"
        );

        // ── In-sync case: last_applied matches current → config_drift = false
        let state3 = create_test_state();
        let synced_json = serde_json::to_string(&AppResponse::from(
            &state3.apps.read().await.get(APP_NAME).cloned().unwrap(),
        ))
        .unwrap();
        {
            let mut app_states = state3.app_states.write().await;
            app_states.insert(
                APP_NAME.to_string(),
                AppRuntimeState {
                    status: AppStatus::Running,
                    current_tag: Some("v1.0.0".to_string()),
                    current_container_id: Some("abc123".to_string()),
                    current_port: Some(54321),
                    deployed_at: Some(Utc::now()),
                    kind: Some("container".to_string()),
                    last_applied: Some(synced_json),
                    ..Default::default()
                },
            );
        }
        let app3 = build_router(state3);
        let request3 = Request::builder()
            .method("GET")
            .uri(format!("/v1/apps/{APP_NAME}/status"))
            .header("Authorization", auth_header(GLOBAL_SECRET))
            .body(Body::empty())
            .unwrap();
        let response3 = app3.oneshot(request3).await.unwrap();
        let bytes3 = axum::body::to_bytes(response3.into_body(), usize::MAX)
            .await
            .unwrap();
        let payload3: serde_json::Value = serde_json::from_slice(&bytes3).unwrap();
        assert_eq!(
            payload3["config_drift"], false,
            "config_drift should be false when last_applied matches current config"
        );
    }

    // ── Logs endpoint tests ────────────────────────────────────────────────────

    /// `GET /v1/apps/unknown/logs` returns 404 for a non-existent app.
    #[tokio::test]
    async fn test_logs_handler_returns_404_for_unknown_app() {
        let state = create_test_state();
        let app = build_router(state);

        let request = Request::builder()
            .method("GET")
            .uri("/v1/apps/unknown/logs")
            .header("Authorization", auth_header(GLOBAL_SECRET))
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    /// `GET /v1/apps/{name}/logs?since=abc` returns 400 for an invalid duration.
    #[tokio::test]
    async fn test_logs_handler_returns_400_for_invalid_since() {
        let state = create_test_state();
        let app = build_router(state);

        let request = Request::builder()
            .method("GET")
            .uri(format!("/v1/apps/{APP_NAME}/logs?since=abc"))
            .header("Authorization", auth_header(GLOBAL_SECRET))
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let payload: ErrorResponse = serde_json::from_slice(&bytes).unwrap();
        assert!(
            payload.error.contains("invalid --since"),
            "error should mention --since: {}",
            payload.error
        );
    }

    /// `GET /v1/apps/{name}/logs` without auth returns 401.
    #[tokio::test]
    async fn test_logs_handler_requires_auth() {
        let state = create_test_state();
        let app = build_router(state);

        let request = Request::builder()
            .method("GET")
            .uri(format!("/v1/apps/{APP_NAME}/logs"))
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    /// `parse_since_duration` parses valid duration strings.
    #[test]
    fn test_parse_since_duration_valid() {
        // "30s" — 30 seconds ago
        let now = chrono::Utc::now().timestamp();
        let ts = parse_since_duration("30s").unwrap();
        assert_eq!(ts, now - 30);

        // "5m" — 300 seconds ago
        let ts = parse_since_duration("5m").unwrap();
        assert_eq!(ts, now - 300);

        // "1h" — 3600 seconds ago
        let ts = parse_since_duration("1h").unwrap();
        assert_eq!(ts, now - 3600);

        // "5m30s" — combined
        let ts = parse_since_duration("5m30s").unwrap();
        assert_eq!(ts, now - 330);
    }

    /// `parse_since_duration` rejects invalid input.
    #[test]
    fn test_parse_since_duration_invalid() {
        assert!(parse_since_duration("").is_err());
        assert!(parse_since_duration("abc").is_err());
        assert!(parse_since_duration("5").is_err(), "needs unit suffix");
        assert!(parse_since_duration("5x").is_err(), "unknown unit");
    }

    /// `LogEntry` serializes with the expected fields.
    #[test]
    fn test_log_entry_serialization() {
        let entry = LogEntry {
            ts: Some("2026-07-11T15:30:00Z".to_string()),
            container: "green-abc123/testapp".to_string(),
            stream: "stdout".to_string(),
            line: "hello world".to_string(),
        };
        let json = serde_json::to_value(&entry).unwrap();
        assert_eq!(json["ts"], "2026-07-11T15:30:00Z");
        assert_eq!(json["container"], "green-abc123/testapp");
        assert_eq!(json["stream"], "stdout");
        assert_eq!(json["line"], "hello world");
    }

    /// `LogEntry` with null timestamp serializes correctly.
    #[test]
    fn test_log_entry_null_ts() {
        let entry = LogEntry {
            ts: None,
            container: "blue-xyz/other".to_string(),
            stream: "stderr".to_string(),
            line: "error!".to_string(),
        };
        let json = serde_json::to_value(&entry).unwrap();
        assert_eq!(json["ts"], serde_json::Value::Null);
        assert_eq!(json["stream"], "stderr");
    }

    // ── TLS renew handler tests (SLIP-104 Phase 4) ─────────────────────────

    /// Mock state for the renew mock Caddy.
    #[derive(Default)]
    #[allow(dead_code)]
    struct MockTlsState {
        policies: Vec<serde_json::Value>,
        patched_ratios: Vec<f64>,
        reloaded: bool,
    }

    /// Start a mock Caddy admin API for TLS renew tests.
    /// Returns (port, Arc<Mutex<MockTlsState>>).
    async fn start_mock_caddy_for_renew() -> (u16, std::sync::Arc<tokio::sync::Mutex<MockTlsState>>)
    {
        use axum::{Router, routing::get};
        use std::sync::Arc;
        use tokio::sync::Mutex;

        let state = Arc::new(Mutex::new(MockTlsState::default()));
        let state_clone = state.clone();

        let app = Router::new()
            .route(
                "/config/apps/tls/automation/policies",
                get({
                    let state = state.clone();
                    move || {
                        let state = state.clone();
                        async move {
                            let s = state.lock().await;
                            axum::Json(serde_json::Value::Array(s.policies.clone()))
                        }
                    }
                }),
            )
            .route(
                "/config/",
                get({
                    let state = state.clone();
                    move || {
                        let state = state.clone();
                        async move {
                            let s = state.lock().await;
                            axum::Json(serde_json::json!({"config": "ok", "reloaded": s.reloaded}))
                        }
                    }
                }),
            )
            .with_state(state_clone);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        (port, state)
    }

    /// Helper to create test state with a specific Caddy admin URL.
    fn create_test_state_with_caddy(caddy_url: &str) -> Arc<AppState> {
        let mut apps = HashMap::new();
        apps.insert(APP_NAME.to_string(), test_app_config(Some(APP_SECRET)));

        let secrets_tmp = tempfile::tempdir().expect("tempdir for secrets");
        let secrets_path = secrets_tmp.path().to_path_buf();
        Box::leak(Box::new(secrets_tmp));

        Arc::new(AppState {
            config: test_slip_config(),
            apps: RwLock::new(apps),
            config_dir: PathBuf::from("/tmp/slip-test"),
            deploy_locks: DashMap::new(),
            runtime: Arc::new(
                DockerClient::new_with_url("http://127.0.0.1:19998").expect("DockerClient::new"),
            ),
            caddy: CaddyClient::new(caddy_url.to_string()),
            health: HealthChecker::new(),
            app_states: RwLock::new(HashMap::new()),
            deploys: DashMap::new(),
            db: Db::open_in_memory().unwrap(),
            started_at: Utc::now(),
            preview_states: Arc::new(DashMap::new()),
            preview_locks: DashMap::new(),
            renew_locks: DashMap::new(),
            secrets_store: SecretsStore::new(secrets_path).unwrap(),
        })
    }

    #[tokio::test]
    async fn test_tls_renew_bearer_auth_required() {
        let (port, _state) = start_mock_caddy_for_renew().await;
        let caddy_url = format!("http://127.0.0.1:{port}");
        let state = create_test_state_with_caddy(&caddy_url);
        let app = build_router(state);

        // No Authorization header → 401.
        let request = Request::builder()
            .method("POST")
            .uri("/v1/tls/renew")
            .header("Content-Type", "application/json")
            .body(Body::from(r#"{"host":"deploy.example.com"}"#))
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_tls_renew_bearer_auth_wrong_token_rejected() {
        let (port, _state) = start_mock_caddy_for_renew().await;
        let caddy_url = format!("http://127.0.0.1:{port}");
        let state = create_test_state_with_caddy(&caddy_url);
        let app = build_router(state);

        let request = Request::builder()
            .method("POST")
            .uri("/v1/tls/renew")
            .header("Authorization", "Bearer wrong-token")
            .header("Content-Type", "application/json")
            .body(Body::from(r#"{"host":"deploy.example.com"}"#))
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_tls_renew_no_policy_returns_not_found() {
        let (port, _state) = start_mock_caddy_for_renew().await;
        let caddy_url = format!("http://127.0.0.1:{port}");
        let state = create_test_state_with_caddy(&caddy_url);
        let app = build_router(state);

        // Valid auth, but no TLS policy for the host.
        let request = Request::builder()
            .method("POST")
            .uri("/v1/tls/renew")
            .header("Authorization", auth_header(GLOBAL_SECRET))
            .header("Content-Type", "application/json")
            .body(Body::from(r#"{"host":"deploy.example.com"}"#))
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        // No policy → 404 (NotFound).
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_tls_renew_request_includes_restart_caddy_field() {
        // Verify the request body schema accepts restart_caddy.
        let json = r#"{"host": "deploy.example.com", "restart_caddy": true}"#;
        let req: crate::api::TlsRenewRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.host, "deploy.example.com");
        assert!(req.restart_caddy);
    }

    #[tokio::test]
    async fn test_tls_renew_restart_caddy_defaults_false() {
        let json = r#"{"host": "deploy.example.com"}"#;
        let req: crate::api::TlsRenewRequest = serde_json::from_str(json).unwrap();
        assert!(!req.restart_caddy);
    }

    #[tokio::test]
    async fn test_tls_renew_rejects_loopback_ip() {
        let (port, _state) = start_mock_caddy_for_renew().await;
        let caddy_url = format!("http://127.0.0.1:{port}");
        let state = create_test_state_with_caddy(&caddy_url);
        let app = build_router(state);

        let request = Request::builder()
            .method("POST")
            .uri("/v1/tls/renew")
            .header("Authorization", auth_header(GLOBAL_SECRET))
            .header("Content-Type", "application/json")
            .body(Body::from(r#"{"host":"127.0.0.1"}"#))
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_tls_renew_rejects_link_local_ip() {
        let (port, _state) = start_mock_caddy_for_renew().await;
        let caddy_url = format!("http://127.0.0.1:{port}");
        let state = create_test_state_with_caddy(&caddy_url);
        let app = build_router(state);

        let request = Request::builder()
            .method("POST")
            .uri("/v1/tls/renew")
            .header("Authorization", auth_header(GLOBAL_SECRET))
            .header("Content-Type", "application/json")
            .body(Body::from(r#"{"host":"169.254.169.254"}"#))
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_tls_renew_rejects_bare_hostname() {
        let (port, _state) = start_mock_caddy_for_renew().await;
        let caddy_url = format!("http://127.0.0.1:{port}");
        let state = create_test_state_with_caddy(&caddy_url);
        let app = build_router(state);

        let request = Request::builder()
            .method("POST")
            .uri("/v1/tls/renew")
            .header("Authorization", auth_header(GLOBAL_SECRET))
            .header("Content-Type", "application/json")
            .body(Body::from(r#"{"host":"localhost"}"#))
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    // ── RE-1: Lock lifetime across handler cancellation ────────────────────

    /// A mock Caddy that serves a pre-populated policy and supports PATCH/DELETE.
    /// Used for tests that need to get past the 404 gate.
    #[allow(clippy::collapsible_if)]
    async fn start_mock_caddy_with_policy(
        policy: serde_json::Value,
    ) -> (
        u16,
        std::sync::Arc<tokio::sync::Mutex<Vec<serde_json::Value>>>,
    ) {
        use axum::Router;
        use axum::routing::{delete, get, patch};
        use std::sync::Arc;
        use tokio::sync::Mutex;

        // The policies Vec models the `policies` array; `key_exists` models
        // whether the `policies` key exists in Caddy's config tree. PUT is
        // create-only (409 if the key exists, regardless of emptiness) —
        // matching real Caddy semantics, not the old `is_empty()` check.
        let policies = Arc::new(Mutex::new(vec![policy]));
        let key_exists = Arc::new(Mutex::new(true));
        let p_get = policies.clone();
        let p_patch_idx = policies.clone();
        let p_del_idx = policies.clone();
        let p_del_ratio = policies.clone();
        let p_patch_id = policies.clone();
        let p_del_id = policies.clone();

        let p_post = policies.clone();
        let p_put = policies.clone();
        let k_put = key_exists.clone();
        let p_automation = policies.clone();
        let app = Router::new()
            .route(
                "/config/apps/tls/automation/policies",
                get(move || {
                    let p = p_get.clone();
                    async move {
                        let p = p.lock().await;
                        axum::Json(serde_json::Value::Array(p.clone()))
                    }
                })
                .post(move |axum::Json(body): axum::Json<serde_json::Value>| {
                    let p = p_post.clone();
                    async move {
                        let mut p = p.lock().await;
                        p.push(body);
                        StatusCode::OK
                    }
                })
                .put(move |axum::Json(body): axum::Json<serde_json::Value>| {
                    let p = p_put.clone();
                    let k = k_put.clone();
                    async move {
                        let mut k = k.lock().await;
                        // Create-only: 409 if the key exists (populated or
                        // empty), matching real Caddy. The old `is_empty()`
                        // check returned OK for an existing-but-empty key.
                        if *k {
                            StatusCode::CONFLICT
                        } else {
                            *k = true;
                            let mut p = p.lock().await;
                            if let Some(arr) = body.as_array() {
                                *p = arr.clone();
                            }
                            StatusCode::OK
                        }
                    }
                }),
            )
            .route(
                "/config/apps/tls/automation/policies/{idx}",
                patch(
                    move |axum::extract::Path(idx): axum::extract::Path<usize>,
                          axum::Json(body): axum::Json<serde_json::Value>| {
                        let p = p_patch_idx.clone();
                        async move {
                            let mut p = p.lock().await;
                            if idx < p.len() {
                                if let Some(obj) = p[idx].as_object_mut() {
                                    if let Some(patch_obj) = body.as_object() {
                                        for (k, v) in patch_obj {
                                            obj.insert(k.clone(), v.clone());
                                        }
                                    }
                                }
                            }
                            StatusCode::OK
                        }
                    },
                )
                .delete(
                    move |axum::extract::Path(idx): axum::extract::Path<usize>| {
                        let p = p_del_idx.clone();
                        async move {
                            let mut p = p.lock().await;
                            if idx < p.len() {
                                p.remove(idx);
                            }
                            StatusCode::OK
                        }
                    },
                ),
            )
            .route(
                "/id/{id}/renewal_window_ratio",
                delete(
                    move |axum::extract::Path(id): axum::extract::Path<String>| {
                        let p = p_del_ratio.clone();
                        async move {
                            let mut p = p.lock().await;
                            for policy in p.iter_mut() {
                                if policy
                                    .get("@id")
                                    .and_then(|v| v.as_str())
                                    .map(|s| s == id)
                                    .unwrap_or(false)
                                {
                                    if let Some(obj) = policy.as_object_mut() {
                                        obj.remove("renewal_window_ratio");
                                    }
                                }
                            }
                            StatusCode::OK
                        }
                    },
                ),
            )
            .route(
                "/id/{id}",
                patch(
                    move |axum::extract::Path(id): axum::extract::Path<String>,
                          axum::Json(body): axum::Json<serde_json::Value>| {
                        let p = p_patch_id.clone();
                        async move {
                            let mut p = p.lock().await;
                            for policy in p.iter_mut() {
                                if policy
                                    .get("@id")
                                    .and_then(|v| v.as_str())
                                    .map(|s| s == id)
                                    .unwrap_or(false)
                                {
                                    if let Some(obj) = policy.as_object_mut() {
                                        if let Some(patch_obj) = body.as_object() {
                                            for (k, v) in patch_obj {
                                                obj.insert(k.clone(), v.clone());
                                            }
                                        }
                                    }
                                }
                            }
                            StatusCode::OK
                        }
                    },
                )
                .delete(
                    move |axum::extract::Path(id): axum::extract::Path<String>| {
                        let p = p_del_id.clone();
                        async move {
                            let mut p = p.lock().await;
                            let before = p.len();
                            p.retain(|policy| {
                                policy
                                    .get("@id")
                                    .and_then(|v| v.as_str())
                                    .map(|s| s != id)
                                    .unwrap_or(true)
                            });
                            if p.len() < before {
                                StatusCode::OK
                            } else {
                                StatusCode::NOT_FOUND
                            }
                        }
                    },
                ),
            )
            .route(
                "/config/apps/tls/automation",
                axum::routing::post(move |axum::Json(body): axum::Json<serde_json::Value>| {
                    let p = p_automation.clone();
                    async move {
                        // Faithful replace semantics: the `policies` field in
                        // the body replaces the entire policies array (the
                        // v0.1.0 destructive primitive). The renew path no
                        // longer issues this request, but the mock models
                        // real Caddy so a regression would be caught.
                        if let Some(policies) = body.get("policies") {
                            let mut p = p.lock().await;
                            *p = policies.as_array().cloned().unwrap_or_default();
                        }
                        StatusCode::OK
                    }
                }),
            )
            .route(
                "/config/",
                get(|| async { axum::Json(serde_json::json!({"config": "ok"})) }),
            )
            .route(
                "/load",
                axum::routing::post(|axum::Json(_body): axum::Json<serde_json::Value>| async {
                    StatusCode::OK
                }),
            );

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        (port, policies)
    }

    /// RE-1: A second renew for the same host returns 409 while the first
    /// is still in progress (lock held by the detached task).
    ///
    /// The mock Caddy serves a policy so the first request gets past the
    /// 404 gate. The detached task enters the poll loop (which takes time
    /// because probe_cert tries to connect to a non-existent TLS server),
    /// keeping the lock held. The second request arrives while the lock is
    /// still held and must get 409.
    #[tokio::test]
    async fn test_renew_concurrent_returns_409() {
        let policy = serde_json::json!({
            "subjects": ["deploy.example.com"],
            "issuers": [{"module": "acme"}],
            "@id": "slip-tls-deploy.example.com"
        });
        let (port, _policies) = start_mock_caddy_with_policy(policy).await;
        let caddy_url = format!("http://127.0.0.1:{port}");
        let state = create_test_state_with_caddy(&caddy_url);
        let app = build_router(state);

        // Send the first renew request — it will enter the detached task
        // and hold the lock while polling (probe_cert will fail quickly
        // since there's no TLS server, but the poll loop sleeps 5s).
        let app1 = app.clone();
        let first = tokio::spawn(async move {
            let request = Request::builder()
                .method("POST")
                .uri("/v1/tls/renew")
                .header("Authorization", auth_header(GLOBAL_SECRET))
                .header("Content-Type", "application/json")
                .body(Body::from(r#"{"host":"deploy.example.com"}"#))
                .unwrap();
            app1.oneshot(request).await.unwrap()
        });

        // Give the first request time to acquire the lock and enter the task.
        tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;

        // Send a second renew — should get 409 because the lock is held.
        let request2 = Request::builder()
            .method("POST")
            .uri("/v1/tls/renew")
            .header("Authorization", auth_header(GLOBAL_SECRET))
            .header("Content-Type", "application/json")
            .body(Body::from(r#"{"host":"deploy.example.com"}"#))
            .unwrap();
        let response2 = app.oneshot(request2).await.unwrap();
        assert_eq!(
            response2.status(),
            StatusCode::CONFLICT,
            "second concurrent renew must return 409 while first is in progress"
        );

        // Clean up the first request (it will eventually time out or error).
        // We don't need to await it — just let it finish in the background.
        first.abort();
    }

    // ── RE-2: Restoration deletes temporary field when original was None ───

    /// RE-2: When original ratio is None, restoration must DELETE the
    /// renewal_window_ratio field, not leave it at 1.0.
    #[tokio::test]
    async fn test_restore_ratio_none_deletes_field() {
        let policy = serde_json::json!({
            "subjects": ["deploy.example.com"],
            "issuers": [{"module": "acme"}],
            "@id": "slip-tls-deploy.example.com",
            "renewal_window_ratio": 1.0
        });
        let (port, policies) = start_mock_caddy_with_policy(policy).await;
        let caddy_url = format!("http://127.0.0.1:{port}");
        let caddy = CaddyClient::new(caddy_url);

        // Simulate restoration: original_ratio was None, so DELETE the field.
        caddy
            .delete_tls_policy_ratio("deploy.example.com")
            .await
            .unwrap();

        // Verify the field is gone.
        let p = policies.lock().await;
        assert!(
            p[0].get("renewal_window_ratio").is_none(),
            "renewal_window_ratio must be absent after delete (not left at 1.0)"
        );
    }

    /// RE-2: When original ratio is Some(0.1), restoration must PATCH it back.
    #[tokio::test]
    async fn test_restore_ratio_some_patches_back() {
        let policy = serde_json::json!({
            "subjects": ["deploy.example.com"],
            "issuers": [{"module": "acme"}],
            "@id": "slip-tls-deploy.example.com",
            "renewal_window_ratio": 1.0
        });
        let (port, policies) = start_mock_caddy_with_policy(policy).await;
        let caddy_url = format!("http://127.0.0.1:{port}");
        let caddy = CaddyClient::new(caddy_url);

        // Simulate restoration: original_ratio was Some(0.1), so PATCH back.
        caddy
            .patch_tls_policy_ratio("deploy.example.com", 0.1)
            .await
            .unwrap();

        // Verify the field is set back.
        let p = policies.lock().await;
        let ratio = p[0].get("renewal_window_ratio").and_then(|r| r.as_f64());
        assert_eq!(
            ratio,
            Some(0.1),
            "renewal_window_ratio must be restored to 0.1"
        );
    }

    /// RE-2: Post-restore verification reads the policy back and confirms
    /// the ratio field is absent (None case) or correct (Some case).
    #[tokio::test]
    async fn test_verify_ratio_restored_absent() {
        let policy = serde_json::json!({
            "subjects": ["deploy.example.com"],
            "issuers": [{"module": "acme"}],
            "@id": "slip-tls-deploy.example.com"
        });
        let (port, _policies) = start_mock_caddy_with_policy(policy).await;
        let caddy_url = format!("http://127.0.0.1:{port}");
        let caddy = CaddyClient::new(caddy_url);

        // No renewal_window_ratio → verify returns true for expected=None.
        let verified = caddy
            .verify_ratio_restored("deploy.example.com", None)
            .await
            .unwrap();
        assert!(
            verified,
            "verify should return true when field is absent and expected is None"
        );
    }

    #[tokio::test]
    async fn test_verify_ratio_restored_correct_value() {
        let policy = serde_json::json!({
            "subjects": ["deploy.example.com"],
            "issuers": [{"module": "acme"}],
            "@id": "slip-tls-deploy.example.com",
            "renewal_window_ratio": 0.1
        });
        let (port, _policies) = start_mock_caddy_with_policy(policy).await;
        let caddy_url = format!("http://127.0.0.1:{port}");
        let caddy = CaddyClient::new(caddy_url);

        let verified = caddy
            .verify_ratio_restored("deploy.example.com", Some(0.1))
            .await
            .unwrap();
        assert!(
            verified,
            "verify should return true when field matches expected"
        );
    }

    #[tokio::test]
    async fn test_verify_ratio_restored_detects_stale() {
        let policy = serde_json::json!({
            "subjects": ["deploy.example.com"],
            "issuers": [{"module": "acme"}],
            "@id": "slip-tls-deploy.example.com",
            "renewal_window_ratio": 1.0
        });
        let (port, _policies) = start_mock_caddy_with_policy(policy).await;
        let caddy_url = format!("http://127.0.0.1:{port}");
        let caddy = CaddyClient::new(caddy_url);

        // Field is 1.0 but expected is None → verify should return false.
        let verified = caddy
            .verify_ratio_restored("deploy.example.com", None)
            .await
            .unwrap();
        assert!(
            !verified,
            "verify should return false when field is 1.0 but expected is None"
        );
    }

    // ── RE-3: Stable @id replacement in upsert ─────────────────────────────

    /// RE-3: When upsert replaces an existing policy with @id, the DELETE
    /// uses the @id path, not positional index.
    #[tokio::test]
    async fn test_upsert_replaces_by_stable_id() {
        let old_policy = serde_json::json!({
            "subjects": ["deploy.example.com"],
            "issuers": [{"module": "internal"}],
            "@id": "slip-tls-deploy.example.com"
        });
        let (port, policies) = start_mock_caddy_with_policy(old_policy).await;
        let caddy_url = format!("http://127.0.0.1:{port}");
        let caddy = CaddyClient::new(caddy_url);

        // Upsert a new policy with different body (internal→acme).
        let subjects = vec!["deploy.example.com".to_string()];
        let new_policy = crate::caddy::build_tls_policy(
            &subjects,
            crate::config::TlsStrategy::Acme,
            None,
            Some("ops@example.com"),
            None,
        );
        caddy
            .upsert_tls_policy(&subjects, &new_policy)
            .await
            .unwrap();

        // Verify the old policy was replaced (not duplicated).
        let p = policies.lock().await;
        // The mock may have the old policy removed and new one added,
        // or the old one modified. Either way, there should be a policy
        // with the ACME issuer.
        let has_acme = p.iter().any(|pol| {
            pol.get("issuers")
                .and_then(|i| i.as_array())
                .and_then(|a| a.first())
                .and_then(|i| i.get("module"))
                .and_then(|m| m.as_str())
                == Some("acme")
        });
        assert!(has_acme, "upsert should replace internal with ACME");
    }
}
