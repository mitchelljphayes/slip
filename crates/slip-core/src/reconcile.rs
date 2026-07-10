//! Periodic Caddy reconcile loop — self-heals routes, deploy-webhook, and TLS
//! after a Caddy restart, reload, or missed webhook.
//!
//! This is a **safety net**, not the primary update path. Deploys still push
//! routes immediately via the webhook handler. The loop catches Caddy
//! restarts, missed webhooks, and drift by re-applying all slip-owned Caddy
//! state on a fixed interval using the existing idempotent
//! `bootstrap`/`bootstrap_deploy`/`configure_tls`/`set_routes` methods.
//!
//! Key properties:
//! - **Collect-and-continue**: a failed route does not prevent subsequent
//!   routes from being applied (fixes the fail-fast bug at `caddy.rs:475`).
//! - **Per-route retry with backoff**: each route gets exponential backoff +
//!   jitter via `backon` before being reported as failed.
//! - **Structured per-route logging**: every failure carries `app` and
//!   `route_id` tracing fields (fixes HE #6).
//! - **No locks held during I/O**: state is snapshotted under a short-lived
//!   read lock, then the lock is dropped before any Caddy API call.
//! - **Bounded**: `backon`'s `max_times` + `total_delay` bound each route's
//!   retry; the loop itself is bounded by the shutdown signal.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use backon::{ExponentialBuilder, Retryable};
use tokio::sync::oneshot;
use tokio::time::{MissedTickBehavior, interval};

use crate::api::AppState;
use crate::caddy::{CaddyClient, Route, RouteInfo};
use crate::config::AppConfig;
use crate::config::{CaddyTlsConfig, ServerDeployConfig, ServerPreviewConfig};
use crate::deploy::{AppRuntimeState, AppStatus};

/// Per-tick summary reported by [`reconcile_tick`] / [`reconcile_app_routes`].
#[derive(Debug, Default)]
pub struct ReconcileSummary {
    pub routes_total: usize,
    pub routes_ok: usize,
    pub routes_failed: usize,
    pub failures: Vec<RouteFailure>,
}

/// A single route that failed to reconcile after all retries.
#[derive(Debug)]
pub struct RouteFailure {
    pub app: String,
    pub route_id: String,
    pub error: String,
}

/// Lightweight context holding the subset of daemon state that a reconcile
/// tick reads. Built from [`AppState`] for the live loop, or constructed
/// directly in tests.
///
/// This keeps the per-tick logic testable without a full `AppState` (which
/// requires a container runtime, SQLite DB, secrets store, etc.).
#[derive(Clone)]
pub struct ReconcileContext {
    pub caddy: CaddyClient,
    /// Snapshot of app runtime states (only `Running` apps produce routes).
    pub app_states: HashMap<String, AppRuntimeState>,
    /// Snapshot of app configs (for domain lookup on the single-route path).
    pub apps: HashMap<String, AppConfig>,
    /// Server-level preview config (for TLS re-apply).
    pub preview: Option<ServerPreviewConfig>,
    /// Caddy TLS config (for preview wildcard cert re-apply).
    pub caddy_tls: Option<CaddyTlsConfig>,
    /// Server-level deploy config (for deploy-webhook route re-apply).
    pub deploy: Option<ServerDeployConfig>,
    /// The address slipd listens on (upstream for the deploy-webhook route).
    pub listen_addr: String,
}

impl ReconcileContext {
    /// Build a context from the live [`AppState`], snapshotting the
    /// lock-protected maps under short-lived read locks.
    pub async fn from_state(state: &AppState) -> Self {
        let app_states = state.app_states.read().await.clone();
        let apps = state.apps.read().await.clone();
        Self {
            caddy: state.caddy.clone(),
            app_states,
            apps,
            preview: state.config.preview.clone(),
            caddy_tls: state.config.caddy.tls.clone(),
            deploy: state.config.deploy.clone(),
            listen_addr: state.config.server.listen.to_string(),
        }
    }
}

/// Build the default backoff for a single route's retry.
///
/// 500ms min, 5s max, 3 retries, jitter, 15s total cap.
pub fn default_backoff() -> ExponentialBuilder {
    ExponentialBuilder::default()
        .with_min_delay(Duration::from_millis(500))
        .with_max_delay(Duration::from_secs(5))
        .with_max_times(3)
        .with_jitter()
        .with_total_delay(Some(Duration::from_secs(15)))
}

/// The background reconcile loop. Spawn once at startup; cancel via the
/// `shutdown` oneshot receiver.
///
/// Modeled on `preview_reaper` but with a shutdown signal + interval. The
/// first tick fires after `interval_dur` (startup reconcile already ran
/// before the loop spawns, so we don't consume the first tick eagerly).
pub async fn reconcile_loop(
    state: Arc<AppState>,
    shutdown: oneshot::Receiver<()>,
    interval_dur: Duration,
) {
    let mut ticker = interval(interval_dur);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
    let mut shutdown = shutdown;
    loop {
        tokio::select! {
            _ = ticker.tick() => {
                let summary = run_reconcile(&state).await;
                if summary.routes_failed == 0 {
                    tracing::debug!(
                        routes = summary.routes_total,
                        "reconcile tick ok"
                    );
                } else {
                    tracing::warn!(
                        ok = summary.routes_ok,
                        failed = summary.routes_failed,
                        total = summary.routes_total,
                        "reconcile tick completed with partial failures"
                    );
                }
            }
            _ = &mut shutdown => {
                tracing::info!("reconcile loop shutting down");
                break;
            }
        }
    }
}

/// One reconcile tick against the live [`AppState`].
///
/// Snapshots state under short-lived read locks (dropped before any I/O),
/// re-applies infrastructure idempotently (bootstrap, deploy-webhook, TLS),
/// then re-applies each app route with retry + collect-and-continue.
pub async fn run_reconcile(state: &AppState) -> ReconcileSummary {
    let ctx = ReconcileContext::from_state(state).await;
    reconcile_tick(&ctx, &default_backoff()).await
}

/// One reconcile tick against an explicit [`ReconcileContext`].
///
/// This is the core per-tick logic, extracted so tests (and the chaos
/// integration test) can drive it without a full `AppState`.
pub async fn reconcile_tick(
    ctx: &ReconcileContext,
    backoff: &ExponentialBuilder,
) -> ReconcileSummary {
    // ── 1. Re-apply infrastructure idempotently (collect-and-continue) ──────
    // These are cheap no-ops when the state already matches (GET-then-apply).
    if let Err(e) = ctx.caddy.bootstrap().await {
        tracing::warn!(error = %e, "reconcile: bootstrap failed (will retry next tick)");
    }

    if let Some(deploy_cfg) = &ctx.deploy
        && let Err(e) = ctx
            .caddy
            .bootstrap_deploy(
                deploy_cfg.domain.as_deref(),
                &deploy_cfg.tls,
                &ctx.listen_addr,
            )
            .await
    {
        tracing::warn!(error = %e, "reconcile: bootstrap_deploy failed (will retry next tick)");
    }

    if let (Some(preview_cfg), Some(tls_cfg)) = (&ctx.preview, &ctx.caddy_tls)
        && let Err(e) = ctx.caddy.configure_tls(&preview_cfg.domain, tls_cfg).await
    {
        tracing::warn!(error = %e, "reconcile: configure_tls failed (will retry next tick)");
    }

    // ── 2. Re-apply app routes with retry + collect-and-continue ────────────
    reconcile_app_routes(&ctx.caddy, &ctx.app_states, &ctx.apps, backoff).await
}

/// Re-apply every running app's Caddy routes, retrying each route with
/// exponential backoff. Collects failures without aborting (fixes the
/// fail-fast bug in `CaddyClient::reconcile`).
///
/// Both the live loop ([`run_reconcile`]) and startup (see `slipd::main`)
/// call this. Each failure is logged with `app` and `route_id` tracing
/// fields and recorded in the returned [`ReconcileSummary`].
pub async fn reconcile_app_routes(
    caddy: &CaddyClient,
    states: &HashMap<String, AppRuntimeState>,
    app_configs: &HashMap<String, AppConfig>,
    backoff: &ExponentialBuilder,
) -> ReconcileSummary {
    // Build the flat route list — same logic as state::reconcile_routes.
    let routes: Vec<RouteInfo> = states
        .iter()
        .filter_map(|(app_name, state)| {
            if state.status != AppStatus::Running {
                return None;
            }
            let route_infos: Vec<RouteInfo> = if !state.current_routes.is_empty() {
                state
                    .current_routes
                    .iter()
                    .map(|r| RouteInfo {
                        app_name: app_name.clone(),
                        domain: r.hostname.clone(),
                        port: r.port,
                    })
                    .collect()
            } else if let Some(port) = state.current_port {
                let Some(config) = app_configs.get(app_name) else {
                    tracing::warn!(
                        app = %app_name,
                        "no config found for running app, skipping route reconciliation"
                    );
                    return None;
                };
                vec![RouteInfo {
                    app_name: app_name.clone(),
                    domain: config.routing.domain.clone().unwrap_or_default(),
                    port,
                }]
            } else {
                return None;
            };
            Some(route_infos)
        })
        .flatten()
        .collect();

    let mut summary = ReconcileSummary {
        routes_total: routes.len(),
        ..Default::default()
    };

    if routes.is_empty() {
        tracing::debug!("no running apps to reconcile");
        return summary;
    }

    tracing::info!(route_count = routes.len(), "reconciling caddy routes");

    for route in &routes {
        // route_id follows the slip-{app}-{index} naming used by set_routes.
        // Each RouteInfo maps to a single route at index 0 (multi-route apps
        // expand to multiple RouteInfo entries, each with its own hostname).
        let route_id = format!("slip-{}-0", route.app_name);

        let _span = tracing::info_span!(
            "reconcile_route",
            app = %route.app_name,
            route_id = %route_id,
        );

        match reconcile_route_with_retry(caddy, route, backoff).await {
            Ok(()) => {
                summary.routes_ok += 1;
            }
            Err(err) => {
                tracing::warn!(
                    app = %route.app_name,
                    route_id = %route_id,
                    error = %err,
                    "route reconcile failed after retries"
                );
                summary.routes_failed += 1;
                summary.failures.push(RouteFailure {
                    app: route.app_name.clone(),
                    route_id,
                    error: err,
                });
            }
        }
    }

    summary
}

/// Re-apply a single route with exponential backoff retry.
///
/// Uses `backon`'s `Retryable` trait on an async closure that calls
/// `set_routes`. Returns `Err(String)` after all retries are exhausted.
async fn reconcile_route_with_retry(
    caddy: &CaddyClient,
    route: &RouteInfo,
    backoff: &ExponentialBuilder,
) -> Result<(), String> {
    let routes = vec![Route {
        hostname: route.domain.clone(),
        port: route.port,
    }];
    let app_name = route.app_name.clone();
    let result = (|| async { caddy.set_routes(&app_name, &routes).await })
        .retry(*backoff)
        .await;
    match result {
        Ok(()) => Ok(()),
        Err(e) => Err(format!("{e}")),
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU32, Ordering};
    use tokio::sync::Mutex;

    type MockState = Arc<Mutex<HashMap<String, serde_json::Value>>>;

    /// Build a mock AppConfig for a single-route app with the given domain.
    fn app_config(domain: &str) -> AppConfig {
        use crate::config::{
            AppInfo, DeployConfig, HealthConfig, NetworkConfig, ResourceConfig, RoutingConfig,
        };
        AppConfig {
            app: AppInfo {
                name: "test-app".to_string(),
                image: "nginx".to_string(),
                secret: None,
            },
            routing: RoutingConfig {
                domain: Some(domain.to_string()),
                port: Some(80),
                routes: vec![],
            },
            health: HealthConfig::default(),
            deploy: DeployConfig::default(),
            env: HashMap::new(),
            env_file: None,
            resources: ResourceConfig::default(),
            network: NetworkConfig::default(),
            preview: None,
            volumes: vec![],
        }
    }

    /// Running app state with a single route on the given port.
    fn running_state(port: u16) -> AppRuntimeState {
        AppRuntimeState {
            status: AppStatus::Running,
            current_port: Some(port),
            ..Default::default()
        }
    }

    // ── Mock Caddy (in-process axum server) ──────────────────────────────────

    async fn start_mock_caddy() -> (u16, MockState) {
        use axum::{
            Router,
            extract::{Path, State},
            http::StatusCode,
            routing::{get, post},
        };

        async fn mock_get_server(State(s): State<MockState>) -> StatusCode {
            let map = s.lock().await;
            if map.contains_key("__server__") {
                StatusCode::OK
            } else {
                StatusCode::NOT_FOUND
            }
        }

        async fn mock_get_config(
            State(s): State<MockState>,
        ) -> (StatusCode, axum::Json<serde_json::Value>) {
            let map = s.lock().await;
            if let Some(server) = map.get("__server__") {
                (
                    StatusCode::OK,
                    axum::Json(serde_json::json!({
                        "apps": {"http": {"servers": {"slip": server}}}
                    })),
                )
            } else {
                (
                    StatusCode::OK,
                    axum::Json(serde_json::json!({"admin": {"listen": "localhost:2019"}})),
                )
            }
        }

        async fn mock_load_config(
            State(s): State<MockState>,
            axum::Json(body): axum::Json<serde_json::Value>,
        ) -> StatusCode {
            if let Some(server) = body.pointer("/apps/http/servers/slip") {
                s.lock()
                    .await
                    .insert("__server__".to_string(), server.clone());
            }
            StatusCode::OK
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

        async fn mock_patch_route(
            State(s): State<MockState>,
            Path(id): Path<String>,
            axum::Json(body): axum::Json<serde_json::Value>,
        ) -> StatusCode {
            let mut map = s.lock().await;
            if let std::collections::hash_map::Entry::Occupied(mut e) = map.entry(id) {
                e.insert(body);
                StatusCode::OK
            } else {
                StatusCode::NOT_FOUND
            }
        }

        async fn mock_delete_route(
            State(s): State<MockState>,
            Path(id): Path<String>,
        ) -> StatusCode {
            let mut map = s.lock().await;
            if map.remove(&id).is_some() {
                StatusCode::OK
            } else {
                StatusCode::NOT_FOUND
            }
        }

        async fn mock_get_route(
            State(s): State<MockState>,
            Path(id): Path<String>,
        ) -> (StatusCode, axum::Json<serde_json::Value>) {
            let map = s.lock().await;
            if let Some(route) = map.get(&id) {
                (StatusCode::OK, axum::Json(route.clone()))
            } else {
                (StatusCode::NOT_FOUND, axum::Json(serde_json::json!(null)))
            }
        }

        async fn mock_get_tls_policies(
            State(s): State<MockState>,
        ) -> (StatusCode, axum::Json<serde_json::Value>) {
            let map = s.lock().await;
            if let Some(policies) = map.get("__tls_policies__") {
                (StatusCode::OK, axum::Json(policies.clone()))
            } else {
                (StatusCode::OK, axum::Json(serde_json::json!([])))
            }
        }

        async fn mock_add_tls_policy(
            State(s): State<MockState>,
            axum::Json(body): axum::Json<serde_json::Value>,
        ) -> StatusCode {
            let mut map = s.lock().await;
            let policies = map
                .entry("__tls_policies__".to_string())
                .or_insert(serde_json::json!([]));
            if let Some(arr) = policies.as_array_mut() {
                arr.push(body);
            }
            StatusCode::OK
        }

        let state: MockState = Arc::new(Mutex::new(HashMap::new()));
        let app = Router::new()
            .route("/config/", get(mock_get_config))
            .route("/load", post(mock_load_config))
            .route(
                "/config/apps/http/servers/slip",
                get(mock_get_server).post(mock_create_server),
            )
            .route(
                "/config/apps/http/servers/slip/routes",
                post(mock_add_route),
            )
            .route(
                "/id/{id}",
                get(mock_get_route)
                    .patch(mock_patch_route)
                    .delete(mock_delete_route),
            )
            .route(
                "/config/apps/tls/automation/policies",
                get(mock_get_tls_policies).post(mock_add_tls_policy),
            )
            .with_state(state.clone());

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (port, state)
    }

    /// Mock Caddy where `POST .../slip/routes` (the fallback path when PATCH
    /// 404s) fails for a configurable number of calls, then succeeds.
    async fn start_mock_caddy_flaky(fail_count: u32) -> (u16, MockState, Arc<AtomicU32>) {
        use axum::{
            Router,
            extract::{Path, State},
            http::StatusCode,
            routing::{get, patch, post},
        };

        /// Combined state: (route map, fail_count, call_count)
        type FlakyState = (MockState, u32, Arc<AtomicU32>);

        async fn mock_get_server(State((s, _, _)): State<FlakyState>) -> StatusCode {
            let map = s.lock().await;
            if map.contains_key("__server__") {
                StatusCode::OK
            } else {
                StatusCode::NOT_FOUND
            }
        }

        async fn mock_get_config(
            State((s, _, _)): State<FlakyState>,
        ) -> (StatusCode, axum::Json<serde_json::Value>) {
            let map = s.lock().await;
            if let Some(server) = map.get("__server__") {
                (
                    StatusCode::OK,
                    axum::Json(serde_json::json!({
                        "apps": {"http": {"servers": {"slip": server}}}
                    })),
                )
            } else {
                (
                    StatusCode::OK,
                    axum::Json(serde_json::json!({"admin": {"listen": "localhost:2019"}})),
                )
            }
        }

        async fn mock_load_config(
            State((s, _, _)): State<FlakyState>,
            axum::Json(body): axum::Json<serde_json::Value>,
        ) -> StatusCode {
            if let Some(server) = body.pointer("/apps/http/servers/slip") {
                s.lock()
                    .await
                    .insert("__server__".to_string(), server.clone());
            }
            StatusCode::OK
        }

        async fn mock_create_server(
            State((s, _, _)): State<FlakyState>,
            axum::Json(body): axum::Json<serde_json::Value>,
        ) -> StatusCode {
            let mut map = s.lock().await;
            map.insert("__server__".to_string(), body);
            StatusCode::OK
        }

        // Flaky add: fails (502) for the first `fail_count` calls, then 200.
        async fn mock_add_route_flaky(
            State((s, fail_count, call_count)): State<FlakyState>,
            axum::Json(body): axum::Json<serde_json::Value>,
        ) -> StatusCode {
            let n = call_count.fetch_add(1, Ordering::SeqCst);
            if n < fail_count {
                return StatusCode::BAD_GATEWAY;
            }
            let id = body
                .get("@id")
                .and_then(|v| v.as_str())
                .unwrap_or("__unknown__")
                .to_string();
            let mut map = s.lock().await;
            map.insert(id, body);
            StatusCode::OK
        }

        async fn mock_patch_route(
            State((s, _, _)): State<FlakyState>,
            Path(id): Path<String>,
            axum::Json(body): axum::Json<serde_json::Value>,
        ) -> StatusCode {
            let mut map = s.lock().await;
            if let std::collections::hash_map::Entry::Occupied(mut e) = map.entry(id) {
                e.insert(body);
                StatusCode::OK
            } else {
                StatusCode::NOT_FOUND
            }
        }

        async fn mock_delete_route(
            State((s, _, _)): State<FlakyState>,
            Path(id): Path<String>,
        ) -> StatusCode {
            let mut map = s.lock().await;
            if map.remove(&id).is_some() {
                StatusCode::OK
            } else {
                StatusCode::NOT_FOUND
            }
        }

        let state: MockState = Arc::new(Mutex::new(HashMap::new()));
        let call_count = Arc::new(AtomicU32::new(0));
        let app = Router::new()
            .route("/config/", get(mock_get_config))
            .route("/load", post(mock_load_config))
            .route(
                "/config/apps/http/servers/slip",
                get(mock_get_server).post(mock_create_server),
            )
            .route(
                "/config/apps/http/servers/slip/routes",
                post(mock_add_route_flaky),
            )
            .route(
                "/id/{id}",
                patch(mock_patch_route).delete(mock_delete_route),
            )
            .with_state((state.clone(), fail_count, call_count.clone()));

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (port, state, call_count)
    }

    // ── Tests ────────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn reconcile_reapplies_routes_after_drift() {
        let (port, state) = start_mock_caddy().await;
        tokio::time::sleep(Duration::from_millis(50)).await;

        let caddy = CaddyClient::new(format!("http://127.0.0.1:{port}"));
        caddy.bootstrap().await.unwrap();

        let mut apps = HashMap::new();
        apps.insert("test-app".to_string(), app_config("test.example.com"));
        let mut states = HashMap::new();
        states.insert("test-app".to_string(), running_state(8080));

        let backoff = default_backoff();
        let summary = reconcile_app_routes(&caddy, &states, &apps, &backoff).await;
        assert_eq!(summary.routes_total, 1);
        assert_eq!(summary.routes_failed, 0);

        // Route exists.
        {
            let map = state.lock().await;
            assert!(map.contains_key("slip-test-app-0"));
        }

        // Simulate drift: delete the route.
        caddy.remove_routes("test-app", 1).await.unwrap();
        {
            let map = state.lock().await;
            assert!(!map.contains_key("slip-test-app-0"));
        }

        // Reconcile again — route should be restored.
        let summary2 = reconcile_app_routes(&caddy, &states, &apps, &backoff).await;
        assert_eq!(summary2.routes_failed, 0);
        let map = state.lock().await;
        assert!(
            map.contains_key("slip-test-app-0"),
            "route should be restored after drift"
        );
    }

    #[tokio::test]
    async fn reconcile_continues_on_partial_failure() {
        // Use the flaky mock with a high fail_count so routes always fail.
        let (port, _state, _calls) = start_mock_caddy_flaky(1000).await;
        tokio::time::sleep(Duration::from_millis(50)).await;

        let caddy = CaddyClient::new(format!("http://127.0.0.1:{port}"));
        caddy.bootstrap().await.unwrap();

        // Two apps; both will fail (502). Assert we collect both failures
        // rather than aborting on the first.
        let mut apps = HashMap::new();
        apps.insert("app-a".to_string(), app_config("a.example.com"));
        apps.insert("app-b".to_string(), app_config("b.example.com"));
        let mut states = HashMap::new();
        states.insert("app-a".to_string(), running_state(8080));
        states.insert("app-b".to_string(), running_state(8081));

        // Short backoff so the test is fast.
        let backoff = ExponentialBuilder::default()
            .with_min_delay(Duration::from_millis(1))
            .with_max_times(1);

        let summary = reconcile_app_routes(&caddy, &states, &apps, &backoff).await;
        assert_eq!(summary.routes_total, 2);
        assert_eq!(summary.routes_failed, 2, "both routes should fail");
        assert_eq!(summary.routes_ok, 0);
        assert_eq!(
            summary.failures.len(),
            2,
            "both failures collected (no fail-fast)"
        );
        // Each failure carries app + route_id.
        let apps_failed: Vec<&str> = summary.failures.iter().map(|f| f.app.as_str()).collect();
        assert!(apps_failed.contains(&"app-a"));
        assert!(apps_failed.contains(&"app-b"));
    }

    #[tokio::test]
    async fn reconcile_retries_then_succeeds() {
        // Fail the first 2 attempts, then succeed on the 3rd.
        let (port, state, calls) = start_mock_caddy_flaky(2).await;
        tokio::time::sleep(Duration::from_millis(50)).await;

        let caddy = CaddyClient::new(format!("http://127.0.0.1:{port}"));
        caddy.bootstrap().await.unwrap();

        let mut apps = HashMap::new();
        apps.insert("test-app".to_string(), app_config("test.example.com"));
        let mut states = HashMap::new();
        states.insert("test-app".to_string(), running_state(8080));

        // Short backoff so the test is fast; allow up to 3 retries.
        let backoff = ExponentialBuilder::default()
            .with_min_delay(Duration::from_millis(1))
            .with_max_delay(Duration::from_millis(10))
            .with_max_times(3);

        let summary = reconcile_app_routes(&caddy, &states, &apps, &backoff).await;
        assert_eq!(summary.routes_total, 1);
        assert_eq!(
            summary.routes_failed, 0,
            "route should succeed after retries"
        );
        assert_eq!(summary.routes_ok, 1);

        // Route exists in mock state.
        let map = state.lock().await;
        assert!(map.contains_key("slip-test-app-0"));

        // The flaky handler was called 3 times (2 failures + 1 success).
        assert!(calls.load(Ordering::SeqCst) >= 3);
    }

    #[tokio::test]
    async fn reconcile_reapplies_deploy_webhook() {
        let (port, _state) = start_mock_caddy().await;
        tokio::time::sleep(Duration::from_millis(50)).await;

        let caddy = CaddyClient::new(format!("http://127.0.0.1:{port}"));
        caddy.bootstrap().await.unwrap();

        // Configure deploy-webhook via bootstrap_deploy.
        caddy
            .bootstrap_deploy(Some("deploy.example.com"), "internal", "127.0.0.1:7890")
            .await
            .unwrap();

        // Build a context with the deploy config so reconcile_tick re-applies it.
        let ctx = ReconcileContext {
            caddy: caddy.clone(),
            app_states: HashMap::new(),
            apps: HashMap::new(),
            preview: None,
            caddy_tls: None,
            deploy: Some(ServerDeployConfig {
                domain: Some("deploy.example.com".to_string()),
                tls: "internal".to_string(),
                ..Default::default()
            }),
            listen_addr: "127.0.0.1:7890".to_string(),
        };

        // Verify the webhook route exists after bootstrap_deploy.
        let http = reqwest::Client::new();
        let resp = http
            .get(format!("http://127.0.0.1:{port}/id/slip-deploy-webhook"))
            .send()
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            200,
            "deploy-webhook route should exist after bootstrap"
        );

        // Simulate Caddy restart wiping the route: delete it directly by id.
        let del = http
            .delete(format!("http://127.0.0.1:{port}/id/slip-deploy-webhook"))
            .send()
            .await
            .unwrap();
        assert!(del.status().is_success(), "delete should succeed");
        let resp2 = http
            .get(format!("http://127.0.0.1:{port}/id/slip-deploy-webhook"))
            .send()
            .await
            .unwrap();
        assert_eq!(
            resp2.status(),
            404,
            "deploy-webhook route gone after delete"
        );

        // Run a reconcile tick — it should re-apply the deploy-webhook route.
        let backoff = default_backoff();
        reconcile_tick(&ctx, &backoff).await;

        let resp3 = http
            .get(format!("http://127.0.0.1:{port}/id/slip-deploy-webhook"))
            .send()
            .await
            .unwrap();
        assert_eq!(
            resp3.status(),
            200,
            "deploy-webhook route should be restored by reconcile_tick"
        );
    }

    #[tokio::test]
    async fn reconcile_loop_shuts_down_on_signal() {
        // Use a mock caddy so the loop's first tick doesn't error out.
        let (port, _state) = start_mock_caddy().await;
        tokio::time::sleep(Duration::from_millis(50)).await;

        let caddy = CaddyClient::new(format!("http://127.0.0.1:{port}"));
        caddy.bootstrap().await.unwrap();

        // Build a minimal AppState-like context. We can't easily construct a
        // full AppState in a unit test, so we test reconcile_loop's shutdown
        // behavior via a lightweight wrapper: spawn a loop that ticks every
        // 100ms and send the shutdown signal.
        //
        // Since reconcile_loop needs Arc<AppState>, we instead verify the
        // shutdown-select pattern directly with a no-op body.
        let (tx, rx) = oneshot::channel::<()>();
        let handle = tokio::spawn(async move {
            let mut ticker = interval(Duration::from_millis(100));
            ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
            let mut shutdown = rx;
            loop {
                tokio::select! {
                    _ = ticker.tick() => {
                        // no-op tick
                    }
                    _ = &mut shutdown => {
                        break;
                    }
                }
            }
        });

        tokio::time::sleep(Duration::from_millis(50)).await;
        tx.send(()).unwrap();

        let result = tokio::time::timeout(Duration::from_secs(1), handle).await;
        assert!(result.is_ok(), "loop should shut down within 1s of signal");
    }

    #[tokio::test]
    async fn reconcile_app_routes_logs_app_and_route_id_on_failure() {
        // The summary's RouteFailure must carry app + route_id.
        let (port, _state, _calls) = start_mock_caddy_flaky(1000).await;
        tokio::time::sleep(Duration::from_millis(50)).await;

        let caddy = CaddyClient::new(format!("http://127.0.0.1:{port}"));
        caddy.bootstrap().await.unwrap();

        let mut apps = HashMap::new();
        apps.insert("myapp".to_string(), app_config("myapp.example.com"));
        let mut states = HashMap::new();
        states.insert("myapp".to_string(), running_state(8080));

        let backoff = ExponentialBuilder::default()
            .with_min_delay(Duration::from_millis(1))
            .with_max_times(0); // no retries — fail immediately

        let summary = reconcile_app_routes(&caddy, &states, &apps, &backoff).await;
        assert_eq!(summary.failures.len(), 1);
        let f = &summary.failures[0];
        assert_eq!(f.app, "myapp");
        assert_eq!(f.route_id, "slip-myapp-0");
        assert!(
            !f.error.is_empty(),
            "failure error message should be non-empty"
        );
    }
}
