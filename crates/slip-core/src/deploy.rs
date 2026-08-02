//! Deploy orchestrator — the state machine that coordinates a full blue-green deploy.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

use crate::api::AppState;
use crate::caddy::ReverseProxy;
use crate::config::{AppConfig, SlipConfig};
use crate::db::Db;
use crate::error::HealthError;
use crate::health::HealthCheck;
use crate::runtime::RuntimeBackend;
use crate::state;

/// Format a [`HealthError`] into a SLIP-91 terminal-tagged reason string.
///
/// - `UnexpectedStatus` → `[health_unexpected_status] health check failed:
///   expected {expected}, got {actual} at {url} after {attempts} attempts`.
///   Carries no response bodies or headers (SLIP-103 D6).
/// - `Unhealthy` → `[health_check_failed] health check failed: {e}` (existing
///   behavior — transport/timeout failures, no response ever received).
///
/// Exit code stays 5 (`output::DEPLOY_FAILED`).
pub fn format_health_reason(e: &HealthError) -> String {
    match e {
        HealthError::UnexpectedStatus {
            expected,
            actual,
            url,
            attempts,
        } => format!(
            "[health_unexpected_status] health check failed: expected {expected}, \
             got {actual} at {url} after {attempts} attempts"
        ),
        HealthError::Unhealthy { .. } => {
            format!("[health_check_failed] health check failed: {e}")
        }
    }
}

// ─── Status types ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DeployStatus {
    Accepted,
    Pulling,
    /// Extracting and merging repo config from the image.
    Configuring,
    Starting,
    HealthChecking,
    Switching,
    /// Recreate: stopping old container (downtime begins).
    StoppingOld,
    /// Recreate: removing Caddy route during downtime.
    RemovingRoute,
    /// Recreate: rollback — restarting old container.
    RestartingOld,
    Completed,
    Failed,
}

impl<'de> serde::Deserialize<'de> for DeployStatus {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        match s.as_str() {
            "accepted" => Ok(Self::Accepted),
            "pulling" => Ok(Self::Pulling),
            "configuring" => Ok(Self::Configuring),
            "starting" => Ok(Self::Starting),
            "health_checking" => Ok(Self::HealthChecking),
            "switching" => Ok(Self::Switching),
            "stopping_old" => Ok(Self::StoppingOld),
            "removing_route" => Ok(Self::RemovingRoute),
            "restarting_old" => Ok(Self::RestartingOld),
            "completed" => Ok(Self::Completed),
            "failed" => Ok(Self::Failed),
            // Unknown variants from older persisted state map to Failed
            _ => Ok(Self::Failed),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TriggerSource {
    Webhook,
    Cli,
    Rollback,
}

// ─── Deploy context ───────────────────────────────────────────────────────────

/// All data describing a single deploy attempt.
#[derive(Debug, Clone, Serialize)]
pub struct DeployContext {
    pub id: String,
    pub app: String,
    pub image: String,
    pub tag: String,
    /// Optional per-container image overrides: container_name → full image reference.
    #[serde(default)]
    pub images: HashMap<String, String>,
    pub status: DeployStatus,
    pub started_at: DateTime<Utc>,
    pub finished_at: Option<DateTime<Utc>>,
    pub error: Option<String>,
    pub triggered_by: TriggerSource,
    pub new_container_id: Option<String>,
    pub new_port: Option<u16>,
    /// Pod name created during pod deploys (None for container deploys).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub new_pod_name: Option<String>,
    /// Path to the rendered manifest written during pod deploys.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub new_manifest_path: Option<PathBuf>,
    /// Set to true when rollback fails catastrophically (old container cannot be
    /// restarted and fallback from previous_tag also fails).
    #[serde(default)]
    pub rollback_failed: bool,
}

impl DeployContext {
    pub fn new(
        id: String,
        app: String,
        image: String,
        tag: String,
        triggered_by: TriggerSource,
    ) -> Self {
        Self {
            id,
            app,
            image,
            tag,
            images: HashMap::new(),
            status: DeployStatus::Accepted,
            started_at: Utc::now(),
            finished_at: None,
            error: None,
            triggered_by,
            new_container_id: None,
            new_port: None,
            new_pod_name: None,
            new_manifest_path: None,
            rollback_failed: false,
        }
    }

    /// Mark the deploy as failed, recording the error message and finish time.
    pub fn fail(&mut self, error: &str) {
        self.status = DeployStatus::Failed;
        self.finished_at = Some(Utc::now());
        self.error = Some(error.to_string());
        tracing::error!(
            deploy_id = %self.id,
            app = %self.app,
            error = error,
            "deploy failed"
        );
    }
}

// ─── Timeout resolution ────────────────────────────────────────────────────────

/// Resolve the effective deploy timeout for a production deploy.
///
/// Resolution order:
/// 1. Per-app `DeployConfig.timeout` (if `Some`)
/// 2. Server-level `[deploy].timeout` (if `Some`)
/// 3. Hardcoded default of 10 minutes
pub(crate) fn resolve_deploy_timeout(
    config: &crate::config::SlipConfig,
    app_config: &crate::config::DeployConfig,
) -> std::time::Duration {
    app_config
        .timeout
        .or_else(|| config.deploy.as_ref().map(|d| d.timeout))
        .unwrap_or_else(|| std::time::Duration::from_secs(600))
}

/// Resolve the effective deploy timeout for a preview deploy.
///
/// Resolution order:
/// 1. Per-app `DeployConfig.timeout` (if `Some`)
/// 2. Server-level `[deploy].preview_timeout` (if `Some`)
/// 3. Hardcoded default of 10 minutes
pub(crate) fn resolve_preview_timeout(
    config: &crate::config::SlipConfig,
    app_config: &crate::config::DeployConfig,
) -> std::time::Duration {
    app_config
        .timeout
        .or_else(|| config.deploy.as_ref().map(|d| d.preview_timeout))
        .unwrap_or_else(|| std::time::Duration::from_secs(600))
}

/// Format a duration for error messages, e.g. "10m0s".
pub(crate) fn format_duration(dur: std::time::Duration) -> String {
    let total_secs = dur.as_secs();
    let mins = total_secs / 60;
    let secs = total_secs % 60;
    format!("{mins}m{secs}s")
}

// ─── App runtime state
#[derive(Debug, Clone)]
pub struct RouteState {
    pub hostname: String,
    pub port: u16,
}

/// Runtime state for a single deployed app (current/previous container, port, etc.).
#[derive(Debug, Clone, Default)]
pub struct AppRuntimeState {
    pub status: AppStatus,
    pub current_tag: Option<String>,
    pub previous_tag: Option<String>,
    pub current_container_id: Option<String>,
    pub previous_container_id: Option<String>,
    pub current_port: Option<u16>,
    /// All current routes for this app (multi-route support).
    pub current_routes: Vec<RouteState>,
    pub deployed_at: Option<DateTime<Utc>>,
    pub deploy_id: Option<String>,
    /// Current pod name (for pod-mode deploys).
    pub current_pod_name: Option<String>,
    /// Path to the rendered manifest for the current pod (for pod-mode deploys).
    pub current_manifest_path: Option<PathBuf>,
    /// App kind: "container", "pod", or "worker".
    pub kind: Option<String>,
    /// The last applied config JSON (from `slip apply`), for drift detection.
    /// `None` when no apply has been recorded. Not serialized (only persisted
    /// via `PersistedAppState`).
    pub last_applied: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub enum AppStatus {
    #[default]
    NotDeployed,
    Running,
    Deploying,
    Failed,
}

// ─── Shared deploy state (subset of AppState) ────────────────────────────────

/// The parts of [`AppState`] that the deploy orchestrator needs, extracted so
/// the inner function can be tested with mock dependencies.
pub(crate) struct DeploySharedState<'a> {
    pub config: &'a SlipConfig,
    pub apps: &'a RwLock<HashMap<String, AppConfig>>,
    pub app_states: &'a RwLock<HashMap<String, AppRuntimeState>>,
    pub deploys: &'a DashMap<String, DeployContext>,
    /// Persistent deploy-history database. `Db` is `Arc`-backed, so cloning is cheap.
    pub db: Db,
    /// Merged registry table (TOML + store creds), built fresh per-deploy so
    /// `slip registry login` takes effect without a daemon restart. Resolved
    /// per-image at each pull via [`crate::registry::resolve_registry_credential`].
    pub registries: Vec<crate::registry::ResolvedRegistry>,
    pub secrets_store: Option<&'a crate::secrets::SecretsStore>,
}

// ─── Core orchestrator ────────────────────────────────────────────────────────

/// Execute a full blue-green deploy.
///
/// This function is designed to be called inside a `tokio::spawn`. It drives
/// the deploy state machine through: Pull → Start → Health Check → Switch →
/// Drain Old → Complete (or Fail at any step).
///
/// The deploy is wrapped in a configurable timeout. If the timeout fires, the
/// deploy is recorded as Failed and the deploy lock (held by the spawn caller)
/// is released when this function returns.
pub async fn execute_deploy(state: Arc<AppState>, mut ctx: DeployContext) {
    // Read app config and resolve timeout before building shared state.
    let app_name = ctx.app.clone();
    let app_config = state.apps.read().await.get(&app_name).cloned();
    let timeout_dur = app_config
        .as_ref()
        .map(|cfg| resolve_deploy_timeout(&state.config, &cfg.deploy))
        .unwrap_or_else(|| std::time::Duration::from_secs(600));

    let shared = DeploySharedState {
        config: &state.config,
        apps: &state.apps,
        app_states: &state.app_states,
        deploys: &state.deploys,
        db: state.db.clone(),
        registries: crate::registry::merged_registry_table(&state.config, &state.secrets_store),
        secrets_store: Some(&state.secrets_store),
    };

    let result = tokio::time::timeout(
        timeout_dur,
        execute_deploy_inner(
            shared,
            state.runtime.as_ref(),
            &state.caddy,
            &state.health,
            &mut ctx,
        ),
    )
    .await;

    match result {
        Ok(()) => {
            // Inner function handled success/failure recording internally.
        }
        Err(_elapsed) => {
            let msg = format!(
                "[health_check_timeout] deploy timed out after {} (health check never passed)",
                format_duration(timeout_dur)
            );
            ctx.fail(&msg);

            // SLIP-91: clean up the orphaned new container. The timeout killed
            // execute_deploy_inner before its own cleanup paths could run, so the
            // new (unhealthy) container is still running. Stop+remove it; leave the
            // old container serving (it was never touched).
            if let Some(ref id) = ctx.new_container_id {
                tracing::warn!(
                    container = %id,
                    app = %ctx.app,
                    "deploy timed out; cleaning up orphaned new container"
                );
                if let Err(e) = state.runtime.stop_and_remove(id).await {
                    tracing::error!(
                        container = %id,
                        error = %e,
                        "failed to clean up orphaned container after timeout"
                    );
                    // Don't fail the whole handler — the deploy is already failed.
                }
            }

            // Use `state` directly (NOT the borrowed `shared`) to avoid
            // holding the `'_` lifetime across the timeout boundary.
            state.deploys.insert(ctx.app.clone(), ctx.clone());
            if let Err(e) = state.db.insert_deploy(&ctx) {
                tracing::error!(
                    deploy_id = %ctx.id,
                    app = %ctx.app,
                    error = %e,
                    "failed to persist timed-out deploy to SQLite"
                );
            }
            set_app_failed(&state.app_states, &app_name);
        }
    }
}

/// Inner deploy state machine — generic over trait objects so it can be driven
/// from tests with mock implementations.
pub(crate) async fn execute_deploy_inner(
    shared: DeploySharedState<'_>,
    runtime: &dyn RuntimeBackend,
    caddy: &dyn ReverseProxy,
    health: &dyn HealthCheck,
    ctx: &mut DeployContext,
) {
    let app_name = ctx.app.clone();
    let app_config = match shared.apps.read().await.get(&app_name) {
        Some(cfg) => cfg.clone(),
        None => {
            ctx.fail(&format!(
                "[app_not_found] app '{}' not found in config",
                app_name
            ));
            record_deploy(&shared, ctx);
            set_app_failed(shared.app_states, &app_name);
            return;
        }
    };

    // Set app status to Deploying at the start
    {
        let mut states = shared.app_states.write().await;
        if let Some(app_state) = states.get_mut(&app_name) {
            app_state.status = AppStatus::Deploying;
        }
    }

    // ── PULL ─────────────────────────────────────────────────────────────────
    ctx.status = DeployStatus::Pulling;
    record_deploy(&shared, ctx);
    tracing::info!(
        app = %app_name,
        tag = %ctx.tag,
        deploy_id = %ctx.id,
        "pulling image"
    );

    if let Err(e) = runtime
        .pull_image(
            &ctx.image,
            &ctx.tag,
            crate::registry::resolve_registry_credential(&ctx.image, &shared.registries),
        )
        .await
    {
        ctx.fail(&format!("[pull_failed] image pull failed: {e}"));
        record_deploy(&shared, ctx);
        set_app_failed(shared.app_states, &app_name);
        return;
    }

    // Pull sidecar images from ctx.images (if any).
    for (container_name, full_ref) in &ctx.images {
        let (sidecar_image, sidecar_tag) = parse_image_ref(full_ref);
        tracing::info!(
            app = %app_name,
            container = %container_name,
            image = %sidecar_image,
            tag = %sidecar_tag,
            "pulling sidecar image"
        );
        if let Err(e) = runtime
            .pull_image(
                sidecar_image,
                sidecar_tag,
                crate::registry::resolve_registry_credential(full_ref, &shared.registries),
            )
            .await
        {
            ctx.fail(&format!(
                "[pull_failed] sidecar image pull failed for '{container_name}': {e}"
            ));
            record_deploy(&shared, ctx);
            set_app_failed(shared.app_states, &app_name);
            return;
        }
    }

    // ── EXTRACT + MERGE CONFIG ────────────────────────────────────────────────
    ctx.status = DeployStatus::Configuring;
    record_deploy(&shared, ctx);

    let merged = match runtime
        .extract_file(&ctx.image, &ctx.tag, "/slip/slip.toml")
        .await
    {
        Ok(Some(bytes)) => {
            tracing::info!(app = %app_name, "found repo config in image");
            match crate::repo_config::parse_repo_config(&bytes) {
                Ok(repo_config) => {
                    if repo_config.app.name != app_name {
                        ctx.fail(&format!(
                            "[config_mismatch] repo config app name '{}' does not match deploy app '{}'",
                            repo_config.app.name, app_name
                        ));
                        record_deploy(&shared, ctx);
                        set_app_failed(shared.app_states, &app_name);
                        return;
                    }
                    match crate::merge::merge_config(&app_config, &repo_config) {
                        Ok(merged) => Some(merged),
                        Err(e) => {
                            ctx.fail(&format!("[config_merge_failed] config merge failed: {e}"));
                            record_deploy(&shared, ctx);
                            set_app_failed(shared.app_states, &app_name);
                            return;
                        }
                    }
                }
                Err(e) => {
                    ctx.fail(&format!(
                        "[config_parse_failed] failed to parse repo config: {e}"
                    ));
                    record_deploy(&shared, ctx);
                    set_app_failed(shared.app_states, &app_name);
                    return;
                }
            }
        }
        Ok(None) => {
            tracing::debug!(app = %app_name, "no repo config in image, using server config only");
            None
        }
        Err(crate::error::RuntimeError::Unsupported(_)) => {
            tracing::debug!(
                app = %app_name,
                "extract_file not supported by runtime, using server config only"
            );
            None
        }
        Err(e) => {
            ctx.fail(&format!(
                "[config_extract_failed] failed to extract config from image: {e}"
            ));
            record_deploy(&shared, ctx);
            set_app_failed(shared.app_states, &app_name);
            return;
        }
    };

    // Use merged config if available, otherwise fall back to server-only config.
    let effective_config = match &merged {
        Some(m) => m.app.clone(),
        None => app_config.clone(),
    };

    // ── STRATEGY DISPATCH ────────────────────────────────────────────────────
    let env_vars = resolve_env_vars_for_app(&effective_config, shared.secrets_store, &app_name);

    // Determine if this is a pod or container deploy.
    let is_pod = merged.as_ref().map(|m| m.kind == "pod").unwrap_or(false);
    let is_worker = merged.as_ref().map(|m| m.kind == "worker").unwrap_or(false);

    // ── ROUTING GUARD ─────────────────────────────────────────────────────────
    // HTTP (non-worker) container apps must have a reachable route.
    if !is_worker {
        let has_routes = !effective_config.routing.routes.is_empty();
        let has_domain = effective_config
            .routing
            .domain
            .as_ref()
            .is_some_and(|d| !d.is_empty());
        let has_port = effective_config.routing.port.is_some_and(|p| p > 0);
        if !(has_routes || (has_domain && has_port)) {
            ctx.fail(
                "[routing_missing] HTTP app requires routing.domain+port or [[routing.routes]]",
            );
            record_deploy(&shared, ctx);
            set_app_failed(shared.app_states, &app_name);
            return;
        }
    }

    match effective_config.deploy.strategy.as_str() {
        "blue-green" => {
            if is_pod {
                execute_blue_green_deploy_pod(
                    &shared,
                    runtime,
                    caddy,
                    health,
                    ctx,
                    &effective_config,
                    &merged,
                    &env_vars,
                    &app_name,
                    is_worker,
                )
                .await;
            } else {
                execute_blue_green_deploy_container(
                    &shared,
                    runtime,
                    caddy,
                    health,
                    ctx,
                    &effective_config,
                    &merged,
                    &env_vars,
                    &app_name,
                    is_worker,
                )
                .await;
            }
        }
        "recreate" => {
            if is_pod {
                // TODO: implement recreate for pod path
                tracing::warn!(
                    app = %app_name,
                    "recreate strategy not yet implemented for pods, falling back to blue-green"
                );
                execute_blue_green_deploy_pod(
                    &shared,
                    runtime,
                    caddy,
                    health,
                    ctx,
                    &effective_config,
                    &merged,
                    &env_vars,
                    &app_name,
                    is_worker,
                )
                .await;
            } else {
                execute_recreate_deploy_container(
                    &shared,
                    runtime,
                    caddy,
                    health,
                    ctx,
                    &effective_config,
                    &merged,
                    &env_vars,
                    &app_name,
                    is_worker,
                )
                .await;
            }
        }
        other => {
            ctx.fail(&format!(
                "[unknown_strategy] unknown deploy strategy: {other}"
            ));
            record_deploy(&shared, ctx);
            set_app_failed(shared.app_states, &app_name);
            return;
        }
    }

    // ── COMPLETED ────────────────────────────────────────────────────────────
    if ctx.status != DeployStatus::Failed {
        ctx.status = DeployStatus::Completed;
        ctx.finished_at = Some(Utc::now());
        record_deploy(&shared, ctx);
        tracing::info!(
            app = %app_name,
            tag = %ctx.tag,
            deploy_id = %ctx.id,
            "deploy completed"
        );
    }
}

// ─── Blue-green deploy: container path ─────────────────────────────────────────

/// Execute a blue-green deploy for a single container.
///
/// Extracted from the original `execute_deploy_inner` — exact same logic,
/// no behavior changes.
#[allow(clippy::too_many_arguments)]
async fn execute_blue_green_deploy_container(
    shared: &DeploySharedState<'_>,
    runtime: &dyn RuntimeBackend,
    caddy: &dyn ReverseProxy,
    health: &dyn HealthCheck,
    ctx: &mut DeployContext,
    effective_config: &AppConfig,
    merged: &Option<crate::merge::MergedConfig>,
    env_vars: &[String],
    app_name: &str,
    is_worker: bool,
) {
    // ── START NEW ────────────────────────────────────────────────────────────
    ctx.status = DeployStatus::Starting;
    record_deploy(shared, ctx);

    // ── CONTAINER DEPLOY FLOW ─────────────────────────────────────────

    let container_volumes: Vec<crate::merge::MergedVolume> = merged
        .as_ref()
        .map(|m| m.volumes.clone())
        .unwrap_or_default();

    match runtime
        .create_and_start(
            app_name,
            &ctx.image,
            &ctx.tag,
            if is_worker {
                0
            } else {
                effective_config.routing.port.unwrap_or(0)
            },
            env_vars.to_vec(),
            &effective_config.network.name,
            &effective_config.resources,
            &container_volumes,
        )
        .await
    {
        Ok((container_id, port)) => {
            ctx.new_container_id = Some(container_id);
            if !is_worker {
                ctx.new_port = Some(port);
            }
            // Workers: current_port stays None
        }
        Err(e) => {
            ctx.fail(&format!(
                "[container_start_failed] container start failed: {e}"
            ));
            record_deploy(shared, ctx);
            set_app_failed(shared.app_states, app_name);
            return;
        }
    }

    // ── HEALTH CHECK ─────────────────────────────────────────────────
    ctx.status = DeployStatus::HealthChecking;
    record_deploy(shared, ctx);

    let new_port: u16;
    if is_worker {
        // Workers: use container_is_running() instead of HTTP health check
        new_port = 0;
        if let Some(ref id) = ctx.new_container_id {
            match runtime.container_is_running(id).await {
                Ok(true) => {}
                Ok(false) => {
                    tracing::error!(app = %app_name, container_id = %id, "worker container not running after start");
                    ctx.fail("[container_exited] worker container exited during start");
                    record_deploy(shared, ctx);
                    set_app_failed(shared.app_states, app_name);
                    return;
                }
                Err(e) => {
                    tracing::error!(app = %app_name, error = %e, "failed to verify worker container state");
                    ctx.fail(&format!(
                        "[container_state_failed] worker container state check failed: {e}"
                    ));
                    record_deploy(shared, ctx);
                    set_app_failed(shared.app_states, app_name);
                    return;
                }
            }
        }
    } else {
        new_port = match ctx.new_port {
            Some(port) => port,
            None => {
                ctx.fail("[internal_error] internal error: port not set after container start");
                record_deploy(shared, ctx);
                set_app_failed(shared.app_states, app_name);
                return;
            }
        };

        if let Err(e) = health.check(new_port, &effective_config.health).await {
            tracing::error!(app = %app_name, error = %e, "health check failed");
            if let Some(ref id) = ctx.new_container_id {
                let _ = runtime.stop_and_remove(id).await;
            }
            ctx.fail(&format_health_reason(&e));
            record_deploy(shared, ctx);
            set_app_failed(shared.app_states, app_name);
            return;
        }

        // Verify container is still running after health check wait
        // (container could have crashed during start_period wait)
        if let Some(ref id) = ctx.new_container_id {
            match runtime.container_is_running(id).await {
                Ok(true) => {}
                Ok(false) => {
                    tracing::error!(app = %app_name, container_id = %id, "container not running after health check");
                    ctx.fail("[container_exited] container exited during health check");
                    record_deploy(shared, ctx);
                    set_app_failed(shared.app_states, app_name);
                    return;
                }
                Err(e) => {
                    tracing::error!(app = %app_name, error = %e, "failed to verify container state");
                    ctx.fail(&format!(
                        "[container_state_failed] container state check failed: {e}"
                    ));
                    record_deploy(shared, ctx);
                    set_app_failed(shared.app_states, app_name);
                    return;
                }
            }
        }
    }

    // ── SWITCH ───────────────────────────────────────────────────────
    ctx.status = DeployStatus::Switching;
    record_deploy(shared, ctx);

    let old_container_id = {
        let states = shared.app_states.read().await;
        states
            .get(app_name)
            .and_then(|s| s.current_container_id.clone())
    };

    if !is_worker
        && let Err(e) = caddy
            .set_routes(
                app_name,
                &merged
                    .as_ref()
                    .map(|m| {
                        m.routes
                            .iter()
                            .map(|r| crate::caddy::Route {
                                hostname: r.hostname.clone(),
                                port: new_port,
                            })
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_else(|| {
                        vec![crate::caddy::Route {
                            hostname: effective_config.routing.domain.clone().unwrap_or_default(),
                            port: new_port,
                        }]
                    }),
            )
            .await
    {
        tracing::error!(app = %app_name, error = %e, "caddy route update failed");
        if let Some(ref id) = ctx.new_container_id {
            let _ = runtime.stop_and_remove(id).await;
        }
        ctx.fail(&format!("caddy route update failed: {e}"));
        record_deploy(shared, ctx);
        set_app_failed(shared.app_states, app_name);
        return;
    }

    // Update app runtime state
    let state_snapshot = {
        let mut states = shared.app_states.write().await;
        let app_state = states.entry(app_name.to_string()).or_default();
        app_state.previous_tag = app_state.current_tag.take();
        app_state.previous_container_id = app_state.current_container_id.take();
        app_state.current_tag = Some(ctx.tag.clone());
        app_state.current_container_id = ctx.new_container_id.clone();
        app_state.current_port = if is_worker { None } else { ctx.new_port };
        app_state.current_routes = merged
            .as_ref()
            .map(|m| {
                m.routes
                    .iter()
                    .map(|r| RouteState {
                        hostname: r.hostname.clone(),
                        port: new_port,
                    })
                    .collect()
            })
            .unwrap_or_default();
        app_state.deployed_at = Some(Utc::now());
        app_state.deploy_id = Some(ctx.id.clone());
        app_state.status = AppStatus::Running;
        app_state.kind = merged.as_ref().map(|m| m.kind.clone());
        app_state.clone()
    };

    // Persist state to disk (non-fatal)
    let state_dir = shared.config.storage.path.join("state");
    if let Err(e) = state::save_app_state(&state_dir, app_name, &state_snapshot) {
        tracing::warn!(app = %app_name, error = %e, "failed to persist app state (non-fatal)");
    }

    // ── DRAIN + STOP OLD ─────────────────────────────────────────────
    if let Some(old_id) = old_container_id {
        tracing::info!(app = %app_name, "draining old container");
        tokio::time::sleep(effective_config.deploy.drain_timeout).await;
        if let Err(e) = runtime.stop_and_remove(&old_id).await {
            tracing::warn!(
                app = %app_name,
                error = %e,
                "failed to stop old container (non-fatal)"
            );
        }
    }

    // ── COMPLETED ────────────────────────────────────────────────────────────
    ctx.status = DeployStatus::Completed;
    ctx.finished_at = Some(Utc::now());
    record_deploy(shared, ctx);
    tracing::info!(
        app = %app_name,
        tag = %ctx.tag,
        deploy_id = %ctx.id,
        "deploy completed"
    );
}

// ─── Blue-green deploy: pod path ───────────────────────────────────────────────

/// Execute a blue-green deploy for a pod.
///
/// Extracted from the original `execute_deploy_inner` — exact same logic,
/// no behavior changes.
#[allow(clippy::too_many_arguments)]
async fn execute_blue_green_deploy_pod(
    shared: &DeploySharedState<'_>,
    runtime: &dyn RuntimeBackend,
    caddy: &dyn ReverseProxy,
    health: &dyn HealthCheck,
    ctx: &mut DeployContext,
    effective_config: &AppConfig,
    merged: &Option<crate::merge::MergedConfig>,
    env_vars: &[String],
    app_name: &str,
    is_worker: bool,
) {
    // ── START NEW ────────────────────────────────────────────────────────────
    ctx.status = DeployStatus::Starting;
    record_deploy(shared, ctx);

    // Get the merged config — required for pod deploys.
    let merged_cfg = merged.as_ref().expect("merged is Some when is_pod is true");

    // Get the manifest path from repo config.
    let manifest_in_image = match &merged_cfg.manifest {
        Some(p) => p.clone(),
        None => {
            ctx.fail(
                "[manifest_missing] pod deploy requires [app].manifest in repo config (slip.toml)",
            );
            record_deploy(shared, ctx);
            set_app_failed(shared.app_states, app_name);
            return;
        }
    };

    // Extract pod.yaml (or custom path) from the image.
    let manifest_bytes = match runtime
        .extract_file(&ctx.image, &ctx.tag, &manifest_in_image)
        .await
    {
        Ok(Some(bytes)) => bytes,
        Ok(None) => {
            ctx.fail(&format!(
                "[manifest_not_found] manifest '{manifest_in_image}' not found in image"
            ));
            record_deploy(shared, ctx);
            set_app_failed(shared.app_states, app_name);
            return;
        }
        Err(e) => {
            ctx.fail(&format!(
                "[manifest_extract_failed] failed to extract manifest from image: {e}"
            ));
            record_deploy(shared, ctx);
            set_app_failed(shared.app_states, app_name);
            return;
        }
    };

    // Generate a unique pod suffix from a ULID fragment.
    let pod_suffix = ulid::Ulid::new().to_string()[..8].to_lowercase();
    let pod_name = format!("{app_name}-{pod_suffix}");

    // Render the manifest with deploy-time transformations.
    let has_workers = merged_cfg.routes.iter().any(|r| r.kind == "worker");
    let render_ctx = crate::manifest::RenderContext {
        app_name: app_name.to_string(),
        tag: ctx.tag.clone(),
        primary_image: effective_config.app.image.clone(),
        pod_suffix: pod_suffix.clone(),
        env_vars: env_vars.to_vec(),
        image_overrides: ctx.images.clone(),
        volumes: merged_cfg.volumes.clone(),
        has_workers,
    };

    let rendered_yaml = match crate::manifest::render_manifest(&manifest_bytes, &render_ctx) {
        Ok(yaml) => yaml,
        Err(e) => {
            ctx.fail(&format!(
                "[manifest_render_failed] failed to render manifest: {e}"
            ));
            record_deploy(shared, ctx);
            set_app_failed(shared.app_states, app_name);
            return;
        }
    };

    // Write rendered manifest to storage dir.
    let manifests_dir = shared.config.storage.path.join("manifests");
    if let Err(e) = std::fs::create_dir_all(&manifests_dir) {
        ctx.fail(&format!(
            "[manifest_dir_failed] failed to create manifests directory: {e}"
        ));
        record_deploy(shared, ctx);
        set_app_failed(shared.app_states, app_name);
        return;
    }
    let manifest_path = manifests_dir.join(format!("{app_name}-{}.yaml", ctx.id));
    if let Err(e) = std::fs::write(&manifest_path, &rendered_yaml) {
        ctx.fail(&format!(
            "[manifest_write_failed] failed to write manifest file: {e}"
        ));
        record_deploy(shared, ctx);
        set_app_failed(shared.app_states, app_name);
        return;
    }

    // Deploy the pod via `podman kube play`.
    if let Err(e) = runtime.deploy_pod(&manifest_path, &pod_name).await {
        ctx.fail(&format!("[pod_deploy_failed] pod deploy failed: {e}"));
        record_deploy(shared, ctx);
        set_app_failed(shared.app_states, app_name);
        return;
    }

    // Record pod name and manifest path in context for later steps.
    ctx.new_pod_name = Some(pod_name.clone());
    ctx.new_manifest_path = Some(manifest_path.clone());

    // ── PER-CONTAINER HEALTH CHECK (pod) ──────────────────────────────
    ctx.status = DeployStatus::HealthChecking;
    record_deploy(shared, ctx);

    if is_worker {
        // App-level worker: skip all health checks, pod was already verified as deployed
        tracing::info!(
            app = app_name,
            "worker pod deployed, skipping HTTP health check"
        );

        // Update app runtime state for worker pod.
        let state_snapshot = {
            let mut states = shared.app_states.write().await;
            let app_state = states.entry(app_name.to_string()).or_default();
            app_state.previous_tag = app_state.current_tag.take();
            app_state.current_tag = Some(ctx.tag.clone());
            app_state.current_pod_name = Some(pod_name.clone());
            app_state.current_manifest_path = Some(manifest_path.clone());
            app_state.current_port = None;
            app_state.current_routes = vec![];
            app_state.deployed_at = Some(Utc::now());
            app_state.deploy_id = Some(ctx.id.clone());
            app_state.status = AppStatus::Running;
            app_state.kind = merged.as_ref().map(|m| m.kind.clone());
            app_state.clone()
        };

        // Persist state to disk (non-fatal).
        let state_dir = shared.config.storage.path.join("state");
        if let Err(e) = state::save_app_state(&state_dir, app_name, &state_snapshot) {
            tracing::warn!(app = app_name, error = %e, "failed to persist app state (non-fatal)");
        }

        // ── DRAIN + TEARDOWN OLD POD ──────────────────────────────────
        let old_pod_manifest = {
            let states = shared.app_states.read().await;
            states
                .get(app_name)
                .and_then(|s| s.current_manifest_path.clone())
        };
        if let Some(old_manifest) = old_pod_manifest {
            tracing::info!(app = app_name, "draining old pod");
            tokio::time::sleep(effective_config.deploy.drain_timeout).await;
            if let Err(e) = runtime.teardown_pod(&old_manifest).await {
                tracing::warn!(
                    app = app_name,
                    error = %e,
                    "failed to teardown old pod (non-fatal)"
                );
            }
        }
    } else {
        // Iterate over routes and check per-container health.
        let mut http_route_ports: Vec<(String, u16)> = Vec::new();
        let mut any_http_failure = false;
        // Track the last health-check error so the deploy reason can carry the
        // structured `health_unexpected_status` detail when applicable.
        let mut last_http_error: Option<HealthError> = None;

        for route in &merged_cfg.routes {
            let container = route.container.as_deref().unwrap_or("web");
            let container_port = route.port;

            if route.kind == "worker" {
                // Worker containers: check container_is_running, warn on failure
                let container_name = format!("{pod_name}-{container}");
                tracing::info!(
                    app = app_name,
                    container = %container,
                    container_name = %container_name,
                    "checking worker container"
                );
                match runtime.container_is_running(&container_name).await {
                    Ok(true) => {
                        tracing::info!(
                            app = app_name,
                            container = %container,
                            "worker container is running"
                        );
                    }
                    Ok(false) => {
                        tracing::warn!(
                            app = app_name,
                            container = %container,
                            "worker container is not running (will be restarted by restartPolicy)"
                        );
                    }
                    Err(e) => {
                        tracing::warn!(
                            app = app_name,
                            container = %container,
                            error = %e,
                            "failed to check worker container state (non-fatal)"
                        );
                    }
                }
            } else {
                // HTTP containers: discover port and health check
                match runtime
                    .pod_container_port(&pod_name, container, container_port)
                    .await
                {
                    Ok(host_port) => {
                        tracing::info!(
                            app = app_name,
                            container = %container,
                            host_port = host_port,
                            "checking HTTP container health"
                        );
                        if let Err(e) = health.check(host_port, &effective_config.health).await {
                            tracing::error!(
                                app = app_name,
                                container = %container,
                                error = %e,
                                "HTTP health check failed"
                            );
                            last_http_error = Some(e);
                            any_http_failure = true;
                        } else {
                            http_route_ports.push((route.hostname.clone(), host_port));
                        }
                    }
                    Err(e) => {
                        tracing::error!(
                            app = app_name,
                            container = %container,
                            error = %e,
                            "failed to get container port"
                        );
                        any_http_failure = true;
                    }
                }
            }
        }

        // If any HTTP container failed, tear down and fail the deploy.
        if any_http_failure {
            if let Err(te) = runtime.teardown_pod(&manifest_path).await {
                tracing::warn!(app = app_name, error = %te, "failed to teardown pod after health check failure (non-fatal)");
            }
            let reason = match &last_http_error {
                Some(e) => format_health_reason(e),
                None => "[health_check_failed] health check failed for one or more HTTP containers"
                    .to_string(),
            };
            ctx.fail(&reason);
            record_deploy(shared, ctx);
            set_app_failed(shared.app_states, app_name);
            return;
        }

        // Record the first HTTP route port for backward compat.
        ctx.new_port = http_route_ports.first().map(|(_, p)| *p);

        // ── SWITCH (pod) ──────────────────────────────────────────────
        ctx.status = DeployStatus::Switching;
        record_deploy(shared, ctx);

        let old_pod_manifest = {
            let states = shared.app_states.read().await;
            states
                .get(app_name)
                .and_then(|s| s.current_manifest_path.clone())
        };

        // Set Caddy routes only for HTTP routes.
        if !http_route_ports.is_empty()
            && let Err(e) = caddy
                .set_routes(
                    app_name,
                    &http_route_ports
                        .iter()
                        .map(|(hostname, port)| crate::caddy::Route {
                            hostname: hostname.clone(),
                            port: *port,
                        })
                        .collect::<Vec<_>>(),
                )
                .await
        {
            tracing::error!(app = app_name, error = %e, "caddy route update failed");
            if let Err(te) = runtime.teardown_pod(&manifest_path).await {
                tracing::warn!(app = app_name, error = %te, "failed to teardown pod after caddy failure (non-fatal)");
            }
            ctx.fail(&format!(
                "[route_update_failed] caddy route update failed: {e}"
            ));
            record_deploy(shared, ctx);
            set_app_failed(shared.app_states, app_name);
            return;
        }

        // Update app runtime state for pod with per-route ports.
        let state_snapshot = {
            let mut states = shared.app_states.write().await;
            let app_state = states.entry(app_name.to_string()).or_default();
            app_state.previous_tag = app_state.current_tag.take();
            app_state.current_tag = Some(ctx.tag.clone());
            app_state.current_pod_name = Some(pod_name.clone());
            app_state.current_manifest_path = Some(manifest_path.clone());
            app_state.current_port = http_route_ports.first().map(|(_, p)| *p);
            app_state.current_routes = http_route_ports
                .iter()
                .map(|(hostname, port)| RouteState {
                    hostname: hostname.clone(),
                    port: *port,
                })
                .collect();
            app_state.deployed_at = Some(Utc::now());
            app_state.deploy_id = Some(ctx.id.clone());
            app_state.status = AppStatus::Running;
            app_state.kind = merged.as_ref().map(|m| m.kind.clone());
            app_state.clone()
        };

        // Persist state to disk (non-fatal).
        let state_dir = shared.config.storage.path.join("state");
        if let Err(e) = state::save_app_state(&state_dir, app_name, &state_snapshot) {
            tracing::warn!(app = app_name, error = %e, "failed to persist app state (non-fatal)");
        }

        // ── DRAIN + TEARDOWN OLD POD ──────────────────────────────────
        if let Some(old_manifest) = old_pod_manifest {
            tracing::info!(app = app_name, "draining old pod");
            tokio::time::sleep(effective_config.deploy.drain_timeout).await;
            if let Err(e) = runtime.teardown_pod(&old_manifest).await {
                tracing::warn!(
                    app = app_name,
                    error = %e,
                    "failed to teardown old pod (non-fatal)"
                );
            }
        }
    }

    // ── COMPLETED ────────────────────────────────────────────────────────────
    if ctx.status != DeployStatus::Failed {
        ctx.status = DeployStatus::Completed;
        ctx.finished_at = Some(Utc::now());
        record_deploy(shared, ctx);
        tracing::info!(
            app = %app_name,
            tag = %ctx.tag,
            deploy_id = %ctx.id,
            "deploy completed"
        );
    }
}

// ─── Recreate deploy: container path ────────────────────────────────────────────

/// Execute a recreate deploy for a single container.
///
/// Flow: stop old → remove route → start new → health check → set route →
/// update state → remove old → complete.
/// On failure: restart old (Tier 1), or create from previous_tag (Tier 2),
/// or mark rollback_failed (Tier 3).
#[allow(clippy::too_many_arguments)]
async fn execute_recreate_deploy_container(
    shared: &DeploySharedState<'_>,
    runtime: &dyn RuntimeBackend,
    caddy: &dyn ReverseProxy,
    health: &dyn HealthCheck,
    ctx: &mut DeployContext,
    effective_config: &AppConfig,
    merged: &Option<crate::merge::MergedConfig>,
    env_vars: &[String],
    app_name: &str,
    is_worker: bool,
) {
    let container_volumes: Vec<crate::merge::MergedVolume> = merged
        .as_ref()
        .map(|m| m.volumes.clone())
        .unwrap_or_default();

    // Read old container id from app state (if any).
    let old_container_id = {
        let states = shared.app_states.read().await;
        states
            .get(app_name)
            .and_then(|s| s.current_container_id.clone())
    };
    let old_tag = {
        let states = shared.app_states.read().await;
        states.get(app_name).and_then(|s| s.current_tag.clone())
    };

    // ── STEP 1: STOP OLD CONTAINER ──────────────────────────────────────────
    if let Some(ref old_id) = old_container_id {
        ctx.status = DeployStatus::StoppingOld;
        record_deploy(shared, ctx);
        tracing::info!(
            app = app_name,
            old_id = %old_id,
            "stopping old container (recreate)"
        );
        if let Err(e) = runtime.stop_container(old_id).await {
            ctx.fail(&format!(
                "[container_stop_failed] failed to stop old container: {e}"
            ));
            record_deploy(shared, ctx);
            set_app_failed(shared.app_states, app_name);
            return;
        }
    }

    // ── STEP 2: REMOVE CADDY ROUTE ─────────────────────────────────────────
    ctx.status = DeployStatus::RemovingRoute;
    record_deploy(shared, ctx);
    if let Err(e) = caddy.remove_route(app_name).await {
        // Non-fatal: route might not exist (first deploy) or already gone.
        tracing::warn!(
            app = app_name,
            error = %e,
            "failed to remove caddy route (non-fatal, continuing)"
        );
    }

    // ── STEP 3: START NEW CONTAINER ─────────────────────────────────────────
    ctx.status = DeployStatus::Starting;
    record_deploy(shared, ctx);

    let create_result = runtime
        .create_and_start(
            app_name,
            &ctx.image,
            &ctx.tag,
            if is_worker {
                0
            } else {
                effective_config.routing.port.unwrap_or(0)
            },
            env_vars.to_vec(),
            &effective_config.network.name,
            &effective_config.resources,
            &container_volumes,
        )
        .await;

    let (new_container_id, new_port) = match create_result {
        Ok((id, port)) => {
            ctx.new_container_id = Some(id.clone());
            if !is_worker {
                ctx.new_port = Some(port);
            }
            (id, port)
        }
        Err(e) => {
            // Rollback: restart old container, restore route.
            tracing::error!(app = app_name, error = %e, "new container failed to start (recreate)");
            rollback_recreate_container(
                shared,
                runtime,
                caddy,
                health,
                ctx,
                app_name,
                &old_container_id,
                &old_tag,
                effective_config,
                &container_volumes,
                env_vars,
                None,
            )
            .await;
            return;
        }
    };

    // ── STEP 4: HEALTH CHECK ───────────────────────────────────────────────
    ctx.status = DeployStatus::HealthChecking;
    record_deploy(shared, ctx);

    let health_ok = if is_worker {
        // Workers: use container_is_running() instead of HTTP health check
        if let Some(ref id) = ctx.new_container_id {
            match runtime.container_is_running(id).await {
                Ok(true) => true,
                Ok(false) => {
                    tracing::error!(app = app_name, container_id = %id, "worker container not running after start");
                    false
                }
                Err(e) => {
                    tracing::error!(app = app_name, error = %e, "failed to verify worker container state");
                    false
                }
            }
        } else {
            false
        }
    } else {
        // HTTP health check
        let check_result = health.check(new_port, &effective_config.health).await;
        if let Err(e) = &check_result {
            tracing::error!(app = app_name, error = %e, "health check failed (recreate)");
        }

        // Also verify container is still running after health check wait
        let still_running = if let Some(ref id) = ctx.new_container_id {
            runtime.container_is_running(id).await.unwrap_or(true)
        } else {
            true
        };

        check_result.is_ok() && still_running
    };

    if !health_ok {
        tracing::error!(
            app = app_name,
            "health check failed, rolling back (recreate)"
        );
        // Remove the failed new container
        let _ = runtime.stop_and_remove(&new_container_id).await;
        rollback_recreate_container(
            shared,
            runtime,
            caddy,
            health,
            ctx,
            app_name,
            &old_container_id,
            &old_tag,
            effective_config,
            &container_volumes,
            env_vars,
            None,
        )
        .await;
        return;
    }

    // ── STEP 5: SET CADDY ROUTE ────────────────────────────────────────────
    ctx.status = DeployStatus::Switching;
    record_deploy(shared, ctx);

    if !is_worker
        && let Err(e) = caddy
            .set_routes(
                app_name,
                &merged
                    .as_ref()
                    .map(|m| {
                        m.routes
                            .iter()
                            .map(|r| crate::caddy::Route {
                                hostname: r.hostname.clone(),
                                port: new_port,
                            })
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_else(|| {
                        vec![crate::caddy::Route {
                            hostname: effective_config.routing.domain.clone().unwrap_or_default(),
                            port: new_port,
                        }]
                    }),
            )
            .await
    {
        tracing::error!(app = app_name, error = %e, "caddy route update failed (recreate)");
        let _ = runtime.stop_and_remove(&new_container_id).await;
        rollback_recreate_container(
            shared,
            runtime,
            caddy,
            health,
            ctx,
            app_name,
            &old_container_id,
            &old_tag,
            effective_config,
            &container_volumes,
            env_vars,
            None,
        )
        .await;
        return;
    }

    // ── STEP 6: UPDATE APP STATE ───────────────────────────────────────────
    let state_snapshot = {
        let mut states = shared.app_states.write().await;
        let app_state = states.entry(app_name.to_string()).or_default();
        app_state.previous_tag = app_state.current_tag.take();
        app_state.previous_container_id = app_state.current_container_id.take();
        app_state.current_tag = Some(ctx.tag.clone());
        app_state.current_container_id = ctx.new_container_id.clone();
        app_state.current_port = if is_worker { None } else { ctx.new_port };
        app_state.current_routes = merged
            .as_ref()
            .map(|m| {
                m.routes
                    .iter()
                    .map(|r| RouteState {
                        hostname: r.hostname.clone(),
                        port: new_port,
                    })
                    .collect()
            })
            .unwrap_or_default();
        app_state.deployed_at = Some(Utc::now());
        app_state.deploy_id = Some(ctx.id.clone());
        app_state.status = AppStatus::Running;
        app_state.kind = merged.as_ref().map(|m| m.kind.clone());
        app_state.clone()
    };

    // Persist state to disk (non-fatal)
    let state_dir = shared.config.storage.path.join("state");
    if let Err(e) = state::save_app_state(&state_dir, app_name, &state_snapshot) {
        tracing::warn!(app = app_name, error = %e, "failed to persist app state (non-fatal)");
    }

    // ── STEP 7: REMOVE OLD CONTAINER ────────────────────────────────────────
    if let Some(ref old_id) = old_container_id {
        tracing::info!(
            app = app_name,
            old_id = %old_id,
            "removing old container (recreate cleanup)"
        );
        if let Err(e) = runtime.stop_and_remove(old_id).await {
            tracing::warn!(
                app = app_name,
                error = %e,
                "failed to remove old container (non-fatal)"
            );
        }
    }

    // ── COMPLETED ────────────────────────────────────────────────────────────
    if ctx.status != DeployStatus::Failed {
        ctx.status = DeployStatus::Completed;
        ctx.finished_at = Some(Utc::now());
        record_deploy(shared, ctx);
        tracing::info!(
            app = %app_name,
            tag = %ctx.tag,
            deploy_id = %ctx.id,
            "deploy completed"
        );
    }
}

// ─── Recreate rollback ────────────────────────────────────────────────────────

/// Rollback a failed recreate deploy.
///
/// Tier 1: restart old container, restore route.
/// Tier 2: create fresh container from previous_tag.
/// Tier 3: mark rollback_failed, log catastrophic error.
///
/// Always removes the failed new container.
#[allow(clippy::too_many_arguments)]
async fn rollback_recreate_container(
    shared: &DeploySharedState<'_>,
    runtime: &dyn RuntimeBackend,
    caddy: &dyn ReverseProxy,
    health: &dyn HealthCheck,
    ctx: &mut DeployContext,
    app_name: &str,
    old_container_id: &Option<String>,
    old_tag: &Option<String>,
    effective_config: &AppConfig,
    container_volumes: &[crate::merge::MergedVolume],
    env_vars: &[String],
    _new_container_id: Option<String>,
) {
    let old_port = {
        let states = shared.app_states.read().await;
        states.get(app_name).and_then(|s| s.current_port)
    };

    // ── TIER 1: Restart old container ───────────────────────────────────────
    if let Some(old_id) = old_container_id {
        ctx.status = DeployStatus::RestartingOld;
        record_deploy(shared, ctx);
        tracing::info!(
            app = app_name,
            old_id = %old_id,
            "Tier 1 rollback: restarting old container"
        );

        if runtime.start_container(old_id).await.is_ok() {
            // Re-discover port (may have changed after restart)
            let container_port = effective_config.routing.port.unwrap_or(0);
            let discovered_port = runtime
                .inspect_container_port(old_id, container_port)
                .await
                .unwrap_or(old_port.unwrap_or(0));

            // Restore Caddy route
            if effective_config.routing.domain.is_none()
                && effective_config.routing.routes.is_empty()
            {
                // Worker — no route to restore
            } else if let Err(e) = caddy
                .set_routes(
                    app_name,
                    &effective_config
                        .routing
                        .effective_routes()
                        .iter()
                        .map(|r| crate::caddy::Route {
                            hostname: r.hostname.clone(),
                            port: discovered_port,
                        })
                        .collect::<Vec<_>>(),
                )
                .await
            {
                tracing::warn!(
                    app = app_name,
                    error = %e,
                    "Tier 1 rollback: failed to restore route (non-fatal)"
                );
            }

            tracing::info!(app = app_name, "Tier 1 rollback succeeded");
            ctx.fail("[rollback_tier1] deploy failed, old container restarted (Tier 1 rollback)");
            record_deploy(shared, ctx);
            set_app_failed(shared.app_states, app_name);
            return;
        }

        tracing::warn!(
            app = app_name,
            old_id = %old_id,
            "Tier 1 rollback failed: old container would not restart"
        );
    }

    // ── TIER 2: Create from previous_tag ────────────────────────────────────
    if let Some(prev_tag) = old_tag {
        tracing::info!(
            app = app_name,
            previous_tag = %prev_tag,
            "Tier 2 rollback: creating container from previous_tag"
        );

        match runtime
            .create_and_start(
                app_name,
                &ctx.image,
                prev_tag,
                effective_config.routing.port.unwrap_or(0),
                env_vars.to_vec(),
                &effective_config.network.name,
                &effective_config.resources,
                container_volumes,
            )
            .await
        {
            Ok((fallback_id, fallback_port)) => {
                // Health check the fallback container
                let fallback_healthy = if effective_config.health.path.is_some() {
                    health
                        .check(fallback_port, &effective_config.health)
                        .await
                        .is_ok()
                } else {
                    true
                };

                if fallback_healthy {
                    // Set route
                    if effective_config.routing.domain.is_none()
                        && effective_config.routing.routes.is_empty()
                    {
                        // Worker — no route
                    } else if let Err(e) = caddy
                        .set_routes(
                            app_name,
                            &effective_config
                                .routing
                                .effective_routes()
                                .iter()
                                .map(|r| crate::caddy::Route {
                                    hostname: r.hostname.clone(),
                                    port: fallback_port,
                                })
                                .collect::<Vec<_>>(),
                        )
                        .await
                    {
                        tracing::warn!(
                            app = app_name,
                            error = %e,
                            "Tier 2 rollback: failed to restore route (non-fatal)"
                        );
                    }

                    // Update app state with fallback container
                    {
                        let mut states = shared.app_states.write().await;
                        if let Some(app_state) = states.get_mut(app_name) {
                            app_state.current_container_id = Some(fallback_id);
                            app_state.current_port = Some(fallback_port);
                            app_state.current_tag = Some(prev_tag.clone());
                        }
                    }

                    tracing::info!(app = app_name, "Tier 2 rollback succeeded");
                    ctx.fail("[rollback_tier2] deploy failed, fallback from previous_tag (Tier 2 rollback)");
                    record_deploy(shared, ctx);
                    set_app_failed(shared.app_states, app_name);
                    return;
                }

                // Fallback container unhealthy — clean it up
                let _ = runtime.stop_and_remove(&fallback_id).await;
                tracing::warn!(
                    app = app_name,
                    "Tier 2 rollback failed: fallback container unhealthy"
                );
            }
            Err(e) => {
                tracing::warn!(
                    app = app_name,
                    error = %e,
                    "Tier 2 rollback failed: could not create fallback container"
                );
            }
        }
    }

    // ── TIER 3: Catastrophic failure ────────────────────────────────────────
    ctx.rollback_failed = true;
    tracing::error!(
        app = app_name,
        "App {} is DOWN. New container failed health check AND old container cannot be restarted. Manual intervention required.",
        app_name,
    );
    ctx.fail("[rollback_failed] deploy failed, rollback failed — manual intervention required");
    record_deploy(shared, ctx);
    set_app_failed(shared.app_states, app_name);
}

// ─── Private helpers ──────────────────────────────────────────────────────────

/// Parse a full image reference into (image_base, tag).
///
/// Handles both `registry/image:tag` and `registry/image@sha256:...` formats.
/// For digest references, the tag portion is the full digest string.
///
/// Examples:
/// - `"ghcr.io/org/app:v1.2.3"` → `("ghcr.io/org/app", "v1.2.3")`
/// - `"redis:7-alpine"` → `("redis", "7-alpine")`
/// - `"ghcr.io/org/app@sha256:abc123"` → `("ghcr.io/org/app", "sha256:abc123")`
fn parse_image_ref(full_ref: &str) -> (&str, &str) {
    // Check for digest reference first (@sha256:...)
    if let Some(at_pos) = full_ref.rfind('@') {
        let image = &full_ref[..at_pos];
        let tag = &full_ref[at_pos + 1..];
        return (image, tag);
    }
    // Standard tag reference (image:tag)
    if let Some(colon_pos) = full_ref.rfind(':') {
        let image = &full_ref[..colon_pos];
        let tag = &full_ref[colon_pos + 1..];
        return (image, tag);
    }
    // No tag — use "latest"
    (full_ref, "latest")
}

/// Record (insert/update) a deploy context: persist to SQLite and update the
/// in-memory cache.
///
/// The cache is keyed by app name and stores only the latest deploy per app.
/// SQLite is the source of truth for `GET /v1/deploys/{id}` (per-deploy history),
/// so every state transition during a deploy must be persisted here — not just
/// the initial "accepted" write done by the API handler.
///
/// The SQLite write is synchronous (the `Db` mutex is held briefly for a fast
/// local WAL write). Failures are logged but non-fatal — deploy history is
/// best-effort and must never block or fail a deploy.
pub(crate) fn record_deploy(shared: &DeploySharedState, ctx: &DeployContext) {
    // Update the in-memory cache (latest deploy per app).
    shared.deploys.insert(ctx.app.clone(), ctx.clone());

    // Persist to SQLite (best-effort).
    if let Err(e) = shared.db.insert_deploy(ctx) {
        tracing::error!(
            deploy_id = %ctx.id,
            app = %ctx.app,
            error = %e,
            "failed to persist deploy to SQLite"
        );
    }
}

/// Set the app status to Failed in the shared state.
fn set_app_failed(app_states: &RwLock<HashMap<String, AppRuntimeState>>, app_name: &str) {
    if let Ok(mut states) = app_states.try_write()
        && let Some(app_state) = states.get_mut(app_name)
    {
        app_state.status = AppStatus::Failed;
    }
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

/// Merge env vars from app config `[env]` section + optional env_file on disk
/// + secrets from the SecretsStore (if provided).
///
/// Secrets take precedence over env vars: if both define `DB_URL`, the secret
/// value wins. A warning is logged when a secret shadows an env key.
pub(crate) fn resolve_env_vars_for_app(
    app_config: &AppConfig,
    secrets_store: Option<&crate::secrets::SecretsStore>,
    app_name: &str,
) -> Vec<String> {
    let mut vars: Vec<String> = app_config
        .env
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect();

    // Read env_file if configured
    if let Some(ref env_file) = app_config.env_file
        && let Ok(contents) = std::fs::read_to_string(&env_file.path)
    {
        for line in contents.lines() {
            let line = line.trim();
            if !line.is_empty() && !line.starts_with('#') {
                vars.push(line.to_string());
            }
        }
    }

    // Inject secrets — they override env vars with matching keys
    if let Some(store) = secrets_store
        && let Ok(secrets) = store.get_all(app_name)
    {
        let env_keys: std::collections::HashSet<String> = app_config.env.keys().cloned().collect();
        for (key, value) in &secrets {
            if env_keys.contains(key) {
                tracing::warn!(
                    app = app_name,
                    key = %key,
                    "secret overrides env var"
                );
            }
            // Remove any existing entry for this key from vars
            vars.retain(|v| !v.starts_with(&format!("{key}=")));
            vars.push(format!("{key}={value}"));
        }
        if !secrets.is_empty() {
            tracing::info!(
                app = app_name,
                secret_count = secrets.len(),
                "injected secrets into env vars"
            );
        }
    }

    vars
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::time::Duration;

    use dashmap::DashMap;
    use tokio::sync::RwLock;

    use super::*;
    use crate::caddy::{ReverseProxy, Route};
    use crate::config::{
        AppConfig, AppInfo, AuthConfig, CaddyConfig, DeployConfig, HealthConfig, RegistriesConfig,
        ResourceConfig, RoutingConfig, ServerConfig, SlipConfig, StorageConfig,
    };
    use crate::error::{CaddyError, HealthError, RuntimeError};
    use crate::health::HealthCheck;
    use crate::runtime::{RegistryCredentials, RuntimeBackend};

    // ── Mock: RuntimeBackend ──────────────────────────────────────────────────

    /// Configurable mock for `RuntimeBackend`.
    struct MockDocker {
        /// Whether `pull_image` should succeed.
        pull_ok: bool,
        /// If true, `pull_image` returns a future that never completes (for timeout tests).
        hung: bool,
        /// If true, `container_is_running` returns a future that never completes
        /// (for timeout tests after container start).
        hung_container_check: bool,
        /// Container ID + port returned by `create_and_start`.
        container_id: String,
        container_port: u16,
        /// Tracks how many times `stop_and_remove` was called.
        stop_count: Arc<AtomicU32>,
        /// Tracks how many times `stop_container` (stop only) was called.
        stop_only_count: Arc<AtomicU32>,
        /// Tracks how many times `start_container` was called.
        start_count: Arc<AtomicU32>,
        /// Whether `start_container` should succeed (for rollback failure tests).
        start_ok: bool,
        /// Whether `stop_container` should succeed.
        stop_ok: bool,
        /// Port returned by `inspect_container_port` / after restart.
        restart_port: Option<u16>,
        /// Result returned by `extract_file` for `/slip/slip.toml`:
        /// - `Ok(Some(bytes))` → file found with content
        /// - `Ok(None)` → file not found
        /// - `Err(e)` → extraction error (including Unsupported)
        extract_result: Result<Option<Vec<u8>>, RuntimeError>,
        /// Optional result returned by `extract_file` for manifest paths.
        /// When `Some`, the mock is in "pod support" mode:
        ///   - `/slip/slip.toml` calls return `extract_result`
        ///   - all other paths return `manifest_extract_result`
        manifest_extract_result: Option<Result<Option<Vec<u8>>, RuntimeError>>,
        /// Port returned by `pod_container_port` (None = Unsupported).
        pod_port: Option<u16>,
        /// Tracks how many times `teardown_pod` was called.
        teardown_count: Arc<AtomicU32>,
        /// Ordered log of method calls for ordering assertions.
        call_log: Arc<Mutex<Vec<String>>>,
        /// Credentials passed to each `pull_image` call, in call order:
        /// `Some(creds)` for a resolved cred, `None` for an anonymous pull.
        /// Used by the two-registry integration test to assert per-image
        /// resolver wiring (SLIP-105 review #4). Existing tests ignore it.
        pulled_credentials: Arc<Mutex<Vec<Option<RegistryCredentials>>>>,
    }

    impl MockDocker {
        fn new() -> Self {
            Self {
                pull_ok: true,
                hung: false,
                hung_container_check: false,
                container_id: "mock-container-id".to_string(),
                container_port: 54321,
                stop_count: Arc::new(AtomicU32::new(0)),
                stop_only_count: Arc::new(AtomicU32::new(0)),
                start_count: Arc::new(AtomicU32::new(0)),
                start_ok: true,
                stop_ok: true,
                restart_port: None,
                // Default: extract_file returns Unsupported (same as the trait default)
                extract_result: Err(RuntimeError::Unsupported(
                    "mock does not implement extract_file".to_string(),
                )),
                manifest_extract_result: None,
                pod_port: None,
                teardown_count: Arc::new(AtomicU32::new(0)),
                call_log: Arc::new(Mutex::new(Vec::new())),
                pulled_credentials: Arc::new(Mutex::new(Vec::new())),
            }
        }

        fn failing_pull() -> Self {
            Self {
                pull_ok: false,
                ..Self::new()
            }
        }

        /// Create a mock where `pull_image` never completes (sleeps forever).
        /// Used with `#[tokio::test(start_paused = true)]` to test deploy timeouts.
        fn hung_pull() -> Self {
            Self {
                hung: true,
                ..Self::new()
            }
        }

        fn with_repo_config(bytes: Vec<u8>) -> Self {
            Self {
                extract_result: Ok(Some(bytes)),
                ..Self::new()
            }
        }

        fn with_no_repo_config() -> Self {
            Self {
                extract_result: Ok(None),
                ..Self::new()
            }
        }

        fn with_extract_error(e: RuntimeError) -> Self {
            Self {
                extract_result: Err(e),
                ..Self::new()
            }
        }

        /// Create a mock with pod support.
        ///
        /// - `slip_toml_bytes`: returned when `/slip/slip.toml` is extracted
        /// - `manifest_bytes`: returned when the manifest path is extracted
        /// - `pod_port`: returned by `pod_container_port`
        fn with_pod_support(
            slip_toml_bytes: Vec<u8>,
            manifest_bytes: Vec<u8>,
            pod_port: u16,
        ) -> Self {
            Self {
                extract_result: Ok(Some(slip_toml_bytes)),
                manifest_extract_result: Some(Ok(Some(manifest_bytes))),
                pod_port: Some(pod_port),
                ..Self::new()
            }
        }

        fn stop_count(&self) -> Arc<AtomicU32> {
            self.stop_count.clone()
        }

        #[allow(dead_code)]
        fn stop_only_count(&self) -> Arc<AtomicU32> {
            self.stop_only_count.clone()
        }

        #[allow(dead_code)]
        fn start_count(&self) -> Arc<AtomicU32> {
            self.start_count.clone()
        }

        fn teardown_count(&self) -> Arc<AtomicU32> {
            self.teardown_count.clone()
        }

        fn call_log(&self) -> Arc<Mutex<Vec<String>>> {
            self.call_log.clone()
        }

        /// Accessor for the credentials recorded by each `pull_image` call
        /// (SLIP-105 review #4). Each entry is `Some(creds)` for a resolved
        /// cred or `None` for an anonymous pull, in call order.
        fn pulled_credentials(&self) -> Arc<Mutex<Vec<Option<RegistryCredentials>>>> {
            self.pulled_credentials.clone()
        }
    }

    fn clone_runtime_error(e: &RuntimeError) -> RuntimeError {
        match e {
            RuntimeError::Unsupported(msg) => RuntimeError::Unsupported(msg.clone()),
            RuntimeError::Connection(msg) => RuntimeError::Connection(msg.clone()),
            RuntimeError::PullFailed(msg) => RuntimeError::PullFailed(msg.clone()),
            RuntimeError::ContainerError(msg) => RuntimeError::ContainerError(msg.clone()),
            RuntimeError::NetworkError(msg) => RuntimeError::NetworkError(msg.clone()),
            RuntimeError::ContainerNotRunning(msg) => {
                RuntimeError::ContainerNotRunning(msg.clone())
            }
            RuntimeError::NoPortAssigned => RuntimeError::NoPortAssigned,
            RuntimeError::ExecFailed(msg) => RuntimeError::ExecFailed(msg.clone()),
        }
    }

    impl RuntimeBackend for MockDocker {
        fn name(&self) -> &str {
            "mock"
        }

        fn ping(
            &self,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<(), RuntimeError>> + Send + '_>,
        > {
            Box::pin(async { Ok(()) })
        }

        fn ensure_network<'a>(
            &'a self,
            _name: &'a str,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<(), RuntimeError>> + Send + 'a>,
        > {
            Box::pin(async { Ok(()) })
        }

        fn pull_image<'a>(
            &'a self,
            _image: &'a str,
            _tag: &'a str,
            credentials: Option<RegistryCredentials>,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<(), RuntimeError>> + Send + 'a>,
        > {
            self.call_log.lock().unwrap().push("pull_image".to_string());
            // Record the resolved credentials for the two-registry integration
            // test (SLIP-105 review #4). Cloning is cheap (two Strings). Existing
            // tests don't read this, so their behaviour is unchanged.
            self.pulled_credentials
                .lock()
                .unwrap()
                .push(credentials.clone());
            if self.hung {
                // Return a future that never completes (sleeps forever).
                // Under `start_paused = true`, this will cause the timeout to fire.
                return Box::pin(async move {
                    tokio::time::sleep(std::time::Duration::from_secs(u64::MAX)).await;
                    Ok(())
                });
            }
            let result = if self.pull_ok {
                Ok(())
            } else {
                Err(RuntimeError::PullFailed("mock pull failure".to_string()))
            };
            Box::pin(async move { result })
        }

        fn create_and_start<'a>(
            &'a self,
            _app_name: &'a str,
            _image: &'a str,
            _tag: &'a str,
            _container_port: u16,
            _env_vars: Vec<String>,
            _network: &'a str,
            _resources: &'a crate::config::ResourceConfig,
            _volumes: &'a [crate::merge::MergedVolume],
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<(String, u16), RuntimeError>> + Send + 'a>,
        > {
            self.call_log
                .lock()
                .unwrap()
                .push("create_and_start".to_string());
            let result = Ok((self.container_id.clone(), self.container_port));
            Box::pin(async move { result })
        }

        fn stop_and_remove<'a>(
            &'a self,
            _container_id: &'a str,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<(), RuntimeError>> + Send + 'a>,
        > {
            self.call_log
                .lock()
                .unwrap()
                .push("stop_and_remove".to_string());
            self.stop_count.fetch_add(1, Ordering::SeqCst);
            Box::pin(async { Ok(()) })
        }

        fn stop_container<'a>(
            &'a self,
            _container_id: &'a str,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<(), RuntimeError>> + Send + 'a>,
        > {
            self.call_log
                .lock()
                .unwrap()
                .push("stop_container".to_string());
            self.stop_only_count.fetch_add(1, Ordering::SeqCst);
            let ok = self.stop_ok;
            Box::pin(async move {
                if ok {
                    Ok(())
                } else {
                    Err(RuntimeError::ContainerError(
                        "mock stop_container failure".to_string(),
                    ))
                }
            })
        }

        fn start_container<'a>(
            &'a self,
            _container_id: &'a str,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<(), RuntimeError>> + Send + 'a>,
        > {
            self.call_log
                .lock()
                .unwrap()
                .push("start_container".to_string());
            self.start_count.fetch_add(1, Ordering::SeqCst);
            let ok = self.start_ok;
            Box::pin(async move {
                if ok {
                    Ok(())
                } else {
                    Err(RuntimeError::ContainerError(
                        "mock start_container failure".to_string(),
                    ))
                }
            })
        }

        fn inspect_container_port<'a>(
            &'a self,
            _container_id: &'a str,
            _container_port: u16,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<u16, RuntimeError>> + Send + 'a>,
        > {
            let port = self.restart_port.unwrap_or(self.container_port);
            Box::pin(async move { Ok(port) })
        }

        fn container_is_running<'a>(
            &'a self,
            _container_id: &'a str,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<bool, RuntimeError>> + Send + 'a>,
        > {
            if self.hung_container_check {
                // Return a future that never completes (sleeps forever).
                // Under `start_paused = true`, this will cause the timeout to fire
                // after the container has been created.
                return Box::pin(async move {
                    tokio::time::sleep(std::time::Duration::from_secs(u64::MAX)).await;
                    Ok(true)
                });
            }
            // Mock containers are always running unless explicitly set otherwise
            Box::pin(async { Ok(true) })
        }

        fn container_exists<'a>(
            &'a self,
            _container_id: &'a str,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<bool, RuntimeError>> + Send + 'a>,
        > {
            Box::pin(async { Ok(true) })
        }

        fn extract_file<'a>(
            &'a self,
            _image: &'a str,
            _tag: &'a str,
            path: &'a str,
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<Output = Result<Option<Vec<u8>>, RuntimeError>> + Send + 'a,
            >,
        > {
            // When in pod-support mode, route /slip/slip.toml to extract_result
            // and all other paths (e.g. the manifest) to manifest_extract_result.
            let result = if let Some(ref manifest_result) = self.manifest_extract_result
                && path != "/slip/slip.toml"
            {
                // Manifest extraction path
                match manifest_result {
                    Ok(opt) => Ok(opt.clone()),
                    Err(e) => Err(clone_runtime_error(e)),
                }
            } else {
                // slip.toml or default path
                match &self.extract_result {
                    Ok(opt) => Ok(opt.clone()),
                    Err(e) => Err(clone_runtime_error(e)),
                }
            };
            Box::pin(async move { result })
        }

        fn deploy_pod<'a>(
            &'a self,
            _manifest: &'a std::path::Path,
            _name: &'a str,
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<Output = Result<crate::runtime::PodInfo, RuntimeError>>
                    + Send
                    + 'a,
            >,
        > {
            if self.pod_port.is_some() {
                let info = crate::runtime::PodInfo {
                    name: _name.to_string(),
                    containers: vec!["web".to_string()],
                };
                Box::pin(async move { Ok(info) })
            } else {
                Box::pin(async {
                    Err(RuntimeError::Unsupported(
                        "pod operations require Podman".to_string(),
                    ))
                })
            }
        }

        fn teardown_pod<'a>(
            &'a self,
            _manifest: &'a std::path::Path,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<(), RuntimeError>> + Send + 'a>,
        > {
            if self.pod_port.is_some() {
                self.teardown_count.fetch_add(1, Ordering::SeqCst);
                Box::pin(async { Ok(()) })
            } else {
                Box::pin(async {
                    Err(RuntimeError::Unsupported(
                        "pod operations require Podman".to_string(),
                    ))
                })
            }
        }

        fn pod_container_port<'a>(
            &'a self,
            _pod: &'a str,
            _container: &'a str,
            _container_port: u16,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<u16, RuntimeError>> + Send + 'a>,
        > {
            let result = match self.pod_port {
                Some(port) => Ok(port),
                None => Err(RuntimeError::Unsupported(
                    "pod operations require Podman".to_string(),
                )),
            };
            Box::pin(async move { result })
        }

        fn list_by_label<'a>(
            &'a self,
            _label_key: &'a str,
            _label_value: &'a str,
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<
                        Output = Result<Vec<crate::runtime::ContainerInfo>, RuntimeError>,
                    > + Send
                    + 'a,
            >,
        > {
            Box::pin(async move { Ok(Vec::new()) })
        }

        fn container_logs<'a>(
            &'a self,
            _container_id: &'a str,
            _since: Option<i64>,
            _follow: bool,
        ) -> std::pin::Pin<
            Box<
                dyn futures_util::Stream<Item = Result<crate::runtime::LogStreamItem, RuntimeError>>
                    + Send
                    + 'a,
            >,
        > {
            // The deploy tests don't exercise log streaming; return an empty stream.
            Box::pin(futures_util::stream::empty())
        }
    }

    // ── Mock: ReverseProxy ────────────────────────────────────────────────────

    struct MockCaddy {
        ok: bool,
    }

    impl MockCaddy {
        fn success() -> Self {
            Self { ok: true }
        }

        fn failing() -> Self {
            Self { ok: false }
        }
    }

    impl ReverseProxy for MockCaddy {
        fn set_route<'a>(
            &'a self,
            _app_name: &'a str,
            _domain: &'a str,
            _upstream_port: u16,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), CaddyError>> + Send + 'a>>
        {
            let result = if self.ok {
                Ok(())
            } else {
                Err(CaddyError::RouteUpdateFailed(
                    "mock caddy failure".to_string(),
                ))
            };
            Box::pin(async move { result })
        }

        fn remove_route<'a>(
            &'a self,
            _app_name: &'a str,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), CaddyError>> + Send + 'a>>
        {
            Box::pin(async { Ok(()) })
        }

        fn set_routes<'a>(
            &'a self,
            _app_name: &'a str,
            _routes: &'a [Route],
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), CaddyError>> + Send + 'a>>
        {
            let result = if self.ok {
                Ok(())
            } else {
                Err(CaddyError::RouteUpdateFailed(
                    "mock caddy failure".to_string(),
                ))
            };
            Box::pin(async move { result })
        }

        fn remove_routes<'a>(
            &'a self,
            _app_name: &'a str,
            _route_count: usize,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), CaddyError>> + Send + 'a>>
        {
            Box::pin(async { Ok(()) })
        }
    }

    // ── Mock: HealthCheck ─────────────────────────────────────────────────────

    struct MockHealth {
        ok: bool,
        /// If true, `check` returns a future that never completes (for timeout tests).
        hung: bool,
        /// When `ok == false`, return this error variant instead of the default
        /// `Unhealthy` (used to exercise the `health_unexpected_status` reason).
        unexpected_status: bool,
    }

    impl MockHealth {
        fn passing() -> Self {
            Self {
                ok: true,
                hung: false,
                unexpected_status: false,
            }
        }

        fn failing() -> Self {
            Self {
                ok: false,
                hung: false,
                unexpected_status: false,
            }
        }

        /// Return `HealthError::UnexpectedStatus` from `check` — used to
        /// exercise the `[health_unexpected_status]` deploy reason tag.
        fn unexpected_status() -> Self {
            Self {
                ok: false,
                hung: false,
                unexpected_status: true,
            }
        }
    }

    impl HealthCheck for MockHealth {
        fn check<'a>(
            &'a self,
            _host_port: u16,
            _config: &'a HealthConfig,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), HealthError>> + Send + 'a>>
        {
            if self.hung {
                // Return a future that never completes (sleeps forever).
                // Under `start_paused = true`, this will cause the timeout to fire.
                return Box::pin(async move {
                    tokio::time::sleep(std::time::Duration::from_secs(u64::MAX)).await;
                    Ok(())
                });
            }
            let result = if self.ok {
                Ok(())
            } else if self.unexpected_status {
                Err(HealthError::UnexpectedStatus {
                    expected: "200".to_string(),
                    actual: 307,
                    url: "http://127.0.0.1:54321/health".to_string(),
                    attempts: 3,
                })
            } else {
                Err(HealthError::Unhealthy {
                    retries: 3,
                    url: "http://127.0.0.1:54321/health".to_string(),
                })
            };
            Box::pin(async move { result })
        }
    }

    // ── Test helpers ──────────────────────────────────────────────────────────

    fn test_slip_config(storage_path: std::path::PathBuf) -> SlipConfig {
        SlipConfig {
            server: ServerConfig::default(),
            caddy: CaddyConfig::default(),
            auth: AuthConfig {
                secret: "test-secret".to_string(),
            },
            registries: RegistriesConfig::default(),
            storage: StorageConfig { path: storage_path },
            runtime: crate::config::RuntimeConfig::default(),
            preview: None,
            deploy: None,
        }
    }

    fn test_app_config() -> AppConfig {
        AppConfig {
            app: AppInfo {
                name: "testapp".to_string(),
                image: "ghcr.io/org/testapp".to_string(),
                secret: None,
            },
            routing: RoutingConfig {
                domain: Some("testapp.example.com".to_string()),
                port: Some(3000),
                routes: vec![],
                tls: None,
            },
            health: HealthConfig {
                // No health path — check always passes without any HTTP call.
                path: None,
                interval: Duration::from_millis(1),
                timeout: Duration::from_millis(10),
                retries: 1,
                start_period: Duration::ZERO,
                expect_status: None,
            },
            deploy: DeployConfig {
                strategy: "blue-green".to_string(),
                // Zero drain timeout so tests don't sleep.
                drain_timeout: Duration::ZERO,
                timeout: None,
            },
            env: HashMap::new(),
            env_file: None,
            resources: ResourceConfig::default(),
            network: crate::config::NetworkConfig::default(),
            preview: None,
            volumes: Vec::new(),
        }
    }

    fn test_deploy_ctx() -> DeployContext {
        DeployContext::new(
            "dep_test001".to_string(),
            "testapp".to_string(),
            "ghcr.io/org/testapp".to_string(),
            "v1.0.0".to_string(),
            TriggerSource::Webhook,
        )
    }

    /// Build a `DeploySharedState` backed by real in-memory structures.
    fn make_shared<'a>(
        config: &'a SlipConfig,
        apps: &'a RwLock<HashMap<String, AppConfig>>,
        app_states: &'a RwLock<HashMap<String, AppRuntimeState>>,
        deploys: &'a DashMap<String, DeployContext>,
    ) -> DeploySharedState<'a> {
        DeploySharedState {
            config,
            apps,
            app_states,
            deploys,
            db: Db::open_in_memory().expect("in-memory db for tests"),
            registries: Vec::new(),
            secrets_store: None,
        }
    }

    /// Build a `DeploySharedState` with an externally-owned `Db` (e.g. for
    /// asserting SQLite persistence after the deploy completes).
    fn make_shared_with_db<'a>(
        config: &'a SlipConfig,
        apps: &'a RwLock<HashMap<String, AppConfig>>,
        app_states: &'a RwLock<HashMap<String, AppRuntimeState>>,
        deploys: &'a DashMap<String, DeployContext>,
        db: Db,
    ) -> DeploySharedState<'a> {
        DeploySharedState {
            config,
            apps,
            app_states,
            deploys,
            db,
            registries: Vec::new(),
            secrets_store: None,
        }
    }

    /// Build a `DeploySharedState` with a populated merged-registry table
    /// (for the two-registry integration test, SLIP-105 review #4).
    fn make_shared_with_registries<'a>(
        config: &'a SlipConfig,
        apps: &'a RwLock<HashMap<String, AppConfig>>,
        app_states: &'a RwLock<HashMap<String, AppRuntimeState>>,
        deploys: &'a DashMap<String, DeployContext>,
        registries: Vec<crate::registry::ResolvedRegistry>,
    ) -> DeploySharedState<'a> {
        DeploySharedState {
            config,
            apps,
            app_states,
            deploys,
            db: Db::open_in_memory().expect("in-memory db for tests"),
            registries,
            secrets_store: None,
        }
    }

    // ── Tests ─────────────────────────────────────────────────────────────────

    /// Happy path: pull → start → health → switch → complete.
    #[tokio::test]
    async fn test_happy_path_full_deploy() {
        let tmp = tempfile::tempdir().unwrap();
        let config = test_slip_config(tmp.path().to_path_buf());
        let mut apps = HashMap::new();
        apps.insert("testapp".to_string(), test_app_config());
        let apps: RwLock<HashMap<String, AppConfig>> = RwLock::new(apps);
        let app_states: RwLock<HashMap<String, AppRuntimeState>> = RwLock::new(HashMap::new());
        let deploys: DashMap<String, DeployContext> = DashMap::new();

        let docker = MockDocker::new();
        let caddy = MockCaddy::success();
        let health = MockHealth::passing();
        let mut ctx = test_deploy_ctx();

        execute_deploy_inner(
            make_shared(&config, &apps, &app_states, &deploys),
            &docker,
            &caddy,
            &health,
            &mut ctx,
        )
        .await;

        // Deploy should be recorded as Completed.
        let recorded = deploys.get("testapp").unwrap();
        assert_eq!(recorded.status, DeployStatus::Completed);
        assert!(recorded.finished_at.is_some());
        assert!(recorded.error.is_none());

        // App runtime state should show Running with the new container.
        let states = app_states.read().await;
        let app = states.get("testapp").expect("app state should exist");
        assert_eq!(app.status, AppStatus::Running);
        assert_eq!(app.current_tag.as_deref(), Some("v1.0.0"));
        assert_eq!(
            app.current_container_id.as_deref(),
            Some("mock-container-id")
        );
        assert_eq!(app.current_port, Some(54321));
    }

    /// SLIP-105 review #4: deploy-level two-registry integration test.
    ///
    /// Proves `execute_deploy_inner` calls `resolve_registry_credential`
    /// per-image and passes the resolved cred to `pull_image`: a main image
    /// on ghcr.io + a sidecar on localhost:5000 receive distinct correct
    /// creds in one deploy cycle. This is the CI-verifiable proof of the
    /// ticket's #1 acceptance criterion ("two registries in one deploy cycle")
    /// at the wiring level (not just the resolver unit level).
    #[tokio::test]
    async fn test_two_registries_one_deploy_cycle_distinct_creds() {
        use crate::registry::{RegistryCredSource, ResolvedRegistry};

        let tmp = tempfile::tempdir().unwrap();
        let config = test_slip_config(tmp.path().to_path_buf());

        // App: main image on ghcr.io, sidecar on localhost:5000.
        let mut app = test_app_config();
        app.app.image = "ghcr.io/me/mainapp".to_string();
        let apps_map = HashMap::from([("testapp".to_string(), app)]);
        let apps: RwLock<HashMap<String, AppConfig>> = RwLock::new(apps_map);
        let app_states: RwLock<HashMap<String, AppRuntimeState>> = RwLock::new(HashMap::new());
        let deploys: DashMap<String, DeployContext> = DashMap::new();

        // Merged registry table: two registries, distinct creds.
        let registries = vec![
            ResolvedRegistry {
                url: "ghcr.io".to_string(),
                username: Some("ghcr-user".to_string()),
                password: "ghcr-tok".to_string(),
                source: RegistryCredSource::Toml,
            },
            ResolvedRegistry {
                url: "localhost:5000".to_string(),
                username: Some("ci".to_string()),
                password: "local-tok".to_string(),
                source: RegistryCredSource::Toml,
            },
        ];

        let docker = MockDocker::new();
        let cred_log = docker.pulled_credentials();
        let caddy = MockCaddy::success();
        let health = MockHealth::passing();

        // Deploy context: main image on ghcr.io + a sidecar on localhost:5000.
        let mut ctx = DeployContext::new(
            "dep_two_reg_001".to_string(),
            "testapp".to_string(),
            "ghcr.io/me/mainapp".to_string(),
            "v1.0.0".to_string(),
            TriggerSource::Webhook,
        );
        ctx.images.insert(
            "sidecar".to_string(),
            "localhost:5000/internal/svc:latest".to_string(),
        );

        execute_deploy_inner(
            make_shared_with_registries(&config, &apps, &app_states, &deploys, registries),
            &docker,
            &caddy,
            &health,
            &mut ctx,
        )
        .await;

        // The deploy should complete (the mock pull never fails).
        let recorded = deploys.get("testapp").unwrap();
        assert_eq!(
            recorded.status,
            DeployStatus::Completed,
            "deploy should complete: {:?}",
            recorded.error
        );

        // Two pull_image calls: main (ghcr.io) then sidecar (localhost:5000).
        let pulls = cred_log.lock().unwrap();
        assert_eq!(pulls.len(), 2, "expected exactly two pull_image calls");

        // Main image pull received the ghcr.io cred.
        let main_cred = pulls[0].as_ref().expect("main pull should have a cred");
        assert_eq!(main_cred.username, "ghcr-user");
        assert_eq!(main_cred.password, "ghcr-tok");

        // Sidecar pull received the localhost:5000 cred — distinct from main.
        let side_cred = pulls[1].as_ref().expect("sidecar pull should have a cred");
        assert_eq!(side_cred.username, "ci");
        assert_eq!(side_cred.password, "local-tok");

        assert_ne!(
            main_cred.password, side_cred.password,
            "distinct creds per image in one deploy cycle"
        );
    }

    /// First deploy: no old container to stop — `stop_and_remove` for old
    /// container should never be called.
    #[tokio::test]
    async fn test_first_deploy_no_old_container() {
        let tmp = tempfile::tempdir().unwrap();
        let config = test_slip_config(tmp.path().to_path_buf());
        let mut apps = HashMap::new();
        apps.insert("testapp".to_string(), test_app_config());
        let apps: RwLock<HashMap<String, AppConfig>> = RwLock::new(apps);
        let app_states: RwLock<HashMap<String, AppRuntimeState>> = RwLock::new(HashMap::new());
        let deploys: DashMap<String, DeployContext> = DashMap::new();

        let docker = MockDocker::new();
        let stop_count = docker.stop_count();
        let caddy = MockCaddy::success();
        let health = MockHealth::passing();

        execute_deploy_inner(
            make_shared(&config, &apps, &app_states, &deploys),
            &docker,
            &caddy,
            &health,
            &mut test_deploy_ctx(),
        )
        .await;

        // `stop_and_remove` should not have been called (no old container).
        assert_eq!(stop_count.load(Ordering::SeqCst), 0);

        // Status should be Completed.
        let recorded = deploys.get("testapp").unwrap();
        assert_eq!(recorded.status, DeployStatus::Completed);
    }

    /// Subsequent deploy: an old container exists and should be stopped after
    /// the new one is live.
    #[tokio::test]
    async fn test_subsequent_deploy_stops_old_container() {
        let tmp = tempfile::tempdir().unwrap();
        let config = test_slip_config(tmp.path().to_path_buf());
        let mut apps = HashMap::new();
        apps.insert("testapp".to_string(), test_app_config());
        let apps: RwLock<HashMap<String, AppConfig>> = RwLock::new(apps);

        // Pre-populate app state with an existing container.
        let mut initial_states = HashMap::new();
        initial_states.insert(
            "testapp".to_string(),
            AppRuntimeState {
                status: AppStatus::Running,
                current_tag: Some("v0.9.0".to_string()),
                current_container_id: Some("old-container-id".to_string()),
                current_port: Some(50000),
                ..Default::default()
            },
        );
        let app_states: RwLock<HashMap<String, AppRuntimeState>> = RwLock::new(initial_states);
        let deploys: DashMap<String, DeployContext> = DashMap::new();

        let docker = MockDocker::new();
        let stop_count = docker.stop_count();
        let caddy = MockCaddy::success();
        let health = MockHealth::passing();

        execute_deploy_inner(
            make_shared(&config, &apps, &app_states, &deploys),
            &docker,
            &caddy,
            &health,
            &mut test_deploy_ctx(),
        )
        .await;

        // `stop_and_remove` should have been called exactly once (old container).
        assert_eq!(stop_count.load(Ordering::SeqCst), 1);

        // New container should now be current.
        let states = app_states.read().await;
        let app = states.get("testapp").unwrap();
        assert_eq!(
            app.current_container_id.as_deref(),
            Some("mock-container-id")
        );
        assert_eq!(
            app.previous_container_id.as_deref(),
            Some("old-container-id")
        );
    }

    /// Health check failure: new container should be stopped, deploy recorded
    /// as Failed.
    #[tokio::test]
    async fn test_health_check_failure_stops_new_container() {
        let tmp = tempfile::tempdir().unwrap();
        let config = test_slip_config(tmp.path().to_path_buf());
        let mut apps = HashMap::new();
        apps.insert("testapp".to_string(), test_app_config());
        let apps: RwLock<HashMap<String, AppConfig>> = RwLock::new(apps);
        let app_states: RwLock<HashMap<String, AppRuntimeState>> = RwLock::new(HashMap::new());
        let deploys: DashMap<String, DeployContext> = DashMap::new();

        let docker = MockDocker::new();
        let stop_count = docker.stop_count();
        let caddy = MockCaddy::success();
        let health = MockHealth::failing(); // health check always fails

        execute_deploy_inner(
            make_shared(&config, &apps, &app_states, &deploys),
            &docker,
            &caddy,
            &health,
            &mut test_deploy_ctx(),
        )
        .await;

        // New container should have been stopped (rollback).
        assert_eq!(
            stop_count.load(Ordering::SeqCst),
            1,
            "new container should be stopped"
        );

        // Deploy should be Failed.
        let recorded = deploys.get("testapp").unwrap();
        assert_eq!(recorded.status, DeployStatus::Failed);
        assert!(
            recorded
                .error
                .as_deref()
                .unwrap_or("")
                .contains("health check failed")
        );

        // App runtime state should NOT have been updated to the new container.
        let states = app_states.read().await;
        assert!(
            states.get("testapp").is_none(),
            "app state should not have been set"
        );
    }

    /// `HealthError::UnexpectedStatus` propagates as the
    /// `[health_unexpected_status]` SLIP-91 terminal tag (AC11). Exit code
    /// stays 5 (DEPLOY_FAILED) — unchanged by this test, exercised in CLI tests.
    #[tokio::test]
    async fn test_health_unexpected_status_propagates_reason() {
        let tmp = tempfile::tempdir().unwrap();
        let config = test_slip_config(tmp.path().to_path_buf());
        let mut apps = HashMap::new();
        apps.insert("testapp".to_string(), test_app_config());
        let apps: RwLock<HashMap<String, AppConfig>> = RwLock::new(apps);
        let app_states: RwLock<HashMap<String, AppRuntimeState>> = RwLock::new(HashMap::new());
        let deploys: DashMap<String, DeployContext> = DashMap::new();

        let docker = MockDocker::new();
        let stop_count = docker.stop_count();
        let caddy = MockCaddy::success();
        let health = MockHealth::unexpected_status();

        execute_deploy_inner(
            make_shared(&config, &apps, &app_states, &deploys),
            &docker,
            &caddy,
            &health,
            &mut test_deploy_ctx(),
        )
        .await;

        // New container should have been stopped (rollback).
        assert_eq!(
            stop_count.load(Ordering::SeqCst),
            1,
            "new container should be stopped"
        );

        // Deploy should be Failed and the error must carry the new tag.
        let recorded = deploys.get("testapp").unwrap();
        assert_eq!(recorded.status, DeployStatus::Failed);
        let err = recorded.error.as_deref().unwrap_or("");
        assert!(
            err.contains("[health_unexpected_status]"),
            "must carry health_unexpected_status tag, got: {err}"
        );
        // Structured detail (no bodies/headers).
        assert!(err.contains("expected 200"), "must carry expected: {err}");
        assert!(err.contains("got 307"), "must carry actual: {err}");
        assert!(
            err.contains("after 3 attempts"),
            "must carry attempts: {err}"
        );
        assert!(
            !err.contains("body") && !err.contains("header"),
            "must not leak bodies or headers: {err}"
        );
    }

    /// Image pull failure: deploy should fail early without starting a container.
    #[tokio::test]
    async fn test_image_pull_failure() {
        let tmp = tempfile::tempdir().unwrap();
        let config = test_slip_config(tmp.path().to_path_buf());
        let mut apps = HashMap::new();
        apps.insert("testapp".to_string(), test_app_config());
        let apps: RwLock<HashMap<String, AppConfig>> = RwLock::new(apps);
        let app_states: RwLock<HashMap<String, AppRuntimeState>> = RwLock::new(HashMap::new());
        let deploys: DashMap<String, DeployContext> = DashMap::new();

        let docker = MockDocker::failing_pull();
        let stop_count = docker.stop_count();
        let caddy = MockCaddy::success();
        let health = MockHealth::passing();

        execute_deploy_inner(
            make_shared(&config, &apps, &app_states, &deploys),
            &docker,
            &caddy,
            &health,
            &mut test_deploy_ctx(),
        )
        .await;

        // No containers should have been started or stopped.
        assert_eq!(
            stop_count.load(Ordering::SeqCst),
            0,
            "no container stop should occur"
        );

        // Deploy should be Failed with a pull error.
        let recorded = deploys.get("testapp").unwrap();
        assert_eq!(recorded.status, DeployStatus::Failed);
        assert!(
            recorded
                .error
                .as_deref()
                .unwrap_or("")
                .contains("image pull failed")
        );

        // App state should be untouched.
        let states = app_states.read().await;
        assert!(states.get("testapp").is_none());
    }

    /// Caddy route update failure: new container should be stopped, old
    /// container should remain, deploy recorded as Failed.
    #[tokio::test]
    async fn test_caddy_route_failure_stops_new_container() {
        let tmp = tempfile::tempdir().unwrap();
        let config = test_slip_config(tmp.path().to_path_buf());
        let mut apps = HashMap::new();
        apps.insert("testapp".to_string(), test_app_config());
        let apps: RwLock<HashMap<String, AppConfig>> = RwLock::new(apps);

        // Pre-populate with an old container to verify it is NOT stopped.
        let mut initial_states = HashMap::new();
        initial_states.insert(
            "testapp".to_string(),
            AppRuntimeState {
                status: AppStatus::Running,
                current_tag: Some("v0.9.0".to_string()),
                current_container_id: Some("old-container-keep".to_string()),
                current_port: Some(50001),
                ..Default::default()
            },
        );
        let app_states: RwLock<HashMap<String, AppRuntimeState>> = RwLock::new(initial_states);
        let deploys: DashMap<String, DeployContext> = DashMap::new();

        let docker = MockDocker::new();
        let stop_count = docker.stop_count();
        let caddy = MockCaddy::failing(); // Caddy always fails
        let health = MockHealth::passing();

        execute_deploy_inner(
            make_shared(&config, &apps, &app_states, &deploys),
            &docker,
            &caddy,
            &health,
            &mut test_deploy_ctx(),
        )
        .await;

        // New container should have been stopped (rollback), but only once.
        assert_eq!(
            stop_count.load(Ordering::SeqCst),
            1,
            "only new container should be stopped"
        );

        // Deploy should be Failed with a caddy error.
        let recorded = deploys.get("testapp").unwrap();
        assert_eq!(recorded.status, DeployStatus::Failed);
        assert!(
            recorded
                .error
                .as_deref()
                .unwrap_or("")
                .contains("caddy route update failed")
        );

        // Old container should still be current (state not updated).
        let states = app_states.read().await;
        let app = states.get("testapp").unwrap();
        assert_eq!(
            app.current_container_id.as_deref(),
            Some("old-container-keep"),
            "old container should be preserved"
        );
    }

    // ── Config extraction integration tests ───────────────────────────────────

    fn valid_repo_config_bytes(app_name: &str) -> Vec<u8> {
        format!(
            r#"
[app]
name = "{app_name}"
kind = "container"

[health]
path = "/healthz"

[defaults.resources]
memory = "256m"
"#
        )
        .into_bytes()
    }

    /// Deploy with a valid repo config in the image: merged config should be used.
    #[tokio::test]
    async fn test_deploy_with_repo_config_uses_merged_config() {
        let tmp = tempfile::tempdir().unwrap();
        let config = test_slip_config(tmp.path().to_path_buf());
        let mut apps = HashMap::new();
        // Server config has no health path
        apps.insert("testapp".to_string(), test_app_config());
        let apps: RwLock<HashMap<String, AppConfig>> = RwLock::new(apps);
        let app_states: RwLock<HashMap<String, AppRuntimeState>> = RwLock::new(HashMap::new());
        let deploys: DashMap<String, DeployContext> = DashMap::new();

        let docker = MockDocker::with_repo_config(valid_repo_config_bytes("testapp"));
        let caddy = MockCaddy::success();
        let health = MockHealth::passing();
        let mut ctx = test_deploy_ctx();

        execute_deploy_inner(
            make_shared(&config, &apps, &app_states, &deploys),
            &docker,
            &caddy,
            &health,
            &mut ctx,
        )
        .await;

        // Deploy should succeed even with a repo config present
        let recorded = deploys.get("testapp").unwrap();
        assert_eq!(recorded.status, DeployStatus::Completed);
        assert!(recorded.error.is_none());
    }

    /// Deploy with no repo config in the image: server config used (backwards compat).
    #[tokio::test]
    async fn test_deploy_without_repo_config_uses_server_config() {
        let tmp = tempfile::tempdir().unwrap();
        let config = test_slip_config(tmp.path().to_path_buf());
        let mut apps = HashMap::new();
        apps.insert("testapp".to_string(), test_app_config());
        let apps: RwLock<HashMap<String, AppConfig>> = RwLock::new(apps);
        let app_states: RwLock<HashMap<String, AppRuntimeState>> = RwLock::new(HashMap::new());
        let deploys: DashMap<String, DeployContext> = DashMap::new();

        // extract_file returns None (file not found in image)
        let docker = MockDocker::with_no_repo_config();
        let caddy = MockCaddy::success();
        let health = MockHealth::passing();
        let mut ctx = test_deploy_ctx();

        execute_deploy_inner(
            make_shared(&config, &apps, &app_states, &deploys),
            &docker,
            &caddy,
            &health,
            &mut ctx,
        )
        .await;

        // Deploy should succeed using server config only
        let recorded = deploys.get("testapp").unwrap();
        assert_eq!(recorded.status, DeployStatus::Completed);
        assert!(recorded.error.is_none());
    }

    /// Deploy with invalid TOML in the repo config: deploy fails with parse error.
    #[tokio::test]
    async fn test_deploy_with_invalid_repo_config_fails() {
        let tmp = tempfile::tempdir().unwrap();
        let config = test_slip_config(tmp.path().to_path_buf());
        let mut apps = HashMap::new();
        apps.insert("testapp".to_string(), test_app_config());
        let apps: RwLock<HashMap<String, AppConfig>> = RwLock::new(apps);
        let app_states: RwLock<HashMap<String, AppRuntimeState>> = RwLock::new(HashMap::new());
        let deploys: DashMap<String, DeployContext> = DashMap::new();

        // extract_file returns Some(invalid TOML bytes)
        let docker = MockDocker::with_repo_config(b"[app\ninvalid toml!!!".to_vec());
        let caddy = MockCaddy::success();
        let health = MockHealth::passing();

        execute_deploy_inner(
            make_shared(&config, &apps, &app_states, &deploys),
            &docker,
            &caddy,
            &health,
            &mut test_deploy_ctx(),
        )
        .await;

        let recorded = deploys.get("testapp").unwrap();
        assert_eq!(recorded.status, DeployStatus::Failed);
        assert!(
            recorded
                .error
                .as_deref()
                .unwrap_or("")
                .contains("failed to parse repo config")
        );
    }

    /// Deploy with `extract_file` returning `Unsupported`: deploy continues
    /// with server config (backwards compat for runtimes without extraction).
    #[tokio::test]
    async fn test_deploy_with_unsupported_extract_file_continues() {
        let tmp = tempfile::tempdir().unwrap();
        let config = test_slip_config(tmp.path().to_path_buf());
        let mut apps = HashMap::new();
        apps.insert("testapp".to_string(), test_app_config());
        let apps: RwLock<HashMap<String, AppConfig>> = RwLock::new(apps);
        let app_states: RwLock<HashMap<String, AppRuntimeState>> = RwLock::new(HashMap::new());
        let deploys: DashMap<String, DeployContext> = DashMap::new();

        // MockDocker::new() returns Unsupported by default
        let docker = MockDocker::new();
        let caddy = MockCaddy::success();
        let health = MockHealth::passing();
        let mut ctx = test_deploy_ctx();

        execute_deploy_inner(
            make_shared(&config, &apps, &app_states, &deploys),
            &docker,
            &caddy,
            &health,
            &mut ctx,
        )
        .await;

        // Should complete successfully using server config
        let recorded = deploys.get("testapp").unwrap();
        assert_eq!(recorded.status, DeployStatus::Completed);
        assert!(recorded.error.is_none());
    }

    /// Deploy where `extract_file` returns a non-Unsupported error: deploy fails.
    #[tokio::test]
    async fn test_deploy_with_extract_file_fatal_error_fails() {
        let tmp = tempfile::tempdir().unwrap();
        let config = test_slip_config(tmp.path().to_path_buf());
        let mut apps = HashMap::new();
        apps.insert("testapp".to_string(), test_app_config());
        let apps: RwLock<HashMap<String, AppConfig>> = RwLock::new(apps);
        let app_states: RwLock<HashMap<String, AppRuntimeState>> = RwLock::new(HashMap::new());
        let deploys: DashMap<String, DeployContext> = DashMap::new();

        // A connection error — not Unsupported — should abort the deploy
        let docker = MockDocker::with_extract_error(RuntimeError::Connection(
            "network unreachable".to_string(),
        ));
        let caddy = MockCaddy::success();
        let health = MockHealth::passing();

        execute_deploy_inner(
            make_shared(&config, &apps, &app_states, &deploys),
            &docker,
            &caddy,
            &health,
            &mut test_deploy_ctx(),
        )
        .await;

        let recorded = deploys.get("testapp").unwrap();
        assert_eq!(recorded.status, DeployStatus::Failed);
        assert!(
            recorded
                .error
                .as_deref()
                .unwrap_or("")
                .contains("failed to extract config from image")
        );
    }

    /// Deploy where repo config's app name doesn't match the deploy app: fails.
    #[tokio::test]
    async fn test_deploy_repo_config_name_mismatch_fails() {
        let tmp = tempfile::tempdir().unwrap();
        let config = test_slip_config(tmp.path().to_path_buf());
        let mut apps = HashMap::new();
        apps.insert("testapp".to_string(), test_app_config());
        let apps: RwLock<HashMap<String, AppConfig>> = RwLock::new(apps);
        let app_states: RwLock<HashMap<String, AppRuntimeState>> = RwLock::new(HashMap::new());
        let deploys: DashMap<String, DeployContext> = DashMap::new();

        // Repo config has a different app name
        let docker = MockDocker::with_repo_config(valid_repo_config_bytes("differentapp"));
        let caddy = MockCaddy::success();
        let health = MockHealth::passing();

        execute_deploy_inner(
            make_shared(&config, &apps, &app_states, &deploys),
            &docker,
            &caddy,
            &health,
            &mut test_deploy_ctx(),
        )
        .await;

        let recorded = deploys.get("testapp").unwrap();
        assert_eq!(recorded.status, DeployStatus::Failed);
        assert!(
            recorded
                .error
                .as_deref()
                .unwrap_or("")
                .contains("does not match deploy app")
        );
    }

    // ── Pod deploy helpers ────────────────────────────────────────────────────

    /// A minimal Kubernetes Pod YAML suitable for pod deploy tests.
    const POD_YAML_FIXTURE: &str = r#"apiVersion: v1
kind: Pod
metadata:
  name: testapp
  labels:
    app: testapp
spec:
  containers:
    - name: web
      image: ghcr.io/org/testapp:latest
      ports:
        - containerPort: 3000
          hostPort: 3000
"#;

    /// Build a pod-kind repo config TOML for `app_name`, pointing to `pod.yaml`.
    fn pod_repo_config_bytes(app_name: &str) -> Vec<u8> {
        format!(
            r#"
[app]
name = "{app_name}"
kind = "pod"
manifest = "/slip/pod.yaml"

[routing]
container = "web"

[health]
path = "/health"
"#
        )
        .into_bytes()
    }

    /// A `DeployContext` for pod tests (same app, different deploy id).
    fn pod_deploy_ctx() -> DeployContext {
        DeployContext::new(
            "dep_pod001".to_string(),
            "testapp".to_string(),
            "ghcr.io/org/testapp".to_string(),
            "v2.0.0".to_string(),
            TriggerSource::Webhook,
        )
    }

    // ── Pod deploy tests ──────────────────────────────────────────────────────

    /// Happy-path pod blue-green deploy: should complete, record pod name, and
    /// set `current_pod_name` + `current_port` on the app state.
    #[tokio::test]
    async fn test_pod_deploy_happy_path() {
        let tmp = tempfile::tempdir().unwrap();
        let config = test_slip_config(tmp.path().to_path_buf());
        let mut apps = HashMap::new();
        apps.insert("testapp".to_string(), test_app_config());
        let apps: RwLock<HashMap<String, AppConfig>> = RwLock::new(apps);
        let app_states: RwLock<HashMap<String, AppRuntimeState>> = RwLock::new(HashMap::new());
        let deploys: DashMap<String, DeployContext> = DashMap::new();

        let docker = MockDocker::with_pod_support(
            pod_repo_config_bytes("testapp"),
            POD_YAML_FIXTURE.as_bytes().to_vec(),
            44444,
        );
        let teardown_count = docker.teardown_count();
        let caddy = MockCaddy::success();
        let health = MockHealth::passing();
        let mut ctx = pod_deploy_ctx();

        execute_deploy_inner(
            make_shared(&config, &apps, &app_states, &deploys),
            &docker,
            &caddy,
            &health,
            &mut ctx,
        )
        .await;

        // Deploy should be Completed.
        let recorded = deploys.get("testapp").unwrap();
        assert_eq!(recorded.status, DeployStatus::Completed);
        assert!(recorded.error.is_none());
        assert!(recorded.new_pod_name.is_some(), "pod name should be set");
        assert!(
            recorded.new_manifest_path.is_some(),
            "manifest path should be set"
        );
        assert_eq!(recorded.new_port, Some(44444));

        // App state should have pod fields set.
        let states = app_states.read().await;
        let app = states.get("testapp").expect("app state should exist");
        assert_eq!(app.status, AppStatus::Running);
        assert_eq!(app.current_tag.as_deref(), Some("v2.0.0"));
        assert!(
            app.current_pod_name.is_some(),
            "current_pod_name should be set"
        );
        assert!(
            app.current_manifest_path.is_some(),
            "current_manifest_path should be set"
        );
        assert_eq!(app.current_port, Some(44444));
        // No teardown of old pod since this is a first deploy.
        assert_eq!(teardown_count.load(Ordering::SeqCst), 0);
    }

    /// Pod deploy health failure: new pod should be torn down, deploy fails.
    #[tokio::test]
    async fn test_pod_deploy_health_failure_tears_down_new_pod() {
        let tmp = tempfile::tempdir().unwrap();
        let config = test_slip_config(tmp.path().to_path_buf());
        let mut apps = HashMap::new();
        apps.insert("testapp".to_string(), test_app_config());
        let apps: RwLock<HashMap<String, AppConfig>> = RwLock::new(apps);
        let app_states: RwLock<HashMap<String, AppRuntimeState>> = RwLock::new(HashMap::new());
        let deploys: DashMap<String, DeployContext> = DashMap::new();

        let docker = MockDocker::with_pod_support(
            pod_repo_config_bytes("testapp"),
            POD_YAML_FIXTURE.as_bytes().to_vec(),
            44444,
        );
        let teardown_count = docker.teardown_count();
        let caddy = MockCaddy::success();
        let health = MockHealth::failing(); // health check fails

        execute_deploy_inner(
            make_shared(&config, &apps, &app_states, &deploys),
            &docker,
            &caddy,
            &health,
            &mut pod_deploy_ctx(),
        )
        .await;

        // Deploy should be Failed.
        let recorded = deploys.get("testapp").unwrap();
        assert_eq!(recorded.status, DeployStatus::Failed);
        assert!(
            recorded
                .error
                .as_deref()
                .unwrap_or("")
                .contains("health check failed")
        );

        // New pod should have been torn down.
        assert_eq!(
            teardown_count.load(Ordering::SeqCst),
            1,
            "new pod should be torn down on health failure"
        );

        // App state should not have been updated.
        let states = app_states.read().await;
        assert!(
            states.get("testapp").is_none(),
            "app state should not have been set on failure"
        );
    }

    /// Pod deploy: kind=pod but repo config has no `manifest` field → fails.
    #[tokio::test]
    async fn test_pod_deploy_missing_manifest_fails() {
        let tmp = tempfile::tempdir().unwrap();
        let config = test_slip_config(tmp.path().to_path_buf());
        let mut apps = HashMap::new();
        apps.insert("testapp".to_string(), test_app_config());
        let apps: RwLock<HashMap<String, AppConfig>> = RwLock::new(apps);
        let app_states: RwLock<HashMap<String, AppRuntimeState>> = RwLock::new(HashMap::new());
        let deploys: DashMap<String, DeployContext> = DashMap::new();

        // Repo config is pod kind but has no manifest path.
        let no_manifest_toml = br#"
[app]
name = "testapp"
kind = "pod"

[routing]
container = "web"
"#
        .to_vec();

        let docker = MockDocker::with_pod_support(
            no_manifest_toml,
            POD_YAML_FIXTURE.as_bytes().to_vec(),
            44444,
        );
        let caddy = MockCaddy::success();
        let health = MockHealth::passing();

        execute_deploy_inner(
            make_shared(&config, &apps, &app_states, &deploys),
            &docker,
            &caddy,
            &health,
            &mut pod_deploy_ctx(),
        )
        .await;

        let recorded = deploys.get("testapp").unwrap();
        assert_eq!(recorded.status, DeployStatus::Failed);
        assert!(
            recorded.error.as_deref().unwrap_or("").contains("manifest"),
            "error should mention manifest: {:?}",
            recorded.error
        );
    }

    /// First pod deploy with no old pod: teardown should NOT be called.
    #[tokio::test]
    async fn test_pod_first_deploy_no_old_pod() {
        let tmp = tempfile::tempdir().unwrap();
        let config = test_slip_config(tmp.path().to_path_buf());
        let mut apps = HashMap::new();
        apps.insert("testapp".to_string(), test_app_config());
        let apps: RwLock<HashMap<String, AppConfig>> = RwLock::new(apps);
        // No pre-existing pod state.
        let app_states: RwLock<HashMap<String, AppRuntimeState>> = RwLock::new(HashMap::new());
        let deploys: DashMap<String, DeployContext> = DashMap::new();

        let docker = MockDocker::with_pod_support(
            pod_repo_config_bytes("testapp"),
            POD_YAML_FIXTURE.as_bytes().to_vec(),
            55555,
        );
        let teardown_count = docker.teardown_count();
        let caddy = MockCaddy::success();
        let health = MockHealth::passing();

        execute_deploy_inner(
            make_shared(&config, &apps, &app_states, &deploys),
            &docker,
            &caddy,
            &health,
            &mut pod_deploy_ctx(),
        )
        .await;

        let recorded = deploys.get("testapp").unwrap();
        assert_eq!(recorded.status, DeployStatus::Completed);
        // teardown_pod should NOT have been called (no old pod).
        assert_eq!(
            teardown_count.load(Ordering::SeqCst),
            0,
            "teardown_pod should not be called on first pod deploy"
        );
    }

    /// Subsequent pod deploy: old pod manifest should be torn down after new pod is live.
    #[tokio::test]
    async fn test_pod_subsequent_deploy_tears_down_old_pod() {
        let tmp = tempfile::tempdir().unwrap();
        let config = test_slip_config(tmp.path().to_path_buf());
        let mut apps = HashMap::new();
        apps.insert("testapp".to_string(), test_app_config());
        let apps: RwLock<HashMap<String, AppConfig>> = RwLock::new(apps);

        // Pre-populate app state with an existing pod.
        let old_manifest_path = tmp.path().join("manifests").join("testapp-old.yaml");
        std::fs::create_dir_all(old_manifest_path.parent().unwrap()).unwrap();
        std::fs::write(&old_manifest_path, b"old manifest content").unwrap();

        let mut initial_states = HashMap::new();
        initial_states.insert(
            "testapp".to_string(),
            AppRuntimeState {
                status: AppStatus::Running,
                current_tag: Some("v1.0.0".to_string()),
                current_pod_name: Some("testapp-oldpod".to_string()),
                current_manifest_path: Some(old_manifest_path.clone()),
                current_port: Some(40000),
                ..Default::default()
            },
        );
        let app_states: RwLock<HashMap<String, AppRuntimeState>> = RwLock::new(initial_states);
        let deploys: DashMap<String, DeployContext> = DashMap::new();

        let docker = MockDocker::with_pod_support(
            pod_repo_config_bytes("testapp"),
            POD_YAML_FIXTURE.as_bytes().to_vec(),
            55556,
        );
        let teardown_count = docker.teardown_count();
        let caddy = MockCaddy::success();
        let health = MockHealth::passing();

        execute_deploy_inner(
            make_shared(&config, &apps, &app_states, &deploys),
            &docker,
            &caddy,
            &health,
            &mut pod_deploy_ctx(),
        )
        .await;

        let recorded = deploys.get("testapp").unwrap();
        assert_eq!(recorded.status, DeployStatus::Completed);

        // teardown_pod should have been called exactly once (old pod).
        assert_eq!(
            teardown_count.load(Ordering::SeqCst),
            1,
            "old pod should be torn down after successful deploy"
        );

        // New pod should now be current.
        let states = app_states.read().await;
        let app = states.get("testapp").unwrap();
        assert_eq!(app.current_port, Some(55556));
        assert!(app.current_pod_name.is_some());
        // New pod name should be different from old.
        assert_ne!(
            app.current_pod_name.as_deref(),
            Some("testapp-oldpod"),
            "new pod should have a different name"
        );
    }

    // ── Rollback deploy tests ────────────────────────────────────────────────

    /// Deploy with TriggerSource::Rollback should complete and record the
    /// correct trigger source.
    #[tokio::test]
    async fn test_rollback_deploy_uses_trigger_source() {
        let tmp = tempfile::tempdir().unwrap();
        let config = test_slip_config(tmp.path().to_path_buf());
        let mut apps = HashMap::new();
        apps.insert("testapp".to_string(), test_app_config());
        let apps: RwLock<HashMap<String, AppConfig>> = RwLock::new(apps);
        let app_states: RwLock<HashMap<String, AppRuntimeState>> = RwLock::new(HashMap::new());
        let deploys: DashMap<String, DeployContext> = DashMap::new();

        let docker = MockDocker::new();
        let caddy = MockCaddy::success();
        let health = MockHealth::passing();

        let mut ctx = DeployContext::new(
            "dep_rollback001".to_string(),
            "testapp".to_string(),
            "ghcr.io/org/testapp".to_string(),
            "v1.0.0".to_string(),
            TriggerSource::Rollback,
        );

        execute_deploy_inner(
            make_shared(&config, &apps, &app_states, &deploys),
            &docker,
            &caddy,
            &health,
            &mut ctx,
        )
        .await;

        // Deploy should complete successfully.
        let recorded = deploys.get("testapp").unwrap();
        assert_eq!(recorded.status, DeployStatus::Completed);
        assert!(recorded.error.is_none());
        // Verify trigger source is Rollback.
        assert_eq!(recorded.triggered_by, TriggerSource::Rollback);
    }

    /// Rollback should flip current_tag ↔ previous_tag.
    /// Pre-populate with current=v2.0, previous=v1.0, then deploy v1.0 (rollback).
    /// After deploy: current=v1.0, previous=v2.0.
    #[tokio::test]
    async fn test_rollback_updates_previous_tag() {
        let tmp = tempfile::tempdir().unwrap();
        let config = test_slip_config(tmp.path().to_path_buf());
        let mut apps = HashMap::new();
        apps.insert("testapp".to_string(), test_app_config());
        let apps: RwLock<HashMap<String, AppConfig>> = RwLock::new(apps);

        // Pre-populate app state with current=v2.0, previous=v1.0.
        let mut initial_states = HashMap::new();
        initial_states.insert(
            "testapp".to_string(),
            AppRuntimeState {
                status: AppStatus::Running,
                current_tag: Some("v2.0".to_string()),
                previous_tag: Some("v1.0".to_string()),
                current_container_id: Some("old-container".to_string()),
                current_port: Some(50000),
                ..Default::default()
            },
        );
        let app_states: RwLock<HashMap<String, AppRuntimeState>> = RwLock::new(initial_states);
        let deploys: DashMap<String, DeployContext> = DashMap::new();

        let docker = MockDocker::new();
        let caddy = MockCaddy::success();
        let health = MockHealth::passing();

        // Deploy v1.0 — simulating a rollback.
        let mut ctx = DeployContext::new(
            "dep_rollback002".to_string(),
            "testapp".to_string(),
            "ghcr.io/org/testapp".to_string(),
            "v1.0".to_string(),
            TriggerSource::Rollback,
        );

        execute_deploy_inner(
            make_shared(&config, &apps, &app_states, &deploys),
            &docker,
            &caddy,
            &health,
            &mut ctx,
        )
        .await;

        // After rollback deploy: current_tag=v1.0, previous_tag=v2.0.
        let states = app_states.read().await;
        let app = states.get("testapp").expect("app state should exist");
        assert_eq!(app.current_tag.as_deref(), Some("v1.0"));
        assert_eq!(app.previous_tag.as_deref(), Some("v2.0"));
    }

    // ── Secrets injection tests ────────────────────────────────────────────────

    #[test]
    fn test_resolve_env_vars_without_secrets() {
        let app_config = AppConfig {
            app: AppInfo {
                name: "testapp".to_string(),
                image: "ghcr.io/org/testapp".to_string(),
                secret: None,
            },
            routing: RoutingConfig {
                domain: Some("testapp.example.com".to_string()),
                port: Some(3000),
                routes: vec![],
                tls: None,
            },
            health: HealthConfig::default(),
            deploy: DeployConfig::default(),
            env: HashMap::from([
                ("KEY_A".to_string(), "val_a".to_string()),
                ("KEY_B".to_string(), "val_b".to_string()),
            ]),
            env_file: None,
            resources: ResourceConfig::default(),
            network: crate::config::NetworkConfig::default(),
            preview: None,
            volumes: Vec::new(),
        };

        let vars = resolve_env_vars_for_app(&app_config, None, "testapp");
        assert_eq!(vars.len(), 2);
        assert!(vars.contains(&"KEY_A=val_a".to_string()));
        assert!(vars.contains(&"KEY_B=val_b".to_string()));
    }

    #[test]
    fn test_resolve_env_vars_with_secrets() {
        let tmp = tempfile::tempdir().unwrap();
        let store = crate::secrets::SecretsStore::new(tmp.path().join("secrets")).unwrap();
        store
            .set("testapp", "DB_URL", "postgres://secret/db")
            .unwrap();
        store.set("testapp", "API_KEY", "sk-secret").unwrap();

        let app_config = AppConfig {
            app: AppInfo {
                name: "testapp".to_string(),
                image: "ghcr.io/org/testapp".to_string(),
                secret: None,
            },
            routing: RoutingConfig {
                domain: Some("testapp.example.com".to_string()),
                port: Some(3000),
                routes: vec![],
                tls: None,
            },
            health: HealthConfig::default(),
            deploy: DeployConfig::default(),
            env: HashMap::from([("KEY_A".to_string(), "val_a".to_string())]),
            env_file: None,
            resources: ResourceConfig::default(),
            network: crate::config::NetworkConfig::default(),
            preview: None,
            volumes: Vec::new(),
        };

        let vars = resolve_env_vars_for_app(&app_config, Some(&store), "testapp");
        assert_eq!(vars.len(), 3);
        assert!(vars.contains(&"KEY_A=val_a".to_string()));
        assert!(vars.contains(&"DB_URL=postgres://secret/db".to_string()));
        assert!(vars.contains(&"API_KEY=sk-secret".to_string()));
    }

    #[test]
    fn test_secrets_override_env() {
        let tmp = tempfile::tempdir().unwrap();
        let store = crate::secrets::SecretsStore::new(tmp.path().join("secrets")).unwrap();
        // Secret with the same key as an env var
        store.set("testapp", "DB_URL", "secret-value").unwrap();

        let app_config = AppConfig {
            app: AppInfo {
                name: "testapp".to_string(),
                image: "ghcr.io/org/testapp".to_string(),
                secret: None,
            },
            routing: RoutingConfig {
                domain: Some("testapp.example.com".to_string()),
                port: Some(3000),
                routes: vec![],
                tls: None,
            },
            health: HealthConfig::default(),
            deploy: DeployConfig::default(),
            env: HashMap::from([("DB_URL".to_string(), "env-value".to_string())]),
            env_file: None,
            resources: ResourceConfig::default(),
            network: crate::config::NetworkConfig::default(),
            preview: None,
            volumes: Vec::new(),
        };

        let vars = resolve_env_vars_for_app(&app_config, Some(&store), "testapp");
        // Only one entry for DB_URL, and it should be the secret value
        assert_eq!(vars.len(), 1);
        assert_eq!(vars[0], "DB_URL=secret-value");
    }

    #[test]
    fn test_deploy_without_secrets_still_works() {
        // No secrets store → same behavior as before
        let app_config = AppConfig {
            app: AppInfo {
                name: "testapp".to_string(),
                image: "ghcr.io/org/testapp".to_string(),
                secret: None,
            },
            routing: RoutingConfig {
                domain: Some("testapp.example.com".to_string()),
                port: Some(3000),
                routes: vec![],
                tls: None,
            },
            health: HealthConfig::default(),
            deploy: DeployConfig::default(),
            env: HashMap::from([("KEY_A".to_string(), "val_a".to_string())]),
            env_file: None,
            resources: ResourceConfig::default(),
            network: crate::config::NetworkConfig::default(),
            preview: None,
            volumes: Vec::new(),
        };

        let vars = resolve_env_vars_for_app(&app_config, None, "testapp");
        assert_eq!(vars, vec!["KEY_A=val_a"]);
    }

    // ── parse_image_ref tests ──────────────────────────────────────────────────

    #[test]
    fn parse_image_ref_standard_tag() {
        let (image, tag) = parse_image_ref("ghcr.io/org/app:v1.2.3");
        assert_eq!(image, "ghcr.io/org/app");
        assert_eq!(tag, "v1.2.3");
    }

    #[test]
    fn parse_image_ref_digest() {
        let (image, tag) = parse_image_ref("ghcr.io/org/app@sha256:abc123def456");
        assert_eq!(image, "ghcr.io/org/app");
        assert_eq!(tag, "sha256:abc123def456");
    }

    #[test]
    fn parse_image_ref_no_tag_defaults_latest() {
        let (image, tag) = parse_image_ref("ghcr.io/org/app");
        assert_eq!(image, "ghcr.io/org/app");
        assert_eq!(tag, "latest");
    }

    #[test]
    fn parse_image_ref_short_name() {
        let (image, tag) = parse_image_ref("redis:7-alpine");
        assert_eq!(image, "redis");
        assert_eq!(tag, "7-alpine");
    }

    #[test]
    fn parse_image_ref_registry_with_port() {
        // registry:5000 is a port, not a tag
        let (image, tag) = parse_image_ref("registry:5000/img:v1");
        assert_eq!(image, "registry:5000/img");
        assert_eq!(tag, "v1");
    }

    // ── Recreate strategy tests ───────────────────────────────────────────────

    fn recreate_app_config() -> AppConfig {
        AppConfig {
            deploy: DeployConfig {
                strategy: "recreate".to_string(),
                drain_timeout: Duration::ZERO,
                timeout: None,
            },
            ..test_app_config()
        }
    }

    /// Happy path: recreate with old container.
    /// Verify: stop_container called on old BEFORE create_and_start,
    /// remove_route called, health check passes, set_route called,
    /// stop_and_remove called on old (cleanup), status=Completed.
    #[tokio::test]
    async fn test_recreate_happy_path_full_deploy() {
        let tmp = tempfile::tempdir().unwrap();
        let config = test_slip_config(tmp.path().to_path_buf());
        let mut apps = HashMap::new();
        apps.insert("testapp".to_string(), recreate_app_config());
        let apps: RwLock<HashMap<String, AppConfig>> = RwLock::new(apps);

        // Pre-populate app state with an existing container.
        let mut initial_states = HashMap::new();
        initial_states.insert(
            "testapp".to_string(),
            AppRuntimeState {
                status: AppStatus::Running,
                current_tag: Some("v0.9.0".to_string()),
                current_container_id: Some("old-container-id".to_string()),
                current_port: Some(50000),
                ..Default::default()
            },
        );
        let app_states: RwLock<HashMap<String, AppRuntimeState>> = RwLock::new(initial_states);
        let deploys: DashMap<String, DeployContext> = DashMap::new();

        let docker = MockDocker::new();
        let stop_only_count = docker.stop_only_count();
        let stop_count = docker.stop_count();
        let caddy = MockCaddy::success();
        let health = MockHealth::passing();

        execute_deploy_inner(
            make_shared(&config, &apps, &app_states, &deploys),
            &docker,
            &caddy,
            &health,
            &mut test_deploy_ctx(),
        )
        .await;

        // stop_container should have been called on old (stop only, not remove)
        assert_eq!(
            stop_only_count.load(Ordering::SeqCst),
            1,
            "stop_container should be called on old container"
        );

        // stop_and_remove should have been called on old (cleanup after success)
        assert_eq!(
            stop_count.load(Ordering::SeqCst),
            1,
            "stop_and_remove should be called on old container (cleanup)"
        );

        // Status should be Completed.
        let recorded = deploys.get("testapp").unwrap();
        assert_eq!(recorded.status, DeployStatus::Completed);
        assert!(recorded.error.is_none());

        // New container should be current.
        let states = app_states.read().await;
        let app = states.get("testapp").unwrap();
        assert_eq!(
            app.current_container_id.as_deref(),
            Some("mock-container-id")
        );
        assert_eq!(
            app.previous_container_id.as_deref(),
            Some("old-container-id")
        );
    }

    /// First deploy with recreate: no old container to stop.
    /// Verify: stop_container NOT called, create_and_start called,
    /// stop_and_remove NOT called (no old to clean up), status=Completed.
    #[tokio::test]
    async fn test_recreate_first_deploy_no_old_container() {
        let tmp = tempfile::tempdir().unwrap();
        let config = test_slip_config(tmp.path().to_path_buf());
        let mut apps = HashMap::new();
        apps.insert("testapp".to_string(), recreate_app_config());
        let apps: RwLock<HashMap<String, AppConfig>> = RwLock::new(apps);
        let app_states: RwLock<HashMap<String, AppRuntimeState>> = RwLock::new(HashMap::new());
        let deploys: DashMap<String, DeployContext> = DashMap::new();

        let docker = MockDocker::new();
        let stop_only_count = docker.stop_only_count();
        let stop_count = docker.stop_count();
        let caddy = MockCaddy::success();
        let health = MockHealth::passing();

        execute_deploy_inner(
            make_shared(&config, &apps, &app_states, &deploys),
            &docker,
            &caddy,
            &health,
            &mut test_deploy_ctx(),
        )
        .await;

        // stop_container should NOT have been called (no old container).
        assert_eq!(stop_only_count.load(Ordering::SeqCst), 0);
        // stop_and_remove should NOT have been called (no old to clean up).
        assert_eq!(stop_count.load(Ordering::SeqCst), 0);

        // Status should be Completed.
        let recorded = deploys.get("testapp").unwrap();
        assert_eq!(recorded.status, DeployStatus::Completed);
        assert!(recorded.error.is_none());
    }

    /// Recreate with health check failure: old container should be restarted.
    #[tokio::test]
    async fn test_recreate_health_check_failure_rollback() {
        let tmp = tempfile::tempdir().unwrap();
        let config = test_slip_config(tmp.path().to_path_buf());
        let mut apps = HashMap::new();
        apps.insert("testapp".to_string(), recreate_app_config());
        let apps: RwLock<HashMap<String, AppConfig>> = RwLock::new(apps);

        // Pre-populate app state with an existing container.
        let mut initial_states = HashMap::new();
        initial_states.insert(
            "testapp".to_string(),
            AppRuntimeState {
                status: AppStatus::Running,
                current_tag: Some("v0.9.0".to_string()),
                current_container_id: Some("old-container-id".to_string()),
                current_port: Some(50000),
                ..Default::default()
            },
        );
        let app_states: RwLock<HashMap<String, AppRuntimeState>> = RwLock::new(initial_states);
        let deploys: DashMap<String, DeployContext> = DashMap::new();

        let docker = MockDocker::new();
        let stop_only_count = docker.stop_only_count();
        let start_count = docker.start_count();
        let stop_count = docker.stop_count();
        let caddy = MockCaddy::success();
        let health = MockHealth::failing(); // health check always fails

        execute_deploy_inner(
            make_shared(&config, &apps, &app_states, &deploys),
            &docker,
            &caddy,
            &health,
            &mut test_deploy_ctx(),
        )
        .await;

        // stop_container should have been called on old.
        assert_eq!(stop_only_count.load(Ordering::SeqCst), 1);

        // start_container should have been called (Tier 1 rollback).
        assert_eq!(start_count.load(Ordering::SeqCst), 1);

        // stop_and_remove should have been called on new container (cleanup).
        assert_eq!(stop_count.load(Ordering::SeqCst), 1);

        // Status should be Failed.
        let recorded = deploys.get("testapp").unwrap();
        assert_eq!(recorded.status, DeployStatus::Failed);
        assert!(
            recorded
                .error
                .as_deref()
                .unwrap_or("")
                .contains("Tier 1 rollback"),
            "error should mention Tier 1 rollback: {:?}",
            recorded.error
        );
        assert!(!recorded.rollback_failed);
    }

    /// Recreate: old container won't stop → deploy fails immediately.
    #[tokio::test]
    async fn test_recreate_old_container_wont_stop() {
        let tmp = tempfile::tempdir().unwrap();
        let config = test_slip_config(tmp.path().to_path_buf());
        let mut apps = HashMap::new();
        apps.insert("testapp".to_string(), recreate_app_config());
        let apps: RwLock<HashMap<String, AppConfig>> = RwLock::new(apps);

        // Pre-populate app state with an existing container.
        let mut initial_states = HashMap::new();
        initial_states.insert(
            "testapp".to_string(),
            AppRuntimeState {
                status: AppStatus::Running,
                current_tag: Some("v0.9.0".to_string()),
                current_container_id: Some("old-container-id".to_string()),
                current_port: Some(50000),
                ..Default::default()
            },
        );
        let app_states: RwLock<HashMap<String, AppRuntimeState>> = RwLock::new(initial_states);
        let deploys: DashMap<String, DeployContext> = DashMap::new();

        let docker = MockDocker {
            stop_ok: false, // stop_container fails
            ..MockDocker::new()
        };
        let stop_only_count = docker.stop_only_count();
        let caddy = MockCaddy::success();
        let health = MockHealth::passing();

        execute_deploy_inner(
            make_shared(&config, &apps, &app_states, &deploys),
            &docker,
            &caddy,
            &health,
            &mut test_deploy_ctx(),
        )
        .await;

        // stop_container should have been attempted.
        assert_eq!(stop_only_count.load(Ordering::SeqCst), 1);

        // Deploy should be Failed.
        let recorded = deploys.get("testapp").unwrap();
        assert_eq!(recorded.status, DeployStatus::Failed);
        assert!(
            recorded
                .error
                .as_deref()
                .unwrap_or("")
                .contains("failed to stop old container")
        );
    }

    /// Recreate with no health check path: health check skipped, deploy completes.
    #[tokio::test]
    async fn test_recreate_no_health_check_path() {
        let tmp = tempfile::tempdir().unwrap();
        let config = test_slip_config(tmp.path().to_path_buf());
        let mut apps = HashMap::new();
        // Use default app config which has health.path = None
        apps.insert("testapp".to_string(), recreate_app_config());
        let apps: RwLock<HashMap<String, AppConfig>> = RwLock::new(apps);

        // Pre-populate app state with an existing container.
        let mut initial_states = HashMap::new();
        initial_states.insert(
            "testapp".to_string(),
            AppRuntimeState {
                status: AppStatus::Running,
                current_tag: Some("v0.9.0".to_string()),
                current_container_id: Some("old-container-id".to_string()),
                current_port: Some(50000),
                ..Default::default()
            },
        );
        let app_states: RwLock<HashMap<String, AppRuntimeState>> = RwLock::new(initial_states);
        let deploys: DashMap<String, DeployContext> = DashMap::new();

        let docker = MockDocker::new();
        let stop_only_count = docker.stop_only_count();
        let stop_count = docker.stop_count();
        let caddy = MockCaddy::success();
        let health = MockHealth::passing();

        execute_deploy_inner(
            make_shared(&config, &apps, &app_states, &deploys),
            &docker,
            &caddy,
            &health,
            &mut test_deploy_ctx(),
        )
        .await;

        // stop_container should have been called on old.
        assert_eq!(stop_only_count.load(Ordering::SeqCst), 1);
        // stop_and_remove should have been called on old (cleanup).
        assert_eq!(stop_count.load(Ordering::SeqCst), 1);

        // Status should be Completed.
        let recorded = deploys.get("testapp").unwrap();
        assert_eq!(recorded.status, DeployStatus::Completed);
        assert!(recorded.error.is_none());
    }

    /// Explicit blue-green strategy should behave exactly as before.
    #[tokio::test]
    async fn test_blue_green_unchanged_with_strategy_field() {
        let tmp = tempfile::tempdir().unwrap();
        let config = test_slip_config(tmp.path().to_path_buf());
        let mut apps = HashMap::new();
        // Explicitly set strategy = "blue-green"
        let mut app_cfg = test_app_config();
        app_cfg.deploy.strategy = "blue-green".to_string();
        apps.insert("testapp".to_string(), app_cfg);
        let apps: RwLock<HashMap<String, AppConfig>> = RwLock::new(apps);

        // Pre-populate app state with an existing container.
        let mut initial_states = HashMap::new();
        initial_states.insert(
            "testapp".to_string(),
            AppRuntimeState {
                status: AppStatus::Running,
                current_tag: Some("v0.9.0".to_string()),
                current_container_id: Some("old-container-id".to_string()),
                current_port: Some(50000),
                ..Default::default()
            },
        );
        let app_states: RwLock<HashMap<String, AppRuntimeState>> = RwLock::new(initial_states);
        let deploys: DashMap<String, DeployContext> = DashMap::new();

        let docker = MockDocker::new();
        let stop_count = docker.stop_count();
        let caddy = MockCaddy::success();
        let health = MockHealth::passing();

        execute_deploy_inner(
            make_shared(&config, &apps, &app_states, &deploys),
            &docker,
            &caddy,
            &health,
            &mut test_deploy_ctx(),
        )
        .await;

        // stop_and_remove should have been called exactly once (old container, after new is live).
        assert_eq!(stop_count.load(Ordering::SeqCst), 1);

        // Status should be Completed.
        let recorded = deploys.get("testapp").unwrap();
        assert_eq!(recorded.status, DeployStatus::Completed);
        assert!(recorded.error.is_none());

        // New container should be current.
        let states = app_states.read().await;
        let app = states.get("testapp").unwrap();
        assert_eq!(
            app.current_container_id.as_deref(),
            Some("mock-container-id")
        );
    }

    // ── Call-log ordering tests ───────────────────────────────────────────────

    /// Recreate strategy: stop_container before create_and_start.
    #[tokio::test]
    async fn test_recreate_stops_old_before_starting_new() {
        let tmp = tempfile::tempdir().unwrap();
        let config = test_slip_config(tmp.path().to_path_buf());
        let mut app_config = test_app_config();
        app_config.deploy.strategy = "recreate".to_string();
        let mut apps = HashMap::new();
        apps.insert("testapp".to_string(), app_config);
        let apps: RwLock<HashMap<String, AppConfig>> = RwLock::new(apps);

        // Seed app_states with a prior running container.
        let mut initial_states = HashMap::new();
        initial_states.insert(
            "testapp".to_string(),
            AppRuntimeState {
                status: AppStatus::Running,
                current_tag: Some("v0.9.0".to_string()),
                current_container_id: Some("old-ctr".into()),
                current_port: Some(50000),
                ..Default::default()
            },
        );
        let app_states: RwLock<HashMap<String, AppRuntimeState>> = RwLock::new(initial_states);
        let deploys: DashMap<String, DeployContext> = DashMap::new();

        let docker = MockDocker::new();
        let call_log = docker.call_log();
        let caddy = MockCaddy::success();
        let health = MockHealth::passing();

        execute_deploy_inner(
            make_shared(&config, &apps, &app_states, &deploys),
            &docker,
            &caddy,
            &health,
            &mut test_deploy_ctx(),
        )
        .await;

        // Assert ordering: stop_container before create_and_start.
        let log = call_log.lock().unwrap();
        let stop_idx = log.iter().position(|s| s == "stop_container");
        let create_idx = log.iter().position(|s| s == "create_and_start");
        assert!(stop_idx.is_some(), "stop_container should have been called");
        assert!(
            create_idx.is_some(),
            "create_and_start should have been called"
        );
        assert!(
            stop_idx.unwrap() < create_idx.unwrap(),
            "stop_container should be called before create_and_start in recreate strategy"
        );

        // Final status should be Completed.
        let recorded = deploys.get("testapp").unwrap();
        assert_eq!(recorded.status, DeployStatus::Completed);
    }

    /// Blue-green strategy: create_and_start before stop_and_remove.
    #[tokio::test]
    async fn test_blue_green_starts_new_before_stopping_old() {
        let tmp = tempfile::tempdir().unwrap();
        let config = test_slip_config(tmp.path().to_path_buf());
        let mut apps = HashMap::new();
        apps.insert("testapp".to_string(), test_app_config());
        let apps: RwLock<HashMap<String, AppConfig>> = RwLock::new(apps);

        // Seed app_states with a prior running container.
        let mut initial_states = HashMap::new();
        initial_states.insert(
            "testapp".to_string(),
            AppRuntimeState {
                status: AppStatus::Running,
                current_tag: Some("v0.9.0".to_string()),
                current_container_id: Some("old-ctr".into()),
                current_port: Some(50000),
                ..Default::default()
            },
        );
        let app_states: RwLock<HashMap<String, AppRuntimeState>> = RwLock::new(initial_states);
        let deploys: DashMap<String, DeployContext> = DashMap::new();

        let docker = MockDocker::new();
        let call_log = docker.call_log();
        let caddy = MockCaddy::success();
        let health = MockHealth::passing();

        execute_deploy_inner(
            make_shared(&config, &apps, &app_states, &deploys),
            &docker,
            &caddy,
            &health,
            &mut test_deploy_ctx(),
        )
        .await;

        // Assert ordering: create_and_start before stop_and_remove.
        let log = call_log.lock().unwrap();
        let create_idx = log.iter().position(|s| s == "create_and_start");
        let stop_remove_idx = log.iter().position(|s| s == "stop_and_remove");
        assert!(
            create_idx.is_some(),
            "create_and_start should have been called"
        );
        assert!(
            stop_remove_idx.is_some(),
            "stop_and_remove should have been called"
        );
        assert!(
            create_idx.unwrap() < stop_remove_idx.unwrap(),
            "create_and_start should be called before stop_and_remove in blue-green strategy"
        );

        // Final status should be Completed.
        let recorded = deploys.get("testapp").unwrap();
        assert_eq!(recorded.status, DeployStatus::Completed);
    }

    // ── SQLite persistence tests ─────────────────────────────────────────────

    /// Deploy with MockHealth::passing persists Completed status to SQLite.
    #[tokio::test]
    async fn test_deploy_persists_final_status_to_sqlite() {
        let tmp = tempfile::tempdir().unwrap();
        let config = test_slip_config(tmp.path().to_path_buf());
        let mut apps = HashMap::new();
        apps.insert("testapp".to_string(), test_app_config());
        let apps: RwLock<HashMap<String, AppConfig>> = RwLock::new(apps);
        let app_states: RwLock<HashMap<String, AppRuntimeState>> = RwLock::new(HashMap::new());
        let deploys: DashMap<String, DeployContext> = DashMap::new();
        let db = Db::open_in_memory().unwrap();

        let docker = MockDocker::new();
        let caddy = MockCaddy::success();
        let health = MockHealth::passing();
        let mut ctx = test_deploy_ctx();

        execute_deploy_inner(
            make_shared_with_db(&config, &apps, &app_states, &deploys, db.clone()),
            &docker,
            &caddy,
            &health,
            &mut ctx,
        )
        .await;

        // Assert the deploy was persisted to SQLite with Completed status.
        let stored = db
            .get_deploy("dep_test001")
            .unwrap()
            .expect("deploy must be in SQLite");
        assert_eq!(stored.status, DeployStatus::Completed);
        assert!(
            stored.finished_at.is_some(),
            "finished_at should be set for a completed deploy"
        );
    }

    /// Deploy with MockHealth::failing persists Failed status to SQLite.
    #[tokio::test]
    async fn test_failed_deploy_persists_failed_status_to_sqlite() {
        let tmp = tempfile::tempdir().unwrap();
        let config = test_slip_config(tmp.path().to_path_buf());
        let mut apps = HashMap::new();
        apps.insert("testapp".to_string(), test_app_config());
        let apps: RwLock<HashMap<String, AppConfig>> = RwLock::new(apps);
        let app_states: RwLock<HashMap<String, AppRuntimeState>> = RwLock::new(HashMap::new());
        let deploys: DashMap<String, DeployContext> = DashMap::new();
        let db = Db::open_in_memory().unwrap();

        let docker = MockDocker::new();
        let caddy = MockCaddy::success();
        let health = MockHealth::failing();
        let mut ctx = test_deploy_ctx();

        execute_deploy_inner(
            make_shared_with_db(&config, &apps, &app_states, &deploys, db.clone()),
            &docker,
            &caddy,
            &health,
            &mut ctx,
        )
        .await;

        // Assert the deploy was persisted to SQLite with Failed status.
        let stored = db
            .get_deploy("dep_test001")
            .unwrap()
            .expect("deploy must be in SQLite");
        assert_eq!(stored.status, DeployStatus::Failed);
        assert!(
            stored.finished_at.is_some(),
            "finished_at should be set for a failed deploy"
        );
    }

    // ── Routing guard test ───────────────────────────────────────────────────

    /// HTTP (non-worker) app without routing must fail deploy with a clear error
    /// and NO create_and_start call.
    #[tokio::test]
    async fn test_http_app_without_routing_fails_deploy() {
        let tmp = tempfile::tempdir().unwrap();
        let config = test_slip_config(tmp.path().to_path_buf());
        let mut app_config = test_app_config();
        // Remove routing: no domain, no port, no routes.
        app_config.routing = RoutingConfig {
            domain: None,
            port: None,
            routes: vec![],
            tls: None,
        };
        let mut apps = HashMap::new();
        apps.insert("testapp".to_string(), app_config);
        let apps: RwLock<HashMap<String, AppConfig>> = RwLock::new(apps);
        let app_states: RwLock<HashMap<String, AppRuntimeState>> = RwLock::new(HashMap::new());
        let deploys: DashMap<String, DeployContext> = DashMap::new();

        let docker = MockDocker::new();
        let call_log = docker.call_log();
        let caddy = MockCaddy::success();
        let health = MockHealth::passing();

        execute_deploy_inner(
            make_shared(&config, &apps, &app_states, &deploys),
            &docker,
            &caddy,
            &health,
            &mut test_deploy_ctx(),
        )
        .await;

        // Deploy should be Failed.
        let recorded = deploys.get("testapp").unwrap();
        assert_eq!(recorded.status, DeployStatus::Failed);
        assert!(
            recorded
                .error
                .as_deref()
                .unwrap_or("")
                .contains("HTTP app requires routing"),
            "error should mention missing routing: {:?}",
            recorded.error
        );

        // No create_and_start should have been called.
        let log = call_log.lock().unwrap();
        assert!(
            !log.contains(&"create_and_start".to_string()),
            "create_and_start should NOT be called for app without routing: {:?}",
            *log
        );
    }

    // ── Deploy timeout tests ──────────────────────────────────────────────────

    /// Build an `AppState` with a mock runtime for timeout tests.
    /// Uses a 1-second server-level deploy timeout so the test completes quickly
    /// under `start_paused = true`.
    fn make_timeout_test_state(docker: MockDocker, timeout_secs: u64) -> Arc<crate::api::AppState> {
        let mut apps = HashMap::new();
        apps.insert("testapp".to_string(), test_app_config());

        let secrets_tmp = tempfile::tempdir().expect("tempdir for secrets");
        let secrets_path = secrets_tmp.path().to_path_buf();
        Box::leak(Box::new(secrets_tmp));

        let mut config = test_slip_config(tempfile::tempdir().unwrap().path().to_path_buf());
        config.deploy = Some(crate::config::ServerDeployConfig {
            timeout: Duration::from_secs(timeout_secs),
            preview_timeout: Duration::from_secs(timeout_secs),
            ..Default::default()
        });

        Arc::new(crate::api::AppState {
            config,
            apps: RwLock::new(apps),
            config_dir: std::path::PathBuf::from("/tmp/slip-test"),
            deploy_locks: DashMap::new(),
            runtime: Arc::new(docker),
            caddy: crate::caddy::CaddyClient::new("http://127.0.0.1:19999".to_string()),
            health: crate::health::HealthChecker::new(),
            app_states: RwLock::new(HashMap::new()),
            deploys: DashMap::new(),
            db: crate::db::Db::open_in_memory().unwrap(),
            started_at: chrono::Utc::now(),
            preview_states: Arc::new(DashMap::new()),
            preview_locks: DashMap::new(),
            renew_locks: DashMap::new(),
            secrets_store: crate::secrets::SecretsStore::new(secrets_path).unwrap(),
        })
    }

    /// A hung pull should time out and record the deploy as Failed.
    #[tokio::test(start_paused = true)]
    async fn test_deploy_timeout_fires_and_records_failure() {
        let docker = MockDocker::hung_pull();
        let state = make_timeout_test_state(docker, 1);

        // Acquire the deploy lock (simulates what the API handler does).
        let lock = state
            .deploy_locks
            .entry("testapp".to_string())
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
            .clone();
        let guard = lock
            .clone()
            .try_lock_owned()
            .expect("lock should be available");

        let ctx = DeployContext::new(
            "dep_timeout001".to_string(),
            "testapp".to_string(),
            "ghcr.io/org/testapp".to_string(),
            "v1.0.0".to_string(),
            TriggerSource::Webhook,
        );

        execute_deploy(state.clone(), ctx).await;

        // The deploy should be recorded as Failed with a timeout error.
        let recorded = state.deploys.get("testapp").unwrap();
        assert_eq!(recorded.status, DeployStatus::Failed);
        assert!(
            recorded
                .error
                .as_deref()
                .unwrap_or("")
                .contains("timed out"),
            "error should mention 'timed out': {:?}",
            recorded.error
        );

        // App runtime state should be Failed.
        let app_states = state.app_states.read().await;
        if let Some(app_state) = app_states.get("testapp") {
            assert_eq!(app_state.status, AppStatus::Failed);
        }

        // The lock guard should still be held (we haven't dropped it yet).
        // Drop it and verify the lock is re-acquirable.
        drop(guard);
        let reacquired = lock.try_lock();
        assert!(
            reacquired.is_ok(),
            "deploy lock should be re-acquirable after timeout"
        );
    }

    /// After a timeout, the deploy lock must be released so a new deploy can start.
    #[tokio::test(start_paused = true)]
    async fn test_deploy_timeout_releases_lock() {
        let docker = MockDocker::hung_pull();
        let state = make_timeout_test_state(docker, 1);

        let lock = state
            .deploy_locks
            .entry("testapp".to_string())
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
            .clone();
        let guard = lock
            .clone()
            .try_lock_owned()
            .expect("lock should be available");

        let ctx = DeployContext::new(
            "dep_timeout002".to_string(),
            "testapp".to_string(),
            "ghcr.io/org/testapp".to_string(),
            "v1.0.0".to_string(),
            TriggerSource::Webhook,
        );

        execute_deploy(state.clone(), ctx).await;

        // Drop the guard that was moved into the spawn (simulated by the wrapper).
        drop(guard);

        // The lock should now be re-acquirable.
        let reacquired = lock.try_lock();
        assert!(
            reacquired.is_ok(),
            "deploy lock must be re-acquirable after timeout completes"
        );
    }

    /// A fast deploy (non-hung mock) should succeed even under a timeout.
    /// Uses `execute_deploy_inner` directly (like all other tests) since the
    /// wrapper `execute_deploy` uses real Caddy/Health clients from AppState.
    #[tokio::test(start_paused = true)]
    async fn test_fast_deploy_succeeds_under_timeout() {
        let tmp = tempfile::tempdir().unwrap();
        let mut config = test_slip_config(tmp.path().to_path_buf());
        config.deploy = Some(crate::config::ServerDeployConfig {
            timeout: Duration::from_secs(600),
            preview_timeout: Duration::from_secs(600),
            ..Default::default()
        });
        let mut apps = HashMap::new();
        apps.insert("testapp".to_string(), test_app_config());
        let apps: RwLock<HashMap<String, AppConfig>> = RwLock::new(apps);
        let app_states: RwLock<HashMap<String, AppRuntimeState>> = RwLock::new(HashMap::new());
        let deploys: DashMap<String, DeployContext> = DashMap::new();

        let docker = MockDocker::new();
        let caddy = MockCaddy::success();
        let health = MockHealth::passing();
        let mut ctx = test_deploy_ctx();

        // Wrap the inner call in a timeout to verify it completes before the deadline.
        let result = tokio::time::timeout(
            Duration::from_secs(600),
            execute_deploy_inner(
                make_shared(&config, &apps, &app_states, &deploys),
                &docker,
                &caddy,
                &health,
                &mut ctx,
            ),
        )
        .await;

        assert!(
            result.is_ok(),
            "inner deploy should complete before timeout"
        );

        let recorded = deploys.get("testapp").unwrap();
        assert_eq!(
            recorded.status,
            DeployStatus::Completed,
            "fast deploy should complete: {:?}",
            recorded.error
        );
    }

    /// A deploy whose health check hangs (never returns) should time out, clean up
    /// the orphaned new container, and record the deploy as Failed with a
    /// health_check_timeout reason.
    #[tokio::test(start_paused = true)]
    async fn test_deploy_timeout_cleans_up_orphaned_container() {
        let docker = MockDocker {
            // Pull succeeds, create_and_start succeeds, but container_is_running
            // hangs forever — simulating a container that never becomes healthy.
            hung_container_check: true,
            ..MockDocker::new()
        };
        let stop_count = docker.stop_count();
        let call_log = docker.call_log();
        let state = make_timeout_test_state(docker, 1);

        // Acquire the deploy lock (simulates what the API handler does).
        let lock = state
            .deploy_locks
            .entry("testapp".to_string())
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
            .clone();
        let guard = lock
            .clone()
            .try_lock_owned()
            .expect("lock should be available");

        let ctx = DeployContext::new(
            "dep_timeout_cleanup001".to_string(),
            "testapp".to_string(),
            "ghcr.io/org/testapp".to_string(),
            "v1.0.0".to_string(),
            TriggerSource::Webhook,
        );

        execute_deploy(state.clone(), ctx).await;

        // The deploy should be recorded as Failed with a health_check_timeout reason.
        let recorded = state.deploys.get("testapp").unwrap();
        assert_eq!(recorded.status, DeployStatus::Failed);
        assert!(
            recorded
                .error
                .as_deref()
                .unwrap_or("")
                .contains("health_check_timeout"),
            "error should contain 'health_check_timeout': {:?}",
            recorded.error
        );

        // stop_and_remove should have been called exactly once (the orphaned new container).
        assert_eq!(
            stop_count.load(Ordering::SeqCst),
            1,
            "orphaned new container should be stopped and removed"
        );

        // The call log should show: pull_image, create_and_start, then stop_and_remove.
        // No stop_and_remove for an old container (there was none).
        {
            let log = call_log.lock().unwrap();
            let create_idx = log.iter().position(|s| s == "create_and_start");
            let stop_remove_idx = log.iter().position(|s| s == "stop_and_remove");
            assert!(
                create_idx.is_some(),
                "create_and_start should have been called"
            );
            assert!(
                stop_remove_idx.is_some(),
                "stop_and_remove should have been called for cleanup"
            );
            assert!(
                create_idx.unwrap() < stop_remove_idx.unwrap(),
                "stop_and_remove should come after create_and_start"
            );
        } // drop log guard before await

        // App runtime state should be Failed.
        let app_states = state.app_states.read().await;
        if let Some(app_state) = app_states.get("testapp") {
            assert_eq!(app_state.status, AppStatus::Failed);
        }

        // The lock guard should still be held (we haven't dropped it yet).
        drop(guard);
        let reacquired = lock.try_lock();
        assert!(
            reacquired.is_ok(),
            "deploy lock should be re-acquirable after timeout"
        );
    }

    /// A deploy that times out with an existing old container: the old container
    /// should NOT be stopped — only the orphaned new container is cleaned up.
    #[tokio::test(start_paused = true)]
    async fn test_deploy_timeout_does_not_stop_old_container() {
        let docker = MockDocker {
            hung_container_check: true,
            ..MockDocker::new()
        };
        let stop_count = docker.stop_count();
        let call_log = docker.call_log();
        let state = make_timeout_test_state(docker, 1);

        // Pre-populate app state with an existing old container.
        {
            let mut states = state.app_states.write().await;
            states.insert(
                "testapp".to_string(),
                AppRuntimeState {
                    status: AppStatus::Running,
                    current_tag: Some("v0.9.0".to_string()),
                    current_container_id: Some("old-container-id".to_string()),
                    current_port: Some(50000),
                    ..Default::default()
                },
            );
        }

        // Acquire the deploy lock.
        let lock = state
            .deploy_locks
            .entry("testapp".to_string())
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
            .clone();
        let guard = lock
            .clone()
            .try_lock_owned()
            .expect("lock should be available");

        let ctx = DeployContext::new(
            "dep_timeout_old001".to_string(),
            "testapp".to_string(),
            "ghcr.io/org/testapp".to_string(),
            "v1.0.0".to_string(),
            TriggerSource::Webhook,
        );

        execute_deploy(state.clone(), ctx).await;

        // The deploy should be Failed.
        let recorded = state.deploys.get("testapp").unwrap();
        assert_eq!(recorded.status, DeployStatus::Failed);

        // stop_and_remove should have been called exactly once (the orphaned new container).
        assert_eq!(
            stop_count.load(Ordering::SeqCst),
            1,
            "only the orphaned new container should be stopped"
        );

        // Verify call ordering: create_and_start before stop_and_remove.
        {
            let log = call_log.lock().unwrap();
            let create_idx = log.iter().position(|s| s == "create_and_start");
            let stop_remove_idx = log.iter().position(|s| s == "stop_and_remove");
            assert!(create_idx.is_some());
            assert!(stop_remove_idx.is_some());
            assert!(
                create_idx.unwrap() < stop_remove_idx.unwrap(),
                "stop_and_remove should come after create_and_start"
            );
        } // drop log guard before await

        // The old container should still be current in app state.
        let app_states = state.app_states.read().await;
        let app = app_states.get("testapp").unwrap();
        assert_eq!(
            app.current_container_id.as_deref(),
            Some("old-container-id"),
            "old container should be preserved"
        );
        assert_eq!(app.status, AppStatus::Failed);

        drop(guard);
    }
}
