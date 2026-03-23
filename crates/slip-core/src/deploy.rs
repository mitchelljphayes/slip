//! Deploy orchestrator — the state machine that coordinates a full blue-green deploy.

use std::sync::Arc;

use chrono::{DateTime, Utc};
use serde::Serialize;

use crate::api::AppState;
use crate::config::AppConfig;
use crate::state;

// ─── Status types ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DeployStatus {
    Accepted,
    Pulling,
    Starting,
    HealthChecking,
    Switching,
    Completed,
    Failed,
}

#[derive(Debug, Clone, Serialize)]
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
    pub status: DeployStatus,
    pub started_at: DateTime<Utc>,
    pub finished_at: Option<DateTime<Utc>>,
    pub error: Option<String>,
    pub triggered_by: TriggerSource,
    pub new_container_id: Option<String>,
    pub new_port: Option<u16>,
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
            status: DeployStatus::Accepted,
            started_at: Utc::now(),
            finished_at: None,
            error: None,
            triggered_by,
            new_container_id: None,
            new_port: None,
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

// ─── App runtime state ────────────────────────────────────────────────────────

/// Runtime state for a single deployed app (current/previous container, port, etc.).
#[derive(Debug, Clone, Default)]
pub struct AppRuntimeState {
    pub status: AppStatus,
    pub current_tag: Option<String>,
    pub previous_tag: Option<String>,
    pub current_container_id: Option<String>,
    pub previous_container_id: Option<String>,
    pub current_port: Option<u16>,
    pub deployed_at: Option<DateTime<Utc>>,
    pub deploy_id: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub enum AppStatus {
    #[default]
    NotDeployed,
    Running,
    Deploying,
    Failed,
}

// ─── Core orchestrator ────────────────────────────────────────────────────────

/// Execute a full blue-green deploy.
///
/// This function is designed to be called inside a `tokio::spawn`. It drives
/// the deploy state machine through: Pull → Start → Health Check → Switch →
/// Drain Old → Complete (or Fail at any step).
pub async fn execute_deploy(state: Arc<AppState>, mut ctx: DeployContext) {
    let app_name = ctx.app.clone();
    let app_config = state.apps.get(&app_name).unwrap().clone();

    // ── PULL ─────────────────────────────────────────────────────────────────
    ctx.status = DeployStatus::Pulling;
    state.record_deploy(&ctx);
    tracing::info!(
        app = %app_name,
        tag = %ctx.tag,
        deploy_id = %ctx.id,
        "pulling image"
    );

    let credentials = state.docker_credentials();
    if let Err(e) = state
        .docker
        .pull_image(&ctx.image, &ctx.tag, credentials)
        .await
    {
        ctx.fail(&format!("image pull failed: {e}"));
        state.record_deploy(&ctx);
        return;
    }

    // ── START NEW ────────────────────────────────────────────────────────────
    ctx.status = DeployStatus::Starting;
    state.record_deploy(&ctx);

    let env_vars = resolve_env_vars_for_app(&app_config);
    match state
        .docker
        .create_and_start(
            &app_name,
            &ctx.image,
            &ctx.tag,
            app_config.routing.port,
            env_vars,
            &app_config.network.name,
            &app_config.resources,
        )
        .await
    {
        Ok((container_id, port)) => {
            ctx.new_container_id = Some(container_id);
            ctx.new_port = Some(port);
        }
        Err(e) => {
            ctx.fail(&format!("container start failed: {e}"));
            state.record_deploy(&ctx);
            return;
        }
    }

    // ── HEALTH CHECK ─────────────────────────────────────────────────────────
    ctx.status = DeployStatus::HealthChecking;
    state.record_deploy(&ctx);

    if let Err(e) = state
        .health
        .check(ctx.new_port.unwrap(), &app_config.health)
        .await
    {
        tracing::error!(app = %app_name, error = %e, "health check failed");
        if let Some(ref id) = ctx.new_container_id {
            let _ = state.docker.stop_and_remove(id).await;
        }
        ctx.fail(&format!("health check failed: {e}"));
        state.record_deploy(&ctx);
        return;
    }

    // ── SWITCH ───────────────────────────────────────────────────────────────
    ctx.status = DeployStatus::Switching;
    state.record_deploy(&ctx);

    let old_container_id = {
        let states = state.app_states.read().await;
        states
            .get(&app_name)
            .and_then(|s| s.current_container_id.clone())
    };

    if let Err(e) = state
        .caddy
        .set_route(&app_name, &app_config.routing.domain, ctx.new_port.unwrap())
        .await
    {
        tracing::error!(app = %app_name, error = %e, "caddy route update failed");
        if let Some(ref id) = ctx.new_container_id {
            let _ = state.docker.stop_and_remove(id).await;
        }
        ctx.fail(&format!("caddy route update failed: {e}"));
        state.record_deploy(&ctx);
        return;
    }

    // Update app runtime state
    let state_snapshot = {
        let mut states = state.app_states.write().await;
        let app_state = states.entry(app_name.clone()).or_default();
        app_state.previous_tag = app_state.current_tag.take();
        app_state.previous_container_id = app_state.current_container_id.take();
        app_state.current_tag = Some(ctx.tag.clone());
        app_state.current_container_id = ctx.new_container_id.clone();
        app_state.current_port = ctx.new_port;
        app_state.deployed_at = Some(Utc::now());
        app_state.deploy_id = Some(ctx.id.clone());
        app_state.status = AppStatus::Running;
        app_state.clone()
    };

    // Persist state to disk (non-fatal)
    let state_dir = state.config.storage.path.join("state");
    if let Err(e) = state::save_app_state(&state_dir, &app_name, &state_snapshot) {
        tracing::warn!(app = %app_name, error = %e, "failed to persist app state (non-fatal)");
    }

    // ── DRAIN + STOP OLD ─────────────────────────────────────────────────────
    if let Some(old_id) = old_container_id {
        tracing::info!(app = %app_name, "draining old container");
        tokio::time::sleep(app_config.deploy.drain_timeout).await;
        if let Err(e) = state.docker.stop_and_remove(&old_id).await {
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
    state.record_deploy(&ctx);
    tracing::info!(
        app = %app_name,
        tag = %ctx.tag,
        deploy_id = %ctx.id,
        "deploy completed"
    );
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

/// Merge env vars from app config `[env]` section + optional env_file on disk.
fn resolve_env_vars_for_app(app_config: &AppConfig) -> Vec<String> {
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

    vars
}
