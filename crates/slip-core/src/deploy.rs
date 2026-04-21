//! Deploy orchestrator — the state machine that coordinates a full blue-green deploy.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use dashmap::DashMap;
use serde::Serialize;
use tokio::sync::RwLock;

use crate::api::AppState;
use crate::caddy::ReverseProxy;
use crate::config::{AppConfig, SlipConfig};
use crate::health::HealthCheck;
use crate::runtime::{RegistryCredentials, RuntimeBackend};
use crate::state;

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
    Completed,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
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
    /// Pod name created during pod deploys (None for container deploys).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub new_pod_name: Option<String>,
    /// Path to the rendered manifest written during pod deploys.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub new_manifest_path: Option<PathBuf>,
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
            new_pod_name: None,
            new_manifest_path: None,
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
    /// Current pod name (for pod-mode deploys).
    pub current_pod_name: Option<String>,
    /// Path to the rendered manifest for the current pod (for pod-mode deploys).
    pub current_manifest_path: Option<PathBuf>,
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
    pub credentials: Option<RegistryCredentials>,
    pub secrets_store: Option<&'a crate::secrets::SecretsStore>,
}

// ─── Core orchestrator ────────────────────────────────────────────────────────

/// Execute a full blue-green deploy.
///
/// This function is designed to be called inside a `tokio::spawn`. It drives
/// the deploy state machine through: Pull → Start → Health Check → Switch →
/// Drain Old → Complete (or Fail at any step).
pub async fn execute_deploy(state: Arc<AppState>, ctx: DeployContext) {
    let shared = DeploySharedState {
        config: &state.config,
        apps: &state.apps,
        app_states: &state.app_states,
        deploys: &state.deploys,
        credentials: state.registry_credentials(),
        secrets_store: Some(&state.secrets_store),
    };
    execute_deploy_inner(
        shared,
        state.runtime.as_ref(),
        &state.caddy,
        &state.health,
        ctx,
    )
    .await;
}

/// Inner deploy state machine — generic over trait objects so it can be driven
/// from tests with mock implementations.
pub(crate) async fn execute_deploy_inner(
    shared: DeploySharedState<'_>,
    runtime: &dyn RuntimeBackend,
    caddy: &dyn ReverseProxy,
    health: &dyn HealthCheck,
    mut ctx: DeployContext,
) {
    let app_name = ctx.app.clone();
    let app_config = match shared.apps.read().await.get(&app_name) {
        Some(cfg) => cfg.clone(),
        None => {
            ctx.fail(&format!("app '{}' not found in config", app_name));
            record_deploy(shared.deploys, &ctx);
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
    record_deploy(shared.deploys, &ctx);
    tracing::info!(
        app = %app_name,
        tag = %ctx.tag,
        deploy_id = %ctx.id,
        "pulling image"
    );

    if let Err(e) = runtime
        .pull_image(&ctx.image, &ctx.tag, shared.credentials)
        .await
    {
        ctx.fail(&format!("image pull failed: {e}"));
        record_deploy(shared.deploys, &ctx);
        set_app_failed(shared.app_states, &app_name);
        return;
    }

    // ── EXTRACT + MERGE CONFIG ────────────────────────────────────────────────
    ctx.status = DeployStatus::Configuring;
    record_deploy(shared.deploys, &ctx);

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
                            "repo config app name '{}' does not match deploy app '{}'",
                            repo_config.app.name, app_name
                        ));
                        record_deploy(shared.deploys, &ctx);
                        set_app_failed(shared.app_states, &app_name);
                        return;
                    }
                    Some(crate::merge::merge_config(&app_config, &repo_config))
                }
                Err(e) => {
                    ctx.fail(&format!("failed to parse repo config: {e}"));
                    record_deploy(shared.deploys, &ctx);
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
            ctx.fail(&format!("failed to extract config from image: {e}"));
            record_deploy(shared.deploys, &ctx);
            set_app_failed(shared.app_states, &app_name);
            return;
        }
    };

    // Use merged config if available, otherwise fall back to server-only config.
    let effective_config = match &merged {
        Some(m) => m.app.clone(),
        None => app_config.clone(),
    };

    // ── START NEW ────────────────────────────────────────────────────────────
    ctx.status = DeployStatus::Starting;
    record_deploy(shared.deploys, &ctx);

    let env_vars = resolve_env_vars_for_app(&effective_config, shared.secrets_store, &app_name);

    // Determine if this is a pod or container deploy.
    let is_pod = merged.as_ref().map(|m| m.kind == "pod").unwrap_or(false);

    if is_pod {
        // ── POD DEPLOY FLOW ───────────────────────────────────────────────

        // Get the merged config — required for pod deploys.
        let merged_cfg = merged.as_ref().expect("merged is Some when is_pod is true");

        // Get the manifest path from repo config.
        let manifest_in_image = match &merged_cfg.manifest {
            Some(p) => p.clone(),
            None => {
                ctx.fail("pod deploy requires [app].manifest in repo config (slip.toml)");
                record_deploy(shared.deploys, &ctx);
                set_app_failed(shared.app_states, &app_name);
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
                    "manifest '{manifest_in_image}' not found in image"
                ));
                record_deploy(shared.deploys, &ctx);
                set_app_failed(shared.app_states, &app_name);
                return;
            }
            Err(e) => {
                ctx.fail(&format!("failed to extract manifest from image: {e}"));
                record_deploy(shared.deploys, &ctx);
                set_app_failed(shared.app_states, &app_name);
                return;
            }
        };

        // Generate a unique pod suffix from a ULID fragment.
        let pod_suffix = ulid::Ulid::new().to_string()[..8].to_lowercase();
        let pod_name = format!("{app_name}-{pod_suffix}");

        // Render the manifest with deploy-time transformations.
        let render_ctx = crate::manifest::RenderContext {
            app_name: app_name.clone(),
            tag: ctx.tag.clone(),
            primary_image: effective_config.app.image.clone(),
            pod_suffix: pod_suffix.clone(),
            env_vars: env_vars.clone(),
            image_overrides: std::collections::HashMap::new(),
        };

        let rendered_yaml = match crate::manifest::render_manifest(&manifest_bytes, &render_ctx) {
            Ok(yaml) => yaml,
            Err(e) => {
                ctx.fail(&format!("failed to render manifest: {e}"));
                record_deploy(shared.deploys, &ctx);
                set_app_failed(shared.app_states, &app_name);
                return;
            }
        };

        // Write rendered manifest to storage dir.
        let manifests_dir = shared.config.storage.path.join("manifests");
        if let Err(e) = std::fs::create_dir_all(&manifests_dir) {
            ctx.fail(&format!("failed to create manifests directory: {e}"));
            record_deploy(shared.deploys, &ctx);
            set_app_failed(shared.app_states, &app_name);
            return;
        }
        let manifest_path = manifests_dir.join(format!("{app_name}-{}.yaml", ctx.id));
        if let Err(e) = std::fs::write(&manifest_path, &rendered_yaml) {
            ctx.fail(&format!("failed to write manifest file: {e}"));
            record_deploy(shared.deploys, &ctx);
            set_app_failed(shared.app_states, &app_name);
            return;
        }

        // Deploy the pod via `podman kube play`.
        if let Err(e) = runtime.deploy_pod(&manifest_path, &pod_name).await {
            ctx.fail(&format!("pod deploy failed: {e}"));
            record_deploy(shared.deploys, &ctx);
            set_app_failed(shared.app_states, &app_name);
            return;
        }

        // Record pod name and manifest path in context for later steps.
        ctx.new_pod_name = Some(pod_name.clone());
        ctx.new_manifest_path = Some(manifest_path.clone());

        // Discover the host port for the routing container.
        let routing_container = merged_cfg.routing_container.as_deref().unwrap_or("web");
        let routing_port = effective_config.routing.port;

        let host_port = match runtime
            .pod_container_port(&pod_name, routing_container, routing_port)
            .await
        {
            Ok(port) => port,
            Err(e) => {
                ctx.fail(&format!("failed to get pod container port: {e}"));
                record_deploy(shared.deploys, &ctx);
                set_app_failed(shared.app_states, &app_name);
                // Tear down the new pod on failure.
                if let Err(te) = runtime.teardown_pod(&manifest_path).await {
                    tracing::warn!(app = %app_name, error = %te, "failed to teardown pod after port lookup failure (non-fatal)");
                }
                return;
            }
        };

        ctx.new_port = Some(host_port);

        // ── HEALTH CHECK (pod) ────────────────────────────────────────────
        ctx.status = DeployStatus::HealthChecking;
        record_deploy(shared.deploys, &ctx);

        if let Err(e) = health.check(host_port, &effective_config.health).await {
            tracing::error!(app = %app_name, error = %e, "health check failed");
            if let Err(te) = runtime.teardown_pod(&manifest_path).await {
                tracing::warn!(app = %app_name, error = %te, "failed to teardown pod after health check failure (non-fatal)");
            }
            ctx.fail(&format!("health check failed: {e}"));
            record_deploy(shared.deploys, &ctx);
            set_app_failed(shared.app_states, &app_name);
            return;
        }

        // ── SWITCH (pod) ──────────────────────────────────────────────────
        ctx.status = DeployStatus::Switching;
        record_deploy(shared.deploys, &ctx);

        let old_pod_manifest = {
            let states = shared.app_states.read().await;
            states
                .get(&app_name)
                .and_then(|s| s.current_manifest_path.clone())
        };

        if let Err(e) = caddy
            .set_route(&app_name, &effective_config.routing.domain, host_port)
            .await
        {
            tracing::error!(app = %app_name, error = %e, "caddy route update failed");
            if let Err(te) = runtime.teardown_pod(&manifest_path).await {
                tracing::warn!(app = %app_name, error = %te, "failed to teardown pod after caddy failure (non-fatal)");
            }
            ctx.fail(&format!("caddy route update failed: {e}"));
            record_deploy(shared.deploys, &ctx);
            set_app_failed(shared.app_states, &app_name);
            return;
        }

        // Update app runtime state for pod.
        let state_snapshot = {
            let mut states = shared.app_states.write().await;
            let app_state = states.entry(app_name.clone()).or_default();
            app_state.previous_tag = app_state.current_tag.take();
            app_state.current_tag = Some(ctx.tag.clone());
            app_state.current_pod_name = Some(pod_name.clone());
            app_state.current_manifest_path = Some(manifest_path.clone());
            app_state.current_port = Some(host_port);
            app_state.deployed_at = Some(Utc::now());
            app_state.deploy_id = Some(ctx.id.clone());
            app_state.status = AppStatus::Running;
            app_state.clone()
        };

        // Persist state to disk (non-fatal).
        let state_dir = shared.config.storage.path.join("state");
        if let Err(e) = state::save_app_state(&state_dir, &app_name, &state_snapshot) {
            tracing::warn!(app = %app_name, error = %e, "failed to persist app state (non-fatal)");
        }

        // ── DRAIN + TEARDOWN OLD POD ──────────────────────────────────────
        if let Some(old_manifest) = old_pod_manifest {
            tracing::info!(app = %app_name, "draining old pod");
            tokio::time::sleep(effective_config.deploy.drain_timeout).await;
            if let Err(e) = runtime.teardown_pod(&old_manifest).await {
                tracing::warn!(
                    app = %app_name,
                    error = %e,
                    "failed to teardown old pod (non-fatal)"
                );
            }
        }
    } else {
        // ── CONTAINER DEPLOY FLOW (unchanged) ────────────────────────────

        match runtime
            .create_and_start(
                &app_name,
                &ctx.image,
                &ctx.tag,
                effective_config.routing.port,
                env_vars,
                &effective_config.network.name,
                &effective_config.resources,
            )
            .await
        {
            Ok((container_id, port)) => {
                ctx.new_container_id = Some(container_id);
                ctx.new_port = Some(port);
            }
            Err(e) => {
                ctx.fail(&format!("container start failed: {e}"));
                record_deploy(shared.deploys, &ctx);
                set_app_failed(shared.app_states, &app_name);
                return;
            }
        }

        // ── HEALTH CHECK ─────────────────────────────────────────────────
        ctx.status = DeployStatus::HealthChecking;
        record_deploy(shared.deploys, &ctx);

        let new_port = match ctx.new_port {
            Some(port) => port,
            None => {
                ctx.fail("internal error: port not set after container start");
                record_deploy(shared.deploys, &ctx);
                set_app_failed(shared.app_states, &app_name);
                return;
            }
        };

        if let Err(e) = health.check(new_port, &effective_config.health).await {
            tracing::error!(app = %app_name, error = %e, "health check failed");
            if let Some(ref id) = ctx.new_container_id {
                let _ = runtime.stop_and_remove(id).await;
            }
            ctx.fail(&format!("health check failed: {e}"));
            record_deploy(shared.deploys, &ctx);
            set_app_failed(shared.app_states, &app_name);
            return;
        }

        // Verify container is still running after health check wait
        // (container could have crashed during start_period wait)
        if let Some(ref id) = ctx.new_container_id {
            match runtime.container_is_running(id).await {
                Ok(true) => {}
                Ok(false) => {
                    tracing::error!(app = %app_name, container_id = %id, "container not running after health check");
                    ctx.fail("container exited during health check");
                    record_deploy(shared.deploys, &ctx);
                    set_app_failed(shared.app_states, &app_name);
                    return;
                }
                Err(e) => {
                    tracing::error!(app = %app_name, error = %e, "failed to verify container state");
                    ctx.fail(&format!("container state check failed: {e}"));
                    record_deploy(shared.deploys, &ctx);
                    set_app_failed(shared.app_states, &app_name);
                    return;
                }
            }
        }

        // ── SWITCH ───────────────────────────────────────────────────────
        ctx.status = DeployStatus::Switching;
        record_deploy(shared.deploys, &ctx);

        let old_container_id = {
            let states = shared.app_states.read().await;
            states
                .get(&app_name)
                .and_then(|s| s.current_container_id.clone())
        };

        if let Err(e) = caddy
            .set_route(&app_name, &effective_config.routing.domain, new_port)
            .await
        {
            tracing::error!(app = %app_name, error = %e, "caddy route update failed");
            if let Some(ref id) = ctx.new_container_id {
                let _ = runtime.stop_and_remove(id).await;
            }
            ctx.fail(&format!("caddy route update failed: {e}"));
            record_deploy(shared.deploys, &ctx);
            set_app_failed(shared.app_states, &app_name);
            return;
        }

        // Update app runtime state
        let state_snapshot = {
            let mut states = shared.app_states.write().await;
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
        let state_dir = shared.config.storage.path.join("state");
        if let Err(e) = state::save_app_state(&state_dir, &app_name, &state_snapshot) {
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
    }

    // ── COMPLETED ────────────────────────────────────────────────────────────
    ctx.status = DeployStatus::Completed;
    ctx.finished_at = Some(Utc::now());
    record_deploy(shared.deploys, &ctx);
    tracing::info!(
        app = %app_name,
        tag = %ctx.tag,
        deploy_id = %ctx.id,
        "deploy completed"
    );
}

// ─── Private helpers ──────────────────────────────────────────────────────────

/// Record (insert/update) a deploy context, evicting an entry if the map exceeds 100.
///
/// Note: Current eviction uses `DashMap::iter().next()` which returns an arbitrary
/// (not oldest) entry. For proper FIFO eviction, we'd need to track insertion order
/// with a separate VecDeque. This is acceptable for Phase 1 but should be improved
/// in Phase 2.
pub fn record_deploy(deploys: &DashMap<String, DeployContext>, ctx: &DeployContext) {
    deploys.insert(ctx.id.clone(), ctx.clone());
    if deploys.len() > 100
        && let Some(oldest) = deploys.iter().next().map(|e| e.key().clone())
    {
        deploys.remove(&oldest);
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
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::time::Duration;

    use dashmap::DashMap;
    use tokio::sync::RwLock;

    use super::*;
    use crate::caddy::ReverseProxy;
    use crate::config::{
        AppConfig, AppInfo, AuthConfig, CaddyConfig, DeployConfig, HealthConfig, RegistryConfig,
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
        /// Container ID + port returned by `create_and_start`.
        container_id: String,
        container_port: u16,
        /// Tracks how many times `stop_and_remove` was called.
        stop_count: Arc<AtomicU32>,
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
    }

    impl MockDocker {
        fn new() -> Self {
            Self {
                pull_ok: true,
                container_id: "mock-container-id".to_string(),
                container_port: 54321,
                stop_count: Arc::new(AtomicU32::new(0)),
                // Default: extract_file returns Unsupported (same as the trait default)
                extract_result: Err(RuntimeError::Unsupported(
                    "mock does not implement extract_file".to_string(),
                )),
                manifest_extract_result: None,
                pod_port: None,
                teardown_count: Arc::new(AtomicU32::new(0)),
            }
        }

        fn failing_pull() -> Self {
            Self {
                pull_ok: false,
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

        fn teardown_count(&self) -> Arc<AtomicU32> {
            self.teardown_count.clone()
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
            _credentials: Option<RegistryCredentials>,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<(), RuntimeError>> + Send + 'a>,
        > {
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
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<(String, u16), RuntimeError>> + Send + 'a>,
        > {
            let result = Ok((self.container_id.clone(), self.container_port));
            Box::pin(async move { result })
        }

        fn stop_and_remove<'a>(
            &'a self,
            _container_id: &'a str,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<(), RuntimeError>> + Send + 'a>,
        > {
            self.stop_count.fetch_add(1, Ordering::SeqCst);
            Box::pin(async { Ok(()) })
        }

        fn container_is_running<'a>(
            &'a self,
            _container_id: &'a str,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<bool, RuntimeError>> + Send + 'a>,
        > {
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
    }

    // ── Mock: HealthCheck ─────────────────────────────────────────────────────

    struct MockHealth {
        ok: bool,
    }

    impl MockHealth {
        fn passing() -> Self {
            Self { ok: true }
        }

        fn failing() -> Self {
            Self { ok: false }
        }
    }

    impl HealthCheck for MockHealth {
        fn check<'a>(
            &'a self,
            _host_port: u16,
            _config: &'a HealthConfig,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), HealthError>> + Send + 'a>>
        {
            let result = if self.ok {
                Ok(())
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
            registry: RegistryConfig { ghcr_token: None },
            storage: StorageConfig { path: storage_path },
            runtime: crate::config::RuntimeConfig::default(),
            preview: None,
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
                domain: "testapp.example.com".to_string(),
                port: 3000,
            },
            health: HealthConfig {
                // No health path — check always passes without any HTTP call.
                path: None,
                interval: Duration::from_millis(1),
                timeout: Duration::from_millis(10),
                retries: 1,
                start_period: Duration::ZERO,
            },
            deploy: DeployConfig {
                strategy: "blue-green".to_string(),
                // Zero drain timeout so tests don't sleep.
                drain_timeout: Duration::ZERO,
            },
            env: HashMap::new(),
            env_file: None,
            resources: ResourceConfig::default(),
            network: crate::config::NetworkConfig::default(),
            preview: None,
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
            credentials: None,
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
        let ctx = test_deploy_ctx();
        let deploy_id = ctx.id.clone();

        execute_deploy_inner(
            make_shared(&config, &apps, &app_states, &deploys),
            &docker,
            &caddy,
            &health,
            ctx,
        )
        .await;

        // Deploy should be recorded as Completed.
        let recorded = deploys.get(&deploy_id).unwrap();
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
            test_deploy_ctx(),
        )
        .await;

        // `stop_and_remove` should not have been called (no old container).
        assert_eq!(stop_count.load(Ordering::SeqCst), 0);

        // Status should be Completed.
        let recorded = deploys.get("dep_test001").unwrap();
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
            test_deploy_ctx(),
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
            test_deploy_ctx(),
        )
        .await;

        // New container should have been stopped (rollback).
        assert_eq!(
            stop_count.load(Ordering::SeqCst),
            1,
            "new container should be stopped"
        );

        // Deploy should be Failed.
        let recorded = deploys.get("dep_test001").unwrap();
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
            test_deploy_ctx(),
        )
        .await;

        // No containers should have been started or stopped.
        assert_eq!(
            stop_count.load(Ordering::SeqCst),
            0,
            "no container stop should occur"
        );

        // Deploy should be Failed with a pull error.
        let recorded = deploys.get("dep_test001").unwrap();
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
            test_deploy_ctx(),
        )
        .await;

        // New container should have been stopped (rollback), but only once.
        assert_eq!(
            stop_count.load(Ordering::SeqCst),
            1,
            "only new container should be stopped"
        );

        // Deploy should be Failed with a caddy error.
        let recorded = deploys.get("dep_test001").unwrap();
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
        let ctx = test_deploy_ctx();
        let deploy_id = ctx.id.clone();

        execute_deploy_inner(
            make_shared(&config, &apps, &app_states, &deploys),
            &docker,
            &caddy,
            &health,
            ctx,
        )
        .await;

        // Deploy should succeed even with a repo config present
        let recorded = deploys.get(&deploy_id).unwrap();
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
        let ctx = test_deploy_ctx();
        let deploy_id = ctx.id.clone();

        execute_deploy_inner(
            make_shared(&config, &apps, &app_states, &deploys),
            &docker,
            &caddy,
            &health,
            ctx,
        )
        .await;

        // Deploy should succeed using server config only
        let recorded = deploys.get(&deploy_id).unwrap();
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
            test_deploy_ctx(),
        )
        .await;

        let recorded = deploys.get("dep_test001").unwrap();
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
        let ctx = test_deploy_ctx();
        let deploy_id = ctx.id.clone();

        execute_deploy_inner(
            make_shared(&config, &apps, &app_states, &deploys),
            &docker,
            &caddy,
            &health,
            ctx,
        )
        .await;

        // Should complete successfully using server config
        let recorded = deploys.get(&deploy_id).unwrap();
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
            test_deploy_ctx(),
        )
        .await;

        let recorded = deploys.get("dep_test001").unwrap();
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
            test_deploy_ctx(),
        )
        .await;

        let recorded = deploys.get("dep_test001").unwrap();
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
        let ctx = pod_deploy_ctx();
        let deploy_id = ctx.id.clone();

        execute_deploy_inner(
            make_shared(&config, &apps, &app_states, &deploys),
            &docker,
            &caddy,
            &health,
            ctx,
        )
        .await;

        // Deploy should be Completed.
        let recorded = deploys.get(&deploy_id).unwrap();
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
            pod_deploy_ctx(),
        )
        .await;

        // Deploy should be Failed.
        let recorded = deploys.get("dep_pod001").unwrap();
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
            pod_deploy_ctx(),
        )
        .await;

        let recorded = deploys.get("dep_pod001").unwrap();
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
            pod_deploy_ctx(),
        )
        .await;

        let recorded = deploys.get("dep_pod001").unwrap();
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
            pod_deploy_ctx(),
        )
        .await;

        let recorded = deploys.get("dep_pod001").unwrap();
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

        let ctx = DeployContext::new(
            "dep_rollback001".to_string(),
            "testapp".to_string(),
            "ghcr.io/org/testapp".to_string(),
            "v1.0.0".to_string(),
            TriggerSource::Rollback,
        );
        let deploy_id = ctx.id.clone();

        execute_deploy_inner(
            make_shared(&config, &apps, &app_states, &deploys),
            &docker,
            &caddy,
            &health,
            ctx,
        )
        .await;

        // Deploy should complete successfully.
        let recorded = deploys.get(&deploy_id).unwrap();
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
        let ctx = DeployContext::new(
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
            ctx,
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
                domain: "testapp.example.com".to_string(),
                port: 3000,
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
                domain: "testapp.example.com".to_string(),
                port: 3000,
            },
            health: HealthConfig::default(),
            deploy: DeployConfig::default(),
            env: HashMap::from([("KEY_A".to_string(), "val_a".to_string())]),
            env_file: None,
            resources: ResourceConfig::default(),
            network: crate::config::NetworkConfig::default(),
            preview: None,
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
                domain: "testapp.example.com".to_string(),
                port: 3000,
            },
            health: HealthConfig::default(),
            deploy: DeployConfig::default(),
            env: HashMap::from([("DB_URL".to_string(), "env-value".to_string())]),
            env_file: None,
            resources: ResourceConfig::default(),
            network: crate::config::NetworkConfig::default(),
            preview: None,
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
                domain: "testapp.example.com".to_string(),
                port: 3000,
            },
            health: HealthConfig::default(),
            deploy: DeployConfig::default(),
            env: HashMap::from([("KEY_A".to_string(), "val_a".to_string())]),
            env_file: None,
            resources: ResourceConfig::default(),
            network: crate::config::NetworkConfig::default(),
            preview: None,
        };

        let vars = resolve_env_vars_for_app(&app_config, None, "testapp");
        assert_eq!(vars, vec!["KEY_A=val_a"]);
    }
}
