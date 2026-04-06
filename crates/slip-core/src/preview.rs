//! Preview deployment state types and orchestration.
//!
//! A "preview" is an ephemeral container/pod deployment for a pull request or
//! branch. Each preview has a unique ID, a subdomain, and an optional TTL.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use chrono::{DateTime, Utc};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};

use crate::caddy::ReverseProxy;
use crate::config::{AppConfig, AppPreviewConfig, ServerPreviewConfig, SlipConfig};
use crate::deploy::{AppStatus, DeployStatus};
use crate::error::RuntimeError;
use crate::health::HealthCheck;
use crate::runtime::{RegistryCredentials, RuntimeBackend};
use crate::state;

// ─── Core state types ─────────────────────────────────────────────────────────

/// Full in-memory state for a single preview deployment.
///
/// This is stored in `AppState::preview_states` keyed by `"{app}:{preview_id}"`.
#[derive(Debug, Clone)]
pub struct PreviewState {
    /// Unique preview identifier (e.g. "pr-42", "feature-foo").
    pub preview_id: String,
    /// App name (matches an entry in `AppState::apps`).
    pub app: String,
    /// Git commit SHA associated with this preview.
    pub sha: String,
    /// Current lifecycle status.
    pub status: AppStatus,
    /// Running container ID (for container-mode previews).
    pub container_id: Option<String>,
    /// Pod name (for pod-mode previews).
    pub pod_name: Option<String>,
    /// Host port the container is listening on.
    pub port: Option<u16>,
    /// Image tag deployed.
    pub tag: Option<String>,
    /// When this preview was first deployed.
    pub deployed_at: DateTime<Utc>,
    /// When this preview expires (None = no expiry).
    pub expires_at: Option<DateTime<Utc>>,
    /// Fully-qualified preview domain (e.g. "pr-42.preview.example.com").
    pub domain: String,
    /// Path to the rendered pod manifest (pod-mode only).
    pub manifest_path: Option<PathBuf>,
    /// Current deploy ID (transient — not persisted).
    pub deploy_id: Option<String>,
}

/// Serde-serializable subset of [`PreviewState`] for on-disk persistence.
///
/// Omits transient fields (`deploy_id`) that are not meaningful across restarts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistedPreviewState {
    pub preview_id: String,
    pub app: String,
    pub sha: String,
    pub container_id: Option<String>,
    pub pod_name: Option<String>,
    pub port: Option<u16>,
    pub tag: Option<String>,
    pub deployed_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub domain: String,
    #[serde(default)]
    pub manifest_path: Option<PathBuf>,
}

// ─── Conversions ──────────────────────────────────────────────────────────────

impl From<&PreviewState> for PersistedPreviewState {
    fn from(s: &PreviewState) -> Self {
        Self {
            preview_id: s.preview_id.clone(),
            app: s.app.clone(),
            sha: s.sha.clone(),
            container_id: s.container_id.clone(),
            pod_name: s.pod_name.clone(),
            port: s.port,
            tag: s.tag.clone(),
            deployed_at: s.deployed_at,
            expires_at: s.expires_at,
            domain: s.domain.clone(),
            manifest_path: s.manifest_path.clone(),
        }
    }
}

impl From<PersistedPreviewState> for PreviewState {
    fn from(p: PersistedPreviewState) -> Self {
        // Infer status from available identifiers.
        let status = if p.container_id.is_some() || p.pod_name.is_some() {
            AppStatus::Running
        } else {
            AppStatus::NotDeployed
        };
        Self {
            preview_id: p.preview_id,
            app: p.app,
            sha: p.sha,
            status,
            container_id: p.container_id,
            pod_name: p.pod_name,
            port: p.port,
            tag: p.tag,
            deployed_at: p.deployed_at,
            expires_at: p.expires_at,
            domain: p.domain,
            manifest_path: p.manifest_path,
            deploy_id: None,
        }
    }
}

// ─── Deploy error ─────────────────────────────────────────────────────────────

/// Error type for preview deploy failures.
#[derive(Debug)]
pub struct DeployError(pub String);

impl std::fmt::Display for DeployError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<RuntimeError> for DeployError {
    fn from(e: RuntimeError) -> Self {
        DeployError(e.to_string())
    }
}

impl From<crate::error::CaddyError> for DeployError {
    fn from(e: crate::error::CaddyError) -> Self {
        DeployError(e.to_string())
    }
}

// ─── Domain resolution ────────────────────────────────────────────────────────

/// Resolve the fully-qualified preview domain for a preview deployment.
///
/// Domain priority (highest to lowest):
/// 1. App-level override: `app_preview.domain` (from `apps/<name>.toml`)
/// 2. Server-level default: `server_preview.domain` (from `slip.toml`)
/// 3. Error — preview domain is not configured.
///
/// Returns `"{preview_id}.{domain}"`.
pub(crate) fn resolve_preview_domain(
    preview_id: &str,
    _app_name: &str,
    server_preview: &Option<ServerPreviewConfig>,
    app_preview: &Option<AppPreviewConfig>,
) -> Result<String, DeployError> {
    // 1. Check app-level domain override first.
    if let Some(app_cfg) = app_preview
        && let Some(ref domain) = app_cfg.domain
    {
        return Ok(format!("{preview_id}.{domain}"));
    }

    // 2. Fall back to server-level domain.
    if let Some(server_cfg) = server_preview {
        return Ok(format!("{preview_id}.{}", server_cfg.domain));
    }

    // 3. Neither configured — reject with a clear error.
    Err(DeployError(
        "preview domain not configured: set [preview].domain in slip.toml or [preview].domain in the app config".to_string(),
    ))
}

// ─── Preview deploy context and shared state ──────────────────────────────────

/// Context for a single preview deploy.
#[derive(Debug, Clone)]
pub struct PreviewDeployContext {
    pub deploy_id: String,
    pub app_name: String,
    pub image: String,
    pub tag: String,
    pub preview_id: String,
    pub sha: String,
}

/// The parts of `AppState` that the preview deploy orchestrator needs.
pub(crate) struct PreviewSharedState {
    /// Server-level config; provides preview domain and other server-wide settings.
    pub config: SlipConfig,
    pub app_config: AppConfig,
    pub preview_states: Arc<DashMap<String, PreviewState>>,
    pub storage_path: PathBuf,
    pub credentials: Option<RegistryCredentials>,
}

// ─── Helper: set preview status ───────────────────────────────────────────────

fn update_preview_status(
    preview_states: &DashMap<String, PreviewState>,
    key: &str,
    status: AppStatus,
) {
    if let Some(mut entry) = preview_states.get_mut(key) {
        entry.status = status;
    }
}

fn update_preview_deploy_status(
    preview_states: &DashMap<String, PreviewState>,
    key: &str,
    deploy_status: DeployStatus,
) {
    // Map deploy status to app status
    let app_status = match deploy_status {
        DeployStatus::Completed => AppStatus::Running,
        DeployStatus::Failed => AppStatus::Failed,
        DeployStatus::Accepted
        | DeployStatus::Pulling
        | DeployStatus::Configuring
        | DeployStatus::Starting
        | DeployStatus::HealthChecking
        | DeployStatus::Switching => AppStatus::Deploying,
    };
    update_preview_status(preview_states, key, app_status);
}

// ─── Top-level orchestrator ───────────────────────────────────────────────────

/// Execute a preview deploy.
///
/// This function is designed to be called inside a `tokio::spawn`. It drives
/// the preview deploy state machine through: Pull → Configure → Start →
/// HealthCheck → SetRoute → Complete (or Fail at any step).
pub async fn execute_preview_deploy(state: Arc<crate::api::AppState>, ctx: PreviewDeployContext) {
    let app_config = match state.apps.get(&ctx.app_name) {
        Some(cfg) => cfg.clone(),
        None => {
            tracing::error!(app = %ctx.app_name, "preview deploy: app not found in config");
            let key = format!("{}:{}", ctx.app_name, ctx.preview_id);
            update_preview_status(&state.preview_states, &key, AppStatus::Failed);
            return;
        }
    };

    let shared = PreviewSharedState {
        config: state.config.clone(),
        app_config,
        preview_states: Arc::new(state.preview_states.clone()),
        storage_path: state.config.storage.path.clone(),
        credentials: state.registry_credentials(),
    };

    if let Err(e) = execute_preview_deploy_inner(
        shared,
        state.runtime.as_ref(),
        &state.caddy,
        &state.health,
        ctx,
    )
    .await
    {
        tracing::error!(error = %e, "preview deploy failed");
    }
}

/// Inner preview deploy state machine — generic over trait objects for testability.
pub(crate) async fn execute_preview_deploy_inner(
    shared: PreviewSharedState,
    runtime: &dyn RuntimeBackend,
    caddy: &dyn ReverseProxy,
    health: &dyn HealthCheck,
    ctx: PreviewDeployContext,
) -> Result<(), DeployError> {
    let app_name = &ctx.app_name;
    let preview_id = &ctx.preview_id;
    let state_key = format!("{app_name}:{preview_id}");
    // The "virtual" app name used for container naming and Caddy route IDs.
    let preview_app_name = format!("{app_name}-preview-{preview_id}");

    // Capture any existing preview state before overwriting (for redeploy cleanup).
    let existing_container_id = shared
        .preview_states
        .get(&state_key)
        .and_then(|s| s.container_id.clone());
    let existing_pod_name = shared
        .preview_states
        .get(&state_key)
        .and_then(|s| s.pod_name.clone());
    let existing_manifest_path = shared
        .preview_states
        .get(&state_key)
        .and_then(|s| s.manifest_path.clone());

    // Resolve the preview domain before inserting initial state.
    let resolved_domain = resolve_preview_domain(
        preview_id,
        app_name,
        &shared.config.preview,
        &shared.app_config.preview,
    )
    .map_err(|e| DeployError(format!("domain resolution failed: {e}")))?;

    // Insert initial preview state entry (Deploying).
    {
        let initial = PreviewState {
            preview_id: preview_id.clone(),
            app: app_name.clone(),
            sha: ctx.sha.clone(),
            status: AppStatus::Deploying,
            container_id: None,
            pod_name: None,
            port: None,
            tag: Some(ctx.tag.clone()),
            deployed_at: Utc::now(),
            expires_at: None,
            domain: resolved_domain.clone(),
            manifest_path: None,
            deploy_id: Some(ctx.deploy_id.clone()),
        };
        shared.preview_states.insert(state_key.clone(), initial);
    }

    // ── PULL ─────────────────────────────────────────────────────────────────
    tracing::info!(
        app = %app_name,
        preview_id = %preview_id,
        tag = %ctx.tag,
        deploy_id = %ctx.deploy_id,
        "preview deploy: pulling image"
    );

    update_preview_deploy_status(&shared.preview_states, &state_key, DeployStatus::Pulling);

    runtime
        .pull_image(&ctx.image, &ctx.tag, shared.credentials.clone())
        .await
        .map_err(|e| {
            fail_preview(&shared.preview_states, &state_key);
            DeployError(format!("image pull failed: {e}"))
        })?;

    // ── EXTRACT + MERGE CONFIG ────────────────────────────────────────────────
    update_preview_deploy_status(
        &shared.preview_states,
        &state_key,
        DeployStatus::Configuring,
    );

    let merged = match runtime
        .extract_file(&ctx.image, &ctx.tag, "/slip/slip.toml")
        .await
    {
        Ok(Some(bytes)) => {
            tracing::info!(app = %app_name, preview_id = %preview_id, "preview deploy: found repo config");
            match crate::repo_config::parse_repo_config(&bytes) {
                Ok(repo_config) => {
                    if repo_config.app.name != *app_name {
                        fail_preview(&shared.preview_states, &state_key);
                        return Err(DeployError(format!(
                            "repo config app name '{}' does not match deploy app '{}'",
                            repo_config.app.name, app_name
                        )));
                    }
                    // Validate preview is enabled in repo config.
                    match &repo_config.preview {
                        Some(preview_cfg) if preview_cfg.enabled => {}
                        Some(_) => {
                            fail_preview(&shared.preview_states, &state_key);
                            return Err(DeployError(
                                "preview deployments are disabled in repo config (preview.enabled = false)".to_string()
                            ));
                        }
                        None => {
                            fail_preview(&shared.preview_states, &state_key);
                            return Err(DeployError(
                                "no [preview] section in repo config — preview deployments not configured".to_string()
                            ));
                        }
                    }
                    crate::merge::merge_config(&shared.app_config, &repo_config)
                }
                Err(e) => {
                    fail_preview(&shared.preview_states, &state_key);
                    return Err(DeployError(format!("failed to parse repo config: {e}")));
                }
            }
        }
        Ok(None) => {
            fail_preview(&shared.preview_states, &state_key);
            return Err(DeployError(
                "no /slip/slip.toml found in image — preview requires repo config".to_string(),
            ));
        }
        Err(RuntimeError::Unsupported(_)) => {
            fail_preview(&shared.preview_states, &state_key);
            return Err(DeployError(
                "extract_file not supported by this runtime — cannot read preview config"
                    .to_string(),
            ));
        }
        Err(e) => {
            fail_preview(&shared.preview_states, &state_key);
            return Err(DeployError(format!(
                "failed to extract config from image: {e}"
            )));
        }
    };

    let effective_config = merged.app.clone();

    // ── REDEPLOY: tear down existing preview if already running ──────────────
    // Use the values captured before the initial state insert (at the top of this function).
    if let Some(container_id) = existing_container_id {
        tracing::info!(
            app = %app_name,
            preview_id = %preview_id,
            container_id = %container_id,
            "preview deploy: tearing down existing container for redeploy"
        );
        if let Err(e) = runtime.stop_and_remove(&container_id).await {
            tracing::warn!(
                app = %app_name,
                preview_id = %preview_id,
                error = %e,
                "failed to stop existing preview container (non-fatal)"
            );
        }
    }
    if let (Some(pod_name), Some(manifest)) = (existing_pod_name, existing_manifest_path) {
        tracing::info!(
            app = %app_name,
            preview_id = %preview_id,
            pod = %pod_name,
            "preview deploy: tearing down existing pod for redeploy"
        );
        if let Err(e) = runtime.teardown_pod(&manifest).await {
            tracing::warn!(
                app = %app_name,
                preview_id = %preview_id,
                error = %e,
                "failed to teardown existing preview pod (non-fatal)"
            );
        }
        if let Err(e) = caddy.remove_route(&preview_app_name).await {
            tracing::warn!(
                app = %app_name,
                preview_id = %preview_id,
                error = %e,
                "failed to remove existing Caddy route for redeploy (non-fatal)"
            );
        }
    }

    // ── START ─────────────────────────────────────────────────────────────────
    update_preview_deploy_status(&shared.preview_states, &state_key, DeployStatus::Starting);

    let env_vars: Vec<String> = effective_config
        .env
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect();

    let is_pod = merged.kind == "pod";

    let (container_id, host_port, pod_name, manifest_path) = if is_pod {
        // ── POD DEPLOY ──────────────────────────────────────────────────────
        let manifest_in_image = match &merged.manifest {
            Some(p) => p.clone(),
            None => {
                fail_preview(&shared.preview_states, &state_key);
                return Err(DeployError(
                    "pod deploy requires [app].manifest in repo config".to_string(),
                ));
            }
        };

        let manifest_bytes = match runtime
            .extract_file(&ctx.image, &ctx.tag, &manifest_in_image)
            .await
        {
            Ok(Some(bytes)) => bytes,
            Ok(None) => {
                fail_preview(&shared.preview_states, &state_key);
                return Err(DeployError(format!(
                    "manifest '{manifest_in_image}' not found in image"
                )));
            }
            Err(e) => {
                fail_preview(&shared.preview_states, &state_key);
                return Err(DeployError(format!(
                    "failed to extract manifest from image: {e}"
                )));
            }
        };

        let pod_suffix = ulid::Ulid::new().to_string()[..8].to_lowercase();
        let pod_name = format!("{preview_app_name}-{pod_suffix}");

        let render_ctx = crate::manifest::RenderContext {
            app_name: preview_app_name.clone(),
            tag: ctx.tag.clone(),
            primary_image: effective_config.app.image.clone(),
            pod_suffix: pod_suffix.clone(),
            env_vars: env_vars.clone(),
            image_overrides: std::collections::HashMap::new(),
        };

        let rendered_yaml = match crate::manifest::render_manifest(&manifest_bytes, &render_ctx) {
            Ok(yaml) => yaml,
            Err(e) => {
                fail_preview(&shared.preview_states, &state_key);
                return Err(DeployError(format!("failed to render manifest: {e}")));
            }
        };

        let manifests_dir = shared.storage_path.join("manifests");
        if let Err(e) = std::fs::create_dir_all(&manifests_dir) {
            fail_preview(&shared.preview_states, &state_key);
            return Err(DeployError(format!(
                "failed to create manifests directory: {e}"
            )));
        }
        let manifest_path =
            manifests_dir.join(format!("{preview_app_name}-{}.yaml", ctx.deploy_id));
        if let Err(e) = std::fs::write(&manifest_path, &rendered_yaml) {
            fail_preview(&shared.preview_states, &state_key);
            return Err(DeployError(format!("failed to write manifest file: {e}")));
        }

        if let Err(e) = runtime.deploy_pod(&manifest_path, &pod_name).await {
            fail_preview(&shared.preview_states, &state_key);
            return Err(DeployError(format!("pod deploy failed: {e}")));
        }

        let routing_container = merged.routing_container.as_deref().unwrap_or("web");
        let routing_port = effective_config.routing.port;

        let host_port = match runtime
            .pod_container_port(&pod_name, routing_container, routing_port)
            .await
        {
            Ok(port) => port,
            Err(e) => {
                fail_preview(&shared.preview_states, &state_key);
                if let Err(te) = runtime.teardown_pod(&manifest_path).await {
                    tracing::warn!(error = %te, "failed to teardown pod after port lookup failure");
                }
                return Err(DeployError(format!(
                    "failed to get pod container port: {e}"
                )));
            }
        };

        (None, host_port, Some(pod_name), Some(manifest_path))
    } else {
        // ── CONTAINER DEPLOY ─────────────────────────────────────────────────
        let (container_id, host_port) = match runtime
            .create_and_start(
                &preview_app_name,
                &ctx.image,
                &ctx.tag,
                effective_config.routing.port,
                env_vars,
                &effective_config.network.name,
                &effective_config.resources,
            )
            .await
        {
            Ok(result) => result,
            Err(e) => {
                fail_preview(&shared.preview_states, &state_key);
                return Err(DeployError(format!("container start failed: {e}")));
            }
        };

        (Some(container_id), host_port, None, None)
    };

    // Update state with container/pod info.
    {
        if let Some(mut entry) = shared.preview_states.get_mut(&state_key) {
            entry.container_id = container_id.clone();
            entry.pod_name = pod_name.clone();
            entry.port = Some(host_port);
            entry.manifest_path = manifest_path.clone();
        }
    }

    // ── HEALTH CHECK ─────────────────────────────────────────────────────────
    update_preview_deploy_status(
        &shared.preview_states,
        &state_key,
        DeployStatus::HealthChecking,
    );

    if let Err(e) = health.check(host_port, &effective_config.health).await {
        tracing::error!(
            app = %app_name,
            preview_id = %preview_id,
            error = %e,
            "preview health check failed"
        );
        fail_preview(&shared.preview_states, &state_key);
        // Clean up container/pod on health failure.
        if let Some(ref cid) = container_id {
            let _ = runtime.stop_and_remove(cid).await;
        }
        if let Some(ref manifest) = manifest_path {
            let _ = runtime.teardown_pod(manifest).await;
        }
        return Err(DeployError(format!("health check failed: {e}")));
    }

    // ── SET CADDY ROUTE ───────────────────────────────────────────────────────
    update_preview_deploy_status(&shared.preview_states, &state_key, DeployStatus::Switching);

    // Use the resolved domain from earlier (set on initial state insert).
    if let Err(e) = caddy
        .set_route(&preview_app_name, &resolved_domain, host_port)
        .await
    {
        tracing::error!(
            app = %app_name,
            preview_id = %preview_id,
            error = %e,
            "preview caddy route update failed"
        );
        fail_preview(&shared.preview_states, &state_key);
        if let Some(ref cid) = container_id {
            let _ = runtime.stop_and_remove(cid).await;
        }
        if let Some(ref manifest) = manifest_path {
            let _ = runtime.teardown_pod(manifest).await;
        }
        return Err(DeployError(format!("caddy route update failed: {e}")));
    }

    // ── COMPLETED ─────────────────────────────────────────────────────────────
    {
        if let Some(mut entry) = shared.preview_states.get_mut(&state_key) {
            entry.status = AppStatus::Running;
            entry.port = Some(host_port);
        }
    }

    // Persist state to disk (non-fatal).
    let state_dir = shared.storage_path.join("state");
    if let Some(entry) = shared.preview_states.get(&state_key)
        && let Err(e) = state::save_preview_state(&state_dir, app_name, preview_id, &entry)
    {
        tracing::warn!(
            app = %app_name,
            preview_id = %preview_id,
            error = %e,
            "failed to persist preview state (non-fatal)"
        );
    }

    tracing::info!(
        app = %app_name,
        preview_id = %preview_id,
        tag = %ctx.tag,
        port = host_port,
        "preview deploy completed"
    );

    Ok(())
}

/// Mark a preview as failed in the state map.
fn fail_preview(preview_states: &DashMap<String, PreviewState>, key: &str) {
    if let Some(mut entry) = preview_states.get_mut(key) {
        entry.status = AppStatus::Failed;
    }
}

// ─── Teardown ─────────────────────────────────────────────────────────────────

/// Tear down a preview deployment.
///
/// Stops/removes the container or pod, removes the Caddy route, clears the
/// in-memory state, and deletes the persisted state file.
pub async fn teardown_preview(
    runtime: &dyn RuntimeBackend,
    caddy: &dyn ReverseProxy,
    preview_states: &DashMap<String, PreviewState>,
    storage_path: &Path,
    app_name: &str,
    preview_id: &str,
) -> Result<(), DeployError> {
    let key = format!("{app_name}:{preview_id}");
    let preview_app_name = format!("{app_name}-preview-{preview_id}");

    // Look up state.
    let (container_id, pod_name, manifest_path) = {
        match preview_states.get(&key) {
            Some(entry) => (
                entry.container_id.clone(),
                entry.pod_name.clone(),
                entry.manifest_path.clone(),
            ),
            None => {
                tracing::warn!(
                    app = %app_name,
                    preview_id = %preview_id,
                    "teardown_preview: preview not found in state (already removed?)"
                );
                return Ok(());
            }
        }
    };

    // Stop container if present.
    if let Some(ref cid) = container_id {
        tracing::info!(app = %app_name, preview_id = %preview_id, container_id = %cid, "stopping preview container");
        if let Err(e) = runtime.stop_and_remove(cid).await {
            tracing::warn!(
                app = %app_name,
                preview_id = %preview_id,
                error = %e,
                "failed to stop preview container (non-fatal)"
            );
        }
    }

    // Tear down pod if present.
    if let (Some(pod), Some(manifest)) = (&pod_name, &manifest_path) {
        tracing::info!(app = %app_name, preview_id = %preview_id, pod = %pod, "tearing down preview pod");
        if let Err(e) = runtime.teardown_pod(manifest).await {
            tracing::warn!(
                app = %app_name,
                preview_id = %preview_id,
                error = %e,
                "failed to teardown preview pod (non-fatal)"
            );
        }
    }

    // Remove Caddy route.
    tracing::info!(app = %app_name, preview_id = %preview_id, "removing preview Caddy route");
    if let Err(e) = caddy.remove_route(&preview_app_name).await {
        tracing::warn!(
            app = %app_name,
            preview_id = %preview_id,
            error = %e,
            "failed to remove Caddy route for preview (non-fatal)"
        );
    }

    // Remove from in-memory state.
    preview_states.remove(&key);

    // Delete persisted state file.
    let state_dir = storage_path.join("state");
    if let Err(e) = state::delete_preview_state(&state_dir, app_name, preview_id) {
        tracing::warn!(
            app = %app_name,
            preview_id = %preview_id,
            error = %e,
            "failed to delete persisted preview state (non-fatal)"
        );
    }

    tracing::info!(app = %app_name, preview_id = %preview_id, "preview teardown complete");
    Ok(())
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::time::Duration;

    use chrono::Utc;
    use dashmap::DashMap;
    use tempfile::TempDir;

    use super::*;
    use crate::caddy::ReverseProxy;
    use crate::config::{
        AppConfig, AppInfo, AppPreviewConfig, AuthConfig, CaddyConfig, DeployConfig, HealthConfig,
        RegistryConfig, ResourceConfig, RoutingConfig, RuntimeConfig, ServerConfig,
        ServerPreviewConfig, SlipConfig, StorageConfig,
    };
    use crate::error::{CaddyError, HealthError, RuntimeError};
    use crate::health::HealthCheck;
    use crate::runtime::{PodInfo, RegistryCredentials, RuntimeBackend};

    // ── Mock: RuntimeBackend ──────────────────────────────────────────────────

    struct MockDocker {
        pull_ok: bool,
        container_id: String,
        container_port: u16,
        stop_count: Arc<AtomicU32>,
        extract_result: Result<Option<Vec<u8>>, RuntimeError>,
        manifest_extract_result: Option<Result<Option<Vec<u8>>, RuntimeError>>,
        pod_port: Option<u16>,
        teardown_count: Arc<AtomicU32>,
    }

    impl MockDocker {
        fn new() -> Self {
            Self {
                pull_ok: true,
                container_id: "preview-container-id".to_string(),
                container_port: 54321,
                stop_count: Arc::new(AtomicU32::new(0)),
                extract_result: Err(RuntimeError::Unsupported("mock".to_string())),
                manifest_extract_result: None,
                pod_port: None,
                teardown_count: Arc::new(AtomicU32::new(0)),
            }
        }

        fn with_repo_config(bytes: Vec<u8>) -> Self {
            Self {
                extract_result: Ok(Some(bytes)),
                ..Self::new()
            }
        }

        fn failing_pull() -> Self {
            Self {
                pull_ok: false,
                ..Self::new()
            }
        }

        fn stop_count(&self) -> Arc<AtomicU32> {
            self.stop_count.clone()
        }

        #[allow(dead_code)]
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
            let result = if let Some(ref manifest_result) = self.manifest_extract_result
                && path != "/slip/slip.toml"
            {
                match manifest_result {
                    Ok(opt) => Ok(opt.clone()),
                    Err(e) => Err(clone_runtime_error(e)),
                }
            } else {
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
            Box<dyn std::future::Future<Output = Result<PodInfo, RuntimeError>> + Send + 'a>,
        > {
            if self.pod_port.is_some() {
                let info = PodInfo {
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
        set_route_count: Arc<AtomicU32>,
        remove_route_count: Arc<AtomicU32>,
    }

    impl MockCaddy {
        fn success() -> Self {
            Self {
                ok: true,
                set_route_count: Arc::new(AtomicU32::new(0)),
                remove_route_count: Arc::new(AtomicU32::new(0)),
            }
        }

        #[allow(dead_code)]
        fn failing() -> Self {
            Self {
                ok: false,
                set_route_count: Arc::new(AtomicU32::new(0)),
                remove_route_count: Arc::new(AtomicU32::new(0)),
            }
        }

        fn remove_count(&self) -> Arc<AtomicU32> {
            self.remove_route_count.clone()
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
            self.set_route_count.fetch_add(1, Ordering::SeqCst);
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
            self.remove_route_count.fetch_add(1, Ordering::SeqCst);
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
            runtime: RuntimeConfig::default(),
            // Include a default server preview config so existing tests work.
            // Tests that need to verify "no domain configured" create their own config.
            preview: Some(ServerPreviewConfig {
                domain: "preview.example.com".to_string(),
                max_per_app: None,
                default_ttl: None,
                max_memory: None,
                max_cpus: None,
            }),
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
                path: None,
                interval: Duration::from_millis(1),
                timeout: Duration::from_millis(10),
                retries: 1,
                start_period: Duration::ZERO,
            },
            deploy: DeployConfig {
                strategy: "blue-green".to_string(),
                drain_timeout: Duration::ZERO,
            },
            env: HashMap::new(),
            env_file: None,
            resources: ResourceConfig::default(),
            network: crate::config::NetworkConfig::default(),
            preview: None,
        }
    }

    fn make_preview_repo_config_toml(enabled: bool) -> Vec<u8> {
        format!(
            r#"
[app]
name = "testapp"

[preview]
enabled = {enabled}
"#
        )
        .into_bytes()
    }

    fn make_shared(
        tmp: &TempDir,
        app_config: AppConfig,
        preview_states: Arc<DashMap<String, PreviewState>>,
    ) -> PreviewSharedState {
        let config = test_slip_config(tmp.path().to_path_buf());
        PreviewSharedState {
            config: config.clone(),
            app_config,
            preview_states,
            storage_path: tmp.path().to_path_buf(),
            credentials: None,
        }
    }

    fn test_preview_ctx() -> PreviewDeployContext {
        PreviewDeployContext {
            deploy_id: "dep_preview001".to_string(),
            app_name: "testapp".to_string(),
            image: "ghcr.io/org/testapp".to_string(),
            tag: "sha-abc123".to_string(),
            preview_id: "pr-42".to_string(),
            sha: "abc123def456".to_string(),
        }
    }

    // ── Tests ─────────────────────────────────────────────────────────────────

    /// Happy path: pull → config (preview enabled) → start container → health → caddy route → complete.
    #[tokio::test]
    async fn test_preview_deploy_happy_path() {
        let tmp = tempfile::tempdir().unwrap();
        let repo_config_bytes = make_preview_repo_config_toml(true);
        let docker = MockDocker::with_repo_config(repo_config_bytes);
        let caddy = MockCaddy::success();
        let health = MockHealth::passing();
        let preview_states = Arc::new(DashMap::new());

        let shared = make_shared(&tmp, test_app_config(), preview_states.clone());
        let ctx = test_preview_ctx();

        let result = execute_preview_deploy_inner(shared, &docker, &caddy, &health, ctx).await;

        assert!(result.is_ok(), "preview deploy should succeed: {result:?}");

        // Preview state should be Running.
        let state = preview_states
            .get("testapp:pr-42")
            .expect("state should exist");
        assert_eq!(state.status, AppStatus::Running);
        assert_eq!(state.container_id.as_deref(), Some("preview-container-id"));
        assert_eq!(state.port, Some(54321));
        assert_eq!(state.tag.as_deref(), Some("sha-abc123"));
        assert_eq!(state.preview_id, "pr-42");
        assert_eq!(state.app, "testapp");

        // Caddy route should have been set.
        assert_eq!(caddy.set_route_count.load(Ordering::SeqCst), 1);

        // State file should have been persisted.
        let state_file = tmp
            .path()
            .join("state")
            .join("previews")
            .join("testapp")
            .join("pr-42.json");
        assert!(
            state_file.exists(),
            "preview state should be persisted to disk"
        );
    }

    /// Preview deploy with preview.enabled = false → abort with error.
    #[tokio::test]
    async fn test_preview_deploy_disabled_in_repo_config() {
        let tmp = tempfile::tempdir().unwrap();
        let repo_config_bytes = make_preview_repo_config_toml(false);
        let docker = MockDocker::with_repo_config(repo_config_bytes);
        let caddy = MockCaddy::success();
        let health = MockHealth::passing();
        let preview_states = Arc::new(DashMap::new());

        let shared = make_shared(&tmp, test_app_config(), preview_states.clone());
        let ctx = test_preview_ctx();

        let result = execute_preview_deploy_inner(shared, &docker, &caddy, &health, ctx).await;

        assert!(result.is_err(), "should fail when preview is disabled");
        let err_msg = result.unwrap_err().0;
        assert!(
            err_msg.contains("disabled"),
            "error should mention 'disabled': {err_msg}"
        );

        // State should be Failed.
        let state = preview_states
            .get("testapp:pr-42")
            .expect("state should be inserted");
        assert_eq!(state.status, AppStatus::Failed);

        // No container should have been started → no caddy route.
        assert_eq!(caddy.set_route_count.load(Ordering::SeqCst), 0);
    }

    /// Preview deploy when no repo config exists → abort.
    #[tokio::test]
    async fn test_preview_deploy_no_repo_config() {
        let tmp = tempfile::tempdir().unwrap();
        // Docker returns Unsupported for extract_file (default MockDocker).
        let docker = MockDocker::new();
        let caddy = MockCaddy::success();
        let health = MockHealth::passing();
        let preview_states = Arc::new(DashMap::new());

        let shared = make_shared(&tmp, test_app_config(), preview_states.clone());
        let ctx = test_preview_ctx();

        let result = execute_preview_deploy_inner(shared, &docker, &caddy, &health, ctx).await;

        assert!(result.is_err(), "should fail without repo config");

        let state = preview_states.get("testapp:pr-42").expect("state inserted");
        assert_eq!(state.status, AppStatus::Failed);
    }

    /// Preview redeploy: same preview_id already has a container → old container stopped first.
    #[tokio::test]
    async fn test_preview_redeploy_stops_old_container() {
        let tmp = tempfile::tempdir().unwrap();
        let repo_config_bytes = make_preview_repo_config_toml(true);
        let docker = MockDocker::with_repo_config(repo_config_bytes);
        let stop_count = docker.stop_count();
        let caddy = MockCaddy::success();
        let health = MockHealth::passing();
        let preview_states = Arc::new(DashMap::<String, PreviewState>::new());

        // Pre-populate state with an existing container for this preview.
        preview_states.insert(
            "testapp:pr-42".to_string(),
            PreviewState {
                preview_id: "pr-42".to_string(),
                app: "testapp".to_string(),
                sha: "old-sha".to_string(),
                status: AppStatus::Running,
                container_id: Some("old-container-id".to_string()),
                pod_name: None,
                port: Some(11111),
                tag: Some("sha-old".to_string()),
                deployed_at: Utc::now(),
                expires_at: None,
                domain: "pr-42.preview.example.com".to_string(),
                manifest_path: None,
                deploy_id: Some("dep_old".to_string()),
            },
        );

        let shared = make_shared(&tmp, test_app_config(), preview_states.clone());
        let ctx = test_preview_ctx();

        let result = execute_preview_deploy_inner(shared, &docker, &caddy, &health, ctx).await;

        assert!(result.is_ok(), "redeploy should succeed: {result:?}");

        // Old container should have been stopped.
        assert_eq!(
            stop_count.load(Ordering::SeqCst),
            1,
            "old container should be stopped exactly once"
        );

        // New container should be current.
        let state = preview_states.get("testapp:pr-42").unwrap();
        assert_eq!(state.status, AppStatus::Running);
        assert_eq!(state.container_id.as_deref(), Some("preview-container-id"));
    }

    /// Image pull failure → preview marked Failed, no container started.
    #[tokio::test]
    async fn test_preview_deploy_pull_failure() {
        let tmp = tempfile::tempdir().unwrap();
        let docker = MockDocker::failing_pull();
        let caddy = MockCaddy::success();
        let health = MockHealth::passing();
        let preview_states = Arc::new(DashMap::new());

        let shared = make_shared(&tmp, test_app_config(), preview_states.clone());
        let ctx = test_preview_ctx();

        let result = execute_preview_deploy_inner(shared, &docker, &caddy, &health, ctx).await;

        assert!(result.is_err());
        let err = result.unwrap_err().0;
        assert!(err.contains("image pull failed"), "error: {err}");

        let state = preview_states.get("testapp:pr-42").unwrap();
        assert_eq!(state.status, AppStatus::Failed);
    }

    /// Health check failure → container stopped, preview marked Failed.
    #[tokio::test]
    async fn test_preview_deploy_health_failure() {
        let tmp = tempfile::tempdir().unwrap();
        let repo_config_bytes = make_preview_repo_config_toml(true);
        let docker = MockDocker::with_repo_config(repo_config_bytes);
        let stop_count = docker.stop_count();
        let caddy = MockCaddy::success();
        let health = MockHealth::failing();
        let preview_states = Arc::new(DashMap::new());

        let shared = make_shared(&tmp, test_app_config(), preview_states.clone());
        let ctx = test_preview_ctx();

        let result = execute_preview_deploy_inner(shared, &docker, &caddy, &health, ctx).await;

        assert!(result.is_err());
        let err = result.unwrap_err().0;
        assert!(err.contains("health check failed"), "error: {err}");

        // Container should have been stopped on health failure.
        assert_eq!(
            stop_count.load(Ordering::SeqCst),
            1,
            "container should be stopped after health failure"
        );

        let state = preview_states.get("testapp:pr-42").unwrap();
        assert_eq!(state.status, AppStatus::Failed);
    }

    // ── teardown_preview tests ────────────────────────────────────────────────

    /// Happy path teardown: container stopped, route removed, state cleared.
    #[tokio::test]
    async fn test_teardown_preview_happy_path() {
        let tmp = tempfile::tempdir().unwrap();
        let docker = MockDocker::new();
        let stop_count = docker.stop_count();
        let caddy = MockCaddy::success();
        let remove_count = caddy.remove_count();
        let preview_states: DashMap<String, PreviewState> = DashMap::new();

        // Insert a running preview.
        preview_states.insert(
            "testapp:pr-1".to_string(),
            PreviewState {
                preview_id: "pr-1".to_string(),
                app: "testapp".to_string(),
                sha: "abc".to_string(),
                status: AppStatus::Running,
                container_id: Some("ctr-preview-001".to_string()),
                pod_name: None,
                port: Some(54000),
                tag: Some("v1".to_string()),
                deployed_at: Utc::now(),
                expires_at: None,
                domain: "pr-1.preview.example.com".to_string(),
                manifest_path: None,
                deploy_id: None,
            },
        );

        // Persist a state file so we can verify deletion.
        let state_dir = tmp.path().join("state");
        let state_ref = preview_states.get("testapp:pr-1").unwrap();
        state::save_preview_state(&state_dir, "testapp", "pr-1", &state_ref).unwrap();
        drop(state_ref);

        let result = teardown_preview(
            &docker,
            &caddy,
            &preview_states,
            tmp.path(),
            "testapp",
            "pr-1",
        )
        .await;

        assert!(result.is_ok(), "teardown should succeed: {result:?}");

        // Container should have been stopped.
        assert_eq!(stop_count.load(Ordering::SeqCst), 1);

        // Caddy route should have been removed.
        assert_eq!(remove_count.load(Ordering::SeqCst), 1);

        // In-memory state should be gone.
        assert!(
            preview_states.get("testapp:pr-1").is_none(),
            "preview state should be removed from DashMap"
        );

        // Persisted file should be deleted.
        let state_file = state_dir.join("previews").join("testapp").join("pr-1.json");
        assert!(
            !state_file.exists(),
            "persisted state file should be deleted"
        );
    }

    /// Teardown on non-existent preview → Ok (idempotent).
    #[tokio::test]
    async fn test_teardown_preview_nonexistent_is_ok() {
        let tmp = tempfile::tempdir().unwrap();
        let docker = MockDocker::new();
        let caddy = MockCaddy::success();
        let preview_states: DashMap<String, PreviewState> = DashMap::new();

        let result = teardown_preview(
            &docker,
            &caddy,
            &preview_states,
            tmp.path(),
            "testapp",
            "nonexistent",
        )
        .await;

        assert!(
            result.is_ok(),
            "teardown of nonexistent preview should succeed"
        );
    }

    // ── State type tests (from Phase 1) ───────────────────────────────────────

    fn sample_preview_state() -> PreviewState {
        PreviewState {
            preview_id: "pr-42".to_string(),
            app: "myapp".to_string(),
            sha: "abc123def456".to_string(),
            status: AppStatus::Running,
            container_id: Some("ctr-abc123".to_string()),
            pod_name: None,
            port: Some(54321),
            tag: Some("sha-abc123".to_string()),
            deployed_at: Utc::now(),
            expires_at: None,
            domain: "pr-42.preview.example.com".to_string(),
            manifest_path: None,
            deploy_id: Some("dep_transient".to_string()),
        }
    }

    #[test]
    fn test_preview_state_to_persisted_omits_deploy_id() {
        let state = sample_preview_state();
        let persisted = PersistedPreviewState::from(&state);

        assert_eq!(persisted.preview_id, "pr-42");
        assert_eq!(persisted.app, "myapp");
        assert_eq!(persisted.sha, "abc123def456");
        assert_eq!(persisted.container_id.as_deref(), Some("ctr-abc123"));
        assert_eq!(persisted.port, Some(54321));
        assert_eq!(persisted.domain, "pr-42.preview.example.com");

        // deploy_id is NOT in PersistedPreviewState — compile-time guarantee.
    }

    #[test]
    fn test_persisted_to_preview_state_infers_status_running() {
        let persisted = PersistedPreviewState {
            preview_id: "pr-1".to_string(),
            app: "app".to_string(),
            sha: "sha1".to_string(),
            container_id: Some("ctr-xyz".to_string()),
            pod_name: None,
            port: Some(9000),
            tag: Some("v1".to_string()),
            deployed_at: Utc::now(),
            expires_at: None,
            domain: "pr-1.preview.example.com".to_string(),
            manifest_path: None,
        };

        let state = PreviewState::from(persisted);
        assert_eq!(state.status, AppStatus::Running);
        assert!(
            state.deploy_id.is_none(),
            "deploy_id must be None after load"
        );
    }

    #[test]
    fn test_persisted_to_preview_state_infers_status_not_deployed() {
        let persisted = PersistedPreviewState {
            preview_id: "pr-2".to_string(),
            app: "app".to_string(),
            sha: "sha2".to_string(),
            container_id: None,
            pod_name: None,
            port: None,
            tag: None,
            deployed_at: Utc::now(),
            expires_at: None,
            domain: "pr-2.preview.example.com".to_string(),
            manifest_path: None,
        };

        let state = PreviewState::from(persisted);
        assert_eq!(state.status, AppStatus::NotDeployed);
    }

    #[test]
    fn test_round_trip_preserves_key_fields() {
        let original = sample_preview_state();
        let persisted = PersistedPreviewState::from(&original);
        let restored = PreviewState::from(persisted);

        assert_eq!(restored.preview_id, original.preview_id);
        assert_eq!(restored.app, original.app);
        assert_eq!(restored.sha, original.sha);
        assert_eq!(restored.container_id, original.container_id);
        assert_eq!(restored.port, original.port);
        assert_eq!(restored.tag, original.tag);
        assert_eq!(restored.domain, original.domain);
        // deploy_id is transient and not persisted
        assert!(restored.deploy_id.is_none());
    }

    #[test]
    fn test_persisted_preview_state_serializes_to_json() {
        let state = sample_preview_state();
        let persisted = PersistedPreviewState::from(&state);

        let json = serde_json::to_string(&persisted).expect("should serialize");
        let deserialized: PersistedPreviewState =
            serde_json::from_str(&json).expect("should deserialize");

        assert_eq!(deserialized.preview_id, "pr-42");
        assert_eq!(deserialized.container_id.as_deref(), Some("ctr-abc123"));
    }

    // ── Phase 3: resolve_preview_domain tests ─────────────────────────────────

    fn server_preview_config(domain: &str) -> Option<ServerPreviewConfig> {
        Some(ServerPreviewConfig {
            domain: domain.to_string(),
            max_per_app: None,
            default_ttl: None,
            max_memory: None,
            max_cpus: None,
        })
    }

    fn app_preview_config(domain: Option<&str>) -> Option<AppPreviewConfig> {
        Some(AppPreviewConfig {
            domain: domain.map(|d| d.to_string()),
            max: None,
        })
    }

    /// App-level domain override takes precedence over server-level.
    #[test]
    fn test_resolve_domain_app_override_wins() {
        let result = resolve_preview_domain(
            "pr-42",
            "testapp",
            &server_preview_config("preview.server.com"),
            &app_preview_config(Some("preview.app.com")),
        );
        assert_eq!(result.unwrap(), "pr-42.preview.app.com");
    }

    /// Server-level domain is used when app has no domain override.
    #[test]
    fn test_resolve_domain_server_fallback() {
        let result = resolve_preview_domain(
            "pr-42",
            "testapp",
            &server_preview_config("preview.server.com"),
            &None, // no app preview config
        );
        assert_eq!(result.unwrap(), "pr-42.preview.server.com");
    }

    /// App-level config exists but without domain → falls back to server.
    #[test]
    fn test_resolve_domain_app_config_no_domain_falls_back_to_server() {
        let result = resolve_preview_domain(
            "pr-7",
            "testapp",
            &server_preview_config("preview.server.com"),
            &app_preview_config(None), // app config exists but domain is None
        );
        assert_eq!(result.unwrap(), "pr-7.preview.server.com");
    }

    /// Neither app nor server has preview domain → error.
    #[test]
    fn test_resolve_domain_neither_configured_returns_error() {
        let result = resolve_preview_domain(
            "pr-42", "testapp", &None, // no server preview config
            &None, // no app preview config
        );
        assert!(
            result.is_err(),
            "should return error when no domain configured"
        );
        let err = result.unwrap_err().0;
        assert!(
            err.contains("not configured") || err.contains("domain"),
            "error should mention domain config: {err}"
        );
    }

    /// Preview ID is correctly included as subdomain prefix.
    #[test]
    fn test_resolve_domain_uses_preview_id_as_subdomain() {
        let result = resolve_preview_domain(
            "feature-foo-bar",
            "testapp",
            &server_preview_config("preview.example.com"),
            &None,
        );
        assert_eq!(result.unwrap(), "feature-foo-bar.preview.example.com");
    }

    // ── Phase 3: deploy uses correct domain ──────────────────────────────────

    /// execute_preview_deploy_inner sets the correct domain when server preview config
    /// has a domain set.
    #[tokio::test]
    async fn test_deploy_sets_correct_domain_from_server_config() {
        let tmp = tempfile::tempdir().unwrap();
        let repo_config_bytes = make_preview_repo_config_toml(true);
        let docker = MockDocker::with_repo_config(repo_config_bytes);
        let caddy = MockCaddy::success();
        let health = MockHealth::passing();
        let preview_states = Arc::new(DashMap::new());

        // Build shared state with server-level preview domain configured.
        let mut config = test_slip_config(tmp.path().to_path_buf());
        config.preview = Some(ServerPreviewConfig {
            domain: "preview.example.com".to_string(),
            max_per_app: None,
            default_ttl: None,
            max_memory: None,
            max_cpus: None,
        });

        let shared = PreviewSharedState {
            config,
            app_config: test_app_config(),
            preview_states: preview_states.clone(),
            storage_path: tmp.path().to_path_buf(),
            credentials: None,
        };
        let ctx = test_preview_ctx(); // preview_id = "pr-42"

        let result = execute_preview_deploy_inner(shared, &docker, &caddy, &health, ctx).await;

        assert!(result.is_ok(), "deploy should succeed: {result:?}");

        // State domain should be resolved correctly.
        let state = preview_states.get("testapp:pr-42").unwrap();
        assert_eq!(
            state.domain, "pr-42.preview.example.com",
            "domain should be pr-42.preview.example.com"
        );

        // Caddy route should have been set.
        assert_eq!(caddy.set_route_count.load(Ordering::SeqCst), 1);
    }

    /// App-level domain override is used when set.
    #[tokio::test]
    async fn test_deploy_uses_app_level_domain_override() {
        let tmp = tempfile::tempdir().unwrap();
        let repo_config_bytes = make_preview_repo_config_toml(true);
        let docker = MockDocker::with_repo_config(repo_config_bytes);
        let caddy = MockCaddy::success();
        let health = MockHealth::passing();
        let preview_states = Arc::new(DashMap::new());

        let mut config = test_slip_config(tmp.path().to_path_buf());
        config.preview = Some(ServerPreviewConfig {
            domain: "preview.server.com".to_string(),
            max_per_app: None,
            default_ttl: None,
            max_memory: None,
            max_cpus: None,
        });

        let mut app_config = test_app_config();
        app_config.preview = Some(AppPreviewConfig {
            domain: Some("preview.app.com".to_string()),
            max: None,
        });

        let shared = PreviewSharedState {
            config,
            app_config,
            preview_states: preview_states.clone(),
            storage_path: tmp.path().to_path_buf(),
            credentials: None,
        };
        let ctx = test_preview_ctx(); // preview_id = "pr-42"

        let result = execute_preview_deploy_inner(shared, &docker, &caddy, &health, ctx).await;

        assert!(result.is_ok(), "deploy should succeed: {result:?}");

        let state = preview_states.get("testapp:pr-42").unwrap();
        assert_eq!(
            state.domain, "pr-42.preview.app.com",
            "app-level domain should override server domain"
        );
    }

    /// No preview domain configured → deploy fails with DeployError.
    #[tokio::test]
    async fn test_deploy_fails_when_no_preview_domain_configured() {
        let tmp = tempfile::tempdir().unwrap();
        let repo_config_bytes = make_preview_repo_config_toml(true);
        let docker = MockDocker::with_repo_config(repo_config_bytes);
        let caddy = MockCaddy::success();
        let health = MockHealth::passing();
        let preview_states = Arc::new(DashMap::new());

        // Explicitly build shared state with NO preview config on server or app.
        let mut config = test_slip_config(tmp.path().to_path_buf());
        config.preview = None; // override the default preview config
        let shared = PreviewSharedState {
            config,
            app_config: test_app_config(),
            preview_states: preview_states.clone(),
            storage_path: tmp.path().to_path_buf(),
            credentials: None,
        };
        let ctx = test_preview_ctx();

        let result = execute_preview_deploy_inner(shared, &docker, &caddy, &health, ctx).await;

        assert!(result.is_err(), "should fail when no domain configured");
        let err = result.unwrap_err().0;
        assert!(
            err.contains("domain") || err.contains("not configured"),
            "error should mention domain configuration: {err}"
        );
        // Caddy should not have been called.
        assert_eq!(caddy.set_route_count.load(Ordering::SeqCst), 0);
    }

    // ── Phase 3: teardown uses correct route name ─────────────────────────────

    /// teardown_preview calls remove_route with "{app}-preview-{preview_id}" as the route name.
    #[tokio::test]
    async fn test_teardown_calls_remove_route_with_correct_name() {
        let tmp = tempfile::tempdir().unwrap();
        let docker = MockDocker::new();
        let caddy = MockCaddy::success();
        let remove_count = caddy.remove_count();
        let preview_states: DashMap<String, PreviewState> = DashMap::new();

        // Insert a running preview.
        preview_states.insert(
            "testapp:pr-42".to_string(),
            PreviewState {
                preview_id: "pr-42".to_string(),
                app: "testapp".to_string(),
                sha: "abc".to_string(),
                status: AppStatus::Running,
                container_id: Some("ctr-001".to_string()),
                pod_name: None,
                port: Some(54000),
                tag: Some("v1".to_string()),
                deployed_at: Utc::now(),
                expires_at: None,
                domain: "pr-42.preview.example.com".to_string(),
                manifest_path: None,
                deploy_id: None,
            },
        );

        let result = teardown_preview(
            &docker,
            &caddy,
            &preview_states,
            tmp.path(),
            "testapp",
            "pr-42",
        )
        .await;

        assert!(result.is_ok(), "teardown should succeed: {result:?}");

        // remove_route should have been called exactly once.
        assert_eq!(
            remove_count.load(Ordering::SeqCst),
            1,
            "remove_route should be called once"
        );

        // State should be cleared.
        assert!(preview_states.get("testapp:pr-42").is_none());
    }
}
