//! Deploy orchestrator — the state machine that coordinates a full blue-green deploy.

use std::collections::HashMap;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use dashmap::DashMap;
use serde::Serialize;
use tokio::sync::RwLock;

use crate::api::AppState;
use crate::caddy::ReverseProxy;
use crate::config::{AppConfig, SlipConfig};
use crate::docker::ContainerRuntime;
use crate::health::HealthCheck;
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

// ─── Shared deploy state (subset of AppState) ────────────────────────────────

/// The parts of [`AppState`] that the deploy orchestrator needs, extracted so
/// the inner function can be tested with mock dependencies.
pub(crate) struct DeploySharedState<'a> {
    pub config: &'a SlipConfig,
    pub apps: &'a HashMap<String, AppConfig>,
    pub app_states: &'a RwLock<HashMap<String, AppRuntimeState>>,
    pub deploys: &'a DashMap<String, DeployContext>,
    pub credentials: Option<bollard::auth::DockerCredentials>,
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
        credentials: state.docker_credentials(),
    };
    execute_deploy_inner(shared, &state.docker, &state.caddy, &state.health, ctx).await;
}

/// Inner deploy state machine — generic over trait objects so it can be driven
/// from tests with mock implementations.
pub(crate) async fn execute_deploy_inner(
    shared: DeploySharedState<'_>,
    docker: &dyn ContainerRuntime,
    caddy: &dyn ReverseProxy,
    health: &dyn HealthCheck,
    mut ctx: DeployContext,
) {
    let app_name = ctx.app.clone();
    let app_config = shared.apps.get(&app_name).unwrap().clone();

    // ── PULL ─────────────────────────────────────────────────────────────────
    ctx.status = DeployStatus::Pulling;
    record_deploy(shared.deploys, &ctx);
    tracing::info!(
        app = %app_name,
        tag = %ctx.tag,
        deploy_id = %ctx.id,
        "pulling image"
    );

    if let Err(e) = docker
        .pull_image(&ctx.image, &ctx.tag, shared.credentials)
        .await
    {
        ctx.fail(&format!("image pull failed: {e}"));
        record_deploy(shared.deploys, &ctx);
        return;
    }

    // ── START NEW ────────────────────────────────────────────────────────────
    ctx.status = DeployStatus::Starting;
    record_deploy(shared.deploys, &ctx);

    let env_vars = resolve_env_vars_for_app(&app_config);
    match docker
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
            record_deploy(shared.deploys, &ctx);
            return;
        }
    }

    // ── HEALTH CHECK ─────────────────────────────────────────────────────────
    ctx.status = DeployStatus::HealthChecking;
    record_deploy(shared.deploys, &ctx);

    if let Err(e) = health
        .check(ctx.new_port.unwrap(), &app_config.health)
        .await
    {
        tracing::error!(app = %app_name, error = %e, "health check failed");
        if let Some(ref id) = ctx.new_container_id {
            let _ = docker.stop_and_remove(id).await;
        }
        ctx.fail(&format!("health check failed: {e}"));
        record_deploy(shared.deploys, &ctx);
        return;
    }

    // ── SWITCH ───────────────────────────────────────────────────────────────
    ctx.status = DeployStatus::Switching;
    record_deploy(shared.deploys, &ctx);

    let old_container_id = {
        let states = shared.app_states.read().await;
        states
            .get(&app_name)
            .and_then(|s| s.current_container_id.clone())
    };

    if let Err(e) = caddy
        .set_route(&app_name, &app_config.routing.domain, ctx.new_port.unwrap())
        .await
    {
        tracing::error!(app = %app_name, error = %e, "caddy route update failed");
        if let Some(ref id) = ctx.new_container_id {
            let _ = docker.stop_and_remove(id).await;
        }
        ctx.fail(&format!("caddy route update failed: {e}"));
        record_deploy(shared.deploys, &ctx);
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

    // ── DRAIN + STOP OLD ─────────────────────────────────────────────────────
    if let Some(old_id) = old_container_id {
        tracing::info!(app = %app_name, "draining old container");
        tokio::time::sleep(app_config.deploy.drain_timeout).await;
        if let Err(e) = docker.stop_and_remove(&old_id).await {
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
    record_deploy(shared.deploys, &ctx);
    tracing::info!(
        app = %app_name,
        tag = %ctx.tag,
        deploy_id = %ctx.id,
        "deploy completed"
    );
}

// ─── Private helpers ──────────────────────────────────────────────────────────

fn record_deploy(deploys: &DashMap<String, DeployContext>, ctx: &DeployContext) {
    deploys.insert(ctx.id.clone(), ctx.clone());
    if deploys.len() > 100
        && let Some(oldest) = deploys.iter().next().map(|e| e.key().clone())
    {
        deploys.remove(&oldest);
    }
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
    use crate::docker::ContainerRuntime;
    use crate::error::{CaddyError, DockerError, HealthError};
    use crate::health::HealthCheck;

    // ── Mock: ContainerRuntime ────────────────────────────────────────────────

    /// Configurable mock for `ContainerRuntime`.
    struct MockDocker {
        /// Whether `pull_image` should succeed.
        pull_ok: bool,
        /// Container ID + port returned by `create_and_start`.
        container_id: String,
        container_port: u16,
        /// Tracks how many times `stop_and_remove` was called.
        stop_count: Arc<AtomicU32>,
    }

    impl MockDocker {
        fn new() -> Self {
            Self {
                pull_ok: true,
                container_id: "mock-container-id".to_string(),
                container_port: 54321,
                stop_count: Arc::new(AtomicU32::new(0)),
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
    }

    impl ContainerRuntime for MockDocker {
        fn pull_image<'a>(
            &'a self,
            _image: &'a str,
            _tag: &'a str,
            _credentials: Option<bollard::auth::DockerCredentials>,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), DockerError>> + Send + 'a>>
        {
            let result = if self.pull_ok {
                Ok(())
            } else {
                Err(DockerError::PullFailed("mock pull failure".to_string()))
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
            Box<dyn std::future::Future<Output = Result<(String, u16), DockerError>> + Send + 'a>,
        > {
            let result = Ok((self.container_id.clone(), self.container_port));
            Box::pin(async move { result })
        }

        fn stop_and_remove<'a>(
            &'a self,
            _container_id: &'a str,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), DockerError>> + Send + 'a>>
        {
            self.stop_count.fetch_add(1, Ordering::SeqCst);
            Box::pin(async { Ok(()) })
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
        apps: &'a HashMap<String, AppConfig>,
        app_states: &'a RwLock<HashMap<String, AppRuntimeState>>,
        deploys: &'a DashMap<String, DeployContext>,
    ) -> DeploySharedState<'a> {
        DeploySharedState {
            config,
            apps,
            app_states,
            deploys,
            credentials: None,
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
}
