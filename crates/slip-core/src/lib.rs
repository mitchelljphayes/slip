pub mod api;
pub mod auth;
pub mod caddy;
pub mod config;
pub mod deploy;
pub mod docker;
pub mod error;
pub mod health;
pub mod manifest;
pub mod merge;
pub mod podman;
pub mod preview;
pub mod repo_config;
pub mod runtime;
pub mod state;

// Re-exports for convenience
pub use api::{AppState, DeployRequest, DeployResponse, PreviewRequestInfo, build_router};
pub use caddy::{CaddyClient, ReverseProxy, RouteInfo};
pub use config::{
    AppConfig, AppInfo, AppPreviewConfig, CaddyConfig, DeployConfig, EnvFileConfig, HealthConfig,
    NetworkConfig, RegistryConfig, ResourceConfig, RoutingConfig, RuntimeConfig, ServerConfig,
    ServerPreviewConfig, SlipConfig, StorageConfig, load_config, resolve_env_vars,
};
pub use deploy::{
    AppRuntimeState, AppStatus, DeployContext, DeployStatus, TriggerSource, execute_deploy,
    record_deploy,
};
pub use docker::{DockerClient, parse_cpu_limit, parse_memory_limit};
pub use error::{CaddyError, ConfigError, HealthError, RuntimeError};
pub use health::{HealthCheck, HealthChecker};
pub use manifest::{ManifestError, RenderContext, render_manifest};
pub use merge::{MergedConfig, merge_config};
pub use podman::PodmanBackend;
pub use preview::{PersistedPreviewState, PreviewState};
pub use repo_config::{PreviewConfig, RepoConfig, parse_repo_config};
pub use runtime::{PodInfo, RegistryCredentials, RuntimeBackend};
pub use state::{
    PersistedAppState, delete_preview_state, load_app_states, load_preview_states,
    reconcile_preview_routes, reconcile_routes, save_app_state, save_preview_state,
    verify_containers,
};
