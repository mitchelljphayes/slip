pub mod api;
pub mod auth;
pub mod caddy;
pub mod config;
pub mod db;
pub mod deploy;
pub mod diff;
pub mod docker;
pub mod error;
pub mod health;
pub mod manifest;
pub mod merge;
pub mod podman;
pub mod preview;
pub mod reconcile;
pub mod repo_config;
pub mod runtime;
pub mod secrets;
pub mod state;
pub mod validate;

// Re-exports for convenience
pub use api::{
    AppResponse, AppState, DeployRequest, DeployResponse, PreviewRequestInfo, build_router,
};
pub use caddy::{CaddyClient, ReverseProxy, RouteInfo};
pub use config::{
    AppConfig, AppInfo, AppPreviewConfig, CaddyConfig, CaddyTlsConfig, DeployConfig, EnvFileConfig,
    HealthConfig, NetworkConfig, ReconcileConfig, RegistryConfig, ResourceConfig, RoutingConfig,
    RuntimeConfig, ServerConfig, ServerPreviewConfig, SlipConfig, StorageConfig, VolumeConfig,
    load_config, resolve_env_vars,
};
pub use db::Db;
pub use deploy::{
    AppRuntimeState, AppStatus, DeployContext, DeployStatus, TriggerSource, execute_deploy,
};
pub use docker::{DockerClient, parse_cpu_limit, parse_memory_limit};
pub use error::{CaddyError, ConfigError, HealthError, RuntimeError};
pub use health::{HealthCheck, HealthChecker};
pub use manifest::{ManifestError, RenderContext, render_manifest};
pub use merge::{MergedConfig, MergedVolume, merge_config};
pub use podman::PodmanBackend;
pub use preview::{PersistedPreviewState, PreviewState};
pub use reconcile::{
    ReconcileContext, ReconcileSummary, RouteFailure, default_backoff, reconcile_app_routes,
    reconcile_loop, reconcile_tick, run_reconcile,
};
pub use repo_config::{
    PreviewConfig, RemoteConfig, RepoConfig, RepoDeployConfig, RepoVolume, parse_repo_config,
};
pub use runtime::{PodInfo, RegistryCredentials, RuntimeBackend};
pub use secrets::SecretsStore;
pub use state::{
    PersistedAppState, delete_preview_state, load_app_states, load_preview_states,
    reconcile_preview_routes, reconcile_routes, save_app_state, save_preview_state,
    verify_containers,
};
pub use validate::{
    ValidationError, ValidationResult, parse_and_validate, validate_image_refs,
    validate_merged_volumes, validate_pod_manifest, validate_repo_config, validate_volumes,
};
