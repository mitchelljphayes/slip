pub mod api;
pub mod auth;
pub mod caddy;
pub mod config;
pub mod deploy;
pub mod docker;
pub mod error;
pub mod health;
pub mod podman;
pub mod runtime;
pub mod state;

// Re-exports for convenience
pub use api::{AppState, DeployRequest, DeployResponse, build_router};
pub use caddy::{CaddyClient, ReverseProxy, RouteInfo};
pub use config::{
    AppConfig, AppInfo, CaddyConfig, DeployConfig, EnvFileConfig, HealthConfig, NetworkConfig,
    RegistryConfig, ResourceConfig, RoutingConfig, RuntimeConfig, ServerConfig, SlipConfig,
    StorageConfig, load_config, resolve_env_vars,
};
pub use deploy::{
    AppRuntimeState, AppStatus, DeployContext, DeployStatus, TriggerSource, execute_deploy,
    record_deploy,
};
pub use docker::{DockerClient, extract_host_port, parse_cpu_limit, parse_memory_limit};
pub use error::{CaddyError, ConfigError, DockerError, HealthError, RuntimeError};
pub use health::{HealthCheck, HealthChecker};
pub use podman::PodmanBackend;
pub use runtime::{PodInfo, RegistryCredentials, RuntimeBackend};
pub use state::{
    PersistedAppState, load_app_states, reconcile_routes, save_app_state, verify_containers,
};
