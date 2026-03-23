pub mod api;
pub mod auth;
pub mod caddy;
pub mod config;
pub mod deploy;
pub mod docker;
pub mod error;
pub mod health;

// Re-exports for convenience
pub use api::{AppState, DeployRequest, DeployResponse, build_router};
pub use caddy::{CaddyClient, RouteInfo};
pub use config::{
    AppConfig, AppInfo, CaddyConfig, DeployConfig, EnvFileConfig, HealthConfig, NetworkConfig,
    RegistryConfig, ResourceConfig, RoutingConfig, ServerConfig, SlipConfig, StorageConfig,
    load_config, resolve_env_vars,
};
pub use docker::{DockerClient, extract_host_port, parse_cpu_limit, parse_memory_limit};
pub use error::{CaddyError, ConfigError, DockerError, HealthError};
pub use health::HealthChecker;
