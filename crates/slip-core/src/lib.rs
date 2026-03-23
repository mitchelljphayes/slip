pub mod api;
pub mod auth;
pub mod caddy;
pub mod config;
pub mod deploy;
pub mod docker;
pub mod error;
pub mod health;

// Re-exports for convenience
pub use config::{
    AppConfig, AppInfo, CaddyConfig, DeployConfig, EnvFileConfig, HealthConfig, NetworkConfig,
    RegistryConfig, ResourceConfig, RoutingConfig, ServerConfig, SlipConfig, StorageConfig,
    load_config, resolve_env_vars,
};
pub use error::ConfigError;
