//! Error types for slip.

use std::path::PathBuf;

/// Errors that can occur when loading or parsing configuration.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("failed to read {path}: {source}")]
    ReadFile {
        path: PathBuf,
        source: std::io::Error,
    },

    #[error("failed to parse {path}: {source}")]
    Parse {
        path: PathBuf,
        source: toml::de::Error,
    },

    #[error("missing environment variable ${var} in {context}")]
    MissingEnvVar { var: String, context: String },

    #[error("app name mismatch: filename '{filename}' but config says '{config_name}'")]
    NameMismatch {
        filename: String,
        config_name: String,
    },
}

/// Errors that can occur during container health checking.
#[derive(Debug, thiserror::Error)]
pub enum HealthError {
    #[error("unhealthy after {retries} attempts at {url}")]
    Unhealthy { retries: u32, url: String },
}

/// Errors that can occur when communicating with the Caddy admin API.
#[derive(Debug, thiserror::Error)]
pub enum CaddyError {
    #[error("caddy HTTP error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("caddy bootstrap failed: {0}")]
    BootstrapFailed(String),
    #[error("caddy route update failed: {0}")]
    RouteUpdateFailed(String),
    #[error("caddy not reachable at {url}: {source}")]
    Unreachable { url: String, source: reqwest::Error },
}

/// Errors that can occur when interacting with the Docker daemon.
#[derive(Debug, thiserror::Error)]
pub enum DockerError {
    #[error("docker API error: {0}")]
    Api(#[from] bollard::errors::Error),
    #[error("image pull failed: {0}")]
    PullFailed(String),
    #[error("no host port assigned to container")]
    NoPortAssigned,
    #[error("container {0} is not running after start")]
    ContainerNotRunning(String),
}

/// Runtime-agnostic errors for container/pod operations.
#[derive(Debug, thiserror::Error)]
pub enum RuntimeError {
    #[error("runtime connection error: {0}")]
    Connection(String),
    #[error("image pull failed: {0}")]
    PullFailed(String),
    #[error("container operation failed: {0}")]
    ContainerError(String),
    #[error("no host port assigned")]
    NoPortAssigned,
    #[error("container {0} is not running")]
    ContainerNotRunning(String),
    #[error("network error: {0}")]
    NetworkError(String),
    #[error("operation not supported by this runtime: {0}")]
    Unsupported(String),
}

impl From<DockerError> for RuntimeError {
    fn from(e: DockerError) -> Self {
        match e {
            DockerError::Api(e) => RuntimeError::ContainerError(e.to_string()),
            DockerError::PullFailed(msg) => RuntimeError::PullFailed(msg),
            DockerError::NoPortAssigned => RuntimeError::NoPortAssigned,
            DockerError::ContainerNotRunning(id) => RuntimeError::ContainerNotRunning(id),
        }
    }
}
