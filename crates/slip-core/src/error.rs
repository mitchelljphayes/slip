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

    #[error("failed to serialize config: {0}")]
    Serialize(String),

    #[error("failed to write {path}: {source}")]
    WriteFile {
        path: PathBuf,
        source: std::io::Error,
    },

    #[error("failed to delete {path}: {source}")]
    DeleteFile {
        path: PathBuf,
        source: std::io::Error,
    },

    /// A volume declared in the repo config has no matching `host_path` in the
    /// server config.
    #[error(
        "volume mount '{mount_path}' declared in repo config has no corresponding host_path in server config"
    )]
    VolumeMissingHostPath { mount_path: String },

    /// A merge error occurred (e.g., route count mismatch).
    #[error("merge error: {0}")]
    Merge(String),

    /// Invalid deploy strategy value.
    #[error("invalid deploy strategy '{strategy}': valid values are {valid:?}")]
    InvalidStrategy {
        strategy: String,
        valid: Vec<&'static str>,
    },

    /// Internal error (e.g. crypto RNG failure).
    #[error("internal error: {0}")]
    Internal(String),
}

/// Errors that can occur during container health checking.
#[derive(Debug, thiserror::Error)]
pub enum HealthError {
    #[error("unhealthy after {retries} attempts at {url}")]
    Unhealthy { retries: u32, url: String },
    /// At least one probe attempt received an HTTP response whose status was
    /// not in `expect_status`. Carries the canonical `expected` string, the
    /// `actual` status code of the last attempt that received a response, the
    /// probe `url`, and the number of `attempts` made. **No response bodies or
    /// headers are ever stored** (SLIP-103 D6).
    #[error(
        "health check failed: expected {expected}, got {actual} at {url} after {attempts} attempts"
    )]
    UnexpectedStatus {
        expected: String,
        actual: u16,
        url: String,
        attempts: u32,
    },
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
    #[error("caddy TLS configuration failed: {0}")]
    TlsConfigFailed(String),
    /// An unowned (non-`slip-tls-*`) Caddy TLS automation policy already
    /// covers the subject Slip wants to manage. Slip refuses to adopt or
    /// shadow it; the operator must reconcile the conflict explicitly.
    #[error(
        "TLS policy conflict on subject '{subject}': an unowned Caddy TLS automation \
         policy already covers it (expected Slip-owned @id '{policy_id}'). \
         Slip will not adopt or duplicate it. Either remove the foreign policy \
         from Caddy (DELETE /config/apps/tls/automation/policies/<N>) or tag it \
         with the expected @id so Slip can manage it."
    )]
    TlsPolicyConflict { subject: String, policy_id: String },
    /// Another Caddy server (from a Caddyfile) already claims the listener
    /// that slip's `slip` server needs. This is a fatal configuration error.
    #[error(
        "Caddy server '{server}' (from your Caddyfile) already claims {listener}. \
         slip owns {listener} via its 'slip' server. \
         Remove site blocks from the Caddyfile, use [deploy] for the webhook \
         and 'slip services expose' / static routes for other hosts."
    )]
    ListenerConflict { server: String, listener: String },
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
    #[error("exec in container failed: {0}")]
    ExecFailed(String),
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
