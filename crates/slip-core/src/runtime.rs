//! Runtime backend abstraction — trait for container/pod lifecycle operations.
//!
//! Implemented by `DockerClient` (Docker) and `PodmanBackend` (Podman).
//! The deploy orchestrator uses `&dyn RuntimeBackend` for all container operations.

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::config::ResourceConfig;
use crate::error::RuntimeError;
use crate::merge::MergedVolume;

/// Abstraction over container runtimes (Docker, Podman).
///
/// Docker supports single containers. Podman supports single containers AND pods.
/// Pod methods have default implementations that return `Unsupported`.
pub trait RuntimeBackend: Send + Sync {
    /// Ping the runtime daemon to verify connectivity.
    fn ping(
        &self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), RuntimeError>> + Send + '_>>;

    /// Ensure a bridge network exists.
    fn ensure_network<'a>(
        &'a self,
        name: &'a str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), RuntimeError>> + Send + 'a>>;

    /// Pull `image:tag` from a registry.
    fn pull_image<'a>(
        &'a self,
        image: &'a str,
        tag: &'a str,
        credentials: Option<RegistryCredentials>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), RuntimeError>> + Send + 'a>>;

    /// Create and start a container; returns `(container_id, host_port)`.
    #[allow(clippy::too_many_arguments, clippy::type_complexity)]
    fn create_and_start<'a>(
        &'a self,
        app_name: &'a str,
        image: &'a str,
        tag: &'a str,
        container_port: u16,
        env_vars: Vec<String>,
        network: &'a str,
        resources: &'a ResourceConfig,
        volumes: &'a [MergedVolume],
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<(String, u16), RuntimeError>> + Send + 'a>,
    >;

    /// Stop a container by ID (without removing it).
    ///
    /// Used by the recreate strategy to stop the old container while keeping it
    /// available for fast rollback. Returns `Ok(())` if already stopped (304).
    fn stop_container<'a>(
        &'a self,
        container_id: &'a str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), RuntimeError>> + Send + 'a>>;

    /// Start a stopped container by ID.
    ///
    /// Used by the recreate strategy to restart the old container during rollback.
    /// Returns an error if the container doesn't exist or is already running.
    fn start_container<'a>(
        &'a self,
        container_id: &'a str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), RuntimeError>> + Send + 'a>>;

    /// Inspect a container and return its host port for the given container port.
    ///
    /// Used after restarting a container during rollback to discover the new
    /// ephemeral port (which may have changed after restart).
    fn inspect_container_port<'a>(
        &'a self,
        container_id: &'a str,
        container_port: u16,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<u16, RuntimeError>> + Send + 'a>>;

    /// Stop and remove a container by ID.
    fn stop_and_remove<'a>(
        &'a self,
        container_id: &'a str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), RuntimeError>> + Send + 'a>>;

    /// Check if a container is currently running.
    fn container_is_running<'a>(
        &'a self,
        container_id: &'a str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<bool, RuntimeError>> + Send + 'a>>;

    /// Check if a container exists (regardless of state).
    fn container_exists<'a>(
        &'a self,
        container_id: &'a str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<bool, RuntimeError>> + Send + 'a>>;

    // ── Pod operations (Podman only, default = Unsupported) ────────────────

    /// Deploy a pod from a Kubernetes YAML manifest.
    fn deploy_pod<'a>(
        &'a self,
        _manifest: &'a Path,
        _name: &'a str,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<PodInfo, RuntimeError>> + Send + 'a>,
    > {
        Box::pin(async {
            Err(RuntimeError::Unsupported(
                "pod operations require Podman".to_string(),
            ))
        })
    }

    /// Tear down a pod by manifest.
    fn teardown_pod<'a>(
        &'a self,
        _manifest: &'a Path,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), RuntimeError>> + Send + 'a>>
    {
        Box::pin(async {
            Err(RuntimeError::Unsupported(
                "pod operations require Podman".to_string(),
            ))
        })
    }

    /// Get the host port mapped to a container's port within a pod.
    fn pod_container_port<'a>(
        &'a self,
        _pod: &'a str,
        _container: &'a str,
        _container_port: u16,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<u16, RuntimeError>> + Send + 'a>>
    {
        Box::pin(async {
            Err(RuntimeError::Unsupported(
                "pod operations require Podman".to_string(),
            ))
        })
    }

    /// Extract a file from an image (create temp container, copy, remove).
    #[allow(clippy::type_complexity)]
    fn extract_file<'a>(
        &'a self,
        _image: &'a str,
        _tag: &'a str,
        _path: &'a str,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Option<Vec<u8>>, RuntimeError>> + Send + 'a>,
    > {
        Box::pin(async {
            Err(RuntimeError::Unsupported(
                "extract_file not implemented for this runtime".to_string(),
            ))
        })
    }

    /// Execute a command inside a running container and return its combined output.
    ///
    /// Returns [`RuntimeError::ExecFailed`] if the command exits with a non-zero
    /// status. Returns [`RuntimeError::Unsupported`] by default — must be
    /// overridden by runtimes that support exec (Docker, Podman).
    fn exec_in_container<'a>(
        &'a self,
        _container_id: &'a str,
        _command: &'a [&'a str],
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<String, RuntimeError>> + Send + 'a>,
    > {
        Box::pin(async {
            Err(RuntimeError::Unsupported(
                "exec_in_container not implemented for this runtime".to_string(),
            ))
        })
    }

    /// List containers matching a given label key=value pair.
    ///
    /// Used by `slip status` to find all containers belonging to a slip app
    /// via the `slip.app` label, rather than name substring matching (which
    /// breaks on truncated tag prefixes — FR §3.11).
    ///
    /// Returns containers in any state (running, exited, etc.) so the status
    /// command can report stale containers.
    fn list_by_label<'a>(
        &'a self,
        label_key: &'a str,
        label_value: &'a str,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Vec<ContainerInfo>, RuntimeError>> + Send + 'a>,
    >;

    /// Stream container logs as an async [`Stream`] of [`LogStreamItem`]s.
    ///
    /// When `follow` is true the stream stays open and yields new lines as
    /// they arrive; when false it yields existing logs then ends.
    ///
    /// `since` is an optional Unix-epoch seconds cutoff; `None` means no
    /// since-filter (return all available logs). The caller (the API handler)
    /// converts a duration string into a Unix timestamp before calling.
    ///
    /// The implementation MUST set `timestamps(true)` on the underlying
    /// runtime call so each line is prefixed with an RFC 3339 timestamp,
    /// which is parsed into `LogStreamItem::ts`.
    fn container_logs<'a>(
        &'a self,
        container_id: &'a str,
        since: Option<i64>,
        follow: bool,
    ) -> std::pin::Pin<
        Box<dyn futures_util::Stream<Item = Result<LogStreamItem, RuntimeError>> + Send + 'a>,
    >;

    /// Return the runtime name ("docker" or "podman").
    fn name(&self) -> &str;
}

/// Registry credentials for image pulls.
#[derive(Clone)]
pub struct RegistryCredentials {
    pub username: String,
    pub password: String,
}

impl std::fmt::Debug for RegistryCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RegistryCredentials")
            .field("username", &self.username)
            .field("password", &"[REDACTED]")
            .finish()
    }
}

/// Info about a deployed pod.
#[derive(Debug, Clone)]
pub struct PodInfo {
    pub name: String,
    pub containers: Vec<String>,
}

/// Lightweight info about a running container, returned by [`RuntimeBackend::list_by_label`].
///
/// Used by `slip status` to discover containers by their `slip.app` label
/// rather than name substrings (which are truncated in the container name —
/// see FR §3.11).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerInfo {
    /// Container ID (short form, 12 chars).
    pub id: String,
    /// Container name (first name, if any).
    pub name: Option<String>,
    /// Docker/Podman state string: "running", "exited", "created", etc.
    pub state: String,
    /// The `slip.tag` label value, if present.
    pub tag: Option<String>,
}

/// Which stream a log line came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogStream {
    StdOut,
    StdErr,
    Console,
}

impl LogStream {
    /// Lowercase wire name used in NDJSON output ("stdout", "stderr", "console").
    pub fn as_str(&self) -> &'static str {
        match self {
            LogStream::StdOut => "stdout",
            LogStream::StdErr => "stderr",
            LogStream::Console => "console",
        }
    }
}

/// A single log line streamed from a container via [`RuntimeBackend::container_logs`].
///
/// When `timestamps(true)` is set on the runtime log call, `ts` is the parsed
/// RFC 3339 timestamp prefix; otherwise it is `None` and `line` contains the
/// raw log line.
#[derive(Debug, Clone)]
pub struct LogStreamItem {
    /// Parsed RFC 3339 timestamp from the `timestamps(true)` prefix, if present.
    pub ts: Option<chrono::DateTime<chrono::Utc>>,
    /// Which stream the line came from.
    pub stream: LogStream,
    /// The log line (timestamp already stripped when `ts` is `Some`).
    pub line: String,
}
