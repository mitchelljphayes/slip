//! Runtime backend abstraction — trait for container/pod lifecycle operations.
//!
//! Implemented by `DockerClient` (Docker) and `PodmanBackend` (Podman).
//! The deploy orchestrator uses `&dyn RuntimeBackend` for all container operations.
//!
//! ## Service-safe methods (SLIP-106 Part 3)
//!
//! [`RuntimeBackend`] also carries structured service lifecycle methods used by
//! the managed-service framework: [`create_and_start_service`], [`inspect_service`],
//! and [`exec_service_probe`]. These are distinct from the app-deploy
//! [`create_and_start`] method — service containers have stable names, no host
//! ports, `unless-stopped` restart policy, OCI healthchecks, ownership labels,
//! bind mounts, and read-only secret mounts. The service methods default to
//! `Unsupported` so existing app paths and fakes are unaffected until a runtime
//! explicitly implements them.

use std::collections::BTreeMap;
use std::path::Path;
use std::pin::Pin;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::config::ResourceConfig;
use crate::error::RuntimeError;
use crate::merge::MergedVolume;
use crate::services::image_ref::PinnedImageRef;

// ─── Service-safe container spec (SLIP-106 Part 3) ───────────────────────────

/// A validated bind mount tuple for a service container.
///
/// The host source path comes from a revalidated `ValidatedBindSource` token
/// (descriptor-confined on Linux). The destination and read-only flag are
/// provider-specified. The host path is a canonical absolute string.
#[derive(Debug, Clone)]
pub struct ServiceMount {
    /// Canonical host source path (from `ValidatedBindSource::canonical_path`).
    pub host_source: String,
    /// Container destination path.
    pub dest: String,
    /// Read-only mount.
    pub read_only: bool,
}

/// OCI healthcheck specification for a service container.
#[derive(Debug, Clone)]
pub struct ServiceHealthcheck {
    /// Command argv (e.g. `["pg_isready", "-U", "postgres", "-d", "postgres"]`).
    pub test_cmd: Vec<String>,
    /// Time between health checks (seconds).
    pub interval_secs: i64,
    /// Time to wait for a health check before considering it failed (seconds).
    pub timeout_secs: i64,
    /// Number of retries before considering the container unhealthy.
    pub retries: i64,
    /// Grace period for startup before health checks count (seconds).
    pub start_period_secs: i64,
}

/// Resource limits for a service container.
#[derive(Debug, Clone, Default)]
pub struct ServiceResourceLimits {
    /// Memory limit in bytes.
    pub memory_bytes: Option<i64>,
    /// CPU limit in nano-CPUs (1 CPU = 1_000_000_000).
    pub nano_cpus: Option<i64>,
    /// PID limit.
    pub pids_limit: Option<i64>,
}

/// Security options for a service container — fail-closed hardening.
#[derive(Debug, Clone, Default)]
pub struct ServiceSecurityOpts {
    /// Read-only root filesystem.
    pub read_only_rootfs: bool,
    /// Tmpfs mounts for writable directories (e.g. `/tmp`, `/run`).
    pub tmpfs_mounts: Vec<(String, String)>,
    // The following are enforced as "no" by construction — the provider
    // sets them, but the backend must reject any container that has them.
    // These fields document the policy; the backend impls enforce the
    // negative invariants.
}

/// A structured, validated specification for creating a service container.
///
/// Construction validates the security-critical invariants:
/// - The image is digest-pinned (no floating tags).
/// - There are zero host port bindings.
/// - There is exactly one network with at least one alias.
/// - The container name is deterministic (`slip-service-<name>`).
/// - Restart policy is `unless-stopped`.
///
/// Fields are private; construction is only through [`new`](Self::new).
#[derive(Debug, Clone)]
pub struct ServiceContainerSpec {
    name: String,
    hostname: String,
    image: PinnedImageRef,
    network: String,
    network_aliases: Vec<String>,
    mounts: Vec<ServiceMount>,
    env: BTreeMap<String, String>,
    labels: BTreeMap<String, String>,
    restart_unless_stopped: bool,
    healthcheck: ServiceHealthcheck,
    resources: ServiceResourceLimits,
    security: ServiceSecurityOpts,
}

impl ServiceContainerSpec {
    /// Construct a validated service container spec.
    ///
    /// # Arguments
    /// * `name` - Deterministic container name (e.g. `slip-service-pg`).
    /// * `hostname` - Container hostname (e.g. `slip-service-pg`).
    /// * `image` - Digest-pinned image reference.
    /// * `network` - The sole network the container joins (e.g. `slip`).
    /// * `network_aliases` - DNS aliases on the network (e.g. `["pg"]`).
    ///   Must be non-empty.
    /// * `mounts` - Bind mount tuples.
    /// * `env` - Allowlisted non-secret env vars.
    /// * `labels` - Ownership labels.
    /// * `healthcheck` - OCI healthcheck.
    /// * `resources` - Resource limits.
    /// * `security` - Security options.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        name: String,
        hostname: String,
        image: PinnedImageRef,
        network: String,
        network_aliases: Vec<String>,
        mounts: Vec<ServiceMount>,
        env: BTreeMap<String, String>,
        labels: BTreeMap<String, String>,
        healthcheck: ServiceHealthcheck,
        resources: ServiceResourceLimits,
        security: ServiceSecurityOpts,
    ) -> Result<Self, RuntimeError> {
        if name.is_empty() || name.len() > 256 {
            return Err(RuntimeError::Unsupported(format!(
                "service container name length {} out of range [1, 256]",
                name.len()
            )));
        }
        if !name.starts_with("slip-service-") {
            return Err(RuntimeError::Unsupported(
                "service container name must start with 'slip-service-'".to_string(),
            ));
        }
        if network.is_empty() {
            return Err(RuntimeError::Unsupported(
                "service container must join exactly one network".to_string(),
            ));
        }
        if network_aliases.is_empty() {
            return Err(RuntimeError::Unsupported(
                "service container must have at least one network alias".to_string(),
            ));
        }
        // Validate that env values are non-secret (no password/token keywords
        // in keys, unless they use the _FILE suffix form which is a path, not
        // a secret value).
        for key in env.keys() {
            let lower = key.to_lowercase();
            // Allow *_FILE env vars (e.g. POSTGRES_PASSWORD_FILE) — these point
            // to mounted secret files, not secret values.
            if lower.ends_with("_file") {
                continue;
            }
            if lower.contains("password")
                || lower.contains("secret")
                || lower.contains("token")
                || lower.contains("pgpassword")
            {
                return Err(RuntimeError::Unsupported(format!(
                    "service env key '{key}' looks secret-bearing -- use _FILE form or mounted secret"
                )));
            }
        }
        Ok(Self {
            name,
            hostname,
            image,
            network,
            network_aliases,
            mounts,
            env,
            labels,
            restart_unless_stopped: true,
            healthcheck,
            resources,
            security,
        })
    }

    pub fn name(&self) -> &str {
        &self.name
    }
    pub fn hostname(&self) -> &str {
        &self.hostname
    }
    pub fn image(&self) -> &PinnedImageRef {
        &self.image
    }
    pub fn network(&self) -> &str {
        &self.network
    }
    pub fn network_aliases(&self) -> &[String] {
        &self.network_aliases
    }
    pub fn mounts(&self) -> &[ServiceMount] {
        &self.mounts
    }
    pub fn env(&self) -> &BTreeMap<String, String> {
        &self.env
    }
    pub fn labels(&self) -> &BTreeMap<String, String> {
        &self.labels
    }
    pub fn restart_unless_stopped(&self) -> bool {
        self.restart_unless_stopped
    }
    pub fn healthcheck(&self) -> &ServiceHealthcheck {
        &self.healthcheck
    }
    pub fn resources(&self) -> &ServiceResourceLimits {
        &self.resources
    }
    pub fn security(&self) -> &ServiceSecurityOpts {
        &self.security
    }
}

/// Inspected state of a service container, used for ownership verification.
///
/// Every field here is security-relevant and compared during ownership
/// verification. Any mismatch → `Blocked`, zero mutations.
#[derive(Debug, Clone)]
pub struct ServiceContainerInspect {
    /// Full 64-hex container ID as reported by the daemon (not the
    /// requested argument). Used to verify the daemon returned the
    /// expected container.
    pub container_id: String,
    /// Container name as reported by the daemon.
    pub name: Option<String>,
    /// Container hostname as reported by the daemon.
    pub hostname: Option<String>,
    /// All labels on the container.
    pub labels: BTreeMap<String, String>,
    /// Image repo-digests as reported by the runtime (e.g.
    /// `["postgres@sha256:..."]`). Used to verify the pulled image matches
    /// the catalog digest.
    pub repo_digests: Vec<String>,
    /// Mounts as reported by the runtime: (source, destination, read_only).
    pub mounts: Vec<(String, String, bool)>,
    /// All networks the container is connected to (must be exactly one).
    pub networks: Vec<String>,
    /// Network name the container is connected to (first/primary).
    pub network: String,
    /// Network aliases on the connected network.
    pub network_aliases: Vec<String>,
    /// Restart policy name (e.g. "unless-stopped").
    pub restart_policy: String,
    /// Health status: "starting", "healthy", "unhealthy", "none".
    pub health_status: String,
    /// Published port bindings (should be empty for services).
    pub port_bindings: Vec<(u16, Option<String>)>,
    /// Whether the container is running.
    pub running: bool,
    /// Whether privileged mode is enabled (must be false).
    pub privileged: bool,
    /// Whether no-new-privileges is set (must be true).
    pub no_new_privileges: bool,
    /// Whether read-only rootfs is set.
    pub read_only_rootfs: bool,
    /// Dropped capabilities list (should contain "ALL").
    pub cap_drop: Vec<String>,
    /// Added capabilities list (should be empty or minimal).
    pub cap_add: Vec<String>,
    /// Security options list (should contain "no-new-privileges:true").
    pub security_options: Vec<String>,
    /// Memory limit in bytes (0 = no limit).
    pub memory_limit: i64,
    /// Nano-CPUs limit (0 = no limit).
    pub nano_cpus: i64,
    /// PID limit (0 = no limit).
    pub pids_limit: i64,
}

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

    // ── Service-safe operations (SLIP-106 Part 3, default = Unsupported) ────

    /// Whether the connected runtime is rootful (the same rootful Podman/Docker
    /// socket the slip daemon uses for app containers). Service containers
    /// require this. Default = `false` (fail closed).
    fn is_rootful(&self) -> Pin<Box<dyn Future<Output = bool> + Send + '_>> {
        Box::pin(async { false })
    }

    /// Create and start a service container from a structured, validated
    /// [`ServiceContainerSpec`]. Returns the full 64-hex container ID.
    ///
    /// The spec enforces: digest-pinned image, zero host ports, exactly one
    /// network with aliases, `unless-stopped` restart policy, OCI healthcheck,
    /// ownership labels, bind mounts, and read-only secret mounts.
    fn create_and_start_service<'a>(
        &'a self,
        _spec: &'a ServiceContainerSpec,
    ) -> Pin<Box<dyn Future<Output = Result<String, RuntimeError>> + Send + 'a>> {
        Box::pin(async {
            Err(RuntimeError::Unsupported(
                "service container creation not implemented for this runtime".to_string(),
            ))
        })
    }

    /// Inspect a service container by its full container ID, returning the
    /// structured [`ServiceContainerInspect`] used for ownership verification.
    fn inspect_service<'a>(
        &'a self,
        _container_id: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<ServiceContainerInspect, RuntimeError>> + Send + 'a>>
    {
        Box::pin(async {
            Err(RuntimeError::Unsupported(
                "service container inspection not implemented for this runtime".to_string(),
            ))
        })
    }

    /// Execute a bounded, structured probe inside a running service container.
    ///
    /// The argv is a static `&[&str]` (no shell, no interpolation). The env
    /// pairs are allowlisted non-secret settings (e.g.
    /// `PGPASSFILE=/run/secrets/slip-pgpass`). The output is capped at
    /// `max_output_bytes` and discarded on success — this method returns
    /// `Ok(())` if the command exits 0, or `Err` with sanitized text on
    /// failure. Never returns stdout/stderr to the caller.
    fn exec_service_probe<'a>(
        &'a self,
        _container_id: &'a str,
        _argv: &'a [&'a str],
        _env: &'a [(&'a str, &'a str)],
        _timeout: Duration,
        _max_output_bytes: usize,
    ) -> Pin<Box<dyn Future<Output = Result<(), RuntimeError>> + Send + 'a>> {
        Box::pin(async {
            Err(RuntimeError::Unsupported(
                "service exec probe not implemented for this runtime".to_string(),
            ))
        })
    }
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
