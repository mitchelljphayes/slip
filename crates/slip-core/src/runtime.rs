//! Runtime backend abstraction — trait for container/pod lifecycle operations.
//!
//! Implemented by `DockerClient` (Docker) and `PodmanBackend` (Podman).
//! The deploy orchestrator uses `&dyn RuntimeBackend` for all container operations.

use std::path::Path;

use crate::config::ResourceConfig;
use crate::error::RuntimeError;

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
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<(String, u16), RuntimeError>> + Send + 'a>,
    >;

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
