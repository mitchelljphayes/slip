//! Docker client wrapper around bollard for container lifecycle management.

use std::collections::HashMap;
use std::pin::Pin;

use bollard::Docker;
use bollard::auth::DockerCredentials;
use bollard::container::{
    Config, CreateContainerOptions, RemoveContainerOptions, StartContainerOptions,
    StopContainerOptions,
};
use bollard::image::CreateImageOptions;
use bollard::models::{ContainerInspectResponse, HostConfig, PortBinding};
use bollard::network::CreateNetworkOptions;
use futures_util::StreamExt;
use tracing::{debug, info, warn};

use crate::config::ResourceConfig;
use crate::error::{DockerError, RuntimeError};
use crate::runtime::{RegistryCredentials, RuntimeBackend};

/// A thin wrapper around [`bollard::Docker`] providing higher-level container
/// lifecycle operations used by the slip deploy daemon.
pub struct DockerClient {
    docker: Docker,
}

impl DockerClient {
    /// Connect to the Docker daemon using platform socket defaults.
    pub fn new() -> Result<Self, DockerError> {
        let docker = Docker::connect_with_socket_defaults()?;
        Ok(Self { docker })
    }

    /// Connect to a Docker daemon at a specific HTTP URL.
    ///
    /// Useful for tests (where no real socket exists) or non-default daemon
    /// addresses. The connection is lazy — no I/O happens until an API call.
    pub fn new_with_url(url: &str) -> Result<Self, DockerError> {
        let docker = Docker::connect_with_http(url, 120, bollard::API_DEFAULT_VERSION)?;
        Ok(Self { docker })
    }

    /// Ping the Docker daemon to verify connectivity.
    ///
    /// Returns Ok(()) if Docker is reachable and responding.
    pub async fn ping(&self) -> Result<(), DockerError> {
        self.docker.ping().await?;
        Ok(())
    }

    /// Pull `image:tag` from a registry, streaming progress to the log.
    ///
    /// `credentials` is passed through to Docker for authenticated registries.
    pub async fn pull_image(
        &self,
        image: &str,
        tag: &str,
        credentials: Option<DockerCredentials>,
    ) -> Result<(), DockerError> {
        info!(image, tag, "pulling image");

        let options = Some(CreateImageOptions {
            from_image: image,
            tag,
            ..Default::default()
        });

        let mut stream = self.docker.create_image(options, None, credentials);

        while let Some(item) = stream.next().await {
            match item {
                Ok(info) => {
                    if let Some(status) = &info.status {
                        debug!(status, "pull progress");
                    }
                    if let Some(err) = info.error {
                        return Err(DockerError::PullFailed(err));
                    }
                }
                Err(e) => return Err(DockerError::PullFailed(e.to_string())),
            }
        }

        info!(image, tag, "image pulled successfully");
        Ok(())
    }

    /// Create and start a container for the given application.
    ///
    /// Returns `(container_id, host_port)` where `host_port` is the ephemeral
    /// port that Docker assigned on `127.0.0.1`.
    #[allow(clippy::too_many_arguments)]
    pub async fn create_and_start(
        &self,
        app_name: &str,
        image: &str,
        tag: &str,
        container_port: u16,
        env_vars: Vec<String>,
        network: &str,
        resources: &ResourceConfig,
    ) -> Result<(String, u16), DockerError> {
        // Container name: slip-{app_name}-{tag_prefix}-{random_suffix}
        // Random suffix prevents name collision on re-deploy of same tag
        let tag_prefix = if tag.len() >= 12 { &tag[..12] } else { tag };
        let suffix = &ulid::Ulid::new().to_string()[..8];
        let container_name = format!("slip-{app_name}-{tag_prefix}-{suffix}");

        info!(container_name, image, tag, "creating container");

        // Port bindings: container_port/tcp → 127.0.0.1 with ephemeral host port
        let port_key = format!("{container_port}/tcp");
        let mut port_bindings: HashMap<String, Option<Vec<PortBinding>>> = HashMap::new();
        port_bindings.insert(
            port_key.clone(),
            Some(vec![PortBinding {
                host_ip: Some("127.0.0.1".to_string()),
                host_port: None, // Docker assigns an ephemeral port
            }]),
        );

        // Labels
        let mut labels: HashMap<String, String> = HashMap::new();
        labels.insert("slip.app".to_string(), app_name.to_string());
        labels.insert("slip.tag".to_string(), tag.to_string());
        labels.insert("slip.managed".to_string(), "true".to_string());

        // Resource limits
        let memory = parse_memory_limit(&resources.memory);
        let nano_cpus = parse_cpu_limit(&resources.cpus);

        let host_config = HostConfig {
            port_bindings: Some(port_bindings),
            network_mode: Some(network.to_string()),
            memory,
            nano_cpus,
            ..Default::default()
        };

        let config: Config<String> = Config {
            image: Some(format!("{image}:{tag}")),
            env: Some(env_vars),
            labels: Some(labels),
            host_config: Some(host_config),
            ..Default::default()
        };

        let create_opts = CreateContainerOptions {
            name: container_name.clone(),
            platform: None::<String>,
        };

        let response = self
            .docker
            .create_container(Some(create_opts), config)
            .await?;

        let container_id = response.id;
        info!(container_id, "container created, starting");

        self.docker
            .start_container(&container_id, None::<StartContainerOptions<String>>)
            .await?;

        // Inspect to find the assigned host port and verify container is running
        let info = self.docker.inspect_container(&container_id, None).await?;

        // Verify the container is actually running (not crashed immediately)
        let running = info.state.as_ref().and_then(|s| s.running).unwrap_or(false);
        if !running {
            warn!(container_id, "container is not running after start");
            return Err(DockerError::ContainerNotRunning(container_id));
        }

        let host_port = extract_host_port(&info, container_port)?;
        info!(container_id, host_port, "container started and running");

        Ok((container_id, host_port))
    }

    /// Stop (with a 10-second timeout) and remove a container by ID.
    pub async fn stop_and_remove(&self, container_id: &str) -> Result<(), DockerError> {
        info!(container_id, "stopping container");

        match self
            .docker
            .stop_container(container_id, Some(StopContainerOptions { t: 10 }))
            .await
        {
            Ok(()) => {}
            Err(bollard::errors::Error::DockerResponseServerError {
                status_code: 304, ..
            }) => {
                // 304 Not Modified = already stopped, that's fine
                warn!(container_id, "container was already stopped");
            }
            Err(e) => return Err(DockerError::Api(e)),
        }

        self.docker
            .remove_container(
                container_id,
                Some(RemoveContainerOptions {
                    force: false,
                    ..Default::default()
                }),
            )
            .await?;

        info!(container_id, "container removed");
        Ok(())
    }

    /// Check whether a container exists (regardless of running state).
    ///
    /// Returns `Ok(true)` if the container exists.
    /// Returns `Ok(false)` if the container is not found (404).
    /// Returns `Err` for other Docker errors (network issues, etc.).
    pub async fn container_exists(&self, container_id: &str) -> Result<bool, DockerError> {
        match self.docker.inspect_container(container_id, None).await {
            Ok(_) => Ok(true),
            Err(bollard::errors::Error::DockerResponseServerError {
                status_code: 404, ..
            }) => Ok(false),
            Err(e) => Err(DockerError::Api(e)),
        }
    }

    /// Check whether a container is currently running.
    ///
    /// Returns `Ok(true)` if the container exists and its state is "running".
    /// Returns `Ok(false)` if the container exists but is not running.
    /// Returns `Err` if the inspect call fails (e.g., container not found).
    pub async fn container_is_running(&self, container_id: &str) -> Result<bool, DockerError> {
        let info = self.docker.inspect_container(container_id, None).await?;
        let running = info.state.as_ref().and_then(|s| s.running).unwrap_or(false);
        Ok(running)
    }

    /// Ensure a Docker bridge network with the given name exists.
    ///
    /// If the network already exists this is a no-op.
    pub async fn ensure_network(&self, name: &str) -> Result<(), DockerError> {
        // Try to inspect the network; if it exists we're done.
        match self
            .docker
            .inspect_network(
                name,
                None::<bollard::network::InspectNetworkOptions<String>>,
            )
            .await
        {
            Ok(_) => {
                debug!(name, "network already exists");
                return Ok(());
            }
            Err(bollard::errors::Error::DockerResponseServerError {
                status_code: 404, ..
            }) => {
                // Network doesn't exist — create it below.
            }
            Err(e) => return Err(DockerError::Api(e)),
        }

        info!(name, "creating docker network");
        self.docker
            .create_network(CreateNetworkOptions {
                name,
                driver: "bridge",
                check_duplicate: true,
                ..Default::default()
            })
            .await?;

        info!(name, "network created");
        Ok(())
    }
}

// ─── RuntimeBackend impl ──────────────────────────────────────────────────────

impl RuntimeBackend for DockerClient {
    fn name(&self) -> &str {
        "docker"
    }

    fn ping(
        &self,
    ) -> Pin<Box<dyn std::future::Future<Output = Result<(), RuntimeError>> + Send + '_>> {
        Box::pin(async {
            DockerClient::ping(self)
                .await
                .map_err(|e| RuntimeError::Connection(e.to_string()))
        })
    }

    fn ensure_network<'a>(
        &'a self,
        name: &'a str,
    ) -> Pin<Box<dyn std::future::Future<Output = Result<(), RuntimeError>> + Send + 'a>> {
        Box::pin(async move {
            DockerClient::ensure_network(self, name)
                .await
                .map_err(|e| RuntimeError::NetworkError(e.to_string()))
        })
    }

    fn pull_image<'a>(
        &'a self,
        image: &'a str,
        tag: &'a str,
        credentials: Option<RegistryCredentials>,
    ) -> Pin<Box<dyn std::future::Future<Output = Result<(), RuntimeError>> + Send + 'a>> {
        Box::pin(async move {
            let creds = credentials.map(|c| DockerCredentials {
                username: Some(c.username),
                password: Some(c.password),
                ..Default::default()
            });
            DockerClient::pull_image(self, image, tag, creds)
                .await
                .map_err(|e| RuntimeError::PullFailed(e.to_string()))
        })
    }

    fn create_and_start<'a>(
        &'a self,
        app_name: &'a str,
        image: &'a str,
        tag: &'a str,
        container_port: u16,
        env_vars: Vec<String>,
        network: &'a str,
        resources: &'a ResourceConfig,
    ) -> Pin<Box<dyn std::future::Future<Output = Result<(String, u16), RuntimeError>> + Send + 'a>>
    {
        Box::pin(async move {
            DockerClient::create_and_start(
                self,
                app_name,
                image,
                tag,
                container_port,
                env_vars,
                network,
                resources,
            )
            .await
            .map_err(RuntimeError::from)
        })
    }

    fn stop_and_remove<'a>(
        &'a self,
        container_id: &'a str,
    ) -> Pin<Box<dyn std::future::Future<Output = Result<(), RuntimeError>> + Send + 'a>> {
        Box::pin(async move {
            DockerClient::stop_and_remove(self, container_id)
                .await
                .map_err(RuntimeError::from)
        })
    }

    fn container_is_running<'a>(
        &'a self,
        container_id: &'a str,
    ) -> Pin<Box<dyn std::future::Future<Output = Result<bool, RuntimeError>> + Send + 'a>> {
        Box::pin(async move {
            DockerClient::container_is_running(self, container_id)
                .await
                .map_err(RuntimeError::from)
        })
    }

    fn container_exists<'a>(
        &'a self,
        container_id: &'a str,
    ) -> Pin<Box<dyn std::future::Future<Output = Result<bool, RuntimeError>> + Send + 'a>> {
        Box::pin(async move {
            DockerClient::container_exists(self, container_id)
                .await
                .map_err(RuntimeError::from)
        })
    }
}

// ─── Helper functions ─────────────────────────────────────────────────────────

/// Parse a human-readable memory limit string (e.g. `"512m"`, `"1g"`, `"256k"`)
/// into a byte count suitable for Docker's `HostConfig.memory` field.
///
/// Returns `None` if `memory` is `None` or the string cannot be parsed.
pub fn parse_memory_limit(memory: &Option<String>) -> Option<i64> {
    let s = memory.as_deref()?.trim().to_ascii_lowercase();
    if s.is_empty() {
        return None;
    }

    let (num_part, multiplier): (&str, i64) = if let Some(rest) = s.strip_suffix('g') {
        (rest, 1024 * 1024 * 1024)
    } else if let Some(rest) = s.strip_suffix("gb") {
        (rest, 1024 * 1024 * 1024)
    } else if let Some(rest) = s.strip_suffix('m') {
        (rest, 1024 * 1024)
    } else if let Some(rest) = s.strip_suffix("mb") {
        (rest, 1024 * 1024)
    } else if let Some(rest) = s.strip_suffix('k') {
        (rest, 1024)
    } else if let Some(rest) = s.strip_suffix("kb") {
        (rest, 1024)
    } else {
        // Bare number — treat as bytes
        (&s, 1)
    };

    let n: i64 = num_part.trim().parse().ok()?;
    Some(n * multiplier)
}

/// Parse a CPU limit string (e.g. `"1.0"`, `"0.5"`) into NanoCPUs
/// (value × 10⁹) suitable for Docker's `HostConfig.nano_cpus` field.
///
/// Returns `None` if `cpus` is `None` or the string cannot be parsed.
pub fn parse_cpu_limit(cpus: &Option<String>) -> Option<i64> {
    let s = cpus.as_deref()?.trim();
    if s.is_empty() {
        return None;
    }
    let n: f64 = s.parse().ok()?;
    #[allow(clippy::cast_possible_truncation)]
    Some((n * 1e9) as i64)
}

/// Extract the host port Docker assigned for `container_port/tcp` from an
/// [`ContainerInspectResponse`].
pub fn extract_host_port(
    info: &ContainerInspectResponse,
    container_port: u16,
) -> Result<u16, DockerError> {
    let key = format!("{container_port}/tcp");

    let bindings = info
        .network_settings
        .as_ref()
        .and_then(|ns| ns.ports.as_ref())
        .and_then(|ports| ports.get(&key))
        .and_then(|v| v.as_ref())
        .ok_or(DockerError::NoPortAssigned)?;

    let host_port_str = bindings
        .first()
        .and_then(|b| b.host_port.as_deref())
        .ok_or(DockerError::NoPortAssigned)?;

    host_port_str
        .parse::<u16>()
        .map_err(|_| DockerError::NoPortAssigned)
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn opt(s: &str) -> Option<String> {
        Some(s.to_string())
    }

    // ── parse_memory_limit ───────────────────────────────────────────────────

    #[test]
    fn memory_none() {
        assert_eq!(parse_memory_limit(&None), None);
    }

    #[test]
    fn memory_megabytes_lowercase() {
        assert_eq!(parse_memory_limit(&opt("512m")), Some(512 * 1024 * 1024));
    }

    #[test]
    fn memory_megabytes_uppercase() {
        assert_eq!(parse_memory_limit(&opt("256M")), Some(256 * 1024 * 1024));
    }

    #[test]
    fn memory_gigabytes() {
        assert_eq!(parse_memory_limit(&opt("2g")), Some(2 * 1024 * 1024 * 1024));
    }

    #[test]
    fn memory_gigabytes_suffix_gb() {
        assert_eq!(parse_memory_limit(&opt("1gb")), Some(1024 * 1024 * 1024));
    }

    #[test]
    fn memory_kilobytes() {
        assert_eq!(parse_memory_limit(&opt("1024k")), Some(1024 * 1024));
    }

    #[test]
    fn memory_bare_bytes() {
        assert_eq!(parse_memory_limit(&opt("1048576")), Some(1_048_576));
    }

    #[test]
    fn memory_invalid() {
        assert_eq!(parse_memory_limit(&opt("notanumber")), None);
    }

    #[test]
    fn memory_empty_string() {
        assert_eq!(parse_memory_limit(&opt("")), None);
    }

    // ── parse_cpu_limit ──────────────────────────────────────────────────────

    #[test]
    fn cpu_none() {
        assert_eq!(parse_cpu_limit(&None), None);
    }

    #[test]
    fn cpu_one_core() {
        assert_eq!(parse_cpu_limit(&opt("1.0")), Some(1_000_000_000));
    }

    #[test]
    fn cpu_half_core() {
        assert_eq!(parse_cpu_limit(&opt("0.5")), Some(500_000_000));
    }

    #[test]
    fn cpu_two_cores() {
        assert_eq!(parse_cpu_limit(&opt("2")), Some(2_000_000_000));
    }

    #[test]
    fn cpu_quarter_core() {
        assert_eq!(parse_cpu_limit(&opt("0.25")), Some(250_000_000));
    }

    #[test]
    fn cpu_invalid() {
        assert_eq!(parse_cpu_limit(&opt("half")), None);
    }

    #[test]
    fn cpu_empty_string() {
        assert_eq!(parse_cpu_limit(&opt("")), None);
    }
}
