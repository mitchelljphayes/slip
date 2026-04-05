//! Podman backend — single container operations via Podman's Docker-compatible API.
//!
//! Podman exposes a Docker-compatible socket API, so we use `bollard` to talk to
//! it. For single container operations, Podman's API is Docker-compatible.
//! Pod operations (Phase 2c) will use `podman kube play` via CLI.

use std::collections::HashMap;
use std::pin::Pin;

use bollard::Docker;
use bollard::auth::DockerCredentials;
use bollard::container::{
    Config, CreateContainerOptions, RemoveContainerOptions, StartContainerOptions,
    StopContainerOptions,
};
use bollard::image::CreateImageOptions;
use bollard::models::{HostConfig, PortBinding};
use bollard::network::CreateNetworkOptions;
use futures_util::StreamExt;
use tracing::{debug, info, warn};

use crate::config::ResourceConfig;
use crate::docker::{
    extract_file_from_tar, extract_host_port, parse_cpu_limit, parse_memory_limit,
};
use crate::error::RuntimeError;
use crate::runtime::{RegistryCredentials, RuntimeBackend};

/// Podman container runtime backend.
///
/// Connects to the Podman socket using the Docker-compatible API via `bollard`.
pub struct PodmanBackend {
    client: Docker,
}

impl PodmanBackend {
    /// Connect to the Podman socket.
    ///
    /// Tries these paths in order:
    /// 1. `$XDG_RUNTIME_DIR/podman/podman.sock`
    /// 2. `/run/podman/podman.sock`
    /// 3. `/var/run/podman/podman.sock`
    pub fn new() -> Result<Self, RuntimeError> {
        let socket_path = Self::find_socket()
            .ok_or_else(|| RuntimeError::Connection("Podman socket not found".to_string()))?;

        let url = format!("unix://{socket_path}");
        let client = Docker::connect_with_unix(&url, 120, bollard::API_DEFAULT_VERSION)
            .map_err(|e| RuntimeError::Connection(format!("failed to connect to Podman: {e}")))?;

        Ok(Self { client })
    }

    fn find_socket() -> Option<String> {
        // Check XDG_RUNTIME_DIR first (rootless Podman)
        if let Ok(xdg) = std::env::var("XDG_RUNTIME_DIR") {
            let path = format!("{xdg}/podman/podman.sock");
            if std::path::Path::new(&path).exists() {
                return Some(path);
            }
        }

        // Check common system paths (rootful Podman)
        for path in &["/run/podman/podman.sock", "/var/run/podman/podman.sock"] {
            if std::path::Path::new(path).exists() {
                return Some(path.to_string());
            }
        }

        None
    }
}

impl RuntimeBackend for PodmanBackend {
    fn name(&self) -> &str {
        "podman"
    }

    fn ping(
        &self,
    ) -> Pin<Box<dyn std::future::Future<Output = Result<(), RuntimeError>> + Send + '_>> {
        Box::pin(async {
            self.client
                .ping()
                .await
                .map(|_| ())
                .map_err(|e| RuntimeError::Connection(e.to_string()))
        })
    }

    fn ensure_network<'a>(
        &'a self,
        name: &'a str,
    ) -> Pin<Box<dyn std::future::Future<Output = Result<(), RuntimeError>> + Send + 'a>> {
        Box::pin(async move {
            match self
                .client
                .inspect_network(
                    name,
                    None::<bollard::network::InspectNetworkOptions<String>>,
                )
                .await
            {
                Ok(_) => {
                    debug!(name, "podman network already exists");
                    return Ok(());
                }
                Err(bollard::errors::Error::DockerResponseServerError {
                    status_code: 404, ..
                }) => {}
                Err(e) => {
                    return Err(RuntimeError::NetworkError(e.to_string()));
                }
            }

            info!(name, "creating podman network");
            self.client
                .create_network(CreateNetworkOptions {
                    name,
                    driver: "bridge",
                    check_duplicate: true,
                    ..Default::default()
                })
                .await
                .map_err(|e| RuntimeError::NetworkError(e.to_string()))?;

            info!(name, "podman network created");
            Ok(())
        })
    }

    fn pull_image<'a>(
        &'a self,
        image: &'a str,
        tag: &'a str,
        credentials: Option<RegistryCredentials>,
    ) -> Pin<Box<dyn std::future::Future<Output = Result<(), RuntimeError>> + Send + 'a>> {
        Box::pin(async move {
            info!(image, tag, "pulling image (podman)");

            let creds = credentials.map(|c| DockerCredentials {
                username: Some(c.username),
                password: Some(c.password),
                ..Default::default()
            });

            let options = Some(CreateImageOptions {
                from_image: image,
                tag,
                ..Default::default()
            });

            let mut stream = self.client.create_image(options, None, creds);

            while let Some(item) = stream.next().await {
                match item {
                    Ok(info) => {
                        if let Some(status) = &info.status {
                            debug!(status, "pull progress");
                        }
                        if let Some(err) = info.error {
                            return Err(RuntimeError::PullFailed(err));
                        }
                    }
                    Err(e) => return Err(RuntimeError::PullFailed(e.to_string())),
                }
            }

            info!(image, tag, "image pulled successfully (podman)");
            Ok(())
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
            let tag_prefix = if tag.len() >= 12 { &tag[..12] } else { tag };
            let suffix = &ulid::Ulid::new().to_string()[..8];
            let container_name = format!("slip-{app_name}-{tag_prefix}-{suffix}");

            info!(container_name, image, tag, "creating container (podman)");

            let port_key = format!("{container_port}/tcp");
            let mut port_bindings: HashMap<String, Option<Vec<PortBinding>>> = HashMap::new();
            port_bindings.insert(
                port_key.clone(),
                Some(vec![PortBinding {
                    host_ip: Some("127.0.0.1".to_string()),
                    host_port: None,
                }]),
            );

            let mut labels: HashMap<String, String> = HashMap::new();
            labels.insert("slip.app".to_string(), app_name.to_string());
            labels.insert("slip.tag".to_string(), tag.to_string());
            labels.insert("slip.managed".to_string(), "true".to_string());

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
                .client
                .create_container(Some(create_opts), config)
                .await
                .map_err(|e| RuntimeError::ContainerError(e.to_string()))?;

            let container_id = response.id;
            info!(container_id, "container created, starting (podman)");

            self.client
                .start_container(&container_id, None::<StartContainerOptions<String>>)
                .await
                .map_err(|e| RuntimeError::ContainerError(e.to_string()))?;

            let info = self
                .client
                .inspect_container(&container_id, None)
                .await
                .map_err(|e| RuntimeError::ContainerError(e.to_string()))?;

            let running = info.state.as_ref().and_then(|s| s.running).unwrap_or(false);
            if !running {
                warn!(
                    container_id,
                    "container is not running after start (podman)"
                );
                return Err(RuntimeError::ContainerNotRunning(container_id));
            }

            let host_port = extract_host_port(&info, container_port)
                .map_err(|_| RuntimeError::NoPortAssigned)?;
            info!(
                container_id,
                host_port, "container started and running (podman)"
            );

            Ok((container_id, host_port))
        })
    }

    fn stop_and_remove<'a>(
        &'a self,
        container_id: &'a str,
    ) -> Pin<Box<dyn std::future::Future<Output = Result<(), RuntimeError>> + Send + 'a>> {
        Box::pin(async move {
            info!(container_id, "stopping container (podman)");

            match self
                .client
                .stop_container(container_id, Some(StopContainerOptions { t: 10 }))
                .await
            {
                Ok(()) => {}
                Err(bollard::errors::Error::DockerResponseServerError {
                    status_code: 304, ..
                }) => {
                    warn!(container_id, "container was already stopped (podman)");
                }
                Err(e) => return Err(RuntimeError::ContainerError(e.to_string())),
            }

            self.client
                .remove_container(
                    container_id,
                    Some(RemoveContainerOptions {
                        force: false,
                        ..Default::default()
                    }),
                )
                .await
                .map_err(|e| RuntimeError::ContainerError(e.to_string()))?;

            info!(container_id, "container removed (podman)");
            Ok(())
        })
    }

    fn container_is_running<'a>(
        &'a self,
        container_id: &'a str,
    ) -> Pin<Box<dyn std::future::Future<Output = Result<bool, RuntimeError>> + Send + 'a>> {
        Box::pin(async move {
            let info = self
                .client
                .inspect_container(container_id, None)
                .await
                .map_err(|e| RuntimeError::ContainerError(e.to_string()))?;
            let running = info.state.as_ref().and_then(|s| s.running).unwrap_or(false);
            Ok(running)
        })
    }

    fn container_exists<'a>(
        &'a self,
        container_id: &'a str,
    ) -> Pin<Box<dyn std::future::Future<Output = Result<bool, RuntimeError>> + Send + 'a>> {
        Box::pin(async move {
            match self.client.inspect_container(container_id, None).await {
                Ok(_) => Ok(true),
                Err(bollard::errors::Error::DockerResponseServerError {
                    status_code: 404, ..
                }) => Ok(false),
                Err(e) => Err(RuntimeError::ContainerError(e.to_string())),
            }
        })
    }

    fn extract_file<'a>(
        &'a self,
        image: &'a str,
        tag: &'a str,
        path: &'a str,
    ) -> Pin<Box<dyn std::future::Future<Output = Result<Option<Vec<u8>>, RuntimeError>> + Send + 'a>>
    {
        Box::pin(async move {
            let image_ref = format!("{image}:{tag}");
            let suffix = &ulid::Ulid::new().to_string()[..8];
            let container_name = format!("slip-extract-{suffix}");

            debug!(
                image_ref,
                container_name, path, "creating temp container for file extraction (podman)"
            );

            let config = bollard::container::Config::<String> {
                image: Some(image_ref),
                ..Default::default()
            };
            let create_opts = bollard::container::CreateContainerOptions {
                name: container_name.clone(),
                platform: None::<String>,
            };

            let response = self
                .client
                .create_container(Some(create_opts), config)
                .await
                .map_err(|e| RuntimeError::ContainerError(e.to_string()))?;
            let container_id = response.id;

            debug!(
                container_id,
                path, "downloading file from temp container (podman)"
            );

            // Download the file as a tar archive — collect Bytes chunks manually
            let mut download = self.client.download_from_container(
                &container_id,
                Some(bollard::container::DownloadFromContainerOptions { path }),
            );

            let mut tar_buf: Vec<u8> = Vec::new();
            let mut download_err: Option<RuntimeError> = None;
            loop {
                match download.next().await {
                    Some(Ok(chunk)) => tar_buf.extend_from_slice(&chunk),
                    Some(Err(bollard::errors::Error::DockerResponseServerError {
                        status_code: 404,
                        ..
                    })) => {
                        // File doesn't exist — clean up and return None
                        let _ = self
                            .client
                            .remove_container(
                                &container_id,
                                Some(bollard::container::RemoveContainerOptions {
                                    force: true,
                                    ..Default::default()
                                }),
                            )
                            .await;
                        return Ok(None);
                    }
                    Some(Err(e)) => {
                        download_err = Some(RuntimeError::ContainerError(e.to_string()));
                        break;
                    }
                    None => break,
                }
            }

            let bytes_result: Result<Vec<u8>, RuntimeError> = match download_err {
                Some(e) => Err(e),
                None => Ok(tar_buf),
            };

            // Always clean up the temp container
            let _ = self
                .client
                .remove_container(
                    &container_id,
                    Some(bollard::container::RemoveContainerOptions {
                        force: true,
                        ..Default::default()
                    }),
                )
                .await;

            debug!(container_id, "temp container removed (podman)");

            let bytes = bytes_result?;
            extract_file_from_tar(&bytes, path)
                .map_err(|e| RuntimeError::ContainerError(e.to_string()))
        })
    }
}
