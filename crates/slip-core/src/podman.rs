//! Podman backend — container and pod operations via Podman.
//!
//! Single container operations use the Docker-compatible socket API via `bollard`.
//! Pod operations use the `podman` CLI (`podman kube play`, `podman port`) since
//! the Docker-compat API doesn't support Kubernetes pod manifests.

use std::collections::HashMap;
use std::path::Path;
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
use crate::runtime::{PodInfo, RegistryCredentials, RuntimeBackend};

/// Podman container runtime backend.
///
/// Single container operations use the Docker-compatible socket API via `bollard`.
/// Pod operations shell out to the `podman` CLI binary.
pub struct PodmanBackend {
    client: Docker,
    /// Path to the `podman` CLI binary (default: `"podman"`).
    podman_path: String,
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

        let podman_path =
            std::env::var("SLIP_PODMAN_PATH").unwrap_or_else(|_| "podman".to_string());

        Ok(Self {
            client,
            podman_path,
        })
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

    // ── Pod operations (shell out to podman CLI) ───────────────────────────

    fn deploy_pod<'a>(
        &'a self,
        manifest: &'a Path,
        name: &'a str,
    ) -> Pin<Box<dyn std::future::Future<Output = Result<PodInfo, RuntimeError>> + Send + 'a>> {
        Box::pin(async move {
            info!(name, manifest = %manifest.display(), "deploying pod via podman kube play");

            let output = tokio::process::Command::new(&self.podman_path)
                .args(["kube", "play", "--start"])
                .arg(manifest)
                .output()
                .await
                .map_err(|e| {
                    RuntimeError::ContainerError(format!("failed to run podman kube play: {e}"))
                })?;

            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                return Err(RuntimeError::ContainerError(format!(
                    "podman kube play failed (exit {}): {stderr}",
                    output.status.code().unwrap_or(-1)
                )));
            }

            let stdout = String::from_utf8_lossy(&output.stdout);
            let pod_info = parse_kube_play_output(&stdout, name)?;

            info!(
                name,
                containers = pod_info.containers.len(),
                "pod deployed successfully"
            );
            Ok(pod_info)
        })
    }

    fn teardown_pod<'a>(
        &'a self,
        manifest: &'a Path,
    ) -> Pin<Box<dyn std::future::Future<Output = Result<(), RuntimeError>> + Send + 'a>> {
        Box::pin(async move {
            info!(manifest = %manifest.display(), "tearing down pod via podman kube play --down");

            let output = tokio::process::Command::new(&self.podman_path)
                .args(["kube", "play", "--down"])
                .arg(manifest)
                .output()
                .await
                .map_err(|e| {
                    RuntimeError::ContainerError(format!(
                        "failed to run podman kube play --down: {e}"
                    ))
                })?;

            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                return Err(RuntimeError::ContainerError(format!(
                    "podman kube play --down failed (exit {}): {stderr}",
                    output.status.code().unwrap_or(-1)
                )));
            }

            info!(manifest = %manifest.display(), "pod torn down successfully");
            Ok(())
        })
    }

    fn pod_container_port<'a>(
        &'a self,
        pod: &'a str,
        container: &'a str,
        container_port: u16,
    ) -> Pin<Box<dyn std::future::Future<Output = Result<u16, RuntimeError>> + Send + 'a>> {
        Box::pin(async move {
            // Podman names pod containers as "<pod>-<container>"
            let full_name = format!("{pod}-{container}");
            let port_spec = format!("{container_port}/tcp");

            debug!(full_name, port_spec, "querying pod container port");

            let output = tokio::process::Command::new(&self.podman_path)
                .args(["port", &full_name, &port_spec])
                .output()
                .await
                .map_err(|e| {
                    RuntimeError::ContainerError(format!("failed to run podman port: {e}"))
                })?;

            if !output.status.success() {
                return Err(RuntimeError::NoPortAssigned);
            }

            let stdout = String::from_utf8_lossy(&output.stdout);
            parse_port_output(&stdout)
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

// ─── Pod CLI output parsers ──────────────────────────────────────────────────

/// Parse `podman kube play` stdout to extract pod info.
///
/// Podman outputs lines like:
/// ```text
/// Pod:
/// 52182abc...
/// Containers:
/// d53fabc...
/// abc1234...
/// ```
///
/// We parse the pod ID and container IDs from this output.
fn parse_kube_play_output(stdout: &str, pod_name: &str) -> Result<PodInfo, RuntimeError> {
    let mut containers: Vec<String> = Vec::new();
    let mut in_containers = false;

    for line in stdout.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        if trimmed.eq_ignore_ascii_case("containers:") || trimmed.eq_ignore_ascii_case("container:")
        {
            in_containers = true;
            continue;
        }

        if trimmed.ends_with(':') {
            // New section header — stop collecting containers
            in_containers = false;
            continue;
        }

        if in_containers {
            containers.push(trimmed.to_string());
        }
    }

    Ok(PodInfo {
        name: pod_name.to_string(),
        containers,
    })
}

/// Parse `podman port` stdout to extract a host port.
///
/// Output format: `0.0.0.0:54321\n` or `[::]:54321\n`
/// We take the last `:` and parse the port number after it.
fn parse_port_output(stdout: &str) -> Result<u16, RuntimeError> {
    let trimmed = stdout.trim();

    // Handle multiple lines — take the first valid one
    for line in trimmed.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if let Some(colon_pos) = line.rfind(':')
            && let Ok(port) = line[colon_pos + 1..].parse::<u16>()
        {
            return Ok(port);
        }
    }

    Err(RuntimeError::NoPortAssigned)
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── parse_kube_play_output ────────────────────────────────────────────

    #[test]
    fn parse_kube_play_single_container() {
        let output = "\
Pod:
52182abcdef0123456789
Containers:
d53fabc123456789
";
        let info = parse_kube_play_output(output, "my-pod-01abc").unwrap();
        assert_eq!(info.name, "my-pod-01abc");
        assert_eq!(info.containers, vec!["d53fabc123456789"]);
    }

    #[test]
    fn parse_kube_play_multiple_containers() {
        let output = "\
Pod:
52182abcdef0
Containers:
d53fabc12345
abc123456789
fff000111222
";
        let info = parse_kube_play_output(output, "stat-stream-01abc").unwrap();
        assert_eq!(info.name, "stat-stream-01abc");
        assert_eq!(info.containers.len(), 3);
        assert_eq!(info.containers[0], "d53fabc12345");
        assert_eq!(info.containers[1], "abc123456789");
        assert_eq!(info.containers[2], "fff000111222");
    }

    #[test]
    fn parse_kube_play_empty_output() {
        let info = parse_kube_play_output("", "my-pod").unwrap();
        assert_eq!(info.name, "my-pod");
        assert!(info.containers.is_empty());
    }

    #[test]
    fn parse_kube_play_with_extra_sections() {
        let output = "\
Pod:
52182abcdef0
Containers:
d53fabc12345
Volumes:

Secrets:
";
        let info = parse_kube_play_output(output, "my-pod").unwrap();
        assert_eq!(info.containers, vec!["d53fabc12345"]);
    }

    #[test]
    fn parse_kube_play_with_whitespace() {
        let output = "  Pod:  \n  52182abc  \n  Containers:  \n  d53fabc  \n  abc123  \n";
        let info = parse_kube_play_output(output, "test").unwrap();
        assert_eq!(info.containers, vec!["d53fabc", "abc123"]);
    }

    // ── parse_port_output ────────────────────────────────────────────────

    #[test]
    fn parse_port_ipv4() {
        let port = parse_port_output("0.0.0.0:54321\n").unwrap();
        assert_eq!(port, 54321);
    }

    #[test]
    fn parse_port_ipv6() {
        let port = parse_port_output("[::]:8080\n").unwrap();
        assert_eq!(port, 8080);
    }

    #[test]
    fn parse_port_127001() {
        let port = parse_port_output("127.0.0.1:3000\n").unwrap();
        assert_eq!(port, 3000);
    }

    #[test]
    fn parse_port_multiple_lines() {
        // podman port can output both IPv4 and IPv6 bindings
        let output = "0.0.0.0:54321\n[::]:54321\n";
        let port = parse_port_output(output).unwrap();
        assert_eq!(port, 54321);
    }

    #[test]
    fn parse_port_empty_fails() {
        let result = parse_port_output("");
        assert!(matches!(result, Err(RuntimeError::NoPortAssigned)));
    }

    #[test]
    fn parse_port_no_colon_fails() {
        let result = parse_port_output("garbage");
        assert!(matches!(result, Err(RuntimeError::NoPortAssigned)));
    }

    #[test]
    fn parse_port_non_numeric_fails() {
        let result = parse_port_output("0.0.0.0:notaport\n");
        assert!(matches!(result, Err(RuntimeError::NoPortAssigned)));
    }
}
