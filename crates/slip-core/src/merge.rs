//! Config merge logic — combines repo-side and server-side configuration.
//!
//! **Repo config** (from the container image) describes what the app *is*:
//! its kind (container vs pod), health check path, routing port defaults,
//! resource defaults, and preview configuration.
//!
//! **Server config** (from disk) describes where it *runs*:
//! domain, secrets, and explicit resource overrides.
//!
//! Merge rules:
//! - Server always wins for: domain, explicitly-set resources.
//! - Repo provides defaults for: health check path, resource limits.
//! - Extra repo metadata (kind, manifest, pod containers, preview) is kept
//!   alongside the merged `AppConfig` in `MergedConfig`.

use std::collections::HashMap;

use crate::config::AppConfig;
use crate::error::ConfigError;
use crate::repo_config::{PreviewConfig, RepoConfig};

/// Merge repo config into server app config.
///
/// The repo config provides defaults for fields the server config leaves unset.
/// The server config always wins for domain, secrets, and explicitly-set resources.
///
/// Volumes are matched by `mount_path`. Every repo-declared volume must have a
/// matching server `host_path`, or an error is returned. Server-only volumes
/// (no matching repo volume) are included as extra mounts.
///
/// Returns a [`MergedConfig`] containing the merged `AppConfig` plus extra
/// metadata from the repo that has no home in the Phase 1 `AppConfig` schema.
pub fn merge_config(server: &AppConfig, repo: &RepoConfig) -> Result<MergedConfig, ConfigError> {
    let mut merged = server.clone();

    // ── Health: repo provides path default if server didn't set one ──────────
    if merged.health.path.is_none() {
        merged.health.path = repo.health.path.clone();
    }

    // ── Resources: repo provides defaults if server left them None ───────────
    if let Some(ref defaults) = repo.defaults.resources {
        if merged.resources.memory.is_none() {
            merged.resources.memory = defaults.memory.clone();
        }
        if merged.resources.cpus.is_none() {
            merged.resources.cpus = defaults.cpus.clone();
        }
    }

    // ── Volumes: match repo volumes to server volumes by mount_path ──────────
    let server_volumes: HashMap<&str, &crate::config::VolumeConfig> = server
        .volumes
        .iter()
        .map(|v| (v.mount_path.as_str(), v))
        .collect();

    let mut merged_volumes = Vec::new();

    for repo_vol in &repo.volumes {
        match server_volumes.get(repo_vol.mount_path.as_str()) {
            Some(server_vol) => {
                // Server always wins for read_only
                merged_volumes.push(MergedVolume {
                    host_path: server_vol.host_path.clone(),
                    mount_path: repo_vol.mount_path.clone(),
                    read_only: server_vol.read_only,
                });
            }
            None => {
                return Err(ConfigError::VolumeMissingHostPath {
                    mount_path: repo_vol.mount_path.clone(),
                });
            }
        }
    }

    // Server-only volumes (no matching repo volume) are included as extra mounts
    for server_vol in &server.volumes {
        if !repo
            .volumes
            .iter()
            .any(|rv| rv.mount_path == server_vol.mount_path)
        {
            merged_volumes.push(MergedVolume {
                host_path: server_vol.host_path.clone(),
                mount_path: server_vol.mount_path.clone(),
                read_only: server_vol.read_only,
            });
        }
    }

    Ok(MergedConfig {
        app: merged,
        kind: repo.app.kind.clone(),
        manifest: repo.app.manifest.clone(),
        health_container: repo.health.container.clone(),
        routing_container: repo.routing.container.clone(),
        preview: repo.preview.clone(),
        volumes: merged_volumes,
    })
}

/// A fully resolved volume after merging repo and server config.
///
/// Combines the server's `host_path` with the repo's `mount_path` and `read_only`.
/// `read_only` follows server-wins precedence.
#[derive(Debug, Clone)]
pub struct MergedVolume {
    /// Absolute path on the host filesystem (from server config).
    pub host_path: String,
    /// Absolute path inside the container (from repo config).
    pub mount_path: String,
    /// Whether the mount should be read-only (server wins, then repo).
    pub read_only: bool,
}

/// The result of merging repo + server config.
///
/// Contains the merged `AppConfig` (base: server, enriched with repo defaults)
/// plus extra fields from the repo that don't have a home in the Phase 1
/// `AppConfig` schema.
#[derive(Debug, Clone)]
pub struct MergedConfig {
    /// The merged app configuration.
    pub app: AppConfig,
    /// App kind: `"container"` or `"pod"`.
    pub kind: String,
    /// Path to the pod manifest (for pod mode).
    pub manifest: Option<String>,
    /// Which container to health check (pod mode only).
    pub health_container: Option<String>,
    /// Which container to route to (pod mode only).
    pub routing_container: Option<String>,
    /// Preview environment configuration from the repo.
    pub preview: Option<PreviewConfig>,
    /// Resolved volume mounts (merged from server + repo configs).
    pub volumes: Vec<MergedVolume>,
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::time::Duration;

    use super::*;
    use crate::config::{
        AppConfig, AppInfo, DeployConfig, HealthConfig, NetworkConfig, ResourceConfig,
        RoutingConfig,
    };
    use crate::repo_config::{
        RepoAppInfo, RepoConfig, RepoDefaults, RepoHealthConfig, RepoResourceConfig,
        RepoRoutingConfig,
    };

    fn base_server_config() -> AppConfig {
        AppConfig {
            app: AppInfo {
                name: "testapp".to_string(),
                image: "ghcr.io/org/testapp".to_string(),
                secret: None,
            },
            routing: RoutingConfig {
                domain: Some("testapp.example.com".to_string()),
                port: Some(3000),
            },
            health: HealthConfig {
                path: None,
                interval: Duration::from_secs(2),
                timeout: Duration::from_secs(5),
                retries: 5,
                start_period: Duration::from_secs(10),
            },
            deploy: DeployConfig {
                strategy: "blue-green".to_string(),
                drain_timeout: Duration::from_secs(30),
            },
            env: HashMap::new(),
            env_file: None,
            resources: ResourceConfig::default(),
            network: NetworkConfig::default(),
            preview: None,
            volumes: Vec::new(),
        }
    }

    fn minimal_repo_config(name: &str) -> RepoConfig {
        RepoConfig {
            app: RepoAppInfo {
                name: name.to_string(),
                kind: "container".to_string(),
                manifest: None,
            },
            health: RepoHealthConfig::default(),
            routing: RepoRoutingConfig::default(),
            defaults: RepoDefaults::default(),
            preview: None,
            deploy: crate::repo_config::RepoDeployConfig::default(),
            volumes: Vec::new(),
        }
    }

    #[test]
    fn merge_server_only_unchanged() {
        let server = base_server_config();
        let repo = minimal_repo_config("testapp");

        let merged = merge_config(&server, &repo).unwrap();

        // App config should be unchanged
        assert_eq!(
            merged.app.routing.domain.as_deref(),
            Some("testapp.example.com")
        );
        assert_eq!(merged.app.routing.port, Some(3000));
        assert!(merged.app.health.path.is_none());
        assert!(merged.app.resources.memory.is_none());
        assert!(merged.app.resources.cpus.is_none());

        // Extra fields from repo
        assert_eq!(merged.kind, "container");
        assert!(merged.manifest.is_none());
        assert!(merged.preview.is_none());
        assert!(merged.volumes.is_empty());
    }

    // ── Repo provides health path; server has none ────────────────────────────

    #[test]
    fn merge_repo_provides_health_path() {
        let server = base_server_config();
        let mut repo = minimal_repo_config("testapp");
        repo.health.path = Some("/healthz".to_string());

        let merged = merge_config(&server, &repo).unwrap();

        assert_eq!(merged.app.health.path.as_deref(), Some("/healthz"));
    }

    // ── Server has health path; repo also has one — server wins ──────────────

    #[test]
    fn merge_server_health_path_wins() {
        let mut server = base_server_config();
        server.health.path = Some("/server-health".to_string());

        let mut repo = minimal_repo_config("testapp");
        repo.health.path = Some("/repo-health".to_string());

        let merged = merge_config(&server, &repo).unwrap();

        // Server's path should be preserved
        assert_eq!(merged.app.health.path.as_deref(), Some("/server-health"));
    }

    // ── Repo provides resource defaults; server has none ─────────────────────

    #[test]
    fn merge_repo_provides_resource_defaults() {
        let server = base_server_config();
        let mut repo = minimal_repo_config("testapp");
        repo.defaults.resources = Some(RepoResourceConfig {
            memory: Some("512m".to_string()),
            cpus: Some("0.5".to_string()),
        });

        let merged = merge_config(&server, &repo).unwrap();

        assert_eq!(merged.app.resources.memory.as_deref(), Some("512m"));
        assert_eq!(merged.app.resources.cpus.as_deref(), Some("0.5"));
    }

    // ── Server has explicit resources; repo has defaults — server wins ────────

    #[test]
    fn merge_server_resources_win_over_repo_defaults() {
        let mut server = base_server_config();
        server.resources.memory = Some("1g".to_string());
        server.resources.cpus = Some("2.0".to_string());

        let mut repo = minimal_repo_config("testapp");
        repo.defaults.resources = Some(RepoResourceConfig {
            memory: Some("256m".to_string()),
            cpus: Some("0.25".to_string()),
        });

        let merged = merge_config(&server, &repo).unwrap();

        // Server's resources should win
        assert_eq!(merged.app.resources.memory.as_deref(), Some("1g"));
        assert_eq!(merged.app.resources.cpus.as_deref(), Some("2.0"));
    }

    // ── Server has memory but not cpus — repo provides cpus default ──────────

    #[test]
    fn merge_partial_resource_override() {
        let mut server = base_server_config();
        server.resources.memory = Some("1g".to_string());
        // server.resources.cpus is None

        let mut repo = minimal_repo_config("testapp");
        repo.defaults.resources = Some(RepoResourceConfig {
            memory: Some("256m".to_string()),
            cpus: Some("0.5".to_string()),
        });

        let merged = merge_config(&server, &repo).unwrap();

        // Server's memory wins, repo's cpus fill the gap
        assert_eq!(merged.app.resources.memory.as_deref(), Some("1g"));
        assert_eq!(merged.app.resources.cpus.as_deref(), Some("0.5"));
    }

    // ── Kind and manifest come through from repo ──────────────────────────────

    #[test]
    fn merge_pod_kind_and_manifest() {
        let server = base_server_config();
        let mut repo = minimal_repo_config("testapp");
        repo.app.kind = "pod".to_string();
        repo.app.manifest = Some("pod.yaml".to_string());
        repo.health.container = Some("web".to_string());
        repo.routing.container = Some("web".to_string());

        let merged = merge_config(&server, &repo).unwrap();

        assert_eq!(merged.kind, "pod");
        assert_eq!(merged.manifest.as_deref(), Some("pod.yaml"));
        assert_eq!(merged.health_container.as_deref(), Some("web"));
        assert_eq!(merged.routing_container.as_deref(), Some("web"));
    }

    // ── Volume merge tests ─────────────────────────────────────────────────────

    fn server_with_volumes(volumes: Vec<crate::config::VolumeConfig>) -> AppConfig {
        let mut server = base_server_config();
        server.volumes = volumes;
        server
    }

    fn repo_with_volumes(volumes: Vec<crate::repo_config::RepoVolume>) -> RepoConfig {
        let mut repo = minimal_repo_config("testapp");
        repo.volumes = volumes;
        repo
    }

    #[test]
    fn merge_volumes_server_only() {
        let server = server_with_volumes(vec![crate::config::VolumeConfig {
            host_path: "/data/myapp".to_string(),
            mount_path: "/app/data".to_string(),
            read_only: false,
        }]);
        let repo = minimal_repo_config("testapp");

        let merged = merge_config(&server, &repo).unwrap();

        assert_eq!(merged.volumes.len(), 1);
        assert_eq!(merged.volumes[0].host_path, "/data/myapp");
        assert_eq!(merged.volumes[0].mount_path, "/app/data");
        assert!(!merged.volumes[0].read_only);
    }

    #[test]
    fn merge_volumes_repo_only_errors() {
        let server = base_server_config();
        let repo = repo_with_volumes(vec![crate::repo_config::RepoVolume {
            mount_path: "/app/data".to_string(),
            read_only: false,
        }]);

        let err = merge_config(&server, &repo).unwrap_err();

        match err {
            crate::error::ConfigError::VolumeMissingHostPath { mount_path } => {
                assert_eq!(mount_path, "/app/data");
            }
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn merge_volumes_matching_repo_and_server() {
        let server = server_with_volumes(vec![crate::config::VolumeConfig {
            host_path: "/data/myapp".to_string(),
            mount_path: "/app/data".to_string(),
            read_only: false,
        }]);
        let repo = repo_with_volumes(vec![crate::repo_config::RepoVolume {
            mount_path: "/app/data".to_string(),
            read_only: true,
        }]);

        let merged = merge_config(&server, &repo).unwrap();

        assert_eq!(merged.volumes.len(), 1);
        assert_eq!(merged.volumes[0].host_path, "/data/myapp");
        assert_eq!(merged.volumes[0].mount_path, "/app/data");
        // Server's read_only (false) wins over repo's (true)
        assert!(!merged.volumes[0].read_only);
    }

    #[test]
    fn merge_volumes_server_extra_included() {
        let server = server_with_volumes(vec![
            crate::config::VolumeConfig {
                host_path: "/data/shared".to_string(),
                mount_path: "/shared".to_string(),
                read_only: true,
            },
            crate::config::VolumeConfig {
                host_path: "/data/myapp".to_string(),
                mount_path: "/app/data".to_string(),
                read_only: false,
            },
        ]);
        let repo = repo_with_volumes(vec![crate::repo_config::RepoVolume {
            mount_path: "/app/data".to_string(),
            read_only: false,
        }]);

        let merged = merge_config(&server, &repo).unwrap();

        assert_eq!(merged.volumes.len(), 2);
        // Server-only volume (no repo match) is included
        let shared = merged
            .volumes
            .iter()
            .find(|v| v.mount_path == "/shared")
            .unwrap();
        assert_eq!(shared.host_path, "/data/shared");
        assert!(shared.read_only);
        // Matched volume
        let data = merged
            .volumes
            .iter()
            .find(|v| v.mount_path == "/app/data")
            .unwrap();
        assert_eq!(data.host_path, "/data/myapp");
    }

    #[test]
    fn merge_volumes_read_only_server_wins() {
        let server = server_with_volumes(vec![crate::config::VolumeConfig {
            host_path: "/data/myapp".to_string(),
            mount_path: "/app/data".to_string(),
            read_only: true,
        }]);
        let repo = repo_with_volumes(vec![crate::repo_config::RepoVolume {
            mount_path: "/app/data".to_string(),
            read_only: false,
        }]);

        let merged = merge_config(&server, &repo).unwrap();

        assert_eq!(merged.volumes.len(), 1);
        // Server's read_only (true) wins over repo's (false)
        assert!(merged.volumes[0].read_only);
    }

    #[test]
    fn merge_volumes_multiple_different_paths() {
        let server = server_with_volumes(vec![
            crate::config::VolumeConfig {
                host_path: "/data/config".to_string(),
                mount_path: "/app/config".to_string(),
                read_only: true,
            },
            crate::config::VolumeConfig {
                host_path: "/data/uploads".to_string(),
                mount_path: "/app/uploads".to_string(),
                read_only: false,
            },
        ]);
        let repo = repo_with_volumes(vec![
            crate::repo_config::RepoVolume {
                mount_path: "/app/config".to_string(),
                read_only: false,
            },
            crate::repo_config::RepoVolume {
                mount_path: "/app/uploads".to_string(),
                read_only: true,
            },
        ]);

        let merged = merge_config(&server, &repo).unwrap();

        assert_eq!(merged.volumes.len(), 2);
        // Server wins for read_only on both
        let config = merged
            .volumes
            .iter()
            .find(|v| v.mount_path == "/app/config")
            .unwrap();
        assert!(config.read_only);
        let uploads = merged
            .volumes
            .iter()
            .find(|v| v.mount_path == "/app/uploads")
            .unwrap();
        assert!(!uploads.read_only);
    }
}
