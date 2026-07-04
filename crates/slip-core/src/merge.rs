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

/// A fully-resolved route after merging repo + server config.
///
/// The server provides the `hostname`, the repo provides the `port` and
/// `container` (pod mode). If the repo doesn't specify a port, the server's
/// port is used.
#[derive(Debug, Clone)]
pub struct MergedRoute {
    /// Hostname/domain for this route (from server config).
    pub hostname: String,
    /// Port to route to (from repo config, falling back to server config).
    pub port: u16,
    /// Which container to route to (pod mode only, from repo config).
    pub container: Option<String>,
    /// Container kind: "http" (default) or "worker".
    pub kind: String,
}

/// A fully-resolved volume after merging repo + server config.
///
/// Contains the `host_path` from the server config and the `mount_path` /
/// `read_only` from the repo config (server `read_only` wins if set).
#[derive(Debug, Clone)]
pub struct MergedVolume {
    /// Absolute path on the host filesystem (from server config).
    pub host_path: String,
    /// Absolute path inside the container (from repo config).
    pub mount_path: String,
    /// Mount the volume read-only inside the container.
    pub read_only: bool,
}

/// Merge repo config into server app config.
///
/// The repo config provides defaults for fields the server config leaves unset.
/// The server config always wins for domain, secrets, and explicitly-set resources.
///
/// Returns a [`MergedConfig`] containing the merged `AppConfig` plus extra
/// metadata from the repo that has no home in the Phase 1 `AppConfig` schema.
///
/// # Errors
///
/// Returns [`ConfigError::VolumeMissingHostPath`] if a repo-declared volume has
/// no matching `host_path` in the server config.
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

    // ── Volumes: match repo volumes to server volumes by mount_path ─────────
    // Build a map of server volumes keyed by mount_path.
    let server_volumes: HashMap<&str, &crate::config::VolumeConfig> = server
        .volumes
        .iter()
        .map(|v| (v.mount_path.as_str(), v))
        .collect();

    let mut merged_volumes = Vec::new();

    // For each repo volume: find matching server volume by mount_path.
    for repo_vol in &repo.volumes {
        match server_volumes.get(repo_vol.mount_path.as_str()) {
            Some(server_vol) => {
                // Server wins for read_only if explicitly set (non-default).
                // Since VolumeConfig.read_only defaults to false, we use the
                // server value when it's true, otherwise fall back to repo.
                let read_only = if server_vol.read_only {
                    true
                } else {
                    repo_vol.read_only
                };
                merged_volumes.push(MergedVolume {
                    host_path: server_vol.host_path.clone(),
                    mount_path: repo_vol.mount_path.clone(),
                    read_only,
                });
            }
            None => {
                // Repo volume without matching server host_path → error.
                return Err(ConfigError::VolumeMissingHostPath {
                    mount_path: repo_vol.mount_path.clone(),
                });
            }
        }
    }

    // For each server volume NOT matched by any repo volume: include it anyway
    // (server-injected extra mount).
    let repo_mount_paths: Vec<&str> = repo.volumes.iter().map(|v| v.mount_path.as_str()).collect();
    for server_vol in &server.volumes {
        if !repo_mount_paths.contains(&server_vol.mount_path.as_str()) {
            merged_volumes.push(MergedVolume {
                host_path: server_vol.host_path.clone(),
                mount_path: server_vol.mount_path.clone(),
                read_only: server_vol.read_only,
            });
        }
    }

    // ── Routes: merge server hostnames with repo ports/containers ────────────
    let server_routes = server.routing.effective_routes();
    let repo_routes = repo.routing.effective_routes();

    let merged_routes = if server_routes.is_empty() && repo_routes.is_empty() {
        // Worker app — no routes.
        vec![]
    } else if !server_routes.is_empty() && repo_routes.is_empty() {
        // Only server has routes (single-route backward compat).
        // Use server hostname + server port.
        server_routes
            .iter()
            .map(|sr| MergedRoute {
                hostname: sr.hostname.clone(),
                port: sr.port.unwrap_or(0),
                container: None,
                kind: "http".to_string(),
            })
            .collect()
    } else if server_routes.is_empty() && !repo_routes.is_empty() {
        // Only repo has routes — error: repo declares routes but server provides no hostnames.
        return Err(ConfigError::Merge(format!(
            "repo declares {} route(s) but server config has no hostnames",
            repo_routes.len()
        )));
    } else {
        // Both have routes — pair by index.
        if server_routes.len() != repo_routes.len() {
            return Err(ConfigError::Merge(format!(
                "route count mismatch: server has {} route(s), repo has {} route(s)",
                server_routes.len(),
                repo_routes.len()
            )));
        }
        server_routes
            .iter()
            .zip(repo_routes.iter())
            .map(|(sr, rr)| {
                let port = rr.port.or(sr.port).unwrap_or(0);
                MergedRoute {
                    hostname: sr.hostname.clone(),
                    port,
                    container: rr.container.clone(),
                    kind: rr.kind.clone(),
                }
            })
            .collect()
    };

    Ok(MergedConfig {
        app: merged,
        kind: repo.app.kind.clone(),
        manifest: repo.app.manifest.clone(),
        health_container: repo.health.container.clone(),
        routing_container: repo.routing.container.clone(),
        routes: merged_routes,
        preview: repo.preview.clone(),
        volumes: merged_volumes,
    })
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
    /// Merged routes (server hostname + repo port/container).
    pub routes: Vec<MergedRoute>,
    /// Preview environment configuration from the repo.
    pub preview: Option<PreviewConfig>,
    /// Fully-resolved volume mounts (merged from repo + server config).
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
        RepoRouteEntry, RepoRoutingConfig,
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
                routes: vec![],
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
                timeout: None,
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
            volumes: Vec::new(),
        }
    }

    // ── Server-only (no repo config fields) ──────────────────────────────────

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

    // ── Volume merge tests ────────────────────────────────────────────────────

    fn server_with_volumes() -> AppConfig {
        let mut cfg = base_server_config();
        cfg.volumes = vec![
            crate::config::VolumeConfig {
                host_path: "/data/app".to_string(),
                mount_path: "/app/data".to_string(),
                read_only: false,
            },
            crate::config::VolumeConfig {
                host_path: "/data/config".to_string(),
                mount_path: "/app/config".to_string(),
                read_only: true,
            },
            crate::config::VolumeConfig {
                host_path: "/data/extra".to_string(),
                mount_path: "/app/extra".to_string(),
                read_only: false,
            },
        ];
        cfg
    }

    fn repo_with_volumes() -> RepoConfig {
        let mut cfg = minimal_repo_config("testapp");
        cfg.volumes = vec![
            crate::repo_config::RepoVolume {
                mount_path: "/app/data".to_string(),
                read_only: false,
            },
            crate::repo_config::RepoVolume {
                mount_path: "/app/config".to_string(),
                read_only: false, // server overrides to true
            },
        ];
        cfg
    }

    #[test]
    fn merge_volumes_server_only() {
        let server = server_with_volumes();
        let repo = minimal_repo_config("testapp");

        let merged = merge_config(&server, &repo).unwrap();

        // All server volumes should be present (no repo volumes to match)
        assert_eq!(merged.volumes.len(), 3);
        assert_eq!(merged.volumes[0].mount_path, "/app/data");
        assert_eq!(merged.volumes[0].host_path, "/data/app");
        assert_eq!(merged.volumes[1].mount_path, "/app/config");
        assert_eq!(merged.volumes[1].host_path, "/data/config");
        assert_eq!(merged.volumes[2].mount_path, "/app/extra");
        assert_eq!(merged.volumes[2].host_path, "/data/extra");
    }

    #[test]
    fn merge_volumes_repo_only_errors() {
        let server = base_server_config(); // no server volumes
        let repo = repo_with_volumes();

        let result = merge_config(&server, &repo);

        assert!(result.is_err());
        match result.unwrap_err() {
            crate::error::ConfigError::VolumeMissingHostPath { mount_path } => {
                assert_eq!(mount_path, "/app/data");
            }
            _ => panic!("expected VolumeMissingHostPath error"),
        }
    }

    #[test]
    fn merge_volumes_matching() {
        let server = server_with_volumes();
        let repo = repo_with_volumes();

        let merged = merge_config(&server, &repo).unwrap();

        // Two matched volumes + one server-only extra
        assert_eq!(merged.volumes.len(), 3);

        // First: /app/data — server read_only=false, repo read_only=false → false
        assert_eq!(merged.volumes[0].mount_path, "/app/data");
        assert_eq!(merged.volumes[0].host_path, "/data/app");
        assert!(!merged.volumes[0].read_only);

        // Second: /app/config — server read_only=true → true (server wins)
        assert_eq!(merged.volumes[1].mount_path, "/app/config");
        assert_eq!(merged.volumes[1].host_path, "/data/config");
        assert!(merged.volumes[1].read_only);

        // Third: /app/extra — server-only extra volume
        assert_eq!(merged.volumes[2].mount_path, "/app/extra");
        assert_eq!(merged.volumes[2].host_path, "/data/extra");
    }

    #[test]
    fn merge_volumes_read_only_server_wins() {
        let mut server = server_with_volumes();
        // Override /app/data to be read-only on server side
        for v in &mut server.volumes {
            if v.mount_path == "/app/data" {
                v.read_only = true;
            }
        }
        let repo = repo_with_volumes();

        let merged = merge_config(&server, &repo).unwrap();

        // Server's read_only=true should win
        let data_vol = merged
            .volumes
            .iter()
            .find(|v| v.mount_path == "/app/data")
            .unwrap();
        assert!(data_vol.read_only);
    }

    #[test]
    fn merge_volumes_multiple_mount_paths() {
        let mut server = base_server_config();
        server.volumes = vec![
            crate::config::VolumeConfig {
                host_path: "/data/one".to_string(),
                mount_path: "/mnt/one".to_string(),
                read_only: false,
            },
            crate::config::VolumeConfig {
                host_path: "/data/two".to_string(),
                mount_path: "/mnt/two".to_string(),
                read_only: true,
            },
        ];
        let mut repo = minimal_repo_config("testapp");
        repo.volumes = vec![
            crate::repo_config::RepoVolume {
                mount_path: "/mnt/one".to_string(),
                read_only: false,
            },
            crate::repo_config::RepoVolume {
                mount_path: "/mnt/two".to_string(),
                read_only: false,
            },
        ];

        let merged = merge_config(&server, &repo).unwrap();

        assert_eq!(merged.volumes.len(), 2);
        assert_eq!(merged.volumes[0].mount_path, "/mnt/one");
        assert_eq!(merged.volumes[0].host_path, "/data/one");
        assert!(!merged.volumes[0].read_only);
        assert_eq!(merged.volumes[1].mount_path, "/mnt/two");
        assert_eq!(merged.volumes[1].host_path, "/data/two");
        assert!(merged.volumes[1].read_only); // server wins
    }

    // ── Multi-route merge tests ──────────────────────────────────────────────

    #[test]
    fn merge_multi_route_single_route_backward_compat() {
        // Single-route backward compat: server has domain/port, repo has port/container
        let server = base_server_config();
        let mut repo = minimal_repo_config("testapp");
        repo.routing.port = Some(8080);
        repo.routing.container = Some("web".to_string());

        let merged = merge_config(&server, &repo).unwrap();

        assert_eq!(merged.routes.len(), 1);
        assert_eq!(merged.routes[0].hostname, "testapp.example.com");
        assert_eq!(merged.routes[0].port, 8080);
        assert_eq!(merged.routes[0].container.as_deref(), Some("web"));
        assert_eq!(merged.routes[0].kind, "http");
    }

    #[test]
    fn merge_multi_route_server_port_fallback() {
        // When repo doesn't specify port, fall back to server port
        let server = base_server_config();
        let mut repo = minimal_repo_config("testapp");
        repo.routing.port = None; // repo has no port

        let merged = merge_config(&server, &repo).unwrap();

        assert_eq!(merged.routes.len(), 1);
        assert_eq!(merged.routes[0].hostname, "testapp.example.com");
        assert_eq!(merged.routes[0].port, 3000); // falls back to server port
        assert!(merged.routes[0].container.is_none());
        assert_eq!(merged.routes[0].kind, "http");
    }

    #[test]
    fn merge_multi_route_full_multi_route() {
        let mut server = base_server_config();
        server.routing.routes = vec![
            crate::config::RouteEntry {
                hostname: "api.example.com".to_string(),
                port: None,
            },
            crate::config::RouteEntry {
                hostname: "admin.example.com".to_string(),
                port: None,
            },
        ];

        let mut repo = minimal_repo_config("testapp");
        repo.routing.routes = vec![
            RepoRouteEntry {
                port: Some(3000),
                container: Some("web".to_string()),
                kind: "http".to_string(),
            },
            RepoRouteEntry {
                port: Some(3001),
                container: Some("admin".to_string()),
                kind: "http".to_string(),
            },
        ];

        let merged = merge_config(&server, &repo).unwrap();

        assert_eq!(merged.routes.len(), 2);
        assert_eq!(merged.routes[0].hostname, "api.example.com");
        assert_eq!(merged.routes[0].port, 3000);
        assert_eq!(merged.routes[0].container.as_deref(), Some("web"));
        assert_eq!(merged.routes[0].kind, "http");
        assert_eq!(merged.routes[1].hostname, "admin.example.com");
        assert_eq!(merged.routes[1].port, 3001);
        assert_eq!(merged.routes[1].container.as_deref(), Some("admin"));
        assert_eq!(merged.routes[1].kind, "http");
    }

    #[test]
    fn merge_multi_route_length_mismatch_error() {
        let mut server = base_server_config();
        server.routing.routes = vec![crate::config::RouteEntry {
            hostname: "api.example.com".to_string(),
            port: None,
        }];

        let mut repo = minimal_repo_config("testapp");
        repo.routing.routes = vec![
            RepoRouteEntry {
                port: Some(3000),
                container: None,
                kind: "http".to_string(),
            },
            RepoRouteEntry {
                port: Some(3001),
                container: None,
                kind: "http".to_string(),
            },
        ];

        let err = merge_config(&server, &repo).unwrap_err();
        match err {
            ConfigError::Merge(msg) => {
                assert!(msg.contains("route count mismatch"));
            }
            _ => panic!("expected Merge error, got: {err}"),
        }
    }

    #[test]
    fn merge_multi_route_repo_only_error() {
        // Server has no routes at all (worker-like), but repo declares routes
        let mut server = base_server_config();
        server.routing.domain = None;
        server.routing.port = None;
        let mut repo = minimal_repo_config("testapp");
        repo.routing.routes = vec![RepoRouteEntry {
            port: Some(3000),
            container: None,
            kind: "http".to_string(),
        }];

        let err = merge_config(&server, &repo).unwrap_err();
        match err {
            ConfigError::Merge(msg) => {
                assert!(msg.contains("repo declares"));
            }
            _ => panic!("expected Merge error, got: {err}"),
        }
    }

    #[test]
    fn merge_multi_route_worker_no_routes() {
        // Worker app: no routes in either config
        let mut server = base_server_config();
        server.routing.domain = None;
        server.routing.port = None;

        let repo = minimal_repo_config("testapp");

        let merged = merge_config(&server, &repo).unwrap();
        assert!(merged.routes.is_empty());
    }

    #[test]
    fn merge_multi_route_kind_propagation() {
        // Verify kind is propagated from repo route to merged route
        let mut server = base_server_config();
        server.routing.routes = vec![
            crate::config::RouteEntry {
                hostname: "api.example.com".to_string(),
                port: None,
            },
            crate::config::RouteEntry {
                hostname: "worker.example.com".to_string(),
                port: None,
            },
        ];

        let mut repo = minimal_repo_config("testapp");
        repo.routing.routes = vec![
            RepoRouteEntry {
                port: Some(3000),
                container: Some("web".to_string()),
                kind: "http".to_string(),
            },
            RepoRouteEntry {
                port: Some(0),
                container: Some("worker".to_string()),
                kind: "worker".to_string(),
            },
        ];

        let merged = merge_config(&server, &repo).unwrap();

        assert_eq!(merged.routes.len(), 2);
        assert_eq!(merged.routes[0].kind, "http");
        assert_eq!(merged.routes[0].container.as_deref(), Some("web"));
        assert_eq!(merged.routes[1].kind, "worker");
        assert_eq!(merged.routes[1].container.as_deref(), Some("worker"));
    }

    #[test]
    fn merge_multi_route_single_route_kind_default() {
        // Single-route backward compat: kind defaults to "http"
        let server = base_server_config();
        let mut repo = minimal_repo_config("testapp");
        repo.routing.port = Some(8080);

        let merged = merge_config(&server, &repo).unwrap();

        assert_eq!(merged.routes.len(), 1);
        assert_eq!(merged.routes[0].kind, "http");
    }
}
