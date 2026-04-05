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

use crate::config::AppConfig;
use crate::repo_config::{PreviewConfig, RepoConfig};

/// Merge repo config into server app config.
///
/// The repo config provides defaults for fields the server config leaves unset.
/// The server config always wins for domain, secrets, and explicitly-set resources.
///
/// Returns a [`MergedConfig`] containing the merged `AppConfig` plus extra
/// metadata from the repo that has no home in the Phase 1 `AppConfig` schema.
pub fn merge_config(server: &AppConfig, repo: &RepoConfig) -> MergedConfig {
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

    MergedConfig {
        app: merged,
        kind: repo.app.kind.clone(),
        manifest: repo.app.manifest.clone(),
        health_container: repo.health.container.clone(),
        routing_container: repo.routing.container.clone(),
        preview: repo.preview.clone(),
    }
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
                domain: "testapp.example.com".to_string(),
                port: 3000,
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
        }
    }

    // ── Server-only (no repo config fields) ──────────────────────────────────

    #[test]
    fn merge_server_only_unchanged() {
        let server = base_server_config();
        let repo = minimal_repo_config("testapp");

        let merged = merge_config(&server, &repo);

        // App config should be unchanged
        assert_eq!(merged.app.routing.domain, "testapp.example.com");
        assert_eq!(merged.app.routing.port, 3000);
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

        let merged = merge_config(&server, &repo);

        assert_eq!(merged.app.health.path.as_deref(), Some("/healthz"));
    }

    // ── Server has health path; repo also has one — server wins ──────────────

    #[test]
    fn merge_server_health_path_wins() {
        let mut server = base_server_config();
        server.health.path = Some("/server-health".to_string());

        let mut repo = minimal_repo_config("testapp");
        repo.health.path = Some("/repo-health".to_string());

        let merged = merge_config(&server, &repo);

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

        let merged = merge_config(&server, &repo);

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

        let merged = merge_config(&server, &repo);

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

        let merged = merge_config(&server, &repo);

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

        let merged = merge_config(&server, &repo);

        assert_eq!(merged.kind, "pod");
        assert_eq!(merged.manifest.as_deref(), Some("pod.yaml"));
        assert_eq!(merged.health_container.as_deref(), Some("web"));
        assert_eq!(merged.routing_container.as_deref(), Some("web"));
    }
}
