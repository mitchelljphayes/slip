//! Repo-side configuration — parsed from `/slip/slip.toml` inside the container image.
//!
//! The repo config describes **what the app is**: its kind (container vs pod),
//! health check settings, routing port, resource defaults, and preview configuration.
//! The server config describes **where it runs**: domain, secrets, resource overrides.

use std::collections::HashMap;
use std::time::Duration;

use serde::Deserialize;

/// A volume declaration from the repo config.
///
/// The repo declares what mount points the app needs (`mount_path`) and whether
/// the mount should be read-only.  The server config provides the `host_path`.
#[derive(Debug, Clone, Deserialize)]
pub struct RepoVolume {
    /// Absolute path inside the container where the volume is mounted.
    pub mount_path: String,
    /// Mount the volume read-only inside the container.
    #[serde(default)]
    pub read_only: bool,
}

/// Laptop-side config: binds a repo to a slipd server + app.
///
/// Written by `slip link`; read by every laptop command to avoid
/// `--server`/`--token`/app flags every time.
/// The token is NEVER stored here — it stays in `SLIP_TOKEN` env / `--token`.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct RemoteConfig {
    /// slipd management API URL, e.g. "https://deploy.example.com"
    pub server: String,
    /// App name this repo deploys as.
    pub app: String,
}

/// Repo-side config extracted from `/slip/slip.toml` in the container image.
#[derive(Debug, Clone, Deserialize)]
pub struct RepoConfig {
    pub app: RepoAppInfo,
    #[serde(default)]
    pub health: RepoHealthConfig,
    #[serde(default)]
    pub routing: RepoRoutingConfig,
    #[serde(default)]
    pub defaults: RepoDefaults,
    pub preview: Option<PreviewConfig>,
    /// Volume mount points the app needs.
    #[serde(default)]
    pub volumes: Vec<RepoVolume>,
    /// Environment variables to push to the server (full-replace semantics).
    #[serde(default)]
    pub env: HashMap<String, String>,
    /// Deploy configuration (strategy, drain timeout, etc.).
    #[serde(default)]
    pub deploy: Option<RepoDeployConfig>,
    /// Laptop-side remote binding (written by `slip link`).
    #[serde(default)]
    pub remote: RemoteConfig,
}

/// Basic application identity from the repo config.
#[derive(Debug, Clone, Deserialize)]
pub struct RepoAppInfo {
    pub name: String,
    /// App kind: "container" (default) or "pod".
    #[serde(default = "default_app_kind")]
    pub kind: String,
    /// Path to Kubernetes Pod YAML manifest (for pod mode).
    pub manifest: Option<String>,
    /// Container image (e.g. "ghcr.io/org/app"). Required for create-on-first-apply.
    pub image: Option<String>,
}

fn default_app_kind() -> String {
    "container".to_string()
}

/// Health-check configuration from the repo config.
///
/// All fields are optional because the server config may provide them instead.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct RepoHealthConfig {
    pub path: Option<String>,
    /// Which container to health check (pod mode only).
    pub container: Option<String>,
    #[serde(default, with = "option_duration_serde")]
    pub interval: Option<Duration>,
    #[serde(default, with = "option_duration_serde")]
    pub timeout: Option<Duration>,
    pub retries: Option<u32>,
    #[serde(default, with = "option_duration_serde")]
    pub start_period: Option<Duration>,
    /// HTTP status codes that count as healthy (see `docs/health.md`). Parsed
    /// at config load — an invalid spec fails `parse_repo_config` before any
    /// deploy. Defaults to `200-399` at probe time when unset.
    #[serde(default)]
    pub expect_status: Option<crate::status_expectation::StatusExpectation>,
}

/// A single route entry in the repo-side routing config.
///
/// The repo declares which `port` and/or `container` to route to.
/// The server provides the `hostname` (domain).
#[derive(Debug, Clone, Deserialize)]
pub struct RepoRouteEntry {
    /// Port to route to.
    #[serde(default)]
    pub port: Option<u16>,
    /// Which container to route to (pod mode only).
    #[serde(default)]
    pub container: Option<String>,
    /// Container kind: "http" (default) or "worker".
    #[serde(default = "default_route_kind")]
    pub kind: String,
}

impl Default for RepoRouteEntry {
    fn default() -> Self {
        Self {
            port: None,
            container: None,
            kind: default_route_kind(),
        }
    }
}

fn default_route_kind() -> String {
    "http".to_string()
}

/// Routing configuration from the repo config.
#[derive(Debug, Clone, Deserialize)]
pub struct RepoRoutingConfig {
    pub port: Option<u16>,
    /// Which container to route to (pod mode only).
    pub container: Option<String>,
    /// Container kind for single-route shorthand: "http" (default) or "worker".
    #[serde(default = "default_route_kind")]
    pub kind: String,
    /// Multiple routes for this app. Each entry has a port and optional container.
    /// When non-empty, takes precedence over `port`/`container`.
    #[serde(default)]
    pub routes: Vec<RepoRouteEntry>,
    /// Domain/hostname for the app (e.g. "myapp.example.com").
    /// Written by `slip init` template; used by `slip apply` for create-on-first-apply.
    pub domain: Option<String>,
}

impl Default for RepoRoutingConfig {
    fn default() -> Self {
        Self {
            port: None,
            container: None,
            kind: default_route_kind(),
            routes: Vec::new(),
            domain: None,
        }
    }
}

impl RepoRoutingConfig {
    /// Returns the effective routes for this config.
    ///
    /// If `routes` is non-empty, returns it directly.
    /// Otherwise, if `port` is set, returns a single `RepoRouteEntry` from `port`/`container`.
    /// Otherwise returns an empty vec.
    pub fn effective_routes(&self) -> Vec<RepoRouteEntry> {
        if !self.routes.is_empty() {
            return self.routes.clone();
        }
        if self.port.is_some() {
            vec![RepoRouteEntry {
                port: self.port,
                container: self.container.clone(),
                kind: self.kind.clone(),
            }]
        } else {
            vec![]
        }
    }
}

/// Default resource configuration from the repo config.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct RepoDefaults {
    pub resources: Option<RepoResourceConfig>,
}

/// Resource limits from the repo config.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct RepoResourceConfig {
    pub memory: Option<String>,
    pub cpus: Option<String>,
}

/// Deploy configuration from the repo config.
///
/// Mirrors the server-side `DeployConfig` for the pushable subset.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct RepoDeployConfig {
    /// Deployment strategy: "blue-green" (default) or "rolling".
    pub strategy: Option<String>,
    /// Max time to wait for connections to drain before cutting over.
    #[serde(default, with = "option_duration_serde")]
    pub drain_timeout: Option<Duration>,
    /// Max time to wait for the deploy to complete.
    #[serde(default, with = "option_duration_serde")]
    pub timeout: Option<Duration>,
}

/// Preview environment configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct PreviewConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default, with = "option_duration_serde")]
    pub ttl: Option<Duration>,
    pub max: Option<u32>,
    pub resources: Option<RepoResourceConfig>,
    pub database: Option<PreviewDatabaseConfig>,
    pub hooks: Option<PreviewHooks>,
}

/// Database provisioning strategy for preview environments.
#[derive(Debug, Clone, Deserialize)]
pub struct PreviewDatabaseConfig {
    #[serde(default = "default_db_strategy")]
    pub strategy: String,
    pub provider: Option<String>,
    pub project_id: Option<String>,
    pub branch_from: Option<String>,
}

fn default_db_strategy() -> String {
    "shared".to_string()
}

/// Lifecycle hooks for preview environments.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct PreviewHooks {
    pub migrate: Option<String>,
    pub seed: Option<String>,
}

// ─── Parsing ──────────────────────────────────────────────────────────────────

/// Parse a repo config from TOML bytes (e.g. extracted from `/slip/slip.toml`).
///
/// Returns a `toml::de::Error` if the bytes are not valid UTF-8 or valid TOML
/// that matches the `RepoConfig` schema.
pub fn parse_repo_config(bytes: &[u8]) -> Result<RepoConfig, toml::de::Error> {
    let s = match std::str::from_utf8(bytes) {
        Ok(s) => s,
        Err(e) => {
            // Synthesize a toml error for invalid UTF-8
            return toml::from_str::<RepoConfig>(&format!("\x00invalid utf8: {e}"))
                .map_err(|_| toml::from_str::<RepoConfig>("!invalid!").unwrap_err());
        }
    };
    toml::from_str(s)
}

// ─── Option<Duration> deserializer ───────────────────────────────────────────

/// Custom `serde` module for deserializing `Option<Duration>` from a
/// human-readable string like `"30s"`, `"5m"`, `"1h"`, or `"200ms"`.
///
/// A missing/null TOML value deserializes to `None`.
mod option_duration_serde {
    use std::time::Duration;

    use serde::{Deserialize, Deserializer};

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<Duration>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let opt: Option<String> = Option::deserialize(deserializer)?;
        match opt {
            None => Ok(None),
            Some(s) => parse_duration(&s)
                .map(Some)
                .map_err(serde::de::Error::custom),
        }
    }

    fn parse_duration(s: &str) -> Result<Duration, String> {
        let s = s.trim();
        if let Some(rest) = s.strip_suffix("ms") {
            let millis: u64 = rest
                .trim()
                .parse()
                .map_err(|_| format!("invalid duration: '{s}'"))?;
            return Ok(Duration::from_millis(millis));
        }
        if let Some(rest) = s.strip_suffix('s') {
            let secs: f64 = rest
                .trim()
                .parse()
                .map_err(|_| format!("invalid duration: '{s}'"))?;
            return Ok(Duration::from_secs_f64(secs));
        }
        if let Some(rest) = s.strip_suffix('m') {
            let mins: u64 = rest
                .trim()
                .parse()
                .map_err(|_| format!("invalid duration: '{s}'"))?;
            return Ok(Duration::from_secs(mins * 60));
        }
        if let Some(rest) = s.strip_suffix('h') {
            let hours: u64 = rest
                .trim()
                .parse()
                .map_err(|_| format!("invalid duration: '{s}'"))?;
            return Ok(Duration::from_secs(hours * 3600));
        }
        Err(format!(
            "invalid duration '{s}': expected suffix 'ms', 's', 'm', or 'h'"
        ))
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    // ── Minimal config ────────────────────────────────────────────────────────

    #[test]
    fn parse_minimal_repo_config() {
        let toml = r#"
[app]
name = "myapp"
"#;
        let cfg = parse_repo_config(toml.as_bytes()).unwrap();
        assert_eq!(cfg.app.name, "myapp");
        assert_eq!(cfg.app.kind, "container");
        assert!(cfg.app.manifest.is_none());
        assert!(cfg.health.path.is_none());
        assert!(cfg.routing.port.is_none());
        assert!(cfg.preview.is_none());
    }

    // ── Full config ───────────────────────────────────────────────────────────

    #[test]
    fn parse_full_repo_config() {
        let toml = r#"
[app]
name = "fullapp"
kind = "container"

[health]
path = "/healthz"
interval = "5s"
timeout = "3s"
retries = 4
start_period = "15s"

[routing]
port = 8080

[defaults.resources]
memory = "256m"
cpus = "0.5"
"#;
        let cfg = parse_repo_config(toml.as_bytes()).unwrap();
        assert_eq!(cfg.app.name, "fullapp");
        assert_eq!(cfg.app.kind, "container");
        assert_eq!(cfg.health.path.as_deref(), Some("/healthz"));
        assert_eq!(cfg.health.interval, Some(Duration::from_secs(5)));
        assert_eq!(cfg.health.timeout, Some(Duration::from_secs(3)));
        assert_eq!(cfg.health.retries, Some(4));
        assert_eq!(cfg.health.start_period, Some(Duration::from_secs(15)));
        assert_eq!(cfg.routing.port, Some(8080));
        let resources = cfg.defaults.resources.as_ref().unwrap();
        assert_eq!(resources.memory.as_deref(), Some("256m"));
        assert_eq!(resources.cpus.as_deref(), Some("0.5"));
    }

    // ── Pod mode config ───────────────────────────────────────────────────────

    #[test]
    fn parse_pod_mode_config() {
        let toml = r#"
[app]
name = "podapp"
kind = "pod"
manifest = "pod.yaml"

[health]
path = "/health"
container = "web"

[routing]
port = 3000
container = "web"
"#;
        let cfg = parse_repo_config(toml.as_bytes()).unwrap();
        assert_eq!(cfg.app.kind, "pod");
        assert_eq!(cfg.app.manifest.as_deref(), Some("pod.yaml"));
        assert_eq!(cfg.health.container.as_deref(), Some("web"));
        assert_eq!(cfg.routing.container.as_deref(), Some("web"));
    }

    // ── Preview config ────────────────────────────────────────────────────────

    #[test]
    fn parse_preview_config() {
        let toml = r#"
[app]
name = "previewapp"

[preview]
enabled = true
ttl = "1h"
max = 10

[preview.resources]
memory = "128m"

[preview.database]
strategy = "branch"
provider = "neon"
project_id = "proj-123"

[preview.hooks]
migrate = "bundle exec rails db:migrate"
seed = "bundle exec rails db:seed"
"#;
        let cfg = parse_repo_config(toml.as_bytes()).unwrap();
        let preview = cfg.preview.as_ref().unwrap();
        assert!(preview.enabled);
        assert_eq!(preview.ttl, Some(Duration::from_secs(3600)));
        assert_eq!(preview.max, Some(10));
        let db = preview.database.as_ref().unwrap();
        assert_eq!(db.strategy, "branch");
        assert_eq!(db.provider.as_deref(), Some("neon"));
        let hooks = preview.hooks.as_ref().unwrap();
        assert_eq!(
            hooks.migrate.as_deref(),
            Some("bundle exec rails db:migrate")
        );
    }

    // ── Error cases ───────────────────────────────────────────────────────────

    #[test]
    fn parse_invalid_toml_returns_error() {
        let bad = b"[app\nname = broken";
        assert!(parse_repo_config(bad).is_err());
    }

    #[test]
    fn parse_invalid_utf8_returns_error() {
        let bad: &[u8] = &[0xFF, 0xFE, 0x00];
        assert!(parse_repo_config(bad).is_err());
    }

    // ── Duration parsing ──────────────────────────────────────────────────────

    #[test]
    fn parse_duration_milliseconds() {
        let toml = r#"
[app]
name = "app"

[health]
interval = "500ms"
"#;
        let cfg = parse_repo_config(toml.as_bytes()).unwrap();
        assert_eq!(cfg.health.interval, Some(Duration::from_millis(500)));
    }

    #[test]
    fn parse_duration_minutes() {
        let toml = r#"
[app]
name = "app"

[preview]
enabled = false
ttl = "30m"
"#;
        let cfg = parse_repo_config(toml.as_bytes()).unwrap();
        let preview = cfg.preview.as_ref().unwrap();
        assert_eq!(preview.ttl, Some(Duration::from_secs(30 * 60)));
    }

    // ── Volume parsing ────────────────────────────────────────────────────────

    #[test]
    fn parse_repo_config_with_volumes() {
        let toml = r#"
[app]
name = "myapp"

[[volumes]]
mount_path = "/app/data"
read_only = false

[[volumes]]
mount_path = "/app/config"
read_only = true
"#;
        let cfg = parse_repo_config(toml.as_bytes()).unwrap();
        assert_eq!(cfg.volumes.len(), 2);
        assert_eq!(cfg.volumes[0].mount_path, "/app/data");
        assert!(!cfg.volumes[0].read_only);
        assert_eq!(cfg.volumes[1].mount_path, "/app/config");
        assert!(cfg.volumes[1].read_only);
    }

    #[test]
    fn parse_repo_config_volume_read_only_defaults_to_false() {
        let toml = r#"
[app]
name = "myapp"

[[volumes]]
mount_path = "/app/data"
"#;
        let cfg = parse_repo_config(toml.as_bytes()).unwrap();
        assert_eq!(cfg.volumes.len(), 1);
        assert!(!cfg.volumes[0].read_only);
    }

    #[test]
    fn parse_repo_config_volume_rejects_host_path() {
        // host_path should NOT be accepted in repo config — it's server-only.
        // serde ignores unknown fields by default, so this parses successfully
        // but host_path is not stored on the struct.
        let toml = r#"
[app]
name = "myapp"

[[volumes]]
mount_path = "/app/data"
host_path = "/data/myapp"
"#;
        let cfg = parse_repo_config(toml.as_bytes()).unwrap();
        assert_eq!(cfg.volumes.len(), 1);
        assert_eq!(cfg.volumes[0].mount_path, "/app/data");
        // host_path is not a field on RepoVolume, so it's silently ignored
    }

    #[test]
    fn parse_repo_config_empty_volumes() {
        let toml = r#"
[app]
name = "myapp"

volumes = []
"#;
        let cfg = parse_repo_config(toml.as_bytes()).unwrap();
        assert!(cfg.volumes.is_empty());
    }

    #[test]
    fn parse_repo_config_no_volumes_key() {
        let toml = r#"
[app]
name = "myapp"
"#;
        let cfg = parse_repo_config(toml.as_bytes()).unwrap();
        assert!(cfg.volumes.is_empty());
    }

    // ── Multi-route repo config ──────────────────────────────────────────────

    #[test]
    fn parse_repo_config_multi_route() {
        let toml = r#"
[app]
name = "multiapp"

[[routing.routes]]
port = 3000
container = "web"

[[routing.routes]]
port = 3001
container = "admin"
"#;
        let cfg = parse_repo_config(toml.as_bytes()).unwrap();
        assert_eq!(cfg.routing.routes.len(), 2);
        assert_eq!(cfg.routing.routes[0].port, Some(3000));
        assert_eq!(cfg.routing.routes[0].container.as_deref(), Some("web"));
        assert_eq!(cfg.routing.routes[1].port, Some(3001));
        assert_eq!(cfg.routing.routes[1].container.as_deref(), Some("admin"));
    }

    #[test]
    fn parse_repo_config_multi_route_takes_precedence() {
        let toml = r#"
[app]
name = "multiapp"

[routing]
port = 8080
container = "old"

[[routing.routes]]
port = 3000
container = "new"
"#;
        let cfg = parse_repo_config(toml.as_bytes()).unwrap();
        let effective = cfg.routing.effective_routes();
        assert_eq!(effective.len(), 1);
        assert_eq!(effective[0].port, Some(3000));
        assert_eq!(effective[0].container.as_deref(), Some("new"));
    }

    #[test]
    fn parse_repo_config_effective_routes_single() {
        let toml = r#"
[app]
name = "webapp"

[routing]
port = 8080
container = "web"
"#;
        let cfg = parse_repo_config(toml.as_bytes()).unwrap();
        let effective = cfg.routing.effective_routes();
        assert_eq!(effective.len(), 1);
        assert_eq!(effective[0].port, Some(8080));
        assert_eq!(effective[0].container.as_deref(), Some("web"));
    }

    #[test]
    fn parse_repo_config_effective_routes_empty() {
        let toml = r#"
[app]
name = "workerapp"
"#;
        let cfg = parse_repo_config(toml.as_bytes()).unwrap();
        let effective = cfg.routing.effective_routes();
        assert!(effective.is_empty());
    }

    #[test]
    fn parse_repo_config_route_entry_defaults() {
        let toml = r#"
[app]
name = "multiapp"

[[routing.routes]]
port = 3000
"#;
        let cfg = parse_repo_config(toml.as_bytes()).unwrap();
        assert_eq!(cfg.routing.routes.len(), 1);
        assert_eq!(cfg.routing.routes[0].port, Some(3000));
        assert!(cfg.routing.routes[0].container.is_none());
        assert_eq!(cfg.routing.routes[0].kind, "http");
    }

    #[test]
    fn parse_repo_config_route_entry_kind_worker() {
        let toml = r#"
[app]
name = "stat-stream"

[[routing.routes]]
hostname = "stat-stream.example.com"
port = 8000
container = "web"
kind = "http"

[[routing.routes]]
port = 0
container = "worker"
kind = "worker"
"#;
        let cfg = parse_repo_config(toml.as_bytes()).unwrap();
        assert_eq!(cfg.routing.routes.len(), 2);
        assert_eq!(cfg.routing.routes[0].kind, "http");
        assert_eq!(cfg.routing.routes[1].kind, "worker");
    }

    #[test]
    fn parse_repo_config_single_route_kind_worker() {
        let toml = r#"
[app]
name = "workerapp"

[routing]
kind = "worker"
"#;
        let cfg = parse_repo_config(toml.as_bytes()).unwrap();
        assert_eq!(cfg.routing.kind, "worker");
    }

    // ── Remote config ────────────────────────────────────────────────────────

    #[test]
    fn parse_repo_config_with_remote() {
        let toml = r#"
[app]
name = "myapp"

[remote]
server = "https://deploy.example.com"
app = "poi"
"#;
        let cfg = parse_repo_config(toml.as_bytes()).unwrap();
        assert_eq!(cfg.remote.server, "https://deploy.example.com");
        assert_eq!(cfg.remote.app, "poi");
    }

    #[test]
    fn parse_repo_config_without_remote() {
        let toml = r#"
[app]
name = "myapp"
"#;
        let cfg = parse_repo_config(toml.as_bytes()).unwrap();
        assert!(cfg.remote.server.is_empty());
        assert!(cfg.remote.app.is_empty());
    }

    // ── Env and Deploy config ──────────────────────────────────────────────

    #[test]
    fn parse_repo_config_with_env_and_deploy() {
        let toml = r#"
[app]
name = "myapp"

[env]
DATABASE_URL = "postgres://localhost/mydb"
LOG_LEVEL = "debug"

[deploy]
strategy = "blue-green"
drain_timeout = "30s"
timeout = "5m"
"#;
        let cfg = parse_repo_config(toml.as_bytes()).unwrap();
        assert_eq!(
            cfg.env.get("DATABASE_URL").unwrap(),
            "postgres://localhost/mydb"
        );
        assert_eq!(cfg.env.get("LOG_LEVEL").unwrap(), "debug");
        assert_eq!(cfg.env.len(), 2);
        let deploy = cfg.deploy.as_ref().unwrap();
        assert_eq!(deploy.strategy.as_deref(), Some("blue-green"));
        assert_eq!(deploy.drain_timeout, Some(Duration::from_secs(30)));
        assert_eq!(deploy.timeout, Some(Duration::from_secs(300)));
    }

    #[test]
    fn parse_repo_config_without_env_and_deploy() {
        let toml = r#"
[app]
name = "myapp"
"#;
        let cfg = parse_repo_config(toml.as_bytes()).unwrap();
        assert!(cfg.env.is_empty());
        assert!(cfg.deploy.is_none());
    }

    #[test]
    fn parse_repo_config_route_entry_kind_defaults_to_http() {
        let toml = r#"
[app]
name = "multiapp"

[[routing.routes]]
port = 3000
container = "web"
"#;
        let cfg = parse_repo_config(toml.as_bytes()).unwrap();
        assert_eq!(cfg.routing.routes[0].kind, "http");
    }

    // ── expect_status parsing ───────────────────────────────────────────────

    #[test]
    fn parse_repo_config_with_expect_status() {
        let toml = r#"
[app]
name = "myapp"

[health]
path = "/healthz"
expect_status = "200,204"
"#;
        let cfg = parse_repo_config(toml.as_bytes()).unwrap();
        let expect = cfg.health.expect_status.expect("expect_status set");
        assert_eq!(expect.canonical(), "200,204");
        assert!(expect.accepts(200));
        assert!(expect.accepts(204));
        assert!(!expect.accepts(307));
    }

    #[test]
    fn parse_repo_config_without_expect_status_defaults_to_none() {
        let toml = r#"
[app]
name = "myapp"

[health]
path = "/healthz"
"#;
        let cfg = parse_repo_config(toml.as_bytes()).unwrap();
        assert!(
            cfg.health.expect_status.is_none(),
            "expect_status must be None when absent — preserves back-compat"
        );
    }

    #[test]
    fn parse_repo_config_invalid_expect_status_errors() {
        let toml = r#"
[app]
name = "myapp"

[health]
expect_status = "99"
"#;
        let err = parse_repo_config(toml.as_bytes()).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("100-599"),
            "prescriptive out-of-range message: {msg}"
        );
    }
}
