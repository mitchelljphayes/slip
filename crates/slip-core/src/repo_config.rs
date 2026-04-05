//! Repo-side configuration — parsed from `/slip/slip.toml` inside the container image.
//!
//! The repo config describes **what the app is**: its kind (container vs pod),
//! health check settings, routing port, resource defaults, and preview configuration.
//! The server config describes **where it runs**: domain, secrets, resource overrides.

use std::time::Duration;

use serde::Deserialize;

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
}

/// Routing configuration from the repo config.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct RepoRoutingConfig {
    pub port: Option<u16>,
    /// Which container to route to (pod mode only).
    pub container: Option<String>,
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
}
