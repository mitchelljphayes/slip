//! Configuration types for slip.
//!
//! Daemon config loaded from `/etc/slip/slip.toml`.
//! App configs loaded from `/etc/slip/apps/*.toml`.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::Duration;

use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::error::ConfigError;

// ─── Custom duration deserializer ────────────────────────────────────────────

/// Deserializes a human-readable duration string like "2s", "30s", "10s" into
/// `std::time::Duration`.
mod duration_serde {
    use std::time::Duration;

    use serde::{Deserialize, Deserializer, Serializer};

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Duration, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        parse_duration(&s).map_err(serde::de::Error::custom)
    }

    pub fn serialize<S>(duration: &Duration, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let secs = duration.as_secs();
        serializer.serialize_str(&format!("{secs}s"))
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

// ─── Default value helpers ────────────────────────────────────────────────────

fn default_listen() -> SocketAddr {
    "0.0.0.0:7890".parse().expect("valid default listen addr")
}

fn default_caddy_admin_api() -> String {
    "http://localhost:2019".to_owned()
}

fn default_storage_path() -> PathBuf {
    PathBuf::from("/var/lib/slip")
}

fn default_health_interval() -> Duration {
    Duration::from_secs(2)
}

fn default_health_timeout() -> Duration {
    Duration::from_secs(5)
}

fn default_health_retries() -> u32 {
    5
}

fn default_health_start_period() -> Duration {
    Duration::from_secs(10)
}

fn default_deploy_strategy() -> String {
    "blue-green".to_owned()
}

fn default_drain_timeout() -> Duration {
    Duration::from_secs(30)
}

fn default_network_name() -> String {
    "slip".to_owned()
}

fn default_env() -> HashMap<String, String> {
    HashMap::new()
}

// ─── Daemon / server config ───────────────────────────────────────────────────

/// Server-level preview deployment configuration.
///
/// Provides defaults and caps for all preview deployments on this daemon.
/// Apps may override the domain via [`AppPreviewConfig`].
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ServerPreviewConfig {
    /// Wildcard base domain for preview subdomains.
    ///
    /// Each preview is served at `{preview_id}.{domain}`.
    /// Example: `"preview.example.com"` → preview URL `"pr-42.preview.example.com"`.
    pub domain: String,
    /// Maximum concurrent previews per app (server-level default).
    pub max_per_app: Option<u32>,
    /// Default TTL for previews as a duration string (e.g. "1h", "24h", "7d").
    ///
    /// Stored as `String` because TOML doesn't natively support `std::time::Duration`.
    /// Parse with the duration helpers in `repo_config.rs` when needed.
    pub default_ttl: Option<String>,
    /// Maximum memory for preview containers (server-level cap).
    ///
    /// Expressed as a Docker-style size string (e.g. "512m", "1g").
    pub max_memory: Option<String>,
    /// Maximum CPU allocation for preview containers (server-level cap).
    ///
    /// Expressed as a fractional string (e.g. "0.5", "1.0").
    pub max_cpus: Option<String>,
}

/// Top-level daemon configuration (`slip.toml`).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SlipConfig {
    pub server: ServerConfig,
    pub caddy: CaddyConfig,
    pub auth: AuthConfig,
    pub registry: RegistryConfig,
    pub storage: StorageConfig,
    #[serde(default)]
    pub runtime: RuntimeConfig,
    /// Optional server-level preview configuration.
    #[serde(default)]
    pub preview: Option<ServerPreviewConfig>,
}

/// Container runtime backend settings.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RuntimeConfig {
    /// Which runtime backend to use: "docker", "podman", or "auto" (default).
    #[serde(default = "default_runtime_backend")]
    pub backend: String,
}

fn default_runtime_backend() -> String {
    "auto".to_string()
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            backend: default_runtime_backend(),
        }
    }
}

/// HTTP server settings.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ServerConfig {
    #[serde(default = "default_listen")]
    pub listen: SocketAddr,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            listen: default_listen(),
        }
    }
}

/// Caddy reverse-proxy settings.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CaddyConfig {
    #[serde(default = "default_caddy_admin_api")]
    pub admin_api: String,
    /// Optional TLS configuration for wildcard certificates (e.g., for preview deployments).
    #[serde(default)]
    pub tls: Option<CaddyTlsConfig>,
}

/// TLS configuration for Caddy to obtain wildcard certificates via DNS challenge.
///
/// This is used for preview deployments that need wildcard certificates
/// (e.g., `*.preview.example.com`) which require DNS-01 challenge validation.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CaddyTlsConfig {
    /// Email address for Let's Encrypt account registration.
    pub email: String,
    /// DNS provider module name (e.g., "cloudflare", "route53", "digitalocean").
    pub dns_provider: String,
    /// Provider-specific configuration as a TOML table.
    ///
    /// Values should use Caddy's `{env.VAR_NAME}` syntax to reference environment
    /// variables. For example, Cloudflare requires:
    /// ```toml
    /// [caddy.tls.dns_provider_config]
    /// api_token = "{env.CLOUDFLARE_API_TOKEN}"
    /// ```
    pub dns_provider_config: Option<toml::value::Table>,
    /// DNS propagation delay before attempting certificate issuance.
    ///
    /// Expressed as a duration string (e.g., "2m", "30s"). Defaults to "2m".
    #[serde(default = "default_propagation_delay")]
    pub propagation_delay: String,
    /// Use Let's Encrypt staging environment for testing.
    ///
    /// Staging certificates are not trusted by browsers but have no rate limits.
    /// Defaults to `false`.
    #[serde(default)]
    pub staging: bool,
}

fn default_propagation_delay() -> String {
    "2m".to_owned()
}

impl Default for CaddyConfig {
    fn default() -> Self {
        Self {
            admin_api: default_caddy_admin_api(),
            tls: None,
        }
    }
}

/// Authentication settings (shared HMAC secret).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AuthConfig {
    pub secret: String,
}

/// Container registry settings.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RegistryConfig {
    pub ghcr_token: Option<String>,
}

/// Persistent storage path.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct StorageConfig {
    #[serde(default = "default_storage_path")]
    pub path: PathBuf,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            path: default_storage_path(),
        }
    }
}

// ─── Per-app config ───────────────────────────────────────────────────────────

/// Per-app override for preview deployment settings.
///
/// When present in an app's `apps/<name>.toml`, these values take precedence
/// over the corresponding server-level [`ServerPreviewConfig`] defaults.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AppPreviewConfig {
    /// App-specific preview base domain (overrides server-level `preview.domain`).
    pub domain: Option<String>,
    /// Maximum concurrent previews for this app (overrides `preview.max_per_app`).
    pub max: Option<u32>,
}

/// Per-application configuration loaded from `apps/<name>.toml`.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AppConfig {
    pub app: AppInfo,
    pub routing: RoutingConfig,
    pub health: HealthConfig,
    pub deploy: DeployConfig,
    #[serde(default = "default_env")]
    pub env: HashMap<String, String>,
    pub env_file: Option<EnvFileConfig>,
    #[serde(default)]
    pub resources: ResourceConfig,
    #[serde(default)]
    pub network: NetworkConfig,
    /// Optional per-app preview configuration.
    #[serde(default)]
    pub preview: Option<AppPreviewConfig>,
}

/// Basic application identity.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AppInfo {
    pub name: String,
    pub image: String,
    pub secret: Option<String>,
}

/// HTTP routing configuration.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RoutingConfig {
    pub domain: String,
    pub port: u16,
}

/// Container health-check configuration.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct HealthConfig {
    pub path: Option<String>,
    #[serde(default = "default_health_interval", with = "duration_serde")]
    pub interval: Duration,
    #[serde(default = "default_health_timeout", with = "duration_serde")]
    pub timeout: Duration,
    #[serde(default = "default_health_retries")]
    pub retries: u32,
    #[serde(default = "default_health_start_period", with = "duration_serde")]
    pub start_period: Duration,
}

impl Default for HealthConfig {
    fn default() -> Self {
        Self {
            path: None,
            interval: default_health_interval(),
            timeout: default_health_timeout(),
            retries: default_health_retries(),
            start_period: default_health_start_period(),
        }
    }
}

/// Deployment strategy settings.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DeployConfig {
    #[serde(default = "default_deploy_strategy")]
    pub strategy: String,
    #[serde(default = "default_drain_timeout", with = "duration_serde")]
    pub drain_timeout: Duration,
}

impl Default for DeployConfig {
    fn default() -> Self {
        Self {
            strategy: default_deploy_strategy(),
            drain_timeout: default_drain_timeout(),
        }
    }
}

/// Optional `.env`-style file to load.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct EnvFileConfig {
    pub path: PathBuf,
}

/// Container resource limits.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct ResourceConfig {
    pub memory: Option<String>,
    pub cpus: Option<String>,
}

/// Container network settings.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct NetworkConfig {
    #[serde(default = "default_network_name")]
    pub name: String,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            name: default_network_name(),
        }
    }
}

// ─── Env var resolution ───────────────────────────────────────────────────────

/// Resolves `${VAR_NAME}` placeholders in `input` using the process environment.
///
/// Returns [`ConfigError::MissingEnvVar`] if any referenced variable is not set.
pub fn resolve_env_vars(input: &str) -> Result<String, ConfigError> {
    static ENV_VAR_REGEX: OnceLock<Regex> = OnceLock::new();
    let re = ENV_VAR_REGEX.get_or_init(|| Regex::new(r"\$\{([^}]+)\}").expect("valid regex"));

    let mut result = input.to_owned();
    // Collect captures first to avoid borrow issues while mutating `result`.
    let vars: Vec<(String, String)> = re
        .captures_iter(input)
        .map(|cap| {
            let full = cap[0].to_owned(); // e.g. "${MY_VAR}"
            let name = cap[1].to_owned(); // e.g. "MY_VAR"
            (full, name)
        })
        .collect();

    for (placeholder, var_name) in vars {
        if var_name.is_empty() {
            return Err(ConfigError::MissingEnvVar {
                var: String::new(),
                context: format!("empty variable name in {}", input),
            });
        }
        let value = std::env::var(&var_name).map_err(|_| ConfigError::MissingEnvVar {
            var: var_name.clone(),
            context: input.to_owned(),
        })?;
        result = result.replace(&placeholder, &value);
    }

    Ok(result)
}

// ─── Config loading ───────────────────────────────────────────────────────────

/// Loads the daemon config from `{path}/slip.toml` and all app configs from
/// `{path}/apps/*.toml`.
///
/// Environment variables in `auth.secret`, `registry.ghcr_token`, each app's
/// `env` values, and each app's `app.secret` are resolved via [`resolve_env_vars`].
///
/// Returns a tuple of `(SlipConfig, HashMap<app_name, AppConfig>)`.
pub fn load_config(path: &Path) -> Result<(SlipConfig, HashMap<String, AppConfig>), ConfigError> {
    // ── 1. Load daemon config ────────────────────────────────────────────────
    let slip_toml_path = path.join("slip.toml");
    let raw = std::fs::read_to_string(&slip_toml_path).map_err(|e| ConfigError::ReadFile {
        path: slip_toml_path.clone(),
        source: e,
    })?;
    let mut slip_cfg: SlipConfig = toml::from_str(&raw).map_err(|e| ConfigError::Parse {
        path: slip_toml_path.clone(),
        source: e,
    })?;

    // Resolve env vars in auth.secret
    slip_cfg.auth.secret = resolve_env_vars(&slip_cfg.auth.secret)?;

    // Resolve env vars in registry.ghcr_token (if present)
    if let Some(token) = slip_cfg.registry.ghcr_token.take() {
        slip_cfg.registry.ghcr_token = Some(resolve_env_vars(&token)?);
    }

    // ── 2. Load app configs ──────────────────────────────────────────────────
    let apps_dir = path.join("apps");
    let mut apps: HashMap<String, AppConfig> = HashMap::new();

    // `apps/` directory is optional — if it doesn't exist we just return empty.
    if apps_dir.is_dir() {
        let entries = std::fs::read_dir(&apps_dir).map_err(|e| ConfigError::ReadFile {
            path: apps_dir.clone(),
            source: e,
        })?;

        for entry in entries {
            let entry = entry.map_err(|e| ConfigError::ReadFile {
                path: apps_dir.clone(),
                source: e,
            })?;
            let entry_path = entry.path();

            // Only process *.toml files
            if entry_path.extension().and_then(|e| e.to_str()) != Some("toml") {
                continue;
            }

            let filename_stem = entry_path
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("")
                .to_owned();

            let raw = std::fs::read_to_string(&entry_path).map_err(|e| ConfigError::ReadFile {
                path: entry_path.clone(),
                source: e,
            })?;
            let mut app_cfg: AppConfig = toml::from_str(&raw).map_err(|e| ConfigError::Parse {
                path: entry_path.clone(),
                source: e,
            })?;

            // Validate: filename stem must match app.name
            if app_cfg.app.name != filename_stem {
                return Err(ConfigError::NameMismatch {
                    filename: filename_stem,
                    config_name: app_cfg.app.name.clone(),
                });
            }

            // Resolve env vars in env values
            for value in app_cfg.env.values_mut() {
                *value = resolve_env_vars(value)?;
            }

            // Resolve env vars in app.secret
            if let Some(secret) = app_cfg.app.secret.take() {
                app_cfg.app.secret = Some(resolve_env_vars(&secret)?);
            }

            apps.insert(app_cfg.app.name.clone(), app_cfg);
        }
    }

    Ok((slip_cfg, apps))
}

// ─── Config write-back functions ──────────────────────────────────────────────

/// Write an app configuration to disk atomically.
///
/// The config is written to `{config_dir}/apps/{name}.toml` using an atomic
/// write (temp file → rename) to ensure consistency.
pub fn write_app_config(config_dir: &Path, app: &AppConfig) -> Result<(), ConfigError> {
    let apps_dir = config_dir.join("apps");
    if !apps_dir.exists() {
        std::fs::create_dir_all(&apps_dir).map_err(|e| ConfigError::WriteFile {
            path: apps_dir.clone(),
            source: e,
        })?;
    }

    let app_name = &app.app.name;
    let target_path = apps_dir.join(format!("{app_name}.toml"));
    let temp_path = apps_dir.join(format!(".{app_name}.toml.tmp"));

    let content = toml::to_string_pretty(app).map_err(|e| ConfigError::Serialize(e.to_string()))?;

    std::fs::write(&temp_path, content).map_err(|e| ConfigError::WriteFile {
        path: temp_path.clone(),
        source: e,
    })?;

    std::fs::rename(&temp_path, &target_path).map_err(|e| ConfigError::WriteFile {
        path: target_path.clone(),
        source: e,
    })?;

    Ok(())
}

/// Delete an app configuration file from disk.
///
/// Removes `{config_dir}/apps/{name}.toml`. Ignores "not found" errors
/// (idempotent).
pub fn delete_app_config(config_dir: &Path, name: &str) -> Result<(), ConfigError> {
    let apps_dir = config_dir.join("apps");
    let path = apps_dir.join(format!("{name}.toml"));

    match std::fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(ConfigError::DeleteFile { path, source: e }),
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::io::Write;

    use tempfile::TempDir;

    use super::*;

    // ── SlipConfig parsing ───────────────────────────────────────────────────

    #[test]
    fn parse_slip_config_valid() {
        let toml = r#"
[server]
listen = "127.0.0.1:8080"

[caddy]
admin_api = "http://localhost:2019"

[auth]
secret = "supersecret"

[registry]
ghcr_token = "ghp_token"

[storage]
path = "/tmp/slip"
"#;
        let cfg: SlipConfig = toml::from_str(toml).unwrap();
        assert_eq!(cfg.server.listen.to_string(), "127.0.0.1:8080");
        assert_eq!(cfg.caddy.admin_api, "http://localhost:2019");
        assert_eq!(cfg.auth.secret, "supersecret");
        assert_eq!(cfg.registry.ghcr_token.as_deref(), Some("ghp_token"));
        assert_eq!(cfg.storage.path, PathBuf::from("/tmp/slip"));
    }

    #[test]
    fn parse_slip_config_defaults() {
        // Minimal valid config — only required fields supplied.
        let toml = r#"
[server]

[caddy]

[auth]
secret = "s"

[registry]

[storage]
"#;
        let cfg: SlipConfig = toml::from_str(toml).unwrap();
        assert_eq!(cfg.server.listen.to_string(), "0.0.0.0:7890");
        assert_eq!(cfg.caddy.admin_api, "http://localhost:2019");
        assert_eq!(cfg.storage.path, PathBuf::from("/var/lib/slip"));
        assert!(cfg.registry.ghcr_token.is_none());
        assert_eq!(cfg.runtime.backend, "auto");
        // TLS config should be None by default
        assert!(cfg.caddy.tls.is_none());
    }

    // ── CaddyTlsConfig parsing ───────────────────────────────────────────────

    #[test]
    fn parse_caddy_tls_config_full() {
        let toml = r#"
[server]

[caddy]
admin_api = "http://localhost:2019"

[caddy.tls]
email = "admin@example.com"
dns_provider = "cloudflare"
propagation_delay = "5m"
staging = true

[caddy.tls.dns_provider_config]
api_token = "{env.CLOUDFLARE_API_TOKEN}"

[auth]
secret = "s"

[registry]

[storage]
"#;
        let cfg: SlipConfig = toml::from_str(toml).unwrap();
        let tls = cfg
            .caddy
            .tls
            .as_ref()
            .expect("tls config should be present");
        assert_eq!(tls.email, "admin@example.com");
        assert_eq!(tls.dns_provider, "cloudflare");
        assert_eq!(tls.propagation_delay, "5m");
        assert!(tls.staging);
        let provider_config = tls.dns_provider_config.as_ref().expect("provider config");
        assert_eq!(
            provider_config.get("api_token").and_then(|v| v.as_str()),
            Some("{env.CLOUDFLARE_API_TOKEN}")
        );
    }

    #[test]
    fn parse_caddy_tls_config_defaults() {
        let toml = r#"
[server]

[caddy]

[caddy.tls]
email = "admin@example.com"
dns_provider = "cloudflare"

[auth]
secret = "s"

[registry]

[storage]
"#;
        let cfg: SlipConfig = toml::from_str(toml).unwrap();
        let tls = cfg
            .caddy
            .tls
            .as_ref()
            .expect("tls config should be present");
        assert_eq!(tls.email, "admin@example.com");
        assert_eq!(tls.dns_provider, "cloudflare");
        // propagation_delay should default to "2m"
        assert_eq!(tls.propagation_delay, "2m");
        // staging should default to false
        assert!(!tls.staging);
        // dns_provider_config should be None
        assert!(tls.dns_provider_config.is_none());
    }

    #[test]
    fn parse_caddy_tls_config_optional() {
        // TLS config is optional - should parse without it
        let toml = r#"
[server]

[caddy]

[auth]
secret = "s"

[registry]

[storage]
"#;
        let cfg: SlipConfig = toml::from_str(toml).unwrap();
        assert!(cfg.caddy.tls.is_none());
    }

    // ── AppConfig parsing ────────────────────────────────────────────────────

    #[test]
    fn parse_app_config_valid() {
        let toml = r#"
[app]
name = "myapp"
image = "ghcr.io/org/myapp:latest"

[routing]
domain = "myapp.example.com"
port = 3000

[health]
path = "/healthz"
interval = "2s"
timeout = "5s"
retries = 3
start_period = "10s"

[deploy]
strategy = "blue-green"
drain_timeout = "30s"

[resources]
memory = "256m"

[network]
name = "slip"
"#;
        let cfg: AppConfig = toml::from_str(toml).unwrap();
        assert_eq!(cfg.app.name, "myapp");
        assert_eq!(cfg.app.image, "ghcr.io/org/myapp:latest");
        assert_eq!(cfg.routing.domain, "myapp.example.com");
        assert_eq!(cfg.routing.port, 3000);
        assert_eq!(cfg.health.path.as_deref(), Some("/healthz"));
        assert_eq!(cfg.health.interval, Duration::from_secs(2));
        assert_eq!(cfg.health.timeout, Duration::from_secs(5));
        assert_eq!(cfg.health.retries, 3);
        assert_eq!(cfg.health.start_period, Duration::from_secs(10));
        assert_eq!(cfg.deploy.strategy, "blue-green");
        assert_eq!(cfg.deploy.drain_timeout, Duration::from_secs(30));
        assert_eq!(cfg.resources.memory.as_deref(), Some("256m"));
        assert_eq!(cfg.network.name, "slip");
    }

    #[test]
    fn parse_app_config_defaults() {
        let toml = r#"
[app]
name = "svc"
image = "example.com/svc:v1"

[routing]
domain = "svc.example.com"
port = 8080

[health]

[deploy]
"#;
        let cfg: AppConfig = toml::from_str(toml).unwrap();
        assert_eq!(cfg.health.interval, Duration::from_secs(2));
        assert_eq!(cfg.health.timeout, Duration::from_secs(5));
        assert_eq!(cfg.health.retries, 5);
        assert_eq!(cfg.health.start_period, Duration::from_secs(10));
        assert_eq!(cfg.deploy.strategy, "blue-green");
        assert_eq!(cfg.deploy.drain_timeout, Duration::from_secs(30));
        assert_eq!(cfg.network.name, "slip");
        assert!(cfg.env.is_empty());
        assert!(cfg.env_file.is_none());
        assert!(cfg.resources.memory.is_none());
    }

    // ── Env var resolution ───────────────────────────────────────────────────

    #[test]
    fn resolve_env_vars_success() {
        // SAFETY: single-threaded test, no concurrent env access.
        unsafe { std::env::set_var("SLIP_TEST_VAR_42", "hello_world") };
        let result = resolve_env_vars("prefix_${SLIP_TEST_VAR_42}_suffix").unwrap();
        assert_eq!(result, "prefix_hello_world_suffix");
    }

    #[test]
    fn resolve_env_vars_missing_returns_error() {
        // Use a name very unlikely to be set in CI.
        // SAFETY: single-threaded test, no concurrent env access.
        unsafe { std::env::remove_var("SLIP_DEFINITELY_NOT_SET_XYZ") };
        let err = resolve_env_vars("${SLIP_DEFINITELY_NOT_SET_XYZ}").unwrap_err();
        match err {
            ConfigError::MissingEnvVar { var, .. } => {
                assert_eq!(var, "SLIP_DEFINITELY_NOT_SET_XYZ");
            }
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn resolve_env_vars_no_placeholders() {
        let result = resolve_env_vars("plain string without vars").unwrap();
        assert_eq!(result, "plain string without vars");
    }

    // ── load_config filesystem tests ─────────────────────────────────────────

    fn write_file(dir: &Path, filename: &str, content: &str) {
        let path = dir.join(filename);
        let mut f = std::fs::File::create(path).unwrap();
        f.write_all(content.as_bytes()).unwrap();
    }

    fn setup_config_dir() -> TempDir {
        let dir = tempfile::tempdir().unwrap();

        // slip.toml
        write_file(
            dir.path(),
            "slip.toml",
            r#"
[server]
listen = "0.0.0.0:7890"

[caddy]
admin_api = "http://localhost:2019"

[auth]
secret = "test-secret"

[registry]

[storage]
path = "/tmp/slip-test"
"#,
        );

        // apps/
        std::fs::create_dir(dir.path().join("apps")).unwrap();

        dir
    }

    #[test]
    fn load_config_no_apps() {
        let dir = setup_config_dir();
        let (cfg, apps) = load_config(dir.path()).unwrap();
        assert_eq!(cfg.auth.secret, "test-secret");
        assert!(apps.is_empty());
    }

    #[test]
    fn load_config_with_valid_app() {
        let dir = setup_config_dir();

        write_file(
            &dir.path().join("apps"),
            "webapp.toml",
            r#"
[app]
name = "webapp"
image = "ghcr.io/org/webapp:latest"

[routing]
domain = "webapp.example.com"
port = 3000

[health]

[deploy]

[env]
LOG_LEVEL = "info"
"#,
        );

        let (_cfg, apps) = load_config(dir.path()).unwrap();
        assert!(apps.contains_key("webapp"));
        let app = &apps["webapp"];
        assert_eq!(app.routing.port, 3000);
        assert_eq!(app.env["LOG_LEVEL"], "info");
    }

    #[test]
    fn load_config_name_mismatch() {
        let dir = setup_config_dir();

        // File is named "wrong.toml" but app.name is "different"
        write_file(
            &dir.path().join("apps"),
            "wrong.toml",
            r#"
[app]
name = "different"
image = "example.com/app:v1"

[routing]
domain = "app.example.com"
port = 8080

[health]

[deploy]
"#,
        );

        let err = load_config(dir.path()).unwrap_err();
        match err {
            ConfigError::NameMismatch {
                filename,
                config_name,
            } => {
                assert_eq!(filename, "wrong");
                assert_eq!(config_name, "different");
            }
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn load_config_env_var_in_secret() {
        // SAFETY: single-threaded test, no concurrent env access.
        unsafe { std::env::set_var("SLIP_TEST_SECRET_TOKEN", "resolved-secret") };

        let dir = tempfile::tempdir().unwrap();
        write_file(
            dir.path(),
            "slip.toml",
            r#"
[server]

[caddy]

[auth]
secret = "${SLIP_TEST_SECRET_TOKEN}"

[registry]

[storage]
"#,
        );

        let (cfg, _) = load_config(dir.path()).unwrap();
        assert_eq!(cfg.auth.secret, "resolved-secret");
    }
}
