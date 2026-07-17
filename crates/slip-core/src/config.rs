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

// ─── TLS strategy enum ────────────────────────────────────────────────────────

/// TLS strategy for a host (deploy-webhook domain or per-app route).
///
/// Maps 1:1 to the Caddy automation policy builder in [`crate::caddy`].
/// Wire format is kebab-case (`"internal"`, `"acme"`, `"cloudflare-dns01"`,
/// `"tailscale"`) — matching the existing config strings.
///
/// - `Internal` — Caddy local CA (self-signed). Works on tailnet/non-public
///   hosts; callers use `--insecure` or install the root CA.
/// - `Acme` — Caddy default ACME (HTTP-01 + TLS-ALPN-01) against Let's Encrypt.
///   Requires a public, reachable host + `acme_email`.
/// - `CloudflareDns01` — ACME DNS-01 via the `caddy-dns/cloudflare` plugin.
///   Requires the plugin compiled into Caddy + `{env.CF_API_TOKEN}` + email.
/// - `Tailscale` — Caddy's built-in `tls.get_certificate.tailscale` manager
///   (core, no plugin). Only valid for `*.ts.net` subjects. `tailscaled`
///   handles issuance + renewal; slip does not shell out or write PEM files.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum TlsStrategy {
    /// Caddy local CA (self-signed).
    Internal,
    /// ACME HTTP-01/TLS-ALPN-01 (Let's Encrypt, public host).
    Acme,
    /// ACME DNS-01 via Cloudflare (`caddy-dns/cloudflare` plugin required).
    CloudflareDns01,
    /// Caddy's built-in Tailscale certificate manager (`.ts.net` only).
    Tailscale,
}

impl TlsStrategy {
    /// Wire string for this strategy (matches the serde kebab-case form).
    pub fn as_str(&self) -> &'static str {
        match self {
            TlsStrategy::Internal => "internal",
            TlsStrategy::Acme => "acme",
            TlsStrategy::CloudflareDns01 => "cloudflare-dns01",
            TlsStrategy::Tailscale => "tailscale",
        }
    }
}

impl std::fmt::Display for TlsStrategy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for TlsStrategy {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "internal" => Ok(TlsStrategy::Internal),
            "acme" => Ok(TlsStrategy::Acme),
            "cloudflare-dns01" => Ok(TlsStrategy::CloudflareDns01),
            "tailscale" => Ok(TlsStrategy::Tailscale),
            other => Err(format!(
                "unknown TLS strategy '{other}' — valid: internal, acme, cloudflare-dns01, tailscale"
            )),
        }
    }
}

// ─── TLD allowlist for auto-internal classification ───────────────────────────

/// Conservative TLD allowlist for auto-internal classification.
///
/// A host whose last label matches one of these suffixes is classified
/// as "non-public" and gets an `internal` CA policy when no explicit `tls`
/// is configured. `.ts.net` is **deliberately excluded** — those hosts
/// use Caddy's built-in Tailscale certificate manager, not internal CA.
///
/// Per best-practices Q3: RFC 6761 reserved + ICANN `.internal` + common
/// home/lab TLDs. An operator can always override with explicit `tls`.
pub const NON_PUBLIC_TLDS: &[&str] = &[
    ".test",
    ".example",
    ".invalid",
    ".localhost",
    ".internal",
    ".local",
    ".lan",
    ".home",
    ".home.arpa",
    ".corp",
];

/// True if `host` ends in `.ts.net` (after stripping a leading `*.` if present).
///
/// Used to gate the `tailscale` strategy (only valid for `.ts.net` subjects)
/// and to exclude `.ts.net` from auto-internal classification.
pub fn is_ts_net_host(host: &str) -> bool {
    let h = host.strip_prefix("*.").unwrap_or(host);
    h.ends_with(".ts.net") || h == "ts.net"
}

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

    pub(super) fn parse_duration(s: &str) -> Result<Duration, String> {
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

/// Serde helpers for `Option<Duration>` — accepts `"10m"` or absent/null.
mod duration_serde_option {
    use std::time::Duration;

    use serde::{Deserialize, Deserializer, Serializer};

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<Duration>, D::Error>
    where
        D: Deserializer<'de>,
    {
        // If the field is absent or null, return None.
        let s = Option::<String>::deserialize(deserializer)?;
        match s {
            None => Ok(None),
            Some(s) => {
                let dur =
                    super::duration_serde::parse_duration(&s).map_err(serde::de::Error::custom)?;
                Ok(Some(dur))
            }
        }
    }

    pub fn serialize<S>(duration: &Option<Duration>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match duration {
            None => serializer.serialize_none(),
            Some(dur) => {
                let secs = dur.as_secs();
                serializer.serialize_some(&format!("{secs}s"))
            }
        }
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

fn default_deploy_timeout() -> Duration {
    Duration::from_secs(600)
}

fn default_network_name() -> String {
    "slip".to_owned()
}

fn default_deploy_tls() -> TlsStrategy {
    TlsStrategy::Internal
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

/// Server-level deploy configuration.
///
/// Provides defaults for all deployments on this daemon.
/// Apps may override the timeout via [`DeployConfig::timeout`].
///
/// The `domain` and `tls` fields control the deploy-webhook ingress that slipd
/// registers in Caddy on startup (see [`CaddyClient::bootstrap_deploy`]).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ServerDeployConfig {
    /// Maximum time a production deploy is allowed to run before being killed.
    #[serde(default = "default_deploy_timeout", with = "duration_serde")]
    pub timeout: Duration,
    /// Maximum time a preview deploy is allowed to run before being killed.
    #[serde(default = "default_deploy_timeout", with = "duration_serde")]
    pub preview_timeout: Duration,
    /// Public domain for the deploy webhook (e.g. "deploy.example.com").
    ///
    /// When set, slipd registers a Caddy route + TLS policy on bootstrap.
    /// When absent, no deploy-webhook route is created (backwards compatible).
    #[serde(default)]
    pub domain: Option<String>,
    /// TLS strategy for the deploy webhook domain.
    ///
    /// Defaults to `internal` (Caddy local CA, self-signed — works on
    /// tailnet-only hosts with `--insecure` callers). Other strategies:
    /// `acme` (HTTP-01/TLS-ALPN-01), `cloudflare-dns01` (DNS-01 via
    /// `caddy-dns/cloudflare`), `tailscale` (built-in manager, `.ts.net`
    /// only).
    #[serde(default = "default_deploy_tls")]
    pub tls: TlsStrategy,
}

impl Default for ServerDeployConfig {
    fn default() -> Self {
        Self {
            timeout: default_deploy_timeout(),
            preview_timeout: default_deploy_timeout(),
            domain: None,
            tls: default_deploy_tls(),
        }
    }
}

/// Top-level daemon configuration (`slip.toml`).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SlipConfig {
    pub server: ServerConfig,
    #[serde(default)]
    pub caddy: CaddyConfig,
    pub auth: AuthConfig,
    pub registry: RegistryConfig,
    pub storage: StorageConfig,
    #[serde(default)]
    pub runtime: RuntimeConfig,
    /// Optional server-level preview configuration.
    #[serde(default)]
    pub preview: Option<ServerPreviewConfig>,
    /// Optional server-level deploy configuration.
    #[serde(default)]
    pub deploy: Option<ServerDeployConfig>,
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
    /// Optional ACME contact email, applied to any `acme`/`cloudflare-dns01`
    /// issuer policy that does not carry its own email. Falls back to
    /// `[caddy.tls].email` if this is absent.
    ///
    /// Required (here or via fallback) when an `acme` or `cloudflare-dns01`
    /// strategy is used. `internal` and `tailscale` strategies never need it.
    #[serde(default)]
    pub acme_email: Option<String>,
    /// Optional ACME CA URL override (e.g. Let's Encrypt staging directory).
    /// Defaults to the production Let's Encrypt directory when absent.
    #[serde(default)]
    pub acme_ca: Option<String>,
    /// Optional TLS configuration for wildcard certificates (e.g., for preview deployments).
    #[serde(default)]
    pub tls: Option<CaddyTlsConfig>,
    /// Reconcile loop configuration (`[caddy.reconcile]`).
    #[serde(default)]
    pub reconcile: ReconcileConfig,
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

/// Caddy reconcile loop configuration (`[caddy.reconcile]`).
///
/// Controls the background safety-net loop that re-applies slip-owned Caddy
/// state (slip HTTP server, app routes, deploy-webhook route, TLS policies)
/// on a fixed interval. The loop self-heals routes after a Caddy restart,
/// reload, or missed webhook. It is **not** the primary update path — deploys
/// still push routes immediately via the webhook handler.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ReconcileConfig {
    /// Interval between reconcile ticks.
    ///
    /// Expressed as a duration string (e.g. "45s", "1m"). Defaults to "45s".
    /// Must be at least 1s; smaller values are rejected at load time.
    #[serde(default = "default_reconcile_interval", with = "duration_serde")]
    pub interval: Duration,
}

fn default_reconcile_interval() -> Duration {
    Duration::from_secs(45)
}

impl Default for ReconcileConfig {
    fn default() -> Self {
        Self {
            interval: default_reconcile_interval(),
        }
    }
}

fn default_propagation_delay() -> String {
    "2m".to_owned()
}

impl Default for CaddyConfig {
    fn default() -> Self {
        Self {
            admin_api: default_caddy_admin_api(),
            acme_email: None,
            acme_ca: None,
            tls: None,
            reconcile: ReconcileConfig::default(),
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

/// A host-path volume mount for a container or pod.
///
/// The **server config** (`apps/<name>.toml`) provides the `host_path` — where
/// on the host filesystem the data lives.  The **repo config** (`slip.toml`)
/// declares the `mount_path` and `read_only` — what the app needs.  The merge
/// matches volumes by `mount_path`.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct VolumeConfig {
    /// Absolute path on the host filesystem.
    pub host_path: String,
    /// Absolute path inside the container.
    pub mount_path: String,
    /// Mount the volume read-only inside the container.
    #[serde(default)]
    pub read_only: bool,
}

/// Per-application configuration loaded from `apps/<name>.toml`.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AppConfig {
    pub app: AppInfo,
    #[serde(default)]
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
    /// Host-path volume mounts for this app.
    #[serde(default)]
    pub volumes: Vec<VolumeConfig>,
}

/// Basic application identity.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AppInfo {
    pub name: String,
    pub image: String,
    pub secret: Option<String>,
}

/// A single route entry in the server-side routing config.
///
/// The server provides the `hostname` (domain). The `port` is optional
/// because the repo config may provide it instead.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RouteEntry {
    /// Hostname/domain for this route (e.g. "api.example.com").
    pub hostname: String,
    /// Port to route to. If `None`, the port comes from the repo config.
    #[serde(default)]
    pub port: Option<u16>,
    /// Explicit TLS strategy override for this route's hostname.
    ///
    /// When `None`, the route inherits the auto-internal classification
    /// (non-public TLD/IP literal → `internal`; public host → Caddy's
    /// default automatic HTTPS, untouched). When `Some`, the explicit
    /// strategy wins over classification.
    #[serde(default)]
    pub tls: Option<TlsStrategy>,
}

/// HTTP routing configuration.
///
/// For HTTP apps (kind = "container" or "pod"), either `domain`/`port` (single
/// route, backward compat) or `routes` (multi-route) must be configured.
/// For worker apps (kind = "worker"), all fields are absent.
///
/// When `routes` is non-empty, it takes precedence over `domain`/`port`.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct RoutingConfig {
    #[serde(default)]
    pub domain: Option<String>,
    #[serde(default)]
    pub port: Option<u16>,
    /// Multiple routes for this app. Each entry has a hostname and optional port.
    /// When non-empty, takes precedence over `domain`/`port`.
    #[serde(default)]
    pub routes: Vec<RouteEntry>,
    /// Explicit TLS strategy override applied to all routes in this config.
    ///
    /// When `Some`, this strategy is applied to every route's hostname unless
    /// an individual `RouteEntry.tls` overrides it. When `None`, each route
    /// falls through to auto-internal classification (absent TLS logic).
    #[serde(default)]
    pub tls: Option<TlsStrategy>,
}

impl RoutingConfig {
    /// Returns the effective routes for this config.
    ///
    /// If `routes` is non-empty, returns it directly.
    /// Otherwise, if `domain` is set, returns a single `RouteEntry` from `domain`/`port`.
    /// Otherwise returns an empty vec (worker app).
    pub fn effective_routes(&self) -> Vec<RouteEntry> {
        if !self.routes.is_empty() {
            return self.routes.clone();
        }
        if let Some(ref domain) = self.domain {
            vec![RouteEntry {
                hostname: domain.clone(),
                port: self.port,
                tls: self.tls,
            }]
        } else {
            vec![]
        }
    }
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
    /// Per-app deploy timeout override. If `Some`, overrides the server-level
    /// `[deploy].timeout` (or `[deploy].preview_timeout` for previews).
    /// If `None`, the server-level default is used.
    #[serde(default, with = "duration_serde_option")]
    pub timeout: Option<Duration>,
}

impl Default for DeployConfig {
    fn default() -> Self {
        Self {
            strategy: default_deploy_strategy(),
            drain_timeout: default_drain_timeout(),
            timeout: None,
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

/// Resolve `${VAR_NAME}` placeholders in `input`, collecting unresolved names
/// as warnings instead of erroring.
///
/// This is the `slip doctor` / `slipd --check` variant (FR §3.10): the running
/// service is fine (it has the env via the systemd `EnvironmentFile`); a manual
/// check that doesn't load the env file should warn, not error. Unresolved
/// placeholders are left in place verbatim and their names are returned in
/// `unresolved` so the caller can report them.
pub fn resolve_env_vars_warn(input: &str) -> (String, Vec<String>) {
    static ENV_VAR_REGEX: OnceLock<Regex> = OnceLock::new();
    let re = ENV_VAR_REGEX.get_or_init(|| Regex::new(r"\$\{([^}]+)\}").expect("valid regex"));

    let mut result = input.to_owned();
    let mut unresolved: Vec<String> = Vec::new();
    let vars: Vec<(String, String)> = re
        .captures_iter(input)
        .map(|cap| {
            let full = cap[0].to_owned();
            let name = cap[1].to_owned();
            (full, name)
        })
        .collect();

    for (placeholder, var_name) in vars {
        if var_name.is_empty() {
            unresolved.push(String::new());
            continue;
        }
        match std::env::var(&var_name) {
            Ok(value) => {
                result = result.replace(&placeholder, &value);
            }
            Err(_) => {
                unresolved.push(var_name);
                // Leave the placeholder in place so it's visible in any
                // rendered config text.
            }
        }
    }

    (result, unresolved)
}

// ─── Strategy validation ───────────────────────────────────────────────────────

/// Validate that `DeployConfig.strategy` is a known value.
///
/// Accepts `"blue-green"` and `"recreate"`. Warns (does not error) if
/// `strategy == "recreate"` and `drain_timeout > Duration::ZERO`.
pub fn validate_deploy_strategy(deploy: &DeployConfig) -> Result<(), ConfigError> {
    let valid: Vec<&'static str> = vec!["blue-green", "recreate"];
    match deploy.strategy.as_str() {
        "blue-green" | "recreate" => {}
        other => {
            return Err(ConfigError::InvalidStrategy {
                strategy: other.to_string(),
                valid,
            });
        }
    }
    if deploy.strategy == "recreate" && deploy.drain_timeout > Duration::ZERO {
        tracing::warn!(
            strategy = "recreate",
            drain_timeout = ?deploy.drain_timeout,
            "drain_timeout has no effect with 'recreate' strategy; the old container is stopped immediately"
        );
    }
    Ok(())
}

// ─── TLS strategy validation ──────────────────────────────────────────────────

/// Context for TLS strategy validation.
pub struct ValidationCtx<'a> {
    /// The resolved ACME email (from `[caddy] acme_email` or `[caddy.tls].email`).
    pub acme_email: Option<&'a str>,
}

/// Validate a `TlsStrategy` for a given host.
///
/// - `Internal` → always ok.
/// - `Acme` / `CloudflareDns01` → requires `acme_email` (resolved from
///   `[caddy] acme_email` or `[caddy.tls].email` fallback). Prescriptive
///   error if both are absent.
/// - `Tailscale` → host must end in `.ts.net` (after stripping `*.`).
///   Prescriptive error on non-`.ts.net` hosts.
pub fn validate_tls_strategy(
    s: &TlsStrategy,
    host: Option<&str>,
    ctx: &ValidationCtx,
) -> Result<(), ConfigError> {
    match s {
        TlsStrategy::Internal => Ok(()),
        TlsStrategy::Acme | TlsStrategy::CloudflareDns01 => {
            if ctx.acme_email.is_none() {
                return Err(ConfigError::Internal(format!(
                    "TLS strategy '{s}' requires [caddy] acme_email — \
                     set it in slip.toml, e.g. acme_email = \"you@example.com\". \
                     (Fallback: [caddy.tls].email is also accepted.)"
                )));
            }
            Ok(())
        }
        TlsStrategy::Tailscale => {
            if let Some(h) = host
                && !is_ts_net_host(h)
            {
                return Err(ConfigError::Internal(format!(
                    "tailscale strategy requires a *.ts.net host — \
                     '{h}' is not a Tailscale certificate domain; \
                     use 'internal' or 'acme' instead"
                )));
            }
            // CT log privacy warning (Tailscale KB 1153): enabling HTTPS
            // publishes *.ts.net cert names to the public Certificate
            // Transparency ledger.
            tracing::warn!(
                "Tailscale HTTPS certificates publish *.ts.net cert names to the \
                 public Certificate Transparency ledger — do not enable if machine \
                 names contain sensitive information (see Tailscale KB 1153)"
            );
            Ok(())
        }
    }
}

/// Resolve the ACME email from `[caddy] acme_email` → `[caddy.tls].email` fallback.
///
/// Returns the first non-None value. Used by both validation and the policy
/// builder to populate the `email` field on ACME issuers.
pub fn resolve_acme_email(config: &SlipConfig) -> Option<String> {
    config
        .caddy
        .acme_email
        .clone()
        .or_else(|| config.caddy.tls.as_ref().map(|t| t.email.clone()))
}

/// Check if a DNS provider config key is likely to contain a secret.
fn is_secret_like_key(key: &str) -> bool {
    let lower = key.to_ascii_lowercase();
    lower.contains("token")
        || lower.contains("key")
        || lower.contains("secret")
        || lower.contains("password")
        || lower.contains("api_token")
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

    // Validate reconcile interval — must be at least 1s to avoid hot-looping.
    if slip_cfg.caddy.reconcile.interval < Duration::from_secs(1) {
        return Err(ConfigError::Internal(format!(
            "[caddy.reconcile] interval must be at least 1s — got {:?}",
            slip_cfg.caddy.reconcile.interval
        )));
    }

    // Validate deploy TLS strategy (if [deploy] is configured).
    let acme_email = resolve_acme_email(&slip_cfg);
    let validation_ctx = ValidationCtx {
        acme_email: acme_email.as_deref(),
    };
    if let Some(deploy_cfg) = &slip_cfg.deploy
        && let Some(domain) = deploy_cfg.domain.as_deref()
    {
        validate_tls_strategy(&deploy_cfg.tls, Some(domain), &validation_ctx)?;
    }

    // Validate DNS provider config: reject literal secrets (server-level).
    if let Some(ref tls) = slip_cfg.caddy.tls
        && let Some(ref table) = tls.dns_provider_config
    {
        for (key, value) in table {
            if is_secret_like_key(key)
                && let Some(s) = value.as_str()
                && (!s.starts_with("{env.") || !s.ends_with('}'))
            {
                return Err(ConfigError::Internal(format!(
                    "DNS provider config key '{key}' contains a literal value — \
                     use the {{env.*}} placeholder syntax instead, \
                     e.g. {key} = \"{{env.CF_API_TOKEN}}\". \
                     Slip must never POST literal secrets to Caddy."
                )));
            }
        }
    }

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

            // Validate deploy strategy
            validate_deploy_strategy(&app_cfg.deploy)?;

            // Validate TLS strategies on routing and route entries.
            if let Some(routing_tls) = &app_cfg.routing.tls {
                validate_tls_strategy(routing_tls, None, &validation_ctx)?;
                // For inherited routing.tls = Tailscale, validate EVERY effective
                // route hostname is .ts.net (not just routes with explicit tls).
                if *routing_tls == TlsStrategy::Tailscale {
                    for route in app_cfg.routing.effective_routes() {
                        if !is_ts_net_host(&route.hostname) {
                            return Err(ConfigError::Internal(format!(
                                "tailscale strategy requires a *.ts.net host — \
                                 route '{host}' is not a Tailscale certificate domain; \
                                 use 'internal' or 'acme' instead",
                                host = route.hostname
                            )));
                        }
                    }
                }
            }
            for route in &app_cfg.routing.routes {
                if let Some(route_tls) = &route.tls {
                    validate_tls_strategy(route_tls, Some(&route.hostname), &validation_ctx)?;
                }
            }

            apps.insert(app_cfg.app.name.clone(), app_cfg);
        }
    }

    Ok((slip_cfg, apps))
}

// ─── [app] secret migration ────────────────────────────────────────────────────

/// Migrate deprecated `[app] secret` values from TOML into the secrets store.
///
/// For each app that has `app.secret` set, the value is written to the secrets
/// store under the reserved `__deploy_key` name.  A deprecation warning is
/// emitted.  The TOML field is then cleared so subsequent writes don't re-migrate.
///
/// This is called once at daemon startup.  The TOML field remains readable as
/// a fallback during the migration window.
pub fn migrate_app_secrets(
    apps: &mut HashMap<String, AppConfig>,
    secrets_store: &crate::secrets::SecretsStore,
) {
    for (name, app_cfg) in apps.iter_mut() {
        if let Some(ref secret) = app_cfg.app.secret {
            // Only migrate if no deploy key already exists in the store.
            if secrets_store.get_deploy_key(name).ok().flatten().is_none() {
                if let Err(e) = secrets_store.set(name, crate::secrets::DEPLOY_KEY_NAME, secret) {
                    tracing::warn!(
                        app = %name,
                        error = %e,
                        "failed to migrate [app] secret to secrets store"
                    );
                } else {
                    tracing::warn!(
                        app = %name,
                        "migrated deprecated [app] secret to secrets store — remove the `secret` field from apps/{}.toml",
                        name
                    );
                }
            }
        }
    }
}

// ─── Config write-back functions ──────────────────────────────────────────────

/// The header comment prepended to generated app TOML files to indicate they
/// are managed by the API and should not be hand-edited.
const MANAGED_BY_SLIP_HEADER: &str =
    "# managed by slip — edit the repo slip.toml and run `slip apply`\n";

/// Write an app configuration to disk atomically.
///
/// The config is written to `{config_dir}/apps/{name}.toml` using an atomic
/// write (temp file → rename) to ensure consistency.
///
/// The file is prefixed with a `# managed by slip` header to indicate it is
/// generated by the API. Hand-editing the generated TOML while slipd runs is
/// **not supported** — the API state always wins. On the next API write (create,
/// update, or delete) the file is fully overwritten, discarding any manual
/// changes. To make permanent changes, edit the repo `slip.toml` and run
/// `slip apply`.
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

    let toml_body =
        toml::to_string_pretty(app).map_err(|e| ConfigError::Serialize(e.to_string()))?;
    let content = format!("{MANAGED_BY_SLIP_HEADER}{toml_body}");

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

    // ── ReconcileConfig parsing ─────────────────────────────────────────────

    #[test]
    fn parse_slip_toml_with_reconcile_section() {
        let toml = r#"
[server]

[caddy]
admin_api = "http://localhost:2019"

[caddy.reconcile]
interval = "30s"

[auth]
secret = "s"

[registry]

[storage]
"#;
        let cfg: SlipConfig = toml::from_str(toml).unwrap();
        assert_eq!(
            cfg.caddy.reconcile.interval,
            Duration::from_secs(30),
            "explicit [caddy.reconcile] interval should parse"
        );
    }

    #[test]
    fn parse_slip_toml_reconcile_defaults() {
        // No [caddy.reconcile] section — should fall back to 45s default.
        let toml = r#"
[server]

[caddy]

[auth]
secret = "s"

[registry]

[storage]
"#;
        let cfg: SlipConfig = toml::from_str(toml).unwrap();
        assert_eq!(
            cfg.caddy.reconcile.interval,
            Duration::from_secs(45),
            "reconcile interval should default to 45s"
        );
    }

    #[test]
    fn parse_slip_toml_reconcile_rejects_subsecond() {
        // Interval below 1s must be rejected at load time. We test the
        // deserialization produces the small duration so the validator in
        // load_config can catch it.
        let toml = r#"
[server]

[caddy]

[caddy.reconcile]
interval = "500ms"

[auth]
secret = "s"

[registry]

[storage]
"#;
        let cfg: SlipConfig = toml::from_str(toml).unwrap();
        assert!(
            cfg.caddy.reconcile.interval < Duration::from_secs(1),
            "500ms should parse to a sub-second duration (rejected by load_config)"
        );
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
        assert_eq!(cfg.routing.domain.as_deref(), Some("myapp.example.com"));
        assert_eq!(cfg.routing.port, Some(3000));
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

    // ── Volume config parsing ────────────────────────────────────────────────

    #[test]
    fn parse_app_config_with_volumes() {
        let toml = r#"
[app]
name = "myapp"
image = "ghcr.io/org/myapp:latest"

[routing]
domain = "myapp.example.com"
port = 3000

[health]

[deploy]

[[volumes]]
host_path = "/data/myapp"
mount_path = "/app/data"
read_only = false

[[volumes]]
host_path = "/data/config"
mount_path = "/app/config"
read_only = true
"#;
        let cfg: AppConfig = toml::from_str(toml).unwrap();
        assert_eq!(cfg.volumes.len(), 2);
        assert_eq!(cfg.volumes[0].host_path, "/data/myapp");
        assert_eq!(cfg.volumes[0].mount_path, "/app/data");
        assert!(!cfg.volumes[0].read_only);
        assert_eq!(cfg.volumes[1].host_path, "/data/config");
        assert_eq!(cfg.volumes[1].mount_path, "/app/config");
        assert!(cfg.volumes[1].read_only);
    }

    #[test]
    fn parse_app_config_volume_read_only_defaults_to_false() {
        let toml = r#"
[app]
name = "myapp"
image = "ghcr.io/org/myapp:latest"

[routing]
domain = "myapp.example.com"
port = 3000

[health]

[deploy]

[[volumes]]
host_path = "/data/myapp"
mount_path = "/app/data"
"#;
        let cfg: AppConfig = toml::from_str(toml).unwrap();
        assert_eq!(cfg.volumes.len(), 1);
        assert!(!cfg.volumes[0].read_only);
    }

    #[test]
    fn parse_app_config_empty_volumes() {
        let toml = r#"
[app]
name = "myapp"
image = "ghcr.io/org/myapp:latest"

[routing]
domain = "myapp.example.com"
port = 3000

[health]

[deploy]

volumes = []
"#;
        let cfg: AppConfig = toml::from_str(toml).unwrap();
        assert!(cfg.volumes.is_empty());
    }

    #[test]
    fn parse_app_config_no_volumes_key() {
        let toml = r#"
[app]
name = "myapp"
image = "ghcr.io/org/myapp:latest"

[routing]
domain = "myapp.example.com"
port = 3000

[health]

[deploy]
"#;
        let cfg: AppConfig = toml::from_str(toml).unwrap();
        assert!(cfg.volumes.is_empty());
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

    #[test]
    fn resolve_env_vars_warn_unresolved_collects_names() {
        // SAFETY: single-threaded test, no concurrent env access.
        unsafe { std::env::remove_var("SLIP_DEFINITELY_NOT_SET_WARN") };
        let (resolved, unresolved) = resolve_env_vars_warn("token=${SLIP_DEFINITELY_NOT_SET_WARN}");
        // Placeholder left in place.
        assert_eq!(resolved, "token=${SLIP_DEFINITELY_NOT_SET_WARN}");
        assert_eq!(unresolved, vec!["SLIP_DEFINITELY_NOT_SET_WARN".to_string()]);
    }

    #[test]
    fn resolve_env_vars_warn_resolved_does_not_warn() {
        // SAFETY: single-threaded test, no concurrent env access.
        unsafe { std::env::set_var("SLIP_TEST_VAR_WARN_OK", "ok") };
        let (resolved, unresolved) = resolve_env_vars_warn("v=${SLIP_TEST_VAR_WARN_OK}");
        assert_eq!(resolved, "v=ok");
        assert!(unresolved.is_empty());
    }

    #[test]
    fn resolve_env_vars_warn_multiple_mixed() {
        // SAFETY: single-threaded test, no concurrent env access.
        unsafe {
            std::env::set_var("SLIP_TEST_VAR_WARN_MIX_A", "a");
            std::env::remove_var("SLIP_TEST_VAR_WARN_MIX_B");
        }
        let (resolved, unresolved) =
            resolve_env_vars_warn("${SLIP_TEST_VAR_WARN_MIX_A}_${SLIP_TEST_VAR_WARN_MIX_B}");
        assert_eq!(resolved, "a_${SLIP_TEST_VAR_WARN_MIX_B}");
        assert_eq!(unresolved, vec!["SLIP_TEST_VAR_WARN_MIX_B".to_string()]);
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
        assert_eq!(app.routing.port, Some(3000));
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

    // ── RoutingConfig optional field deserialization ──────────────────────────

    #[test]
    fn routing_config_optional_fields_deserialize() {
        // RoutingConfig with no domain or port should deserialize to None
        let toml = r#"
[app]
name = "workerapp"
image = "worker:latest"

[routing]

[health]

[deploy]
"#;
        let cfg: AppConfig = toml::from_str(toml).unwrap();
        assert!(
            cfg.routing.domain.is_none(),
            "domain should be None when omitted"
        );
        assert!(
            cfg.routing.port.is_none(),
            "port should be None when omitted"
        );
    }

    #[test]
    fn routing_config_with_fields_deserialize() {
        // RoutingConfig with domain and port should still work
        let toml = r#"
[app]
name = "webapp"
image = "web:latest"

[routing]
domain = "webapp.example.com"
port = 3000

[health]

[deploy]
"#;
        let cfg: AppConfig = toml::from_str(toml).unwrap();
        assert_eq!(cfg.routing.domain.as_deref(), Some("webapp.example.com"));
        assert_eq!(cfg.routing.port, Some(3000));
    }

    // ── Multi-route deserialization ──────────────────────────────────────────

    #[test]
    fn routing_config_with_multi_route() {
        let toml = r#"
[app]
name = "multiapp"
image = "web:latest"

[[routing.routes]]
hostname = "api.example.com"
port = 3000

[[routing.routes]]
hostname = "admin.example.com"
port = 3001

[health]

[deploy]
"#;
        let cfg: AppConfig = toml::from_str(toml).unwrap();
        assert_eq!(cfg.routing.routes.len(), 2);
        assert_eq!(cfg.routing.routes[0].hostname, "api.example.com");
        assert_eq!(cfg.routing.routes[0].port, Some(3000));
        assert_eq!(cfg.routing.routes[1].hostname, "admin.example.com");
        assert_eq!(cfg.routing.routes[1].port, Some(3001));
    }

    #[test]
    fn routing_config_multi_route_takes_precedence() {
        // When routes is non-empty, effective_routes returns routes, not domain/port
        let toml = r#"
[app]
name = "multiapp"
image = "web:latest"

[routing]
domain = "old.example.com"
port = 8080

[[routing.routes]]
hostname = "new.example.com"
port = 3000

[health]

[deploy]
"#;
        let cfg: AppConfig = toml::from_str(toml).unwrap();
        let effective = cfg.routing.effective_routes();
        assert_eq!(effective.len(), 1);
        assert_eq!(effective[0].hostname, "new.example.com");
        assert_eq!(effective[0].port, Some(3000));
    }

    #[test]
    fn routing_config_effective_routes_single() {
        let toml = r#"
[app]
name = "webapp"
image = "web:latest"

[routing]
domain = "myapp.example.com"
port = 3000

[health]

[deploy]
"#;
        let cfg: AppConfig = toml::from_str(toml).unwrap();
        let effective = cfg.routing.effective_routes();
        assert_eq!(effective.len(), 1);
        assert_eq!(effective[0].hostname, "myapp.example.com");
        assert_eq!(effective[0].port, Some(3000));
    }

    #[test]
    fn routing_config_effective_routes_worker() {
        let toml = r#"
[app]
name = "workerapp"
image = "worker:latest"

[routing]

[health]

[deploy]
"#;
        let cfg: AppConfig = toml::from_str(toml).unwrap();
        let effective = cfg.routing.effective_routes();
        assert!(effective.is_empty());
    }

    #[test]
    fn routing_config_route_entry_port_defaults_to_none() {
        let toml = r#"
[app]
name = "multiapp"
image = "web:latest"

[[routing.routes]]
hostname = "api.example.com"

[health]

[deploy]
"#;
        let cfg: AppConfig = toml::from_str(toml).unwrap();
        assert_eq!(cfg.routing.routes.len(), 1);
        assert_eq!(cfg.routing.routes[0].hostname, "api.example.com");
        assert!(cfg.routing.routes[0].port.is_none());
    }

    // ── Deploy timeout config tests ──────────────────────────────────────────

    #[test]
    fn parse_slip_config_with_deploy_section() {
        let toml = r#"
[server]

[caddy]

[auth]
secret = "s"

[registry]

[storage]

[deploy]
timeout = "5m"
preview_timeout = "15m"
"#;
        let cfg: SlipConfig = toml::from_str(toml).unwrap();
        let deploy = cfg.deploy.expect("deploy config should be present");
        assert_eq!(deploy.timeout, Duration::from_secs(300));
        assert_eq!(deploy.preview_timeout, Duration::from_secs(900));
    }

    #[test]
    fn parse_slip_config_deploy_defaults() {
        let toml = r#"
[server]

[caddy]

[auth]
secret = "s"

[registry]

[storage]
"#;
        let cfg: SlipConfig = toml::from_str(toml).unwrap();
        assert!(cfg.deploy.is_none(), "deploy should be None when absent");
    }

    #[test]
    fn parse_app_config_with_timeout_override() {
        let toml = r#"
[app]
name = "myapp"
image = "ghcr.io/org/myapp:latest"

[routing]
domain = "myapp.example.com"
port = 3000

[health]

[deploy]
timeout = "30s"
"#;
        let cfg: AppConfig = toml::from_str(toml).unwrap();
        assert_eq!(cfg.deploy.timeout, Some(Duration::from_secs(30)));
    }

    #[test]
    fn parse_app_config_timeout_defaults_to_none() {
        let toml = r#"
[app]
name = "myapp"
image = "ghcr.io/org/myapp:latest"

[routing]
domain = "myapp.example.com"
port = 3000

[health]

[deploy]
"#;
        let cfg: AppConfig = toml::from_str(toml).unwrap();
        assert_eq!(cfg.deploy.timeout, None);
    }

    // ── TlsStrategy enum tests (SLIP-104 Phase 1) ───────────────────────────

    #[test]
    fn tls_strategy_serde_roundtrips_all_four_variants() {
        for (s, v) in [
            (TlsStrategy::Internal, "internal"),
            (TlsStrategy::Acme, "acme"),
            (TlsStrategy::CloudflareDns01, "cloudflare-dns01"),
            (TlsStrategy::Tailscale, "tailscale"),
        ] {
            let json = serde_json::to_string(&s).unwrap();
            assert_eq!(json, format!("\"{v}\""));
            let parsed: TlsStrategy = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, s);
        }
    }

    #[test]
    fn tls_strategy_toml_roundtrips() {
        let toml = r#"
[app]
name = "app"
image = "img:latest"

[routing]
domain = "app.test"
port = 80
tls = "internal"

[health]

[deploy]
"#;
        let cfg: AppConfig = toml::from_str(toml).unwrap();
        assert_eq!(cfg.routing.tls, Some(TlsStrategy::Internal));
    }

    #[test]
    fn tls_strategy_unknown_string_fails_at_deserialize() {
        let toml = r#"
[app]
name = "app"
image = "img:latest"

[routing]
domain = "app.test"
port = 80
tls = "bogus-strategy"

[health]

[deploy]
"#;
        let result: Result<AppConfig, _> = toml::from_str(toml);
        assert!(result.is_err(), "unknown TLS strategy must fail to parse");
    }

    #[test]
    fn tls_strategy_display_matches_wire_string() {
        assert_eq!(TlsStrategy::Internal.to_string(), "internal");
        assert_eq!(TlsStrategy::Acme.to_string(), "acme");
        assert_eq!(TlsStrategy::CloudflareDns01.to_string(), "cloudflare-dns01");
        assert_eq!(TlsStrategy::Tailscale.to_string(), "tailscale");
    }

    #[test]
    fn is_ts_net_host_true_for_ts_net() {
        assert!(is_ts_net_host("host.tailnet.ts.net"));
        assert!(is_ts_net_host("machine.example.ts.net"));
        // Wildcard subjects also match.
        assert!(is_ts_net_host("*.tailnet.ts.net"));
    }

    #[test]
    fn is_ts_net_host_false_for_non_ts_net() {
        assert!(!is_ts_net_host("deploy.example.com"));
        assert!(!is_ts_net_host("arrakeen.test"));
        assert!(!is_ts_net_host("10.0.0.1"));
    }

    #[test]
    fn validate_tls_strategy_internal_always_ok() {
        let ctx = ValidationCtx { acme_email: None };
        assert!(validate_tls_strategy(&TlsStrategy::Internal, Some("any.host"), &ctx).is_ok());
        assert!(validate_tls_strategy(&TlsStrategy::Internal, None, &ctx).is_ok());
    }

    #[test]
    fn validate_tls_strategy_acme_requires_email() {
        let ctx = ValidationCtx { acme_email: None };
        let err = validate_tls_strategy(&TlsStrategy::Acme, Some("deploy.example.com"), &ctx)
            .unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("acme_email"),
            "error must name the remedy: {msg}"
        );
    }

    #[test]
    fn validate_tls_strategy_acme_ok_with_email_via_fallback() {
        let ctx = ValidationCtx {
            acme_email: Some("ops@example.com"),
        };
        assert!(
            validate_tls_strategy(&TlsStrategy::Acme, Some("deploy.example.com"), &ctx).is_ok()
        );
    }

    #[test]
    fn validate_tls_strategy_cloudflare_dns01_requires_email() {
        let ctx = ValidationCtx { acme_email: None };
        assert!(
            validate_tls_strategy(&TlsStrategy::CloudflareDns01, Some("tailnet.ts.net"), &ctx)
                .is_err()
        );
    }

    #[test]
    fn validate_tls_strategy_tailscale_ok_for_ts_net_host() {
        let ctx = ValidationCtx { acme_email: None };
        assert!(
            validate_tls_strategy(&TlsStrategy::Tailscale, Some("host.tailnet.ts.net"), &ctx)
                .is_ok()
        );
    }

    #[test]
    fn validate_tls_strategy_tailscale_rejects_non_ts_net_host() {
        let ctx = ValidationCtx { acme_email: None };
        let err = validate_tls_strategy(&TlsStrategy::Tailscale, Some("deploy.example.com"), &ctx)
            .unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("*.ts.net"),
            "error must mention the remedy: {msg}"
        );
    }

    #[test]
    fn resolve_acme_email_prefers_top_level() {
        let toml = r#"
[server]

[caddy]
admin_api = "http://localhost:2019"
acme_email = "top@example.com"

[caddy.tls]
email = "fallback@example.com"
dns_provider = "cloudflare"

[auth]
secret = "s"

[registry]

[storage]
"#;
        let cfg: SlipConfig = toml::from_str(toml).unwrap();
        assert_eq!(resolve_acme_email(&cfg).as_deref(), Some("top@example.com"));
    }

    #[test]
    fn resolve_acme_email_falls_back_to_caddy_tls_email() {
        let toml = r#"
[server]

[caddy]
admin_api = "http://localhost:2019"

[caddy.tls]
email = "fallback@example.com"
dns_provider = "cloudflare"

[auth]
secret = "s"

[registry]

[storage]
"#;
        let cfg: SlipConfig = toml::from_str(toml).unwrap();
        assert_eq!(
            resolve_acme_email(&cfg).as_deref(),
            Some("fallback@example.com")
        );
    }

    #[test]
    fn resolve_acme_email_none_when_both_absent() {
        let toml = r#"
[server]

[caddy]
admin_api = "http://localhost:2019"

[auth]
secret = "s"

[registry]

[storage]
"#;
        let cfg: SlipConfig = toml::from_str(toml).unwrap();
        assert!(resolve_acme_email(&cfg).is_none());
    }

    #[test]
    fn routing_config_without_tls_deserializes_to_none() {
        let toml = r#"
[app]
name = "app"
image = "img:latest"

[routing]
domain = "app.example.com"
port = 80

[health]

[deploy]
"#;
        let cfg: AppConfig = toml::from_str(toml).unwrap();
        assert!(
            cfg.routing.tls.is_none(),
            "absent tls must deserialize to None"
        );
    }

    #[test]
    fn route_entry_without_tls_deserializes_to_none() {
        let toml = r#"
[app]
name = "multiapp"
image = "web:latest"

[[routing.routes]]
hostname = "api.example.com"
port = 3000

[health]

[deploy]
"#;
        let cfg: AppConfig = toml::from_str(toml).unwrap();
        assert_eq!(cfg.routing.routes.len(), 1);
        assert!(cfg.routing.routes[0].tls.is_none());
    }

    #[test]
    fn load_config_rejects_tailscale_on_non_ts_net_deploy_domain() {
        let dir = tempfile::tempdir().unwrap();
        write_file(
            dir.path(),
            "slip.toml",
            r#"
[server]

[caddy]
acme_email = "ops@example.com"

[auth]
secret = "s"

[registry]

[storage]

[deploy]
domain = "deploy.example.com"
tls = "tailscale"
"#,
        );
        std::fs::create_dir(dir.path().join("apps")).unwrap();
        let err = load_config(dir.path()).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("*.ts.net"),
            "must mention ts.net remedy: {msg}"
        );
    }

    #[test]
    fn load_config_rejects_acme_without_email() {
        let dir = tempfile::tempdir().unwrap();
        write_file(
            dir.path(),
            "slip.toml",
            r#"
[server]

[caddy]

[auth]
secret = "s"

[registry]

[storage]

[deploy]
domain = "deploy.example.com"
tls = "acme"
"#,
        );
        std::fs::create_dir(dir.path().join("apps")).unwrap();
        let err = load_config(dir.path()).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("acme_email"),
            "must mention acme_email remedy: {msg}"
        );
    }

    #[test]
    fn load_config_accepts_tailscale_on_ts_net_deploy_domain() {
        let dir = tempfile::tempdir().unwrap();
        write_file(
            dir.path(),
            "slip.toml",
            r#"
[server]

[caddy]

[auth]
secret = "s"

[registry]

[storage]

[deploy]
domain = "host.tailnet.ts.net"
tls = "tailscale"
"#,
        );
        std::fs::create_dir(dir.path().join("apps")).unwrap();
        let (cfg, _) = load_config(dir.path()).unwrap();
        assert_eq!(cfg.deploy.unwrap().tls, TlsStrategy::Tailscale);
    }

    #[test]
    fn load_config_rejects_routing_tailscale_on_non_ts_net_route() {
        // routing.tls = "tailscale" with a non-.ts.net route hostname must fail
        // at load time (inherited strategy validation).
        let dir = tempfile::tempdir().unwrap();
        write_file(
            dir.path(),
            "slip.toml",
            r#"
[server]

[caddy]

[auth]
secret = "s"

[registry]

[storage]
"#,
        );
        std::fs::create_dir(dir.path().join("apps")).unwrap();
        write_file(
            &dir.path().join("apps"),
            "myapp.toml",
            r#"
[app]
name = "myapp"
image = "img:latest"

[routing]
tls = "tailscale"

[[routing.routes]]
hostname = "deploy.example.com"

[health]

[deploy]
"#,
        );
        let err = load_config(dir.path()).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("*.ts.net"),
            "must mention ts.net remedy for inherited routing.tls: {msg}"
        );
    }

    #[test]
    fn load_config_rejects_literal_dns_provider_token() {
        let dir = tempfile::tempdir().unwrap();
        write_file(
            dir.path(),
            "slip.toml",
            r#"
[server]

[caddy]

[caddy.tls]
email = "ops@example.com"
dns_provider = "cloudflare"

[caddy.tls.dns_provider_config]
api_token = "literal-secret-token-value-here-1234567890"

[auth]
secret = "s"

[registry]

[storage]
"#,
        );
        std::fs::create_dir(dir.path().join("apps")).unwrap();
        let err = load_config(dir.path()).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("{env.*}") || msg.contains("placeholder"),
            "must mention {{env.*}} placeholder requirement: {msg}"
        );
    }

    #[test]
    fn load_config_accepts_env_placeholder_dns_provider_token() {
        let dir = tempfile::tempdir().unwrap();
        write_file(
            dir.path(),
            "slip.toml",
            r#"
[server]

[caddy]

[caddy.tls]
email = "ops@example.com"
dns_provider = "cloudflare"

[caddy.tls.dns_provider_config]
api_token = "{env.CF_API_TOKEN}"

[auth]
secret = "s"

[registry]

[storage]
"#,
        );
        std::fs::create_dir(dir.path().join("apps")).unwrap();
        let (cfg, _) = load_config(dir.path()).unwrap();
        assert!(cfg.caddy.tls.is_some());
    }
}
