# Technical Specification: slip

**Status:** Draft  
**Author:** MJP  
**Date:** March 2026  
**PRD:** [prd.md](./prd.md)  
**Design Doc:** [slip-design.md](./slip-design.md)

---

## Overview

This document specifies the technical design for **slip**, a Rust deployment daemon. It covers the architecture, data models, API contracts, integration details, concurrency model, and implementation plan with enough precision for a builder to implement without ambiguity.

The design doc defines *what* slip does. The PRD defines *why* and *what's in scope*. This spec defines *how* to build it.

## Background

See [PRD](./prd.md) for the problem statement and [design doc](./slip-design.md) for the high-level architecture. Key constraints carried forward:

- Single server, multiple apps, blue-green deploys only
- Webhook-driven (no SSH), HMAC-SHA256 auth
- Caddy admin API for routing (no Caddyfile), Docker API via bollard (no CLI shelling)
- Rust, axum, SQLite, systemd
- Phase 1 scope: core deploy loop — single app deployable via `curl`

## Goals & Non-Goals

### Goals (Phase 1)

- Define every type, API contract, and state transition precisely enough to build from
- Specify the Caddy admin API integration at the HTTP request level
- Specify the Docker/bollard integration at the function call level
- Define the concurrency model — how deploy tasks are spawned and how state is shared
- Define error handling taxonomy and propagation
- Define testing strategy

### Non-Goals

- CLI (`slip` binary) — Phase 2, separate spec
- SQLite deploy history — Phase 2
- Hot-reload, secrets management — Phase 2
- Production hardening (locking, drain, timeouts) — Phase 3

---

## Architecture

### Workspace Layout

```
slip/
├── Cargo.toml                  # [workspace] members
├── crates/
│   ├── slipd/                  # daemon binary
│   │   ├── Cargo.toml
│   │   └── src/
│   │       └── main.rs         # entry point: config loading, server startup
│   ├── slip-cli/               # CLI binary (Phase 2)
│   │   ├── Cargo.toml
│   │   └── src/
│   │       └── main.rs
│   └── slip-core/              # shared library
│       ├── Cargo.toml
│       └── src/
│           ├── lib.rs
│           ├── config.rs       # config types + parsing
│           ├── deploy.rs       # deploy orchestrator (state machine)
│           ├── docker.rs       # Docker client wrapper
│           ├── caddy.rs        # Caddy admin API client
│           ├── health.rs       # health check runner
│           ├── auth.rs         # HMAC verification
│           ├── api.rs          # API request/response types
│           └── error.rs        # error types
└── docs/
```

> **Note:** The CLI crate is named `slip-cli` (not `slip`) to avoid Cargo workspace ambiguity with the project name. The binary it produces will still be called `slip` via `[[bin]] name = "slip"` in its Cargo.toml.

### Component Diagram

```
                    ┌────────────────────────────────────────────────┐
                    │                    slipd                        │
                    │                                                │
  POST /v1/deploy   │  ┌──────────┐     ┌──────────────────┐        │
 ──────────────────►│  │  axum    │────►│ DeployOrchestrator│        │
                    │  │  router  │     │  (state machine)  │        │
  GET /v1/deploys/  │  │          │     └────────┬─────────┘        │
 ──────────────────►│  └──────────┘              │                  │
                    │       │                    │                  │
                    │       │            ┌───────┼───────┐          │
                    │       ▼            ▼       ▼       ▼          │
                    │  ┌─────────┐  ┌────────┐ ┌─────┐ ┌─────┐    │
                    │  │AppState │  │DockerClient│CaddyClient│HealthChecker│
                    │  │(RwLock) │  │(bollard)│ │(reqwest)│ │(reqwest)│    │
                    │  └─────────┘  └────┬───┘ └──┬──┘ └──┬──┘    │
                    └────────────────────┼────────┼───────┼────────┘
                                         │        │       │
                                    Docker socket  Caddy   Container
                                    /var/run/      :2019   :ephemeral
                                    docker.sock
```

### Concurrency Model

- **axum server** runs on the tokio runtime (multi-threaded by default)
- **Shared state** is held in `Arc<AppState>` passed to handlers via axum's `State` extractor
- **Deploys** are spawned as `tokio::spawn` tasks — the webhook handler returns 202 immediately, the deploy runs in the background
- **App state** (current containers, tags) is protected by `tokio::sync::RwLock` — multiple readers for status, exclusive writer during deploy switch
- **One deploy at a time per app** — enforced by a `tokio::sync::Mutex` per app in Phase 1 (upgraded to proper deploy locking in Phase 3). If a deploy is in progress, new requests for the same app return 409 Conflict.

---

## Data Model

### Configuration Types

```rust
// ── slip-core/src/config.rs ──

/// Root daemon configuration. Loaded from /etc/slip/slip.toml
#[derive(Debug, Deserialize)]
pub struct SlipConfig {
    pub server: ServerConfig,
    pub caddy: CaddyConfig,
    pub auth: AuthConfig,
    pub registry: RegistryConfig,
    pub storage: StorageConfig,
}

#[derive(Debug, Deserialize)]
pub struct ServerConfig {
    /// Socket address to listen on. Default: "0.0.0.0:7890"
    pub listen: SocketAddr,
}

#[derive(Debug, Deserialize)]
pub struct CaddyConfig {
    /// Caddy admin API base URL. Default: "http://localhost:2019"
    pub admin_api: String,
}

#[derive(Debug, Deserialize)]
pub struct AuthConfig {
    /// Global HMAC shared secret. Resolved from env var at load time.
    /// Individual apps can override this.
    pub secret: String,
}

#[derive(Debug, Deserialize)]
pub struct RegistryConfig {
    /// GHCR personal access token. Resolved from env var at load time.
    pub ghcr_token: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct StorageConfig {
    /// Path to slip state directory. Default: "/var/lib/slip"
    pub path: PathBuf,
}

/// Per-app configuration. Loaded from /etc/slip/apps/{name}.toml
#[derive(Debug, Clone, Deserialize)]
pub struct AppConfig {
    pub app: AppInfo,
    pub routing: RoutingConfig,
    pub health: HealthConfig,
    pub deploy: DeployConfig,
    #[serde(default)]
    pub env: HashMap<String, String>,
    pub env_file: Option<EnvFileConfig>,
    #[serde(default)]
    pub resources: ResourceConfig,
    #[serde(default)]
    pub network: NetworkConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AppInfo {
    /// Unique app name. Must match filename (walden-api.toml → name = "walden-api")
    pub name: String,
    /// Full image reference without tag (e.g., "ghcr.io/mitchelljphayes/walden-api")
    pub image: String,
    /// Per-app HMAC secret. Overrides global secret if set.
    pub secret: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RoutingConfig {
    /// Domain(s) to route to this app (e.g., "api.walden.sh")
    pub domain: String,
    /// Container's internal listening port
    pub port: u16,
}

#[derive(Debug, Clone, Deserialize)]
pub struct HealthConfig {
    /// Health check path (e.g., "/health"). None = skip health checks.
    pub path: Option<String>,
    /// Time between health check attempts. Default: "2s"
    #[serde(default = "default_health_interval")]
    pub interval: Duration,
    /// Timeout for each health check request. Default: "5s"
    #[serde(default = "default_health_timeout")]
    pub timeout: Duration,
    /// Max retry attempts before declaring unhealthy. Default: 5
    #[serde(default = "default_health_retries")]
    pub retries: u32,
    /// Grace period before first health check. Default: "10s"
    #[serde(default = "default_health_start_period")]
    pub start_period: Duration,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DeployConfig {
    /// Deploy strategy. Only "blue-green" supported in Phase 1.
    #[serde(default = "default_strategy")]
    pub strategy: String,
    /// Seconds to wait for old connections to drain. Default: "30s"
    #[serde(default = "default_drain_timeout")]
    pub drain_timeout: Duration,
}

#[derive(Debug, Clone, Deserialize)]
pub struct EnvFileConfig {
    /// Path to .env file on the server (e.g., "/etc/slip/secrets/walden-api.env")
    pub path: PathBuf,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct ResourceConfig {
    /// Memory limit (e.g., "512m"). Parsed to bytes for Docker API.
    pub memory: Option<String>,
    /// CPU limit (e.g., "1.0"). Converted to NanoCPUs for Docker API.
    pub cpus: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct NetworkConfig {
    /// Docker network name. Default: "slip"
    #[serde(default = "default_network")]
    pub name: String,
}
```

### Environment Variable Resolution

Config values containing `${VAR_NAME}` are resolved at config load time from the process environment:

```rust
/// Resolve ${VAR} references in a string from the process environment.
/// Returns Err if a referenced variable is not set.
fn resolve_env_vars(input: &str) -> Result<String, ConfigError> {
    // regex: \$\{([A-Z_][A-Z0-9_]*)\}
    // For each match, std::env::var(capture_group_1)
    // If not found: ConfigError::MissingEnvVar { var, context }
}
```

This runs on `AuthConfig.secret`, `RegistryConfig.ghcr_token`, and all values in `AppConfig.env`. Values in `env_file` are read raw at deploy time (they're already resolved on the server).

### Runtime State

```rust
// ── slip-core/src/lib.rs (or state.rs) ──

/// Shared application state, wrapped in Arc and passed to all handlers.
pub struct AppState {
    pub config: SlipConfig,
    pub apps: HashMap<String, AppConfig>,
    /// Runtime state for each app (current container, tag, etc.)
    pub app_states: RwLock<HashMap<String, AppRuntimeState>>,
    /// Per-app deploy locks. Prevents concurrent deploys to the same app.
    pub deploy_locks: DashMap<String, Arc<Mutex<()>>>,
    /// Clients (created once, reused)
    pub docker: DockerClient,
    pub caddy: CaddyClient,
}

/// Runtime state for a single app. Updated atomically during the SWITCH step.
#[derive(Debug, Clone)]
pub struct AppRuntimeState {
    pub status: AppStatus,
    pub current_tag: Option<String>,
    pub previous_tag: Option<String>,
    pub current_container_id: Option<String>,
    pub previous_container_id: Option<String>,
    pub current_port: Option<u16>,
    pub deployed_at: Option<DateTime<Utc>>,
    pub deploy_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum AppStatus {
    /// App is registered but has never been deployed
    NotDeployed,
    /// App is running and healthy
    Running,
    /// A deploy is in progress
    Deploying,
    /// Last deploy failed; previous version still running (or nothing running)
    Failed,
}
```

### Deploy State Machine

A deploy transitions through these states:

```
accepted → pulling → starting → health_checking → switching → completed
                                       │                          
                                       └──► failed (at any step)
```

```rust
// ── slip-core/src/deploy.rs ──

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DeployStatus {
    Accepted,
    Pulling,
    Starting,
    HealthChecking,
    Switching,
    Completed,
    Failed,
}

/// Tracks the state of a single deploy.
pub struct DeployContext {
    pub id: String,             // ULID: "dep_01JQXYZ..."
    pub app: String,
    pub image: String,
    pub tag: String,
    pub status: DeployStatus,
    pub started_at: DateTime<Utc>,
    pub finished_at: Option<DateTime<Utc>>,
    pub error: Option<String>,
    pub triggered_by: TriggerSource,
    /// Container ID of the newly created container (set after Starting)
    pub new_container_id: Option<String>,
    /// Ephemeral host port of the new container (set after Starting)
    pub new_port: Option<u16>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TriggerSource {
    Webhook,
    Cli,
    Rollback,
}
```

### Deploy ID Format

IDs use ULID with a `dep_` prefix: `dep_01JQXYZ4ABCDE12345FGHIJK`

```rust
fn new_deploy_id() -> String {
    format!("dep_{}", ulid::Ulid::new().to_string().to_lowercase())
}
```

---

## API Design

### slipd HTTP API

All endpoints are served by slipd on the configured listen address (default `0.0.0.0:7890`).

#### `POST /v1/deploy`

Trigger a new deploy. This is the primary endpoint — called by CI.

**Authentication:** HMAC-SHA256 via `X-Slip-Signature` header.

**Request:**
```json
{
  "app": "walden-api",
  "image": "ghcr.io/mitchelljphayes/walden-api",
  "tag": "sha-abc123f"
}
```

**Validation rules:**
1. `X-Slip-Signature` header must be present and valid (401 if not)
2. `app` must match a registered app config (404 if not)
3. `image` must match the app's configured `image` field exactly (400 if not — prevents deploying arbitrary images)
4. `tag` must be non-empty (400 if not)
5. No deploy already in progress for this app (409 if there is)

**Success response (202 Accepted):**
```json
{
  "deploy_id": "dep_01jqxyz4abcde12345fghijk",
  "app": "walden-api",
  "tag": "sha-abc123f",
  "status": "accepted"
}
```

**Error responses:**

| Status | Body | Condition |
|--------|------|-----------|
| 400 | `{"error": "image mismatch: got X, expected Y"}` | Image doesn't match config |
| 400 | `{"error": "missing field: tag"}` | Invalid payload |
| 401 | `{"error": "invalid signature"}` | HMAC verification failed |
| 404 | `{"error": "unknown app: foo"}` | App not registered |
| 409 | `{"error": "deploy already in progress for walden-api"}` | Concurrent deploy |

#### `GET /v1/deploys/:deploy_id`

Poll deploy status. Used by CI to check if a deploy completed.

**Authentication:** None in Phase 1 (management endpoints will be Tailscale-only in Phase 3).

**Response (200):**
```json
{
  "deploy_id": "dep_01jqxyz4abcde12345fghijk",
  "app": "walden-api",
  "tag": "sha-abc123f",
  "status": "health_checking",
  "started_at": "2026-03-23T10:30:00Z",
  "finished_at": null,
  "error": null
}
```

If deploy_id not found: **404** `{"error": "deploy not found"}`.

#### `GET /v1/status`

Overall daemon and app status.

**Response (200):**
```json
{
  "daemon": "ok",
  "uptime_seconds": 86400,
  "apps": {
    "walden-api": {
      "status": "running",
      "tag": "sha-abc123f",
      "deployed_at": "2026-03-23T10:30:00Z",
      "container_id": "a1b2c3d4e5f6",
      "health": "healthy",
      "port": 49152
    }
  }
}
```

### HMAC-SHA256 Authentication

The same pattern as GitHub webhook signature verification:

```rust
// ── slip-core/src/auth.rs ──

use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

type HmacSha256 = Hmac<Sha256>;

/// Verify an HMAC-SHA256 signature.
///
/// `header` is the raw X-Slip-Signature value: "sha256=abcdef1234..."
/// `body` is the raw request body bytes.
/// `secret` is the HMAC key.
///
/// Returns true if valid.
pub fn verify_signature(header: &str, body: &[u8], secret: &str) -> bool {
    let expected_prefix = "sha256=";
    let hex_signature = match header.strip_prefix(expected_prefix) {
        Some(s) => s,
        None => return false,
    };

    let expected_bytes = match hex::decode(hex_signature) {
        Ok(b) => b,
        Err(_) => return false,
    };

    let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
        .expect("HMAC accepts any key length");
    mac.update(body);
    let computed = mac.finalize().into_bytes();

    // Constant-time comparison to prevent timing attacks
    computed.as_slice().ct_eq(&expected_bytes).into()
}
```

**Secret resolution order** for a given app:
1. `app.secret` (per-app override) if set in the app's TOML
2. `auth.secret` (global) from `slip.toml`

---

## Integration Details

### Docker Integration (via bollard)

All Docker operations use the `bollard` crate with async/await. slipd connects to the Docker socket at startup:

```rust
// ── slip-core/src/docker.rs ──

use bollard::Docker;
use bollard::query_parameters::CreateContainerOptionsBuilder;
use bollard::models::{ContainerConfig, HostConfig, PortBinding};

pub struct DockerClient {
    docker: Docker,
}

impl DockerClient {
    pub fn new() -> Result<Self, DockerError> {
        let docker = Docker::connect_with_socket_defaults()?;
        Ok(Self { docker })
    }
}
```

#### Image Pull

```rust
impl DockerClient {
    /// Pull an image from a registry.
    /// `image_ref` is the full reference: "ghcr.io/mitchelljphayes/walden-api:sha-abc123f"
    /// `credentials` is optional registry auth.
    pub async fn pull_image(
        &self,
        image: &str,
        tag: &str,
        credentials: Option<DockerCredentials>,
    ) -> Result<(), DockerError> {
        let options = CreateImageOptionsBuilder::default()
            .from_image(image)
            .tag(tag)
            .build();

        let mut stream = self.docker.create_image(Some(options), None, credentials);

        while let Some(result) = stream.next().await {
            match result {
                Ok(info) => {
                    if let Some(error) = info.error {
                        return Err(DockerError::PullFailed(error));
                    }
                    // Log progress via tracing
                }
                Err(e) => return Err(DockerError::Api(e)),
            }
        }
        Ok(())
    }
}
```

#### Container Create & Start

```rust
impl DockerClient {
    /// Create and start a new container.
    /// Returns (container_id, host_port).
    pub async fn create_and_start(
        &self,
        app_name: &str,
        image: &str,
        tag: &str,
        container_port: u16,
        env_vars: Vec<String>,       // ["KEY=value", ...]
        network: &str,
        resources: &ResourceConfig,
    ) -> Result<(String, u16), DockerError> {
        let image_ref = format!("{}:{}", image, tag);
        let container_name = format!("slip-{}-{}", app_name, &tag[..12.min(tag.len())]);

        // Port binding: expose container_port to a random host port
        let mut port_bindings = HashMap::new();
        port_bindings.insert(
            format!("{}/tcp", container_port),
            Some(vec![PortBinding {
                host_ip: Some("127.0.0.1".to_string()),
                host_port: None,  // Docker assigns ephemeral port
            }]),
        );

        let host_config = HostConfig {
            port_bindings: Some(port_bindings),
            network_mode: Some(network.to_string()),
            memory: parse_memory_limit(&resources.memory),
            nano_cpus: parse_cpu_limit(&resources.cpus),
            ..Default::default()
        };

        let mut labels = HashMap::new();
        labels.insert("slip.app".to_string(), app_name.to_string());
        labels.insert("slip.tag".to_string(), tag.to_string());
        labels.insert("slip.managed".to_string(), "true".to_string());

        let config = ContainerConfig {
            image: Some(image_ref),
            env: Some(env_vars),
            labels: Some(labels),
            host_config: Some(host_config),
            ..Default::default()
        };

        let options = CreateContainerOptionsBuilder::default()
            .name(&container_name)
            .build();

        let container = self.docker.create_container(Some(options), config).await?;
        self.docker.start_container::<String>(&container.id, None).await?;

        // Inspect to discover the assigned ephemeral port
        let info = self.docker.inspect_container(&container.id, None).await?;
        let host_port = extract_host_port(&info, container_port)?;

        Ok((container.id, host_port))
    }
}
```

#### Port Discovery

After starting a container, we inspect it to find the Docker-assigned host port:

```rust
fn extract_host_port(
    info: &ContainerInspectResponse,
    container_port: u16,
) -> Result<u16, DockerError> {
    let port_key = format!("{}/tcp", container_port);
    let bindings = info
        .network_settings.as_ref()
        .and_then(|ns| ns.ports.as_ref())
        .and_then(|ports| ports.get(&port_key))
        .and_then(|b| b.as_ref())
        .and_then(|bindings| bindings.first())
        .ok_or(DockerError::NoPortAssigned)?;

    bindings
        .host_port.as_ref()
        .and_then(|p| p.parse::<u16>().ok())
        .ok_or(DockerError::NoPortAssigned)
}
```

#### Container Stop & Remove

```rust
impl DockerClient {
    pub async fn stop_and_remove(&self, container_id: &str) -> Result<(), DockerError> {
        // Stop with a 10-second timeout
        let options = StopContainerOptionsBuilder::default()
            .t(10)
            .build();
        self.docker.stop_container(container_id, Some(options)).await?;
        self.docker.remove_container(container_id, None).await?;
        Ok(())
    }
}
```

#### Docker Network Bootstrap

On startup, slipd ensures the `slip` Docker network exists:

```rust
impl DockerClient {
    pub async fn ensure_network(&self, name: &str) -> Result<(), DockerError> {
        match self.docker.inspect_network::<String>(name, None).await {
            Ok(_) => Ok(()),  // already exists
            Err(_) => {
                let config = NetworkCreateRequest {
                    name: name.to_string(),
                    driver: Some("bridge".to_string()),
                    ..Default::default()
                };
                self.docker.create_network(config).await?;
                Ok(())
            }
        }
    }
}
```

### Caddy Integration (via reqwest)

slip manages routes through Caddy's admin API at `http://localhost:2019`.

```rust
// ── slip-core/src/caddy.rs ──

pub struct CaddyClient {
    client: reqwest::Client,
    base_url: String,  // "http://localhost:2019"
}
```

#### Caddy Bootstrap

On first startup, slipd creates a `slip` server block in Caddy if it doesn't exist. This block is separate from any existing Caddyfile-managed server — Caddy supports multiple server blocks.

```rust
impl CaddyClient {
    /// Ensure the `slip` server block exists in Caddy's config.
    /// Idempotent — safe to call on every startup.
    pub async fn bootstrap(&self) -> Result<(), CaddyError> {
        let url = format!("{}/config/apps/http/servers/slip", self.base_url);

        // Check if it exists
        let resp = self.client.get(&url).send().await?;
        if resp.status().is_success() {
            return Ok(()); // already exists
        }

        // Create the slip server block
        let server = serde_json::json!({
            "listen": [":443"],
            "routes": []
        });

        let resp = self.client
            .post(&url)
            .json(&server)
            .send()
            .await?;

        if !resp.status().is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(CaddyError::BootstrapFailed(body));
        }

        Ok(())
    }
}
```

#### Route Management

**Key design detail:** Each app gets a route in the `slip` server's routes array. Routes are identified by their `@id` field (a Caddy feature for addressable config). This avoids fragile index-based addressing.

```rust
impl CaddyClient {
    /// Add or update a route for an app.
    /// Uses Caddy's @id feature to make routes addressable by app name.
    pub async fn set_route(
        &self,
        app_name: &str,
        domain: &str,
        upstream_port: u16,
    ) -> Result<(), CaddyError> {
        let route_id = format!("slip-{}", app_name);
        let route = serde_json::json!({
            "@id": route_id,
            "match": [{"host": [domain]}],
            "handle": [{
                "handler": "subroute",
                "routes": [{
                    "handle": [{
                        "handler": "reverse_proxy",
                        "upstreams": [{"dial": format!("localhost:{}", upstream_port)}]
                    }]
                }]
            }],
            "terminal": true
        });

        // Try PATCH first (update existing)
        let patch_url = format!(
            "{}/id/{}",
            self.base_url, route_id
        );
        let resp = self.client
            .patch(&patch_url)
            .json(&route)
            .send()
            .await?;

        if resp.status().is_success() {
            return Ok(());
        }

        // If PATCH fails (route doesn't exist yet), POST to append
        let post_url = format!(
            "{}/config/apps/http/servers/slip/routes",
            self.base_url
        );
        let resp = self.client
            .post(&post_url)
            .json(&route)
            .send()
            .await?;

        if !resp.status().is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(CaddyError::RouteUpdateFailed(body));
        }

        Ok(())
    }

    /// Remove a route for an app.
    pub async fn remove_route(&self, app_name: &str) -> Result<(), CaddyError> {
        let route_id = format!("slip-{}", app_name);
        let url = format!("{}/id/{}", self.base_url, route_id);
        self.client.delete(&url).send().await?;
        Ok(())
    }
}
```

> **Important:** The design doc originally used index-based route addressing (`routes/0/handle/0/...`). This spec uses Caddy's `@id` feature instead, which lets us address routes by name (`/id/slip-walden-api`). This is critical — with multiple apps, index-based addressing is fragile and race-prone.

#### Caddy Reconciliation on Startup

When slipd starts, it reconciles Caddy routes with known app state:

```rust
impl CaddyClient {
    /// Re-register routes for all currently-running apps.
    /// Called on slipd startup to recover from Caddy restarts.
    pub async fn reconcile(
        &self,
        app_states: &HashMap<String, AppRuntimeState>,
        app_configs: &HashMap<String, AppConfig>,
    ) -> Result<(), CaddyError> {
        for (name, state) in app_states {
            if let (Some(port), AppStatus::Running) = (state.current_port, &state.status) {
                if let Some(config) = app_configs.get(name) {
                    self.set_route(name, &config.routing.domain, port).await?;
                }
            }
        }
        Ok(())
    }
}
```

### Health Check Implementation

```rust
// ── slip-core/src/health.rs ──

pub struct HealthChecker {
    client: reqwest::Client,
}

impl HealthChecker {
    /// Run health checks against a container.
    /// Returns Ok(()) if healthy, Err if all retries exhausted.
    pub async fn check(
        &self,
        host_port: u16,
        config: &HealthConfig,
    ) -> Result<(), HealthError> {
        let path = match &config.path {
            Some(p) => p.as_str(),
            None => return Ok(()),  // no health check configured — pass
        };

        let url = format!("http://127.0.0.1:{}{}", host_port, path);

        // Wait for start_period before first check
        tokio::time::sleep(config.start_period).await;

        for attempt in 1..=config.retries {
            match tokio::time::timeout(
                config.timeout,
                self.client.get(&url).send(),
            ).await {
                Ok(Ok(resp)) if resp.status().is_success() => {
                    tracing::info!(
                        attempt,
                        total = config.retries,
                        "health check passed"
                    );
                    return Ok(());
                }
                Ok(Ok(resp)) => {
                    tracing::warn!(
                        attempt,
                        status = %resp.status(),
                        "health check returned non-success status"
                    );
                }
                Ok(Err(e)) => {
                    tracing::warn!(
                        attempt,
                        error = %e,
                        "health check connection failed"
                    );
                }
                Err(_) => {
                    tracing::warn!(attempt, "health check timed out");
                }
            }

            if attempt < config.retries {
                tokio::time::sleep(config.interval).await;
            }
        }

        Err(HealthError::Unhealthy {
            retries: config.retries,
            url,
        })
    }
}
```

---

## The Deploy Orchestrator

This is the core logic. A deploy is an async function that runs in the background after the webhook handler returns 202.

```rust
// ── slip-core/src/deploy.rs ──

/// Execute a deploy. Called as a spawned task.
///
/// This function owns the full lifecycle:
/// validate → pull → start → health check → switch → stop old → record
pub async fn execute_deploy(
    state: Arc<AppState>,
    mut ctx: DeployContext,
) {
    let app_name = ctx.app.clone();
    let app_config = match state.apps.get(&app_name) {
        Some(c) => c.clone(),
        None => {
            ctx.fail("app config not found");
            state.record_deploy(&ctx);
            return;
        }
    };

    // ── PULL ──
    ctx.status = DeployStatus::Pulling;
    state.record_deploy(&ctx);
    tracing::info!(app = %app_name, tag = %ctx.tag, "pulling image");

    let credentials = state.config.registry.ghcr_token.as_ref().map(|token| {
        DockerCredentials {
            username: Some("slip".to_string()),
            password: Some(token.clone()),
            serveraddress: Some(extract_registry(&ctx.image)),
            ..Default::default()
        }
    });

    if let Err(e) = state.docker.pull_image(&ctx.image, &ctx.tag, credentials).await {
        ctx.fail(&format!("image pull failed: {}", e));
        state.record_deploy(&ctx);
        return;
    }

    // ── START NEW ──
    ctx.status = DeployStatus::Starting;
    state.record_deploy(&ctx);

    let env_vars = resolve_env_vars_for_app(&app_config, &state.config)?;

    match state.docker.create_and_start(
        &app_name,
        &ctx.image,
        &ctx.tag,
        app_config.routing.port,
        env_vars,
        &app_config.network.name,
        &app_config.resources,
    ).await {
        Ok((container_id, port)) => {
            ctx.new_container_id = Some(container_id);
            ctx.new_port = Some(port);
        }
        Err(e) => {
            ctx.fail(&format!("container start failed: {}", e));
            state.record_deploy(&ctx);
            return;
        }
    };

    // ── HEALTH CHECK ──
    ctx.status = DeployStatus::HealthChecking;
    state.record_deploy(&ctx);

    let health_checker = HealthChecker::new();
    if let Err(e) = health_checker.check(ctx.new_port.unwrap(), &app_config.health).await {
        tracing::error!(app = %app_name, error = %e, "health check failed, rolling back");

        // Clean up the failed new container
        if let Some(ref id) = ctx.new_container_id {
            let _ = state.docker.stop_and_remove(id).await;
        }

        ctx.fail(&format!("health check failed: {}", e));
        state.record_deploy(&ctx);
        return;
    }

    // ── SWITCH ──
    ctx.status = DeployStatus::Switching;
    state.record_deploy(&ctx);

    // Capture old container info before switching
    let old_container_id = {
        let states = state.app_states.read().await;
        states.get(&app_name).and_then(|s| s.current_container_id.clone())
    };

    // Update Caddy route to point to new container
    if let Err(e) = state.caddy.set_route(
        &app_name,
        &app_config.routing.domain,
        ctx.new_port.unwrap(),
    ).await {
        tracing::error!(app = %app_name, error = %e, "caddy route update failed, rolling back");

        // Clean up new container
        if let Some(ref id) = ctx.new_container_id {
            let _ = state.docker.stop_and_remove(id).await;
        }

        ctx.fail(&format!("caddy route update failed: {}", e));
        state.record_deploy(&ctx);
        return;
    }

    // Update app runtime state (under write lock)
    {
        let mut states = state.app_states.write().await;
        let app_state = states.entry(app_name.clone()).or_insert_with(|| {
            AppRuntimeState::new()
        });

        app_state.previous_tag = app_state.current_tag.take();
        app_state.previous_container_id = app_state.current_container_id.take();
        app_state.current_tag = Some(ctx.tag.clone());
        app_state.current_container_id = ctx.new_container_id.clone();
        app_state.current_port = ctx.new_port;
        app_state.deployed_at = Some(Utc::now());
        app_state.deploy_id = Some(ctx.id.clone());
        app_state.status = AppStatus::Running;
    }

    // ── DRAIN + STOP OLD ──
    // Wait for drain_timeout then stop the old container
    if let Some(old_id) = old_container_id {
        tracing::info!(
            app = %app_name,
            drain_timeout = ?app_config.deploy.drain_timeout,
            "draining old container"
        );
        tokio::time::sleep(app_config.deploy.drain_timeout).await;

        if let Err(e) = state.docker.stop_and_remove(&old_id).await {
            // Non-fatal: old container cleanup failure is logged but doesn't fail the deploy
            tracing::warn!(app = %app_name, error = %e, "failed to stop old container");
        }
    }

    // ── RECORD ──
    ctx.status = DeployStatus::Completed;
    ctx.finished_at = Some(Utc::now());
    state.record_deploy(&ctx);

    tracing::info!(
        app = %app_name,
        tag = %ctx.tag,
        deploy_id = %ctx.id,
        duration_ms = (Utc::now() - ctx.started_at).num_milliseconds(),
        "deploy completed"
    );
}
```

### Deploy Tracking (In-Memory for Phase 1)

Phase 1 stores active/recent deploys in memory. Phase 2 adds SQLite persistence.

```rust
impl AppState {
    /// Store a deploy snapshot. In Phase 1 this is in-memory only.
    /// Phase 2 writes to SQLite.
    pub fn record_deploy(&self, ctx: &DeployContext) {
        // In Phase 1: store in a DashMap<String, DeployContext> keyed by deploy_id
        // Capped at last 100 deploys to bound memory
        self.deploys.insert(ctx.id.clone(), ctx.clone());
    }
}
```

---

## Error Handling

### Error Types

```rust
// ── slip-core/src/error.rs ──

#[derive(Debug, thiserror::Error)]
pub enum SlipError {
    #[error("config error: {0}")]
    Config(#[from] ConfigError),

    #[error("docker error: {0}")]
    Docker(#[from] DockerError),

    #[error("caddy error: {0}")]
    Caddy(#[from] CaddyError),

    #[error("health check error: {0}")]
    Health(#[from] HealthError),

    #[error("auth error: {0}")]
    Auth(#[from] AuthError),
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("failed to read config file {path}: {source}")]
    ReadFile { path: PathBuf, source: std::io::Error },

    #[error("failed to parse config {path}: {source}")]
    Parse { path: PathBuf, source: toml::de::Error },

    #[error("missing environment variable ${var} referenced in {context}")]
    MissingEnvVar { var: String, context: String },

    #[error("app name mismatch: filename says {filename}, config says {config_name}")]
    NameMismatch { filename: String, config_name: String },
}

#[derive(Debug, thiserror::Error)]
pub enum DockerError {
    #[error("docker API error: {0}")]
    Api(#[from] bollard::errors::Error),

    #[error("image pull failed: {0}")]
    PullFailed(String),

    #[error("no host port assigned to container")]
    NoPortAssigned,
}

#[derive(Debug, thiserror::Error)]
pub enum CaddyError {
    #[error("caddy HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("caddy bootstrap failed: {0}")]
    BootstrapFailed(String),

    #[error("caddy route update failed: {0}")]
    RouteUpdateFailed(String),

    #[error("caddy not reachable at {url}: {source}")]
    Unreachable { url: String, source: reqwest::Error },
}

#[derive(Debug, thiserror::Error)]
pub enum HealthError {
    #[error("unhealthy after {retries} attempts at {url}")]
    Unhealthy { retries: u32, url: String },
}

#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("missing X-Slip-Signature header")]
    MissingSignature,

    #[error("invalid signature")]
    InvalidSignature,
}
```

### Error Propagation

- **Config errors** → slipd fails to start with a clear message. Exit code 1.
- **Docker/Caddy unreachable on startup** → slipd fails to start. These are prerequisites.
- **Deploy errors** → caught by the deploy orchestrator, deploy marked as `failed`, logged, the old container keeps running.
- **API handler errors** → converted to appropriate HTTP status codes via axum's `IntoResponse`.

---

## Startup Sequence

When `slipd` starts:

```
1. Parse CLI args (--config path)
2. Load and validate slip.toml
3. Resolve env vars in config
4. Load all app configs from /etc/slip/apps/*.toml
5. Validate each app config
6. Connect to Docker socket (fail fast if unavailable)
7. Ensure "slip" Docker network exists
8. Connect to Caddy admin API (fail fast if unavailable)
9. Bootstrap Caddy "slip" server block (idempotent)
10. Load persisted app state from disk (Phase 2: SQLite)
11. Reconcile Caddy routes with known running containers
12. Start axum HTTP server on configured listen address
13. Log "slipd started" with version, listen address, number of apps
```

### App State Persistence (Phase 1: Filesystem)

In Phase 1 (before SQLite), app runtime state is persisted as JSON to allow recovery across daemon restarts:

```
/var/lib/slip/state/
├── walden-api.json
├── walden-web.json
└── sh-web.json
```

```rust
#[derive(Serialize, Deserialize)]
pub struct PersistedAppState {
    pub current_tag: Option<String>,
    pub previous_tag: Option<String>,
    pub current_container_id: Option<String>,
    pub current_port: Option<u16>,
    pub deployed_at: Option<DateTime<Utc>>,
}
```

On startup, slipd reads these files and verifies the containers are still running (via Docker inspect). If a container is gone, the state is cleared.

---

## Container Naming Convention

```
slip-{app_name}-{tag_prefix}
```

Examples:
- `slip-walden-api-sha-abc123f`
- `slip-walden-web-sha-def456a`

The tag is truncated to 12 characters to keep names reasonable. All slip-managed containers are labelled with:
- `slip.app={app_name}`
- `slip.tag={full_tag}`
- `slip.managed=true`

These labels are used during reconciliation to find slip-owned containers.

---

## Security Considerations

### Binding

- **Deploy endpoint** (`/v1/deploy`): Always HMAC-protected. In Phase 1, all endpoints share the same listen address. Phase 3 adds dual-bind (public for deploy, Tailscale for management).
- **Caddy admin API**: Bound to localhost by default (Caddy's own security). slipd is the only consumer.
- **Docker socket**: slipd runs as a `slip` user in the `docker` group.

### Secret Handling

- HMAC secrets: loaded from env vars, never logged, never returned in API responses.
- Registry credentials: loaded from env vars, passed to bollard, never logged.
- App env vars: read from env files on disk, injected into containers at create time, never logged.
- Log redaction: the `tracing` subscriber should never log secret values. Env var values are not included in structured log events.

### Image Allow-List

The deploy endpoint validates that the `image` field in the webhook payload exactly matches the `app.image` field in the app's config. This prevents an attacker with a valid HMAC secret from deploying an arbitrary image — they can only deploy tags of the pre-registered image.

---

## Testing Strategy

### Unit Tests

| Module | What to test |
|--------|-------------|
| `config.rs` | TOML parsing, env var resolution, validation errors, default values |
| `auth.rs` | HMAC verification (valid, invalid, missing header, wrong prefix, timing-safe) |
| `health.rs` | Success on first try, success after retries, failure after exhausting retries, timeout, no health path configured |
| `error.rs` | Error formatting, conversion to HTTP status codes |

### Integration Tests (with Docker)

These require a running Docker daemon. Use `#[cfg(feature = "integration")]` or a separate test binary.

| Test | Description |
|------|-------------|
| `docker_pull_start_stop` | Pull a known image (e.g., `nginx:alpine`), create container, verify it starts, inspect port, stop and remove |
| `docker_network` | Ensure network creation is idempotent |
| `full_deploy_cycle` | End-to-end: webhook → pull → start → health check → Caddy update → stop old |

### Integration Tests (with Caddy)

Require a running Caddy instance with admin API enabled.

| Test | Description |
|------|-------------|
| `caddy_bootstrap` | Create slip server block, verify it exists, call again (idempotent) |
| `caddy_set_route` | Add a route, verify via GET, update upstream, verify change |
| `caddy_remove_route` | Add then remove a route, verify it's gone |
| `caddy_reconcile` | Bootstrap, add routes, delete them externally, run reconcile, verify restored |

### API Tests (axum test client)

Use `axum::test::TestClient` or `tower::ServiceExt` to test handlers without a real server.

| Test | Description |
|------|-------------|
| `deploy_valid_signature` | Valid payload + signature → 202 |
| `deploy_invalid_signature` | Wrong signature → 401 |
| `deploy_unknown_app` | Valid signature, unknown app → 404 |
| `deploy_image_mismatch` | Valid signature, wrong image → 400 |
| `deploy_concurrent_reject` | Two deploys to same app → first 202, second 409 |
| `status_endpoint` | Returns correct app states |
| `deploy_status_poll` | Deploy status progresses through states |

### Smoke Test Script

A bash script for validating the full end-to-end flow on a real server:

```bash
#!/bin/bash
# smoke-test.sh — run against a live slipd instance

SLIP_URL="${SLIP_URL:-http://localhost:7890}"
SLIP_SECRET="${SLIP_SECRET:-test-secret}"
APP="smoke-test-app"
IMAGE="nginx"
TAG="alpine"

PAYLOAD="{\"app\":\"$APP\",\"image\":\"$IMAGE\",\"tag\":\"$TAG\"}"
SIGNATURE=$(echo -n "$PAYLOAD" | openssl dgst -sha256 -hmac "$SLIP_SECRET" | cut -d' ' -f2)

# Trigger deploy
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$SLIP_URL/v1/deploy" \
  -H "Content-Type: application/json" \
  -H "X-Slip-Signature: sha256=$SIGNATURE" \
  -d "$PAYLOAD")

HTTP_CODE=$(echo "$RESPONSE" | tail -1)
BODY=$(echo "$RESPONSE" | head -1)

[ "$HTTP_CODE" = "202" ] && echo "PASS: deploy accepted" || echo "FAIL: expected 202, got $HTTP_CODE"

DEPLOY_ID=$(echo "$BODY" | jq -r '.deploy_id')

# Poll until completed or failed
for i in $(seq 1 30); do
  STATUS=$(curl -s "$SLIP_URL/v1/deploys/$DEPLOY_ID" | jq -r '.status')
  echo "  status: $STATUS"
  [ "$STATUS" = "completed" ] && echo "PASS: deploy completed" && exit 0
  [ "$STATUS" = "failed" ] && echo "FAIL: deploy failed" && exit 1
  sleep 2
done

echo "FAIL: deploy timed out"
exit 1
```

---

## Implementation Plan (Phase 1)

Suggested build order, roughly one ticket per step. Each step produces testable, working code.

| Order | Component | Depends On | Description |
|-------|-----------|-----------|-------------|
| 1 | **Project scaffolding** | — | Cargo workspace, crate stubs, CI (cargo check, clippy, test) |
| 2 | **Config parsing** | 1 | `SlipConfig`, `AppConfig` types, TOML loading, env var resolution, validation |
| 3 | **Auth module** | 1 | HMAC-SHA256 verification, unit tests |
| 4 | **HTTP server + deploy endpoint** | 2, 3 | axum server, `POST /v1/deploy` handler, request validation, 202 response |
| 5 | **Docker client** | 1 | bollard wrapper: pull, create, start, stop, remove, network bootstrap, port discovery |
| 6 | **Health checker** | 1 | HTTP health check with retries, timeouts, start period |
| 7 | **Caddy client** | 1 | reqwest wrapper: bootstrap, set_route (with @id), remove_route |
| 8 | **Deploy orchestrator** | 4, 5, 6, 7 | State machine: pull → start → health check → switch → stop old. Background task. |
| 9 | **Status + polling endpoints** | 8 | `GET /v1/status`, `GET /v1/deploys/:id` |
| 10 | **State persistence** | 8 | JSON file persistence for app runtime state, startup reconciliation |
| 11 | **End-to-end testing** | all | Integration tests with Docker + Caddy, smoke test script |

---

## Alternatives Considered

### Caddyfile rewriting instead of admin API

**Rejected.** The admin API allows atomic route updates without file writes or reloads. Caddyfile rewriting introduces race conditions (multiple apps writing the same file) and requires a reload step. The admin API is exactly what Caddy recommends for dynamic config.

### Index-based Caddy route addressing (from design doc)

**Changed to `@id`-based addressing.** The design doc used `routes/0/handle/0/...` paths. With multiple apps, route indices shift when routes are added or removed, making index-based addressing fragile. Caddy's `@id` feature (`/id/slip-walden-api`) gives stable, named addressing.

### Fixed port allocation per app

**Rejected.** Docker ephemeral ports eliminate port collision risks and don't require a port registry. The trade-off is an extra `inspect_container` call after start — negligible cost.

### Go instead of Rust

**Rejected.** Rust produces a single static binary with no runtime dependencies, which is ideal for a system daemon. The team is more familiar with Rust, and the ecosystem (bollard, axum, serde) covers all our needs.

### SQLite from Phase 1

**Deferred to Phase 2.** Phase 1 uses JSON file persistence for app state and in-memory tracking for deploys. This keeps the dependency surface smaller and gets us to a working deploy loop faster. SQLite is added in Phase 2 for deploy history and querying.

---

## Appendix: Dependency Versions

Suggested starting versions (check for latest at build time):

```toml
# Cargo.toml (workspace dependencies)
[workspace.dependencies]
axum = "0.8"
bollard = "0.18"
reqwest = { version = "0.12", features = ["json"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
toml = "0.8"
tokio = { version = "1", features = ["full"] }
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["json", "env-filter"] }
hmac = "0.12"
sha2 = "0.10"
hex = "0.4"
subtle = "2"
ulid = "1"
thiserror = "2"
chrono = { version = "0.4", features = ["serde"] }
dashmap = "6"
clap = { version = "4", features = ["derive"] }
```
