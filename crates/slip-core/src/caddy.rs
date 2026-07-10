//! Caddy admin API client for dynamic route management.

use crate::config::CaddyTlsConfig;
use crate::error::CaddyError;
use serde_json::json;

// ─── Types ─────────────────────────────────────────────────────────────────────

/// A single route to be registered with the reverse proxy.
#[derive(Debug, Clone)]
pub struct Route {
    pub hostname: String,
    pub port: u16,
}

// ─── Trait ────────────────────────────────────────────────────────────────────

/// Abstraction over reverse-proxy route management used by the deploy
/// orchestrator. Implemented by [`CaddyClient`]; can be mocked in tests.
pub trait ReverseProxy: Send + Sync {
    /// Create or update the reverse-proxy route for an app.
    fn set_route<'a>(
        &'a self,
        app_name: &'a str,
        domain: &'a str,
        upstream_port: u16,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), CaddyError>> + Send + 'a>>;

    /// Remove the reverse-proxy route for an app.
    ///
    /// A 404 response (route already gone) is treated as success.
    fn remove_route<'a>(
        &'a self,
        app_name: &'a str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), CaddyError>> + Send + 'a>>;

    /// Create or update multiple routes for an app.
    ///
    /// Each route gets a unique `@id = "slip-{app_name}-{index}"`.
    fn set_routes<'a>(
        &'a self,
        app_name: &'a str,
        routes: &'a [Route],
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), CaddyError>> + Send + 'a>>;

    /// Remove all routes for an app.
    ///
    /// `route_count` specifies how many `@id`s to delete (0..route_count).
    /// A 404 for any individual route is treated as success (idempotent).
    fn remove_routes<'a>(
        &'a self,
        app_name: &'a str,
        route_count: usize,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), CaddyError>> + Send + 'a>>;
}

impl ReverseProxy for CaddyClient {
    fn set_route<'a>(
        &'a self,
        app_name: &'a str,
        domain: &'a str,
        upstream_port: u16,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), CaddyError>> + Send + 'a>>
    {
        let app_name = app_name.to_string();
        let domain = domain.to_string();
        Box::pin(async move {
            let routes = vec![Route {
                hostname: domain,
                port: upstream_port,
            }];
            CaddyClient::set_routes(self, &app_name, &routes).await
        })
    }

    fn remove_route<'a>(
        &'a self,
        app_name: &'a str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), CaddyError>> + Send + 'a>>
    {
        let app_name = app_name.to_string();
        Box::pin(async move { CaddyClient::remove_routes(self, &app_name, 1).await })
    }

    fn set_routes<'a>(
        &'a self,
        app_name: &'a str,
        routes: &'a [Route],
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), CaddyError>> + Send + 'a>>
    {
        let app_name = app_name.to_string();
        let routes = routes.to_vec();
        Box::pin(async move { CaddyClient::set_routes(self, &app_name, &routes).await })
    }

    fn remove_routes<'a>(
        &'a self,
        app_name: &'a str,
        route_count: usize,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), CaddyError>> + Send + 'a>>
    {
        let app_name = app_name.to_string();
        Box::pin(async move { CaddyClient::remove_routes(self, &app_name, route_count).await })
    }
}

/// Info needed to reconcile a single app's route.
pub struct RouteInfo {
    pub app_name: String,
    pub domain: String,
    pub port: u16,
}

/// Client for the Caddy admin API.
#[derive(Clone)]
pub struct CaddyClient {
    client: reqwest::Client,
    base_url: String,
}

impl CaddyClient {
    /// Create a new `CaddyClient` pointed at the given admin API base URL.
    ///
    /// # Example
    /// ```
    /// let client = slip_core::CaddyClient::new("http://localhost:2019".to_string());
    /// ```
    pub fn new(base_url: String) -> Self {
        Self {
            client: reqwest::Client::new(),
            base_url,
        }
    }

    /// Check if Caddy admin API is reachable.
    pub async fn ping(&self) -> Result<(), CaddyError> {
        let url = format!("{}/config/", self.base_url);
        let resp = self.client.get(&url).send().await?;
        if resp.status().is_success() {
            Ok(())
        } else {
            Err(CaddyError::Http(resp.error_for_status().unwrap_err()))
        }
    }

    /// Ensure the slip HTTP server block exists in Caddy.
    ///
    /// Idempotent: if the block already exists, this is a no-op.
    ///
    /// Works against a freshly-started Caddy whose config contains only the
    /// `admin` endpoint (no `apps` tree). Rather than POSTing into a path that
    /// may not exist yet (`config/apps/http/servers`), this reads the full
    /// config, merges the slip server block in, and atomically reloads it via
    /// `POST /load` — preserving any existing config (e.g. `admin`).
    ///
    /// ## Conflict detection (SLIP-88)
    ///
    /// Before merging, this method scans the existing config for any HTTP server
    /// (other than `slip`) that already claims `:443` (or whatever the `slip`
    /// server listens on). If found, it returns
    /// [`CaddyError::ListenerConflict`] — a prescriptive error that names the
    /// conflicting server and the remedy — instead of crash-looping on a
    /// rejected `POST /load`.
    pub async fn bootstrap(&self) -> Result<(), CaddyError> {
        // Fetch the current full config.
        let cfg_url = format!("{}/config/", self.base_url);
        let resp = self.client.get(&cfg_url).send().await?;
        let mut config: serde_json::Value = if resp.status().is_success() {
            resp.json().await.unwrap_or(serde_json::Value::Null)
        } else {
            serde_json::Value::Null
        };

        // If the slip server block already exists, nothing to do.
        if config.pointer("/apps/http/servers/slip").is_some() {
            return Ok(());
        }

        // ── SLIP-88: Detect listener conflict before POST /load ──────────────
        let slip_listener = ":443";
        if let Some(servers) = config
            .pointer("/apps/http/servers")
            .and_then(|v| v.as_object())
        {
            for (name, server) in servers {
                if name == "slip" {
                    continue;
                }
                if let Some(listen) = server.get("listen").and_then(|v| v.as_array())
                    && listen.iter().any(|l| l.as_str() == Some(slip_listener))
                {
                    return Err(CaddyError::ListenerConflict {
                        server: name.clone(),
                        listener: slip_listener.to_string(),
                    });
                }
            }
        }

        // Ensure we have an object to build on (fresh Caddy may return `null`).
        if !config.is_object() {
            config = json!({});
        }

        // Walk/create the nested structure: apps.http.servers.slip
        let root = config.as_object_mut().expect("config is an object");
        let apps = root.entry("apps").or_insert_with(|| json!({}));
        if !apps.is_object() {
            *apps = json!({});
        }
        let http = apps
            .as_object_mut()
            .expect("apps is an object")
            .entry("http")
            .or_insert_with(|| json!({}));
        if !http.is_object() {
            *http = json!({});
        }
        let servers = http
            .as_object_mut()
            .expect("http is an object")
            .entry("servers")
            .or_insert_with(|| json!({}));
        if !servers.is_object() {
            *servers = json!({});
        }
        servers
            .as_object_mut()
            .expect("servers is an object")
            .insert(
                "slip".to_string(),
                json!({
                    "listen": [":443"],
                    "routes": []
                }),
            );

        // Atomically load the merged config.
        let load_url = format!("{}/load", self.base_url);
        let load_resp = self.client.post(&load_url).json(&config).send().await?;

        if load_resp.status().is_success() {
            Ok(())
        } else {
            let status = load_resp.status();
            let text = load_resp.text().await.unwrap_or_default();
            Err(CaddyError::BootstrapFailed(format!(
                "POST {load_url} returned {status}: {text}"
            )))
        }
    }

    /// Register the deploy-webhook route and TLS policy in Caddy (SLIP-87).
    ///
    /// When `domain` is set, this method:
    /// 1. Creates a route with `@id = "slip-deploy-webhook"` that reverse-proxies
    ///    `<domain>` → `<upstream_addr>` (the slipd listen address).
    /// 2. Adds a TLS automation policy for `<domain>` using the configured
    ///    strategy (default: `"internal"` → Caddy local CA, self-signed).
    ///
    /// The route is slip-owned: it uses the `slip-*` @id prefix and is
    /// re-applied on every reconcile pass. It is NOT deleted by `remove_routes`
    /// (which targets `slip-{app_name}-{index}` — the deploy-webhook id is
    /// `slip-deploy-webhook`, no numeric suffix).
    ///
    /// When `domain` is `None`, this is a no-op (backwards compatible).
    ///
    /// # Arguments
    ///
    /// * `domain` - The deploy webhook domain (e.g. `"deploy.example.com"`).
    ///   Pass `None` to skip (no `[deploy]` section in config).
    /// * `tls_strategy` - TLS strategy string (`"internal"`, etc.).
    /// * `upstream_addr` - The slipd listen address (e.g. `"127.0.0.1:7890"`).
    pub async fn bootstrap_deploy(
        &self,
        domain: Option<&str>,
        tls_strategy: &str,
        upstream_addr: &str,
    ) -> Result<(), CaddyError> {
        let domain = match domain {
            Some(d) => d,
            None => return Ok(()),
        };

        // ── 1. Register the deploy-webhook route ─────────────────────────────
        let route_id = "slip-deploy-webhook";
        let route_body = json!({
            "@id": route_id,
            "match": [{"host": [domain]}],
            "handle": [{
                "handler": "subroute",
                "routes": [{
                    "handle": [{
                        "handler": "reverse_proxy",
                        "upstreams": [{"dial": upstream_addr}]
                    }]
                }]
            }],
            "terminal": true
        });

        // Try to update an existing route via @id.
        let patch_url = format!("{}/id/{route_id}", self.base_url);
        let patch_resp = self
            .client
            .patch(&patch_url)
            .json(&route_body)
            .send()
            .await?;
        if !patch_resp.status().is_success() {
            // Route didn't exist — append it.
            let post_url = format!("{}/config/apps/http/servers/slip/routes", self.base_url);
            let post_resp = self.client.post(&post_url).json(&route_body).send().await?;
            if !post_resp.status().is_success() {
                let status = post_resp.status();
                let text = post_resp.text().await.unwrap_or_default();
                return Err(CaddyError::RouteUpdateFailed(format!(
                    "POST {post_url} returned {status}: {text}"
                )));
            }
        }

        // ── 2. Register the TLS automation policy ────────────────────────────
        if tls_strategy == "internal" {
            // Check if a policy with matching subjects already exists (idempotency)
            let policies_url = format!("{}/config/apps/tls/automation/policies", self.base_url);
            let resp = self.client.get(&policies_url).send().await?;

            let mut already_exists = false;
            if resp.status().is_success() {
                let policies: Vec<serde_json::Value> = resp.json().await.unwrap_or_default();
                for policy in policies {
                    if let Some(subjects) = policy.get("subjects").and_then(|s| s.as_array())
                        && subjects.iter().any(|s| s.as_str() == Some(domain))
                    {
                        already_exists = true;
                        break;
                    }
                }
            }

            if !already_exists {
                // Build the TLS policy with internal (self-signed) issuer.
                // NOTE: "issuers" is PLURAL and an ARRAY — the singular form
                // "issuer" silently fails in Caddy.
                let policy = json!({
                    "subjects": [domain],
                    "issuers": [{"module": "internal"}]
                });

                // Ensure the parent TLS automation path exists.
                let automation_url = format!("{}/config/apps/tls/automation", self.base_url);
                let automation_body = json!({"policies": []});
                let _ = self
                    .client
                    .post(&automation_url)
                    .json(&automation_body)
                    .send()
                    .await;

                // Append the policy.
                let post_url = format!("{}/config/apps/tls/automation/policies", self.base_url);
                let post_resp = self.client.post(&post_url).json(&policy).send().await?;
                if !post_resp.status().is_success() {
                    let status = post_resp.status();
                    let text = post_resp.text().await.unwrap_or_default();
                    return Err(CaddyError::TlsConfigFailed(format!(
                        "POST {post_url} returned {status}: {text}"
                    )));
                }
            }
        }
        // Future strategies (acme, cloudflare-dns01, tailscale) land in SLIP-104.

        Ok(())
    }

    /// Create or update the reverse-proxy route for an app.
    pub async fn set_route(
        &self,
        app_name: &str,
        domain: &str,
        upstream_port: u16,
    ) -> Result<(), CaddyError> {
        let routes = vec![Route {
            hostname: domain.to_string(),
            port: upstream_port,
        }];
        self.set_routes(app_name, &routes).await
    }

    /// Create or update multiple routes for an app.
    ///
    /// Each route gets a unique `@id = "slip-{app_name}-{index}"`.
    pub async fn set_routes(&self, app_name: &str, routes: &[Route]) -> Result<(), CaddyError> {
        for (i, route) in routes.iter().enumerate() {
            let route_id = format!("slip-{app_name}-{i}");
            let route_body = json!({
                "@id": route_id,
                "match": [{"host": [route.hostname]}],
                "handle": [{
                    "handler": "subroute",
                    "routes": [{
                        "handle": [{
                            "handler": "reverse_proxy",
                            "upstreams": [{"dial": format!("localhost:{}", route.port)}]
                        }]
                    }]
                }],
                "terminal": true
            });

            // Try to update an existing route via @id.
            let patch_url = format!("{}/id/{route_id}", self.base_url);
            let patch_resp = self
                .client
                .patch(&patch_url)
                .json(&route_body)
                .send()
                .await?;
            if patch_resp.status().is_success() {
                continue;
            }

            // Route didn't exist — append it.
            let post_url = format!("{}/config/apps/http/servers/slip/routes", self.base_url);
            let post_resp = self.client.post(&post_url).json(&route_body).send().await?;
            if post_resp.status().is_success() {
                continue;
            }
            let status = post_resp.status();
            let text = post_resp.text().await.unwrap_or_default();
            return Err(CaddyError::RouteUpdateFailed(format!(
                "POST {post_url} returned {status}: {text}"
            )));
        }
        Ok(())
    }

    /// Remove the reverse-proxy route for an app.
    ///
    /// A 404 response is treated as success (route already gone).
    pub async fn remove_route(&self, app_name: &str) -> Result<(), CaddyError> {
        self.remove_routes(app_name, 1).await
    }

    /// Remove all routes for an app.
    ///
    /// Iterates from `0..route_count` and DELETE `/id/slip-{app_name}-{index}`.
    /// A 404 for any individual route is treated as success (idempotent).
    pub async fn remove_routes(
        &self,
        app_name: &str,
        route_count: usize,
    ) -> Result<(), CaddyError> {
        for i in 0..route_count {
            let route_id = format!("slip-{app_name}-{i}");
            let url = format!("{}/id/{route_id}", self.base_url);
            let resp = self.client.delete(&url).send().await?;

            if resp.status().is_success() || resp.status() == reqwest::StatusCode::NOT_FOUND {
                continue;
            }
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            return Err(CaddyError::RouteUpdateFailed(format!(
                "DELETE {url} returned {status}: {text}"
            )));
        }
        Ok(())
    }

    /// Reconcile all routes from a slice of `RouteInfo`.
    ///
    /// Calls `set_routes` for every entry. Returns the first error encountered.
    pub async fn reconcile(&self, routes: &[RouteInfo]) -> Result<(), CaddyError> {
        for route in routes {
            let r = vec![Route {
                hostname: route.domain.clone(),
                port: route.port,
            }];
            self.set_routes(&route.app_name, &r).await?;
        }
        Ok(())
    }

    /// Configure TLS for wildcard certificates on a preview domain.
    ///
    /// Sets up a TLS connection policy with DNS-01 challenge for obtaining
    /// wildcard certificates (e.g., `*.preview.example.com`).
    ///
    /// This method is idempotent: if a policy with matching subjects already
    /// exists, it returns success without making changes.
    ///
    /// # Arguments
    ///
    /// * `preview_domain` - The base domain for previews (e.g., `preview.example.com`)
    /// * `tls_config` - TLS configuration including DNS provider settings
    ///
    /// # Example
    ///
    /// ```ignore
    /// let tls_config = CaddyTlsConfig {
    ///     email: "admin@example.com".to_string(),
    ///     dns_provider: "cloudflare".to_string(),
    ///     dns_provider_config: Some(toml::value::Table::new()),
    ///     propagation_delay: "2m".to_string(),
    ///     staging: false,
    /// };
    /// client.configure_tls("preview.example.com", &tls_config).await?;
    /// ```
    pub async fn configure_tls(
        &self,
        preview_domain: &str,
        tls_config: &CaddyTlsConfig,
    ) -> Result<(), CaddyError> {
        let wildcard_subject = format!("*.{preview_domain}");

        // Check if a policy with matching subjects already exists (idempotency)
        let policies_url = format!("{}/config/apps/tls/automation/policies", self.base_url);
        let resp = self.client.get(&policies_url).send().await?;

        if resp.status().is_success() {
            let policies: Vec<serde_json::Value> = resp.json().await.unwrap_or_default();
            // Check if any policy already has our wildcard subject
            for policy in policies {
                if let Some(subjects) = policy.get("subjects").and_then(|s| s.as_array())
                    && subjects
                        .iter()
                        .any(|s| s.as_str() == Some(&wildcard_subject))
                {
                    // Policy already exists, nothing to do
                    return Ok(());
                }
            }
        }

        // Build the DNS provider config for Caddy
        // Caddy expects provider config values to use {env.VAR_NAME} syntax
        // Provider config fields are siblings of "name", not nested under "config"
        let mut provider = json!({"name": tls_config.dns_provider});
        if let Some(config_table) = &tls_config.dns_provider_config {
            for (key, value) in config_table {
                // Convert TOML value to JSON value and merge as sibling of "name"
                provider[key] = serde_json::to_value(value).unwrap_or(json!(null));
            }
        }

        // Determine CA URL based on staging flag
        let ca_url = if tls_config.staging {
            "https://acme-staging-v02.api.letsencrypt.org/directory"
        } else {
            "https://acme-v02.api.letsencrypt.org/directory"
        };

        // Build the TLS policy with ACME issuer using DNS challenge
        // Note: Caddy uses "issuers" (array) and "dns" (not "dns-01")
        let policy = json!({
            "subjects": [&wildcard_subject],
            "issuers": [{
                "module": "acme",
                "email": tls_config.email,
                "challenges": {
                    "dns": {
                        "provider": provider,
                        "propagation_delay": tls_config.propagation_delay
                    }
                },
                "ca": ca_url
            }]
        });

        // Ensure the parent TLS automation path exists before appending policy
        // POST to the automation path creates the structure if it doesn't exist
        let automation_url = format!("{}/config/apps/tls/automation", self.base_url);
        let automation_body = json!({"policies": []});
        // Ignore errors here - if it already exists, Caddy returns an error but that's fine
        let _ = self
            .client
            .post(&automation_url)
            .json(&automation_body)
            .send()
            .await;

        // Append the policy to the automation policies
        let post_url = format!("{}/config/apps/tls/automation/policies", self.base_url);
        let post_resp = self.client.post(&post_url).json(&policy).send().await?;

        if post_resp.status().is_success() {
            Ok(())
        } else {
            let status = post_resp.status();
            let text = post_resp.text().await.unwrap_or_default();
            Err(CaddyError::TlsConfigFailed(format!(
                "POST {post_url} returned {status}: {text}"
            )))
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        Router,
        extract::{Path, State},
        http::StatusCode,
        routing::{get, patch, post},
    };
    use std::collections::HashMap;
    use std::sync::Arc;
    use tokio::sync::Mutex;

    type MockState = Arc<Mutex<HashMap<String, serde_json::Value>>>;

    // -----------------------------------------------------------------------
    // Mock handler implementations
    // -----------------------------------------------------------------------

    async fn mock_get_server(State(state): State<MockState>) -> StatusCode {
        let map = state.lock().await;
        if map.contains_key("__server__") {
            StatusCode::OK
        } else {
            StatusCode::NOT_FOUND
        }
    }

    /// Mock `GET /config/` — returns the full config, reflecting whether the
    /// slip server block has been created.
    async fn mock_get_config(
        State(state): State<MockState>,
    ) -> (StatusCode, axum::Json<serde_json::Value>) {
        let map = state.lock().await;
        if let Some(server) = map.get("__server__") {
            (
                StatusCode::OK,
                axum::Json(json!({
                    "apps": {"http": {"servers": {"slip": server}}}
                })),
            )
        } else {
            // Fresh Caddy: only the admin endpoint is configured.
            (
                StatusCode::OK,
                axum::Json(json!({"admin": {"listen": "localhost:2019"}})),
            )
        }
    }

    /// Mock `POST /load` — stores the slip server block from the loaded config.
    async fn mock_load_config(
        State(state): State<MockState>,
        axum::Json(body): axum::Json<serde_json::Value>,
    ) -> StatusCode {
        if let Some(server) = body.pointer("/apps/http/servers/slip") {
            state
                .lock()
                .await
                .insert("__server__".to_string(), server.clone());
        }
        StatusCode::OK
    }

    async fn mock_create_server(
        State(state): State<MockState>,
        axum::Json(body): axum::Json<serde_json::Value>,
    ) -> StatusCode {
        let mut map = state.lock().await;
        map.insert("__server__".to_string(), body);
        StatusCode::OK
    }

    async fn mock_add_route(
        State(state): State<MockState>,
        axum::Json(body): axum::Json<serde_json::Value>,
    ) -> StatusCode {
        let id = body
            .get("@id")
            .and_then(|v| v.as_str())
            .unwrap_or("__unknown__")
            .to_string();
        let mut map = state.lock().await;
        map.insert(id, body);
        StatusCode::OK
    }

    async fn mock_patch_route(
        State(state): State<MockState>,
        Path(id): Path<String>,
        axum::Json(body): axum::Json<serde_json::Value>,
    ) -> StatusCode {
        let mut map = state.lock().await;
        if let std::collections::hash_map::Entry::Occupied(mut e) = map.entry(id) {
            e.insert(body);
            StatusCode::OK
        } else {
            StatusCode::NOT_FOUND
        }
    }

    async fn mock_delete_route(
        State(state): State<MockState>,
        Path(id): Path<String>,
    ) -> StatusCode {
        let mut map = state.lock().await;
        if map.remove(&id).is_some() {
            StatusCode::OK
        } else {
            StatusCode::NOT_FOUND
        }
    }

    async fn mock_get_tls_policies(
        State(state): State<MockState>,
    ) -> (StatusCode, axum::Json<serde_json::Value>) {
        let map = state.lock().await;
        if let Some(policies) = map.get("__tls_policies__") {
            (StatusCode::OK, axum::Json(policies.clone()))
        } else {
            (StatusCode::OK, axum::Json(json!([])))
        }
    }

    async fn mock_add_tls_policy(
        State(state): State<MockState>,
        axum::Json(body): axum::Json<serde_json::Value>,
    ) -> StatusCode {
        let mut map = state.lock().await;
        // Get existing policies or create empty array
        let policies = map
            .entry("__tls_policies__".to_string())
            .or_insert(json!([]));
        if let Some(arr) = policies.as_array_mut() {
            arr.push(body);
        }
        StatusCode::OK
    }

    /// Mock `GET /config/` that returns a config with a conflicting server on :443.
    async fn mock_get_config_with_conflict() -> (StatusCode, axum::Json<serde_json::Value>) {
        (
            StatusCode::OK,
            axum::Json(json!({
                "admin": {"listen": "localhost:2019"},
                "apps": {
                    "http": {
                        "servers": {
                            "srv0": {
                                "listen": [":443"],
                                "routes": [{
                                    "@id": "caddyfile-route",
                                    "match": [{"host": ["other.example.com"]}],
                                    "handle": [{"handler": "subroute", "routes": []}]
                                }]
                            }
                        }
                    }
                }
            })),
        )
    }

    async fn mock_add_tls_policy_fail(
        State(state): State<MockState>,
        axum::Json(_body): axum::Json<serde_json::Value>,
    ) -> StatusCode {
        // Check if we should fail
        let map = state.lock().await;
        if map.contains_key("__tls_fail__") {
            StatusCode::INTERNAL_SERVER_ERROR
        } else {
            drop(map);
            let mut map = state.lock().await;
            let policies = map
                .entry("__tls_policies__".to_string())
                .or_insert(json!([]));
            if let Some(arr) = policies.as_array_mut() {
                arr.push(_body);
            }
            StatusCode::OK
        }
    }

    // -----------------------------------------------------------------------
    // Test helpers
    // -----------------------------------------------------------------------

    async fn start_mock_caddy() -> (u16, MockState) {
        let state: MockState = Arc::new(Mutex::new(HashMap::new()));
        let app = Router::new()
            .route("/config/", get(mock_get_config))
            .route("/load", post(mock_load_config))
            .route(
                "/config/apps/http/servers/slip",
                get(mock_get_server).post(mock_create_server),
            )
            .route(
                "/config/apps/http/servers/slip/routes",
                post(mock_add_route),
            )
            .route(
                "/id/{id}",
                patch(mock_patch_route).delete(mock_delete_route),
            )
            .route(
                "/config/apps/tls/automation/policies",
                get(mock_get_tls_policies).post(mock_add_tls_policy),
            )
            .with_state(state.clone());

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (port, state)
    }

    /// Mock Caddy that can be configured to fail TLS policy POST requests
    async fn start_mock_caddy_with_tls_failure() -> (u16, MockState) {
        let state: MockState = Arc::new(Mutex::new(HashMap::new()));
        let app = Router::new()
            .route("/config/", get(mock_get_config))
            .route("/load", post(mock_load_config))
            .route(
                "/config/apps/http/servers/slip",
                get(mock_get_server).post(mock_create_server),
            )
            .route(
                "/config/apps/http/servers/slip/routes",
                post(mock_add_route),
            )
            .route(
                "/id/{id}",
                patch(mock_patch_route).delete(mock_delete_route),
            )
            .route(
                "/config/apps/tls/automation/policies",
                get(mock_get_tls_policies).post(mock_add_tls_policy_fail),
            )
            .with_state(state.clone());

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (port, state)
    }

    // -----------------------------------------------------------------------
    // Tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_bootstrap_creates_server_block() {
        let (port, state) = start_mock_caddy().await;
        let client = CaddyClient::new(format!("http://127.0.0.1:{port}"));

        assert!(!state.lock().await.contains_key("__server__"));

        client.bootstrap().await.expect("bootstrap should succeed");

        assert!(
            state.lock().await.contains_key("__server__"),
            "server block should have been created"
        );
    }

    #[tokio::test]
    async fn test_bootstrap_is_idempotent() {
        let (port, state) = start_mock_caddy().await;
        let client = CaddyClient::new(format!("http://127.0.0.1:{port}"));

        // Pre-populate server block.
        state
            .lock()
            .await
            .insert("__server__".to_string(), json!({"listen": [":443"]}));

        // Should not fail and should not change the existing value.
        client
            .bootstrap()
            .await
            .expect("idempotent bootstrap should succeed");

        let map = state.lock().await;
        assert_eq!(
            map["__server__"],
            json!({"listen": [":443"]}),
            "existing server block should be unchanged"
        );
    }

    #[tokio::test]
    async fn test_set_route_creates_new_route() {
        let (port, state) = start_mock_caddy().await;
        let client = CaddyClient::new(format!("http://127.0.0.1:{port}"));

        client
            .set_route("walden-api", "walden-api.example.com", 8080)
            .await
            .expect("set_route should succeed");

        let map = state.lock().await;
        assert!(
            map.contains_key("slip-walden-api-0"),
            "route should have been stored"
        );
        assert_eq!(
            map["slip-walden-api-0"]["@id"], "slip-walden-api-0",
            "@id field should match"
        );
    }

    #[tokio::test]
    async fn test_set_route_updates_existing_route() {
        let (port, state) = start_mock_caddy().await;
        let client = CaddyClient::new(format!("http://127.0.0.1:{port}"));

        // Pre-populate a route so PATCH will succeed.
        state.lock().await.insert(
            "slip-myapp-0".to_string(),
            json!({"@id": "slip-myapp-0", "port": 9000}),
        );

        client
            .set_route("myapp", "myapp.example.com", 9001)
            .await
            .expect("set_route update should succeed");

        let map = state.lock().await;
        // The route should now reflect the new upstream port.
        let route = &map["slip-myapp-0"];
        let dial = route["handle"][0]["routes"][0]["handle"][0]["upstreams"][0]["dial"]
            .as_str()
            .unwrap_or("");
        assert_eq!(dial, "localhost:9001", "dial address should be updated");
    }

    #[tokio::test]
    async fn test_remove_route_removes_existing_route() {
        let (port, state) = start_mock_caddy().await;
        let client = CaddyClient::new(format!("http://127.0.0.1:{port}"));

        state.lock().await.insert(
            "slip-todelete-0".to_string(),
            json!({"@id": "slip-todelete-0"}),
        );

        client
            .remove_route("todelete")
            .await
            .expect("remove_route should succeed");

        assert!(
            !state.lock().await.contains_key("slip-todelete-0"),
            "route should have been removed"
        );
    }

    #[tokio::test]
    async fn test_remove_route_ignores_not_found() {
        let (port, _state) = start_mock_caddy().await;
        let client = CaddyClient::new(format!("http://127.0.0.1:{port}"));

        // Route never existed — should be OK.
        client
            .remove_route("nonexistent")
            .await
            .expect("remove_route on nonexistent route should succeed");
    }

    #[tokio::test]
    async fn test_reconcile_registers_multiple_routes() {
        let (port, state) = start_mock_caddy().await;
        let client = CaddyClient::new(format!("http://127.0.0.1:{port}"));

        let routes = vec![
            RouteInfo {
                app_name: "app-one".to_string(),
                domain: "one.example.com".to_string(),
                port: 8001,
            },
            RouteInfo {
                app_name: "app-two".to_string(),
                domain: "two.example.com".to_string(),
                port: 8002,
            },
            RouteInfo {
                app_name: "app-three".to_string(),
                domain: "three.example.com".to_string(),
                port: 8003,
            },
        ];

        client
            .reconcile(&routes)
            .await
            .expect("reconcile should succeed");

        let map = state.lock().await;
        assert!(
            map.contains_key("slip-app-one-0"),
            "app-one should be registered"
        );
        assert!(
            map.contains_key("slip-app-two-0"),
            "app-two should be registered"
        );
        assert!(
            map.contains_key("slip-app-three-0"),
            "app-three should be registered"
        );
    }

    // -----------------------------------------------------------------------
    // Multi-route tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_set_routes_creates_multiple_routes() {
        let (port, state) = start_mock_caddy().await;
        let client = CaddyClient::new(format!("http://127.0.0.1:{port}"));

        let routes = vec![
            Route {
                hostname: "api.example.com".to_string(),
                port: 3000,
            },
            Route {
                hostname: "admin.example.com".to_string(),
                port: 3001,
            },
        ];

        client
            .set_routes("myapp", &routes)
            .await
            .expect("set_routes should succeed");

        let map = state.lock().await;
        assert!(map.contains_key("slip-myapp-0"), "route 0 should exist");
        assert!(map.contains_key("slip-myapp-1"), "route 1 should exist");
        assert_eq!(
            map["slip-myapp-0"]["@id"], "slip-myapp-0",
            "route 0 @id should match"
        );
        assert_eq!(
            map["slip-myapp-1"]["@id"], "slip-myapp-1",
            "route 1 @id should match"
        );
        let dial0 =
            map["slip-myapp-0"]["handle"][0]["routes"][0]["handle"][0]["upstreams"][0]["dial"]
                .as_str()
                .unwrap_or("");
        assert_eq!(dial0, "localhost:3000", "route 0 dial should be correct");
        let dial1 =
            map["slip-myapp-1"]["handle"][0]["routes"][0]["handle"][0]["upstreams"][0]["dial"]
                .as_str()
                .unwrap_or("");
        assert_eq!(dial1, "localhost:3001", "route 1 dial should be correct");
    }

    #[tokio::test]
    async fn test_set_routes_updates_existing_routes() {
        let (port, state) = start_mock_caddy().await;
        let client = CaddyClient::new(format!("http://127.0.0.1:{port}"));

        // Pre-populate routes so PATCH will succeed.
        state.lock().await.insert(
            "slip-myapp-0".to_string(),
            json!({"@id": "slip-myapp-0", "port": 9000}),
        );
        state.lock().await.insert(
            "slip-myapp-1".to_string(),
            json!({"@id": "slip-myapp-1", "port": 9001}),
        );

        let routes = vec![
            Route {
                hostname: "api.example.com".to_string(),
                port: 3000,
            },
            Route {
                hostname: "admin.example.com".to_string(),
                port: 3001,
            },
        ];

        client
            .set_routes("myapp", &routes)
            .await
            .expect("set_routes should succeed");

        let map = state.lock().await;
        let dial0 =
            map["slip-myapp-0"]["handle"][0]["routes"][0]["handle"][0]["upstreams"][0]["dial"]
                .as_str()
                .unwrap_or("");
        assert_eq!(dial0, "localhost:3000", "route 0 dial should be updated");
        let dial1 =
            map["slip-myapp-1"]["handle"][0]["routes"][0]["handle"][0]["upstreams"][0]["dial"]
                .as_str()
                .unwrap_or("");
        assert_eq!(dial1, "localhost:3001", "route 1 dial should be updated");
    }

    #[tokio::test]
    async fn test_remove_routes_removes_all() {
        let (port, state) = start_mock_caddy().await;
        let client = CaddyClient::new(format!("http://127.0.0.1:{port}"));

        state
            .lock()
            .await
            .insert("slip-myapp-0".to_string(), json!({"@id": "slip-myapp-0"}));
        state
            .lock()
            .await
            .insert("slip-myapp-1".to_string(), json!({"@id": "slip-myapp-1"}));
        state
            .lock()
            .await
            .insert("slip-myapp-2".to_string(), json!({"@id": "slip-myapp-2"}));

        client
            .remove_routes("myapp", 3)
            .await
            .expect("remove_routes should succeed");

        let map = state.lock().await;
        assert!(
            !map.contains_key("slip-myapp-0"),
            "route 0 should be removed"
        );
        assert!(
            !map.contains_key("slip-myapp-1"),
            "route 1 should be removed"
        );
        assert!(
            !map.contains_key("slip-myapp-2"),
            "route 2 should be removed"
        );
    }

    #[tokio::test]
    async fn test_remove_routes_ignores_not_found() {
        let (port, _state) = start_mock_caddy().await;
        let client = CaddyClient::new(format!("http://127.0.0.1:{port}"));

        // No routes exist — should be OK.
        client
            .remove_routes("nonexistent", 3)
            .await
            .expect("remove_routes on nonexistent routes should succeed");
    }

    #[tokio::test]
    async fn test_reconcile_with_multi_route_apps() {
        let (port, state) = start_mock_caddy().await;
        let client = CaddyClient::new(format!("http://127.0.0.1:{port}"));

        // RouteInfo uses one entry per app. Each app gets routes starting at index 0.
        let routes = vec![
            RouteInfo {
                app_name: "app-one".to_string(),
                domain: "one.example.com".to_string(),
                port: 8001,
            },
            RouteInfo {
                app_name: "app-two".to_string(),
                domain: "two.example.com".to_string(),
                port: 8002,
            },
        ];

        client
            .reconcile(&routes)
            .await
            .expect("reconcile should succeed");

        let map = state.lock().await;
        assert!(
            map.contains_key("slip-app-one-0"),
            "app-one route should exist"
        );
        assert!(
            map.contains_key("slip-app-two-0"),
            "app-two route should exist"
        );
    }

    // -----------------------------------------------------------------------
    // configure_tls tests
    // -----------------------------------------------------------------------

    fn test_tls_config() -> CaddyTlsConfig {
        CaddyTlsConfig {
            email: "admin@example.com".to_string(),
            dns_provider: "cloudflare".to_string(),
            dns_provider_config: None,
            propagation_delay: "2m".to_string(),
            staging: false,
        }
    }

    #[tokio::test]
    async fn test_configure_tls_creates_policy() {
        let (port, state) = start_mock_caddy().await;
        let client = CaddyClient::new(format!("http://127.0.0.1:{port}"));
        let tls_config = test_tls_config();

        client
            .configure_tls("preview.example.com", &tls_config)
            .await
            .expect("configure_tls should succeed");

        let map = state.lock().await;
        let policies = map.get("__tls_policies__").expect("policies should exist");
        let arr = policies.as_array().expect("policies should be an array");
        assert_eq!(arr.len(), 1, "should have one policy");
        let policy = &arr[0];
        assert_eq!(
            policy["subjects"][0].as_str(),
            Some("*.preview.example.com"),
            "subject should be wildcard domain"
        );
        assert_eq!(
            policy["issuers"][0]["module"].as_str(),
            Some("acme"),
            "issuer should be ACME"
        );
        assert_eq!(
            policy["issuers"][0]["email"].as_str(),
            Some("admin@example.com"),
            "email should match"
        );
    }

    #[tokio::test]
    async fn test_configure_tls_is_idempotent() {
        let (port, state) = start_mock_caddy().await;
        let client = CaddyClient::new(format!("http://127.0.0.1:{port}"));
        let tls_config = test_tls_config();

        // Pre-populate with existing policy for the same domain
        state.lock().await.insert(
            "__tls_policies__".to_string(),
            json!([{
                "subjects": ["*.preview.example.com"],
                "issuers": [{"module": "acme"}]
            }]),
        );

        // Should succeed without adding a new policy
        client
            .configure_tls("preview.example.com", &tls_config)
            .await
            .expect("configure_tls should succeed for existing policy");

        let map = state.lock().await;
        let policies = map.get("__tls_policies__").expect("policies should exist");
        let arr = policies.as_array().expect("policies should be an array");
        // Should still be 1 policy (not 2)
        assert_eq!(arr.len(), 1, "should not add duplicate policy");
    }

    #[tokio::test]
    async fn test_configure_tls_uses_staging_ca() {
        let (port, state) = start_mock_caddy().await;
        let client = CaddyClient::new(format!("http://127.0.0.1:{port}"));
        let mut tls_config = test_tls_config();
        tls_config.staging = true;

        client
            .configure_tls("preview.example.com", &tls_config)
            .await
            .expect("configure_tls should succeed");

        let map = state.lock().await;
        let policies = map.get("__tls_policies__").expect("policies should exist");
        let arr = policies.as_array().expect("policies should be an array");
        let policy = &arr[0];
        assert_eq!(
            policy["issuers"][0]["ca"].as_str(),
            Some("https://acme-staging-v02.api.letsencrypt.org/directory"),
            "should use staging CA"
        );
    }

    #[tokio::test]
    async fn test_configure_tls_includes_provider_config() {
        let (port, state) = start_mock_caddy().await;
        let client = CaddyClient::new(format!("http://127.0.0.1:{port}"));

        let mut provider_config = toml::value::Table::new();
        provider_config.insert(
            "api_token".to_string(),
            toml::Value::String("{env.CLOUDFLARE_API_TOKEN}".to_string()),
        );

        let tls_config = CaddyTlsConfig {
            email: "admin@example.com".to_string(),
            dns_provider: "cloudflare".to_string(),
            dns_provider_config: Some(provider_config),
            propagation_delay: "5m".to_string(),
            staging: false,
        };

        client
            .configure_tls("preview.example.com", &tls_config)
            .await
            .expect("configure_tls should succeed");

        let map = state.lock().await;
        let policies = map.get("__tls_policies__").expect("policies should exist");
        let arr = policies.as_array().expect("policies should be an array");
        let policy = &arr[0];
        // Check provider config is flattened (sibling of "name", not nested under "config")
        let provider = &policy["issuers"][0]["challenges"]["dns"]["provider"];
        assert_eq!(
            provider["name"].as_str(),
            Some("cloudflare"),
            "provider name should match"
        );
        assert_eq!(
            provider["api_token"].as_str(),
            Some("{env.CLOUDFLARE_API_TOKEN}"),
            "provider config should be flattened as sibling of name"
        );
        // Check propagation_delay is in challenges.dns, not at issuer level
        assert_eq!(
            policy["issuers"][0]["challenges"]["dns"]["propagation_delay"].as_str(),
            Some("5m"),
            "propagation_delay should be in challenges.dns"
        );
    }

    #[tokio::test]
    async fn test_configure_tls_returns_error_on_post_failure() {
        let (port, state) = start_mock_caddy_with_tls_failure().await;
        let client = CaddyClient::new(format!("http://127.0.0.1:{port}"));
        let tls_config = test_tls_config();

        // Configure mock to fail on POST
        state
            .lock()
            .await
            .insert("__tls_fail__".to_string(), json!(true));

        let result = client
            .configure_tls("preview.example.com", &tls_config)
            .await;
        assert!(
            result.is_err(),
            "configure_tls should return error when POST fails"
        );
        let err = result.unwrap_err();
        assert!(
            matches!(err, CaddyError::TlsConfigFailed(_)),
            "error should be TlsConfigFailed"
        );
    }

    // -----------------------------------------------------------------------
    // SLIP-88: Listener conflict detection tests
    // -----------------------------------------------------------------------

    /// Mock Caddy that returns a config with a conflicting server on :443.
    async fn start_mock_caddy_with_conflict() -> u16 {
        let app = Router::new()
            .route("/config/", get(mock_get_config_with_conflict))
            .route(
                "/load",
                post(|axum::Json(_body): axum::Json<serde_json::Value>| async {
                    StatusCode::INTERNAL_SERVER_ERROR
                }),
            );

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        port
    }

    #[tokio::test]
    async fn test_bootstrap_detects_listener_conflict() {
        let port = start_mock_caddy_with_conflict().await;
        let client = CaddyClient::new(format!("http://127.0.0.1:{port}"));

        let result = client.bootstrap().await;
        assert!(
            result.is_err(),
            "bootstrap should fail on listener conflict"
        );

        let err = result.unwrap_err();
        match &err {
            CaddyError::ListenerConflict { server, listener } => {
                assert_eq!(server, "srv0", "should name the conflicting server");
                assert_eq!(listener, ":443", "should name the conflicting listener");
            }
            other => panic!("expected ListenerConflict, got: {other}"),
        }

        // Verify the error message is prescriptive
        let msg = err.to_string();
        assert!(
            msg.contains("srv0"),
            "error should name the conflicting server"
        );
        assert!(
            msg.contains(":443"),
            "error should name the conflicting listener"
        );
        assert!(
            msg.contains("Caddyfile"),
            "error should mention Caddyfile as the source"
        );
        assert!(
            msg.contains("[deploy]"),
            "error should mention [deploy] as the remedy"
        );
    }

    #[tokio::test]
    async fn test_bootstrap_no_conflict_when_slip_server_exists() {
        // When the slip server already exists, bootstrap should be a no-op
        // even if other servers are present (they coexist).
        let state: MockState = Arc::new(Mutex::new(HashMap::new()));
        state.lock().await.insert(
            "__server__".to_string(),
            json!({"listen": [":443"], "routes": []}),
        );

        let app = Router::new()
            .route("/config/", get(mock_get_config))
            .route("/load", post(mock_load_config))
            .with_state(state.clone());

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let client = CaddyClient::new(format!("http://127.0.0.1:{port}"));
        client
            .bootstrap()
            .await
            .expect("bootstrap should succeed when slip server exists");
    }

    // -----------------------------------------------------------------------
    // SLIP-87: Deploy-webhook bootstrap tests
    // -----------------------------------------------------------------------

    /// Mock Caddy that supports deploy-webhook bootstrap (route + TLS policy).
    async fn start_mock_caddy_for_deploy() -> (u16, MockState) {
        let state: MockState = Arc::new(Mutex::new(HashMap::new()));
        let app = Router::new()
            .route("/config/", get(mock_get_config))
            .route("/load", post(mock_load_config))
            .route(
                "/config/apps/http/servers/slip",
                get(mock_get_server).post(mock_create_server),
            )
            .route(
                "/config/apps/http/servers/slip/routes",
                post(mock_add_route),
            )
            .route("/id/{id}", patch(mock_patch_route))
            .route(
                "/config/apps/tls/automation/policies",
                get(mock_get_tls_policies).post(mock_add_tls_policy),
            )
            .route(
                "/config/apps/tls/automation",
                post(|axum::Json(_body): axum::Json<serde_json::Value>| async { StatusCode::OK }),
            )
            .with_state(state.clone());

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (port, state)
    }

    #[tokio::test]
    async fn test_bootstrap_deploy_creates_route_and_tls_policy() {
        let (port, state) = start_mock_caddy_for_deploy().await;
        let client = CaddyClient::new(format!("http://127.0.0.1:{port}"));

        // First bootstrap the slip server.
        client.bootstrap().await.expect("bootstrap should succeed");

        // Now bootstrap the deploy webhook.
        client
            .bootstrap_deploy(Some("deploy.example.com"), "internal", "127.0.0.1:7890")
            .await
            .expect("bootstrap_deploy should succeed");

        let map = state.lock().await;

        // Verify the route was created with the correct @id.
        assert!(
            map.contains_key("slip-deploy-webhook"),
            "deploy-webhook route should exist"
        );
        let route = &map["slip-deploy-webhook"];
        assert_eq!(
            route["@id"], "slip-deploy-webhook",
            "@id should be slip-deploy-webhook"
        );
        // Verify the upstream dial address.
        let dial = route["handle"][0]["routes"][0]["handle"][0]["upstreams"][0]["dial"]
            .as_str()
            .unwrap_or("");
        assert_eq!(
            dial, "127.0.0.1:7890",
            "should proxy to slipd listen address"
        );

        // Verify the TLS policy was created with issuers (plural!) and internal module.
        let policies = map
            .get("__tls_policies__")
            .expect("TLS policies should exist");
        let arr = policies.as_array().expect("policies should be an array");
        assert_eq!(arr.len(), 1, "should have one TLS policy");
        let policy = &arr[0];
        assert_eq!(
            policy["subjects"][0].as_str(),
            Some("deploy.example.com"),
            "subject should be the deploy domain"
        );
        // CRITICAL: issuers is PLURAL and an ARRAY — the singular form silently fails.
        assert!(
            policy.get("issuers").is_some(),
            "policy should have 'issuers' (plural, array)"
        );
        assert!(
            policy.get("issuer").is_none(),
            "policy should NOT have 'issuer' (singular) — that silently fails"
        );
        assert_eq!(
            policy["issuers"][0]["module"].as_str(),
            Some("internal"),
            "issuer module should be 'internal' (Caddy local CA)"
        );
    }

    #[tokio::test]
    async fn test_bootstrap_deploy_no_domain_is_noop() {
        let (port, state) = start_mock_caddy_for_deploy().await;
        let client = CaddyClient::new(format!("http://127.0.0.1:{port}"));

        client.bootstrap().await.expect("bootstrap should succeed");

        // No domain → no-op.
        client
            .bootstrap_deploy(None, "internal", "127.0.0.1:7890")
            .await
            .expect("bootstrap_deploy with None domain should be a no-op");

        let map = state.lock().await;
        assert!(
            !map.contains_key("slip-deploy-webhook"),
            "no route should be created when domain is None"
        );
        assert!(
            map.get("__tls_policies__").is_none(),
            "no TLS policy should be created when domain is None"
        );
    }

    #[tokio::test]
    async fn test_bootstrap_deploy_updates_existing_route() {
        let (port, state) = start_mock_caddy_for_deploy().await;
        let client = CaddyClient::new(format!("http://127.0.0.1:{port}"));

        client.bootstrap().await.expect("bootstrap should succeed");

        // First call creates the route.
        client
            .bootstrap_deploy(Some("deploy.example.com"), "internal", "127.0.0.1:7890")
            .await
            .expect("first bootstrap_deploy should succeed");

        // Second call with different upstream should update it.
        client
            .bootstrap_deploy(Some("deploy.example.com"), "internal", "127.0.0.1:7891")
            .await
            .expect("second bootstrap_deploy should succeed");

        let map = state.lock().await;
        let route = &map["slip-deploy-webhook"];
        let dial = route["handle"][0]["routes"][0]["handle"][0]["upstreams"][0]["dial"]
            .as_str()
            .unwrap_or("");
        assert_eq!(dial, "127.0.0.1:7891", "should update the upstream address");
    }

    #[tokio::test]
    async fn test_bootstrap_deploy_tls_policy_is_idempotent() {
        let (port, state) = start_mock_caddy_for_deploy().await;
        let client = CaddyClient::new(format!("http://127.0.0.1:{port}"));

        client.bootstrap().await.expect("bootstrap should succeed");

        // First call creates route + TLS policy.
        client
            .bootstrap_deploy(Some("deploy.example.com"), "internal", "127.0.0.1:7890")
            .await
            .expect("first bootstrap_deploy should succeed");

        // Second call should not create a duplicate TLS policy.
        client
            .bootstrap_deploy(Some("deploy.example.com"), "internal", "127.0.0.1:7890")
            .await
            .expect("second bootstrap_deploy should succeed");

        let map = state.lock().await;
        let policies = map
            .get("__tls_policies__")
            .expect("TLS policies should exist");
        let arr = policies.as_array().expect("policies should be an array");
        assert_eq!(
            arr.len(),
            1,
            "should still have exactly one TLS policy (no duplicates)"
        );
    }
}
