//! Caddy admin API client for dynamic route management.

use crate::config::CaddyTlsConfig;
use crate::error::CaddyError;
use serde_json::json;

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
}

impl ReverseProxy for CaddyClient {
    fn set_route<'a>(
        &'a self,
        app_name: &'a str,
        domain: &'a str,
        upstream_port: u16,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), CaddyError>> + Send + 'a>>
    {
        Box::pin(CaddyClient::set_route(
            self,
            app_name,
            domain,
            upstream_port,
        ))
    }

    fn remove_route<'a>(
        &'a self,
        app_name: &'a str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), CaddyError>> + Send + 'a>>
    {
        Box::pin(CaddyClient::remove_route(self, app_name))
    }
}

/// Info needed to reconcile a single app's route.
pub struct RouteInfo {
    pub app_name: String,
    pub domain: String,
    pub port: u16,
}

/// Client for the Caddy admin API.
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
    pub async fn bootstrap(&self) -> Result<(), CaddyError> {
        let url = format!("{}/config/apps/http/servers/slip", self.base_url);
        let resp = self.client.get(&url).send().await?;
        if resp.status().is_success() {
            // Server block already exists — nothing to do.
            return Ok(());
        }

        // Create the server block.
        let body = json!({
            "listen": [":443"],
            "routes": []
        });
        let create_resp = self.client.post(&url).json(&body).send().await?;

        if create_resp.status().is_success() {
            Ok(())
        } else {
            let status = create_resp.status();
            let text = create_resp.text().await.unwrap_or_default();
            Err(CaddyError::BootstrapFailed(format!(
                "POST {url} returned {status}: {text}"
            )))
        }
    }

    /// Create or update the reverse-proxy route for an app.
    pub async fn set_route(
        &self,
        app_name: &str,
        domain: &str,
        upstream_port: u16,
    ) -> Result<(), CaddyError> {
        let route_id = format!("slip-{app_name}");
        let route = json!({
            "@id": route_id,
            "match": [{"host": [domain]}],
            "handle": [{
                "handler": "subroute",
                "routes": [{
                    "handle": [{
                        "handler": "reverse_proxy",
                        "upstreams": [{"dial": format!("localhost:{upstream_port}")}]
                    }]
                }]
            }],
            "terminal": true
        });

        // Try to update an existing route via @id.
        let patch_url = format!("{}/id/{route_id}", self.base_url);
        let patch_resp = self.client.patch(&patch_url).json(&route).send().await?;
        if patch_resp.status().is_success() {
            return Ok(());
        }

        // Route didn't exist — append it.
        let post_url = format!("{}/config/apps/http/servers/slip/routes", self.base_url);
        let post_resp = self.client.post(&post_url).json(&route).send().await?;
        if post_resp.status().is_success() {
            Ok(())
        } else {
            let status = post_resp.status();
            let text = post_resp.text().await.unwrap_or_default();
            Err(CaddyError::RouteUpdateFailed(format!(
                "POST {post_url} returned {status}: {text}"
            )))
        }
    }

    /// Remove the reverse-proxy route for an app.
    ///
    /// A 404 response is treated as success (route already gone).
    pub async fn remove_route(&self, app_name: &str) -> Result<(), CaddyError> {
        let route_id = format!("slip-{app_name}");
        let url = format!("{}/id/{route_id}", self.base_url);
        let resp = self.client.delete(&url).send().await?;

        if resp.status().is_success() || resp.status() == reqwest::StatusCode::NOT_FOUND {
            Ok(())
        } else {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            Err(CaddyError::RouteUpdateFailed(format!(
                "DELETE {url} returned {status}: {text}"
            )))
        }
    }

    /// Reconcile all routes from a slice of `RouteInfo`.
    ///
    /// Calls `set_route` for every entry. Returns the first error encountered.
    pub async fn reconcile(&self, routes: &[RouteInfo]) -> Result<(), CaddyError> {
        for route in routes {
            self.set_route(&route.app_name, &route.domain, route.port)
                .await?;
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
            map.contains_key("slip-walden-api"),
            "route should have been stored"
        );
        assert_eq!(
            map["slip-walden-api"]["@id"], "slip-walden-api",
            "@id field should match"
        );
    }

    #[tokio::test]
    async fn test_set_route_updates_existing_route() {
        let (port, state) = start_mock_caddy().await;
        let client = CaddyClient::new(format!("http://127.0.0.1:{port}"));

        // Pre-populate a route so PATCH will succeed.
        state.lock().await.insert(
            "slip-myapp".to_string(),
            json!({"@id": "slip-myapp", "port": 9000}),
        );

        client
            .set_route("myapp", "myapp.example.com", 9001)
            .await
            .expect("set_route update should succeed");

        let map = state.lock().await;
        // The route should now reflect the new upstream port.
        let route = &map["slip-myapp"];
        let dial = route["handle"][0]["routes"][0]["handle"][0]["upstreams"][0]["dial"]
            .as_str()
            .unwrap_or("");
        assert_eq!(dial, "localhost:9001", "dial address should be updated");
    }

    #[tokio::test]
    async fn test_remove_route_removes_existing_route() {
        let (port, state) = start_mock_caddy().await;
        let client = CaddyClient::new(format!("http://127.0.0.1:{port}"));

        state
            .lock()
            .await
            .insert("slip-todelete".to_string(), json!({"@id": "slip-todelete"}));

        client
            .remove_route("todelete")
            .await
            .expect("remove_route should succeed");

        assert!(
            !state.lock().await.contains_key("slip-todelete"),
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
            map.contains_key("slip-app-one"),
            "app-one should be registered"
        );
        assert!(
            map.contains_key("slip-app-two"),
            "app-two should be registered"
        );
        assert!(
            map.contains_key("slip-app-three"),
            "app-three should be registered"
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
}
