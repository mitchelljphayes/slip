//! Caddy admin API client for dynamic route management.

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
    use std::{
        collections::HashMap,
        sync::{Arc, Mutex},
    };

    type MockState = Arc<Mutex<HashMap<String, serde_json::Value>>>;

    // -----------------------------------------------------------------------
    // Mock handler implementations
    // -----------------------------------------------------------------------

    async fn mock_get_server(State(state): State<MockState>) -> StatusCode {
        let map = state.lock().unwrap();
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
        let mut map = state.lock().unwrap();
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
        let mut map = state.lock().unwrap();
        map.insert(id, body);
        StatusCode::OK
    }

    async fn mock_patch_route(
        State(state): State<MockState>,
        Path(id): Path<String>,
        axum::Json(body): axum::Json<serde_json::Value>,
    ) -> StatusCode {
        let mut map = state.lock().unwrap();
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
        let mut map = state.lock().unwrap();
        if map.remove(&id).is_some() {
            StatusCode::OK
        } else {
            StatusCode::NOT_FOUND
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

        assert!(!state.lock().unwrap().contains_key("__server__"));

        client.bootstrap().await.expect("bootstrap should succeed");

        assert!(
            state.lock().unwrap().contains_key("__server__"),
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
            .unwrap()
            .insert("__server__".to_string(), json!({"listen": [":443"]}));

        // Should not fail and should not change the existing value.
        client
            .bootstrap()
            .await
            .expect("idempotent bootstrap should succeed");

        let map = state.lock().unwrap();
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

        let map = state.lock().unwrap();
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
        state.lock().unwrap().insert(
            "slip-myapp".to_string(),
            json!({"@id": "slip-myapp", "port": 9000}),
        );

        client
            .set_route("myapp", "myapp.example.com", 9001)
            .await
            .expect("set_route update should succeed");

        let map = state.lock().unwrap();
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
            .unwrap()
            .insert("slip-todelete".to_string(), json!({"@id": "slip-todelete"}));

        client
            .remove_route("todelete")
            .await
            .expect("remove_route should succeed");

        assert!(
            !state.lock().unwrap().contains_key("slip-todelete"),
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

        let map = state.lock().unwrap();
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
}
