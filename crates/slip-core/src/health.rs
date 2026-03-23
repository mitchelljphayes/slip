//! Health check runner — polls container health endpoints before allowing traffic switch.

use tracing::{info, warn};

use crate::config::HealthConfig;
use crate::error::HealthError;

/// Polls a container's HTTP health endpoint until it responds successfully or
/// all retries are exhausted.
pub struct HealthChecker {
    client: reqwest::Client,
}

impl HealthChecker {
    /// Create a new `HealthChecker` with a default [`reqwest::Client`].
    pub fn new() -> Self {
        Self {
            client: reqwest::Client::new(),
        }
    }

    /// Check the health of a container listening on `host_port`.
    ///
    /// - If `config.path` is `None` → returns `Ok(())` immediately.
    /// - Otherwise builds `http://127.0.0.1:{host_port}{path}`, waits
    ///   `start_period`, then polls up to `retries` times with `timeout` per
    ///   request and `interval` between failures.
    pub async fn check(&self, host_port: u16, config: &HealthConfig) -> Result<(), HealthError> {
        let path = match &config.path {
            Some(p) => p.clone(),
            None => return Ok(()),
        };

        let url = format!("http://127.0.0.1:{host_port}{path}");

        // Wait for the container to (hopefully) start before first probe.
        tokio::time::sleep(config.start_period).await;

        for attempt in 1..=config.retries {
            let result = tokio::time::timeout(config.timeout, self.client.get(&url).send()).await;

            let success = match result {
                Ok(Ok(resp)) if resp.status().is_success() => true,
                Ok(Ok(resp)) => {
                    warn!(
                        attempt,
                        status = resp.status().as_u16(),
                        url,
                        "health check returned non-2xx"
                    );
                    false
                }
                Ok(Err(err)) => {
                    warn!(attempt, url, error = %err, "health check request failed");
                    false
                }
                Err(_) => {
                    warn!(attempt, url, "health check timed out");
                    false
                }
            };

            if success {
                info!(attempt, url, "health check passed");
                return Ok(());
            }

            // Sleep between retries, but not after the last attempt.
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

impl Default for HealthChecker {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::time::Duration;

    use axum::http::StatusCode;

    use super::*;

    /// Spawn a tiny axum server that responds to `GET /health`.
    ///
    /// `make_response` is called on each request and returns the status code to
    /// send back.  Returns the local port the server is listening on.
    async fn start_mock_server<F>(make_response: F) -> u16
    where
        F: Fn(u32) -> StatusCode + Send + Sync + 'static,
    {
        let counter = Arc::new(AtomicU32::new(0));
        let handler = Arc::new(make_response);

        let app = axum::Router::new().route(
            "/health",
            axum::routing::get(move || {
                let count = counter.fetch_add(1, Ordering::SeqCst);
                let status = handler(count);
                async move { status }
            }),
        );

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test listener");
        let port = listener.local_addr().unwrap().port();

        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        port
    }

    fn fast_config(path: &str, retries: u32) -> HealthConfig {
        HealthConfig {
            path: Some(path.to_owned()),
            interval: Duration::from_millis(10),
            timeout: Duration::from_millis(100),
            retries,
            start_period: Duration::ZERO,
        }
    }

    // ── healthy on first try ─────────────────────────────────────────────────

    #[tokio::test]
    async fn healthy_on_first_try() {
        let port = start_mock_server(|_| StatusCode::OK).await;
        let checker = HealthChecker::new();
        let config = fast_config("/health", 3);
        checker
            .check(port, &config)
            .await
            .expect("should be healthy");
    }

    // ── healthy after retries ────────────────────────────────────────────────

    #[tokio::test]
    async fn healthy_after_retries() {
        // First 2 calls return 500, 3rd returns 200.
        let port = start_mock_server(|count| {
            if count < 2 {
                StatusCode::INTERNAL_SERVER_ERROR
            } else {
                StatusCode::OK
            }
        })
        .await;

        let checker = HealthChecker::new();
        let config = fast_config("/health", 3);
        checker
            .check(port, &config)
            .await
            .expect("should become healthy after retries");
    }

    // ── unhealthy after all retries ──────────────────────────────────────────

    #[tokio::test]
    async fn unhealthy_after_all_retries() {
        let port = start_mock_server(|_| StatusCode::INTERNAL_SERVER_ERROR).await;
        let checker = HealthChecker::new();
        let config = fast_config("/health", 3);

        let err = checker
            .check(port, &config)
            .await
            .expect_err("should exhaust retries");
        match err {
            HealthError::Unhealthy { retries, url } => {
                assert_eq!(retries, 3);
                assert!(url.contains("/health"), "url should contain path");
            }
        }
    }

    // ── no health path configured ────────────────────────────────────────────

    #[tokio::test]
    async fn no_health_path_returns_ok() {
        let checker = HealthChecker::new();
        let config = HealthConfig {
            path: None,
            ..HealthConfig::default()
        };
        // Should return Ok(()) immediately — no server needed.
        checker
            .check(9999, &config)
            .await
            .expect("no path → always Ok");
    }
}
