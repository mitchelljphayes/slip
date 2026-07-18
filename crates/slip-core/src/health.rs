//! Health check runner — polls container health endpoints before allowing traffic switch.

use tracing::{info, warn};

use crate::config::HealthConfig;
use crate::error::HealthError;
use crate::status_expectation::StatusExpectation;

// ─── Trait ────────────────────────────────────────────────────────────────────

/// Abstraction over container health checking used by the deploy orchestrator.
/// Implemented by [`HealthChecker`]; can be mocked in tests.
pub trait HealthCheck: Send + Sync {
    /// Check the health of a container listening on `host_port`.
    fn check<'a>(
        &'a self,
        host_port: u16,
        config: &'a HealthConfig,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), HealthError>> + Send + 'a>>;
}

impl HealthCheck for HealthChecker {
    fn check<'a>(
        &'a self,
        host_port: u16,
        config: &'a HealthConfig,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), HealthError>> + Send + 'a>>
    {
        Box::pin(HealthChecker::check(self, host_port, config))
    }
}

/// Construct the shared probe client used by both the deploy health checker
/// and the `slip status <app>` sync probe.
///
/// **Does not follow redirects.** `reqwest::redirect::Policy::none()` makes the
/// original response (e.g. a `307`) observable, so `expect_status` can decide
/// whether it counts as healthy. With the default `200-399`, a `307` is
/// accepted; with an explicit `expect_status = "200"` it is rejected (the
/// FN #5 / FR §3.7 fix). See `docs/health.md` §5.
pub(crate) fn probe_client() -> reqwest::Client {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("probe client")
}

/// Shared status matcher used by the deploy health checker and the
/// `slip status <app>` sync probe.
///
/// `expected = None` → resolve to `StatusExpectation::default()` (`200-399`,
/// Kubernetes-compatible). `expected = Some(e)` → `e.accepts(resp.status())`.
/// **No duplicate policy** — both sites call this single function (SLIP-103 D5).
pub(crate) fn status_matches(
    resp: &reqwest::Response,
    expected: Option<&StatusExpectation>,
) -> bool {
    match expected {
        Some(e) => e.accepts(resp.status().as_u16()),
        None => StatusExpectation::default().accepts(resp.status().as_u16()),
    }
}

/// Polls a container's HTTP health endpoint until it responds successfully or
/// all retries are exhausted.
pub struct HealthChecker {
    client: reqwest::Client,
}

impl HealthChecker {
    /// Create a new `HealthChecker` with a no-redirect probe client.
    pub fn new() -> Self {
        Self {
            client: probe_client(),
        }
    }

    /// Borrow the internal HTTP client (used by `slip status` for sync probes).
    pub fn client(&self) -> &reqwest::Client {
        &self.client
    }

    /// Check the health of a container listening on `host_port`.
    ///
    /// - If `config.path` is `None` → waits for `start_period` then returns `Ok(())`.
    ///   This gives the container time to start before traffic is switched.
    /// - Otherwise builds `http://127.0.0.1:{host_port}{path}`, waits
    ///   `start_period`, then polls up to `retries` times with `timeout` per
    ///   request and `interval` between failures.
    ///
    /// The probe client does **not** follow redirects — the original response
    /// status is evaluated against `expect_status` (default `200-399`). If any
    /// attempt received a response whose status was not accepted, the final
    /// error is [`HealthError::UnexpectedStatus`] (carrying `expected`,
    /// `actual`, `url`, `attempts`). If every attempt was a transport/timeout
    /// failure (no response ever received), the final error is
    /// [`HealthError::Unhealthy`] (existing semantics preserved).
    pub async fn check(&self, host_port: u16, config: &HealthConfig) -> Result<(), HealthError> {
        let path = match &config.path {
            Some(p) => p.clone(),
            None => {
                // No health check path configured — wait for start_period to give
                // the container time to initialize, then return success.
                tokio::time::sleep(config.start_period).await;
                return Ok(());
            }
        };

        let url = format!("http://127.0.0.1:{host_port}{path}");
        // Resolve the expectation at probe time (D2): absent → default 200-399.
        let expectation = config.expect_status.clone().unwrap_or_default();
        let expected_canonical = expectation.canonical();

        // Wait for the container to (hopefully) start before first probe.
        tokio::time::sleep(config.start_period).await;

        let mut last_observed_status: Option<u16> = None;

        for attempt in 1..=config.retries {
            let result = tokio::time::timeout(config.timeout, self.client.get(&url).send()).await;

            let success = match result {
                Ok(Ok(resp)) => {
                    let status = resp.status().as_u16();
                    last_observed_status = Some(status);
                    if status_matches(&resp, Some(&expectation)) {
                        true
                    } else {
                        warn!(
                            attempt,
                            status,
                            url,
                            expected = %expected_canonical,
                            "health check returned unexpected status"
                        );
                        false
                    }
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

        // If we ever saw an HTTP response, the failure is an unexpected status;
        // otherwise it's a transport/timeout failure (existing Unhealthy semantics).
        match last_observed_status {
            Some(actual) => Err(HealthError::UnexpectedStatus {
                expected: expected_canonical,
                actual,
                url,
                attempts: config.retries,
            }),
            None => Err(HealthError::Unhealthy {
                retries: config.retries,
                url,
            }),
        }
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
            expect_status: None,
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
    //
    // A 500 response from every attempt is an HTTP response → UnexpectedStatus
    // (the new variant). `Unhealthy` is reserved for transport/timeout failures
    // where no response was ever received.

    #[tokio::test]
    async fn unexpected_status_after_all_retries() {
        let port = start_mock_server(|_| StatusCode::INTERNAL_SERVER_ERROR).await;
        let checker = HealthChecker::new();
        let config = fast_config("/health", 3);

        let err = checker
            .check(port, &config)
            .await
            .expect_err("should exhaust retries");
        match err {
            HealthError::UnexpectedStatus {
                expected,
                actual,
                url,
                attempts,
            } => {
                // Default expectation is 200-399 (probed at runtime).
                assert_eq!(expected, "200-399");
                assert_eq!(actual, 500);
                assert!(url.contains("/health"), "url should contain path");
                assert_eq!(attempts, 3, "retries still apply to unexpected status");
            }
            HealthError::Unhealthy { .. } => {
                panic!("HTTP 500 response must be UnexpectedStatus, not Unhealthy")
            }
        }
    }

    /// Connection refused (no server) → `Unhealthy` (transport-only semantics
    /// preserved). No HTTP response was ever received.
    #[tokio::test]
    async fn transport_failure_is_unhealthy() {
        let checker = HealthChecker::new();
        let config = fast_config("/health", 2);

        // Nothing is listening on this port — every attempt is a connect-refused.
        let err = checker
            .check(1, &config)
            .await
            .expect_err("should fail to connect");
        match err {
            HealthError::Unhealthy { retries, url } => {
                assert_eq!(retries, 2);
                assert!(url.contains("/health"));
            }
            HealthError::UnexpectedStatus { .. } => {
                panic!("transport failure must stay Unhealthy, not UnexpectedStatus")
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

    // ── expect_status matrix (AC6, AC7, AC8) ─────────────────────────────────

    fn config_with_expect(path: &str, retries: u32, expect: &str) -> HealthConfig {
        HealthConfig {
            path: Some(path.to_owned()),
            interval: Duration::from_millis(10),
            timeout: Duration::from_millis(100),
            retries,
            start_period: Duration::ZERO,
            expect_status: Some(StatusExpectation::parse(expect).unwrap()),
        }
    }

    /// AC6: explicit `expect_status = "200"` rejects an initial 307 (no
    /// redirects followed).
    #[tokio::test]
    async fn explicit_200_rejects_307_no_redirect() {
        let port = start_mock_server(|_| StatusCode::TEMPORARY_REDIRECT).await;
        let checker = HealthChecker::new();
        let config = config_with_expect("/health", 2, "200");

        let err = checker
            .check(port, &config)
            .await
            .expect_err("307 must not be healthy under expect_status=200");
        match err {
            HealthError::UnexpectedStatus {
                expected, actual, ..
            } => {
                assert_eq!(expected, "200");
                assert_eq!(actual, 307, "307 observed, not chased (Policy::none())");
            }
            other => panic!("expected UnexpectedStatus, got {other:?}"),
        }
    }

    /// AC7 part 1: default (None) accepts 307 because the default 200-399
    /// includes 307.
    #[tokio::test]
    async fn default_accepts_307() {
        let port = start_mock_server(|_| StatusCode::TEMPORARY_REDIRECT).await;
        let checker = HealthChecker::new();
        let config = fast_config("/health", 2); // expect_status = None → default 200-399
        checker
            .check(port, &config)
            .await
            .expect("default 200-399 must accept 307");
    }

    /// AC7 part 2: explicit `expect_status = "200,307"` accepts 307.
    #[tokio::test]
    async fn explicit_list_accepts_307() {
        let port = start_mock_server(|_| StatusCode::TEMPORARY_REDIRECT).await;
        let checker = HealthChecker::new();
        let config = config_with_expect("/health", 2, "200,307");
        checker
            .check(port, &config)
            .await
            .expect("explicit list including 307 must accept it");
    }

    /// Range `200-299` accepts 204; rejects 300.
    #[tokio::test]
    async fn range_accepts_in_range_rejects_outside() {
        let port_204 = start_mock_server(|_| StatusCode::NO_CONTENT).await;
        let checker = HealthChecker::new();
        let config = config_with_expect("/health", 2, "200-299");
        checker
            .check(port_204, &config)
            .await
            .expect("204 is in 200-299");

        let port_300 = start_mock_server(|_| StatusCode::MULTIPLE_CHOICES).await;
        let err = checker
            .check(port_300, &config)
            .await
            .expect_err("300 is outside 200-299");
        match err {
            HealthError::UnexpectedStatus { actual, .. } => assert_eq!(actual, 300),
            other => panic!("expected UnexpectedStatus, got {other:?}"),
        }
    }

    /// AC8: retries still apply to unexpected status. A 500 returned on every
    /// attempt exhausts the retry budget and surfaces `UnexpectedStatus` with
    /// `attempts = retries`.
    #[tokio::test]
    async fn unexpected_status_retries_still_apply() {
        let port = start_mock_server(|_| StatusCode::INTERNAL_SERVER_ERROR).await;
        let checker = HealthChecker::new();
        let config = config_with_expect("/health", 4, "200");

        let err = checker
            .check(port, &config)
            .await
            .expect_err("must exhaust");
        match err {
            HealthError::UnexpectedStatus {
                expected,
                actual,
                attempts,
                ..
            } => {
                assert_eq!(expected, "200");
                assert_eq!(actual, 500);
                assert_eq!(attempts, 4, "retries budget honored");
            }
            other => panic!("expected UnexpectedStatus, got {other:?}"),
        }
    }

    /// Mixed range + single: `200-299,503` accepts 200 and 503.
    #[tokio::test]
    async fn mixed_range_and_single() {
        let port_200 = start_mock_server(|_| StatusCode::OK).await;
        let port_503 = start_mock_server(|_| StatusCode::SERVICE_UNAVAILABLE).await;
        let checker = HealthChecker::new();
        let config = config_with_expect("/health", 2, "200-299,503");
        checker
            .check(port_200, &config)
            .await
            .expect("200 in 200-299,503");
        checker
            .check(port_503, &config)
            .await
            .expect("503 explicitly accepted");
    }

    /// Slow server (per-request timeout, no response) → `Unhealthy` (existing
    /// timeout semantics preserved — AC10).
    #[tokio::test]
    async fn slow_server_times_out_as_unhealthy() {
        let checker = HealthChecker::new();
        // Bind a socket but never accept — the connect hangs and times out.
        // Simpler: spawn a server that sleeps longer than the per-request timeout.
        let app = axum::Router::new().route(
            "/health",
            axum::routing::get(|| async {
                tokio::time::sleep(Duration::from_secs(5)).await;
                StatusCode::OK
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let mut config = fast_config("/health", 1);
        config.timeout = Duration::from_millis(50);
        let err = checker
            .check(port, &config)
            .await
            .expect_err("must time out");
        match err {
            HealthError::Unhealthy { .. } => {}
            HealthError::UnexpectedStatus { .. } => {
                panic!("timeout (no response) must be Unhealthy, not UnexpectedStatus")
            }
        }
    }

    /// `Policy::none()` is actually set: a 307 must be observed (not chased).
    /// The fact that the unexpected-status path sees `actual == 307` proves it.
    /// This test exists as an explicit guard in case a future refactor
    /// accidentally swaps the client back to the default redirect policy.
    #[tokio::test]
    async fn policy_none_is_observed_via_307() {
        let port = start_mock_server(|_| StatusCode::TEMPORARY_REDIRECT).await;
        let checker = HealthChecker::new();
        let config = config_with_expect("/health", 1, "200");
        let err = checker.check(port, &config).await.expect_err("must fail");
        match err {
            HealthError::UnexpectedStatus { actual: 307, .. } => {}
            other => panic!("expected to observe the original 307, got {other:?}"),
        }
    }
}
