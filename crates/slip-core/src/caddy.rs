//! Caddy admin API client for dynamic route management.

use crate::config::{CaddyTlsConfig, NON_PUBLIC_TLDS, TlsStrategy, is_ts_net_host};
use crate::error::CaddyError;
use serde_json::{Value, json};
use std::net::IpAddr;

// ─── Types ─────────────────────────────────────────────────────────────────────

/// A single route to be registered with the reverse proxy.
#[derive(Debug, Clone)]
pub struct Route {
    pub hostname: String,
    pub port: u16,
}

// ─── Pure TLS policy builder ───────────────────────────────────────────────────

/// Default production Let's Encrypt ACME directory.
const DEFAULT_ACME_CA: &str = "https://acme-v02.api.letsencrypt.org/directory";

/// Build a Caddy TLS automation policy as a pure `serde_json::Value`.
///
/// This is the single, generalized policy builder for all four strategies.
/// It does NOT talk to Caddy — it's pure and unit-testable in isolation.
///
/// # Arguments
/// * `subjects` — the host(s) this policy applies to (e.g. `["deploy.example.com"]`,
///   `["*.preview.example.com"]`).
/// * `strategy` — the TLS strategy.
/// * `dns_config` — DNS-01 provider config (required for `CloudflareDns01`).
/// * `acme_email` — ACME contact email (required for `Acme`/`CloudflareDns01`).
/// * `ca_url` — ACME CA URL override (None = production LE directory).
///
/// # Output shapes
/// - `Internal` → `{"subjects":[...], "issuers":[{"module":"internal"}]}`
/// - `Acme` → `{"subjects":[...], "issuers":[{"module":"acme","ca":...,"email":...}]}`
/// - `CloudflareDns01` → the existing `configure_tls` shape, parameterized by `subjects`.
/// - `Tailscale` → `{"subjects":[...], "get_certificate":[{"via":"tailscale"}]}` — NO `issuers`.
pub fn build_tls_policy(
    subjects: &[String],
    strategy: TlsStrategy,
    dns_config: Option<&CaddyTlsConfig>,
    acme_email: Option<&str>,
    ca_url: Option<&str>,
) -> Value {
    let subjects_json: Vec<Value> = subjects.iter().map(|s| Value::from(s.as_str())).collect();
    match strategy {
        TlsStrategy::Internal => json!({
            "subjects": subjects_json,
            "issuers": [{"module": "internal"}]
        }),
        TlsStrategy::Acme => {
            let ca = ca_url.unwrap_or(DEFAULT_ACME_CA);
            let mut issuer = json!({
                "module": "acme",
                "ca": ca,
            });
            if let Some(email) = acme_email {
                issuer["email"] = Value::from(email);
            }
            json!({
                "subjects": subjects_json,
                "issuers": [issuer]
            })
        }
        TlsStrategy::CloudflareDns01 => {
            let dns = dns_config.expect("CloudflareDns01 requires dns_config");
            let ca = ca_url.unwrap_or(if dns.staging {
                "https://acme-staging-v02.api.letsencrypt.org/directory"
            } else {
                DEFAULT_ACME_CA
            });

            // Build the DNS provider config (same shape as configure_tls).
            // Provider config fields are siblings of "name", not nested.
            let mut provider = json!({"name": dns.dns_provider});
            if let Some(config_table) = &dns.dns_provider_config {
                for (key, value) in config_table {
                    provider[key] = serde_json::to_value(value).unwrap_or(json!(null));
                }
            }

            let mut issuer = json!({
                "module": "acme",
                "ca": ca,
                "challenges": {
                    "dns": {
                        "provider": provider,
                        "propagation_delay": dns.propagation_delay,
                    }
                }
            });
            if let Some(email) = acme_email {
                issuer["email"] = Value::from(email);
            }

            json!({
                "subjects": subjects_json,
                "issuers": [issuer]
            })
        }
        TlsStrategy::Tailscale => {
            // Tailscale is a certificate MANAGER, not an issuer.
            // Caddy's implicitTailscaleManagersOnly() skips ACME provisioning
            // for all-.ts.net subjects with a Tailscale manager.
            // NO issuers[] key — adding one would cause public-CA log spam.
            json!({
                "subjects": subjects_json,
                "get_certificate": [{"via": "tailscale"}]
            })
        }
    }
}

// ─── Certificate probe (TLS handshake with SNI → leaf cert metadata) ──────────

/// Observed certificate metadata from a TLS handshake.
///
/// Used by `slip tls renew` to prove a certificate actually changed (fingerprint
/// and/or `notAfter` advanced) rather than relying on config/reload alone.
/// This is **observation only** — the TLS connection accepts any server
/// certificate (including self-signed/internal) without verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertProbe {
    /// SHA-256 fingerprint of the leaf certificate (hex).
    pub fingerprint: String,
    /// `notAfter` as an RFC 3339 string (e.g. `"2026-10-30T00:00:00Z"`), or
    /// `None` if the cert could not be parsed.
    pub not_after: Option<String>,
}

/// Probe a host's served TLS certificate by performing a raw TLS handshake
/// with SNI, accepting any certificate (including self-signed/internal).
///
/// Connects to `host:443`, does a TLS handshake with SNI=`host`, reads the
/// leaf certificate, and returns its SHA-256 fingerprint + notAfter.
///
/// This is **observation only** — no certificate verification is performed.
/// The purpose is to read public metadata (fingerprint, notAfter) to prove
/// that a renewal actually occurred, not to validate trust.
///
/// Returns `Ok(Some(probe))` on success, `Ok(None)` if no cert was served
/// (TLS handshake failed or no cert in chain), or `Err` on connection error.
pub async fn probe_cert(host: &str) -> Result<Option<CertProbe>, String> {
    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
    use rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};
    use tokio_rustls::TlsConnector;

    // A verifier that accepts any certificate — observation only.
    #[derive(Debug)]
    struct NoVerify;

    impl ServerCertVerifier for NoVerify {
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp_response: &[u8],
            _now: UnixTime,
        ) -> Result<ServerCertVerified, rustls::Error> {
            Ok(ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            vec![
                SignatureScheme::RSA_PKCS1_SHA256,
                SignatureScheme::ECDSA_NISTP256_SHA256,
                SignatureScheme::RSA_PSS_SHA256,
                SignatureScheme::RSA_PKCS1_SHA384,
                SignatureScheme::ECDSA_NISTP384_SHA384,
                SignatureScheme::RSA_PSS_SHA384,
                SignatureScheme::ED25519,
            ]
        }
    }

    let config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(std::sync::Arc::new(NoVerify))
        .with_no_client_auth();

    let connector = TlsConnector::from(std::sync::Arc::new(config));

    let addr = format!("{host}:443");
    let tcp = match tokio::time::timeout(
        std::time::Duration::from_secs(10),
        tokio::net::TcpStream::connect(&addr),
    )
    .await
    {
        Ok(Ok(stream)) => stream,
        Ok(Err(e)) => return Err(format!("TCP connect to {addr} failed: {e}")),
        Err(_) => return Err(format!("TCP connect to {addr} timed out (10s)")),
    };

    let server_name = ServerName::try_from(host.to_string())
        .map_err(|e| format!("invalid server name '{host}': {e}"))?;

    let tls_stream = match tokio::time::timeout(
        std::time::Duration::from_secs(10),
        connector.connect(server_name, tcp),
    )
    .await
    {
        Ok(Ok(stream)) => stream,
        Ok(Err(e)) => return Err(format!("TLS handshake to {host}:443 failed: {e}")),
        Err(_) => return Err(format!("TLS handshake to {host}:443 timed out (10s)")),
    };

    // Extract the leaf certificate from the peer cert chain.
    let cert_chain = tls_stream.get_ref().1.peer_certificates();

    let Some(leaf) = cert_chain.and_then(|c| c.first()) else {
        return Ok(None);
    };

    // Compute SHA-256 fingerprint of the DER-encoded leaf cert.
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(leaf.as_ref());
    let fingerprint = hex::encode(hasher.finalize());

    // Parse notAfter using x509-parser.
    let not_after = parse_cert_not_after(leaf.as_ref());

    Ok(Some(CertProbe {
        fingerprint,
        not_after,
    }))
}

/// Parse the `notAfter` field from a DER-encoded X.509 certificate.
///
/// Returns an RFC 3339 string, or `None` if parsing fails.
pub fn parse_cert_not_after(der: &[u8]) -> Option<String> {
    use x509_parser::parse_x509_certificate;

    let (_, cert) = parse_x509_certificate(der).ok()?;
    let ts = cert.validity().not_after.timestamp();
    let dt = chrono::DateTime::from_timestamp(ts, 0)?;
    Some(dt.format("%Y-%m-%dT%H:%M:%SZ").to_string())
}

/// Compare two cert probes to determine if renewal occurred.
///
/// Returns `true` if the fingerprint changed OR the notAfter advanced
/// (including absent→present). Returns `false` if both are identical
/// or both are absent.
pub fn cert_renewed(before: Option<&CertProbe>, after: Option<&CertProbe>) -> bool {
    match (before, after) {
        (None, Some(_)) => true, // absent → valid cert
        (Some(b), Some(a)) => {
            b.fingerprint != a.fingerprint    // fingerprint changed
                || match (&b.not_after, &a.not_after) {
                    (Some(bn), Some(an)) => an > bn, // notAfter advanced
                    (None, Some(_)) => true,         // notAfter absent → present
                    _ => false,
                }
        }
        _ => false,
    }
}

/// Classification of a host for auto-internal TLS.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsClassification {
    /// Host is non-public (TLD in allowlist or private/CGNAT IP literal) →
    /// auto-internal when no explicit TLS is set.
    NonPublic,
    /// Host is public → leave Caddy's automatic HTTPS untouched.
    Public,
}

/// Classify a host as non-public or public based on the TLD allowlist and
/// IP-literal checks (no live DNS resolution).
///
/// - TLD suffix match against `NON_PUBLIC_TLDS` → `NonPublic`.
/// - IP literal → private/CGNAT check via `is_private_or_cgnat`.
/// - `.ts.net` → always `Public` (handled by Tailscale manager, never internal).
pub fn classify_host_tls(host: &str) -> TlsClassification {
    // .ts.net is never auto-internal — handled by Tailscale manager.
    if is_ts_net_host(host) {
        return TlsClassification::Public;
    }
    // TLD suffix check.
    for tld in NON_PUBLIC_TLDS {
        if host.ends_with(tld) {
            return TlsClassification::NonPublic;
        }
    }
    // IP literal check.
    if let Ok(ip) = host.parse::<IpAddr>()
        && crate::doctor::is_private_or_cgnat(&ip)
    {
        return TlsClassification::NonPublic;
    }
    TlsClassification::Public
}

/// Decision for a route's TLS policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouteTlsDecision {
    /// Apply the given strategy (explicit override or auto-internal).
    Apply(TlsStrategy),
    /// Leave Caddy's default automatic HTTPS untouched (public absent-TLS).
    LeaveDefault,
}

/// Resolve the effective TLS decision for a route.
///
/// - Explicit `tls` override always wins.
/// - Absent TLS + non-public host → `Apply(Internal)` (kills LE spam).
/// - Absent TLS + public host → `LeaveDefault` (correction #3: no synthesized ACME).
pub fn resolve_route_tls(host: &str, explicit: Option<TlsStrategy>) -> RouteTlsDecision {
    if let Some(s) = explicit {
        return RouteTlsDecision::Apply(s);
    }
    match classify_host_tls(host) {
        TlsClassification::NonPublic => RouteTlsDecision::Apply(TlsStrategy::Internal),
        TlsClassification::Public => RouteTlsDecision::LeaveDefault,
    }
}

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
            client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .unwrap_or_else(|_| reqwest::Client::new()),
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
    /// * `tls_strategy` - TLS strategy (`TlsStrategy::Internal`, etc.).
    /// * `upstream_addr` - The slipd listen address (e.g. `"127.0.0.1:7890"`).
    /// * `acme_email` - Resolved ACME email (from `[caddy] acme_email` or fallback).
    /// * `dns_config` - DNS-01 config (required for `CloudflareDns01`).
    /// * `ca_url` - ACME CA URL override (None = production LE).
    pub async fn bootstrap_deploy(
        &self,
        domain: Option<&str>,
        tls_strategy: &TlsStrategy,
        upstream_addr: &str,
        acme_email: Option<&str>,
        dns_config: Option<&CaddyTlsConfig>,
        ca_url: Option<&str>,
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
        let subjects = vec![domain.to_string()];
        let policy = build_tls_policy(&subjects, *tls_strategy, dns_config, acme_email, ca_url);
        self.upsert_tls_policy(&subjects, &policy).await?;

        Ok(())
    }

    /// Idempotent upsert of a TLS automation policy.
    ///
    /// Assigns a stable `@id = "slip-tls-<first-subject>"` to slip-owned policies.
    /// If a policy with matching `@id` already exists:
    /// - If the existing policy body matches the desired policy → no-op (idempotent).
    /// - If the body differs (strategy transition, reconcile repair) → replace
    ///   by DELETE + POST (not silent no-op).
    ///   If no matching `@id` → ensure parent path exists, then POST (append).
    ///
    ///
    /// Works for both `issuers`-based and `get_certificate`-based policies.
    pub async fn upsert_tls_policy(
        &self,
        subjects: &[String],
        policy: &Value,
    ) -> Result<(), CaddyError> {
        // Derive the stable @id from the first subject.
        let policy_id = tls_policy_id(subjects.first().map(|s| s.as_str()).unwrap_or("unknown"));

        let policies_url = format!("{}/config/apps/tls/automation/policies", self.base_url);
        let resp = self.client.get(&policies_url).send().await?;

        let mut existing_index: Option<usize> = None;
        let mut existing_body: Option<Value> = None;
        if resp.status().is_success() {
            let policies: Vec<Value> = resp.json().await.unwrap_or_default();
            for (i, existing) in policies.iter().enumerate() {
                // Match by @id (stable) or by subjects (fallback for pre-@id policies).
                let id_match = existing
                    .get("@id")
                    .and_then(|v| v.as_str())
                    .map(|s| s == policy_id)
                    .unwrap_or(false);
                let subject_match = existing
                    .get("subjects")
                    .and_then(|s| s.as_array())
                    .map(|subjects_arr| {
                        subjects_arr.iter().any(|s| {
                            s.as_str()
                                .map(|subj| subjects.iter().any(|req| req == subj))
                                .unwrap_or(false)
                        })
                    })
                    .unwrap_or(false);
                if id_match || subject_match {
                    existing_index = Some(i);
                    existing_body = Some(existing.clone());
                    break;
                }
            }
        }

        if let Some(existing) = &existing_body {
            // Compare bodies (ignoring @id which we add to the desired policy).
            let mut desired = policy.clone();
            if let Some(d_obj) = desired.as_object_mut() {
                d_obj.insert("@id".to_string(), Value::String(policy_id.clone()));
            }
            // Strip @id from existing for comparison if present.
            let mut existing_cmp = existing.clone();
            if let Some(e_obj) = existing_cmp.as_object_mut() {
                e_obj.remove("@id");
            }
            if existing_cmp == *policy {
                // Bodies match (ignoring @id) — idempotent no-op.
                return Ok(());
            }
            // Bodies differ — replace. DELETE the old policy, then POST the new one.
            // Prefer DELETE by @id (stable) over positional index (TOCTOU-safe).
            tracing::info!(
                policy_id = %policy_id,
                "replacing existing TLS policy (strategy transition or reconcile repair)"
            );
            // If the existing policy has an @id, DELETE via /id/<@id>.
            // Otherwise fall back to positional index (legacy policies).
            let existing_id = existing
                .get("@id")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            let delete_result = if let Some(ref existing_policy_id) = existing_id {
                let delete_url = format!("{}/id/{}", self.base_url, existing_policy_id);
                self.client.delete(&delete_url).send().await
            } else {
                let delete_url = format!(
                    "{}/config/apps/tls/automation/policies/{}",
                    self.base_url,
                    existing_index.unwrap()
                );
                self.client.delete(&delete_url).send().await
            };
            let _ = delete_result; // best-effort: if DELETE fails, POST may still work
        }

        // Ensure the parent TLS automation path exists.
        let automation_url = format!("{}/config/apps/tls/automation", self.base_url);
        let automation_body = json!({"policies": []});
        let _ = self
            .client
            .post(&automation_url)
            .json(&automation_body)
            .send()
            .await;

        // Append the policy with @id.
        let mut policy_with_id = policy.clone();
        if let Some(obj) = policy_with_id.as_object_mut() {
            obj.insert("@id".to_string(), Value::String(policy_id));
        }
        let post_url = format!("{}/config/apps/tls/automation/policies", self.base_url);
        let post_resp = self
            .client
            .post(&post_url)
            .json(&policy_with_id)
            .send()
            .await?;
        if !post_resp.status().is_success() {
            let status = post_resp.status();
            let text = post_resp.text().await.unwrap_or_default();
            return Err(CaddyError::TlsConfigFailed(format!(
                "POST {post_url} returned {status}: {text}"
            )));
        }

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
        let subjects = vec![wildcard_subject.clone()];

        // Build the policy via the generalized builder.
        // The email comes from CaddyTlsConfig.email (the preview TLS config).
        let policy = build_tls_policy(
            &subjects,
            TlsStrategy::CloudflareDns01,
            Some(tls_config),
            Some(&tls_config.email),
            None, // CA URL is derived from tls_config.staging inside the builder
        );

        self.upsert_tls_policy(&subjects, &policy).await
    }

    /// Query Caddy's TLS automation policies to determine the certificate
    /// issuer for a given domain.
    ///
    /// Returns `Ok(Some(issuer_string))` where issuer is `"internal"`
    /// (self-signed) or `"acme"` (Let's Encrypt / ACME). Returns `Ok(None)`
    /// when no matching policy is found (Caddy's default issuer is ACME).
    pub async fn get_tls_issuer(&self, domain: &str) -> Result<Option<String>, CaddyError> {
        let policies_url = format!("{}/config/apps/tls/automation/policies", self.base_url);
        let resp = self.client.get(&policies_url).send().await?;

        if !resp.status().is_success() {
            // No TLS automation config → Caddy uses ACME by default.
            return Ok(None);
        }

        let policies: Vec<serde_json::Value> = resp.json().await.unwrap_or_default();

        for policy in policies {
            // Check if this policy's subjects include the domain or a wildcard
            // that matches it.
            if let Some(subjects) = policy.get("subjects").and_then(|s| s.as_array()) {
                let matches = subjects.iter().any(|s| {
                    s.as_str()
                        .map(|subj| domain == subj || is_wildcard_match(subj, domain))
                        .unwrap_or(false)
                });
                if matches {
                    // Determine issuer module.
                    if let Some(issuers) = policy.get("issuers").and_then(|i| i.as_array())
                        && let Some(first_issuer) = issuers.first()
                        && let Some(module) = first_issuer.get("module").and_then(|m| m.as_str())
                    {
                        return Ok(Some(module.to_string()));
                    }
                    return Ok(Some("unknown".to_string()));
                }
            }
        }

        // No matching policy → Caddy default is ACME.
        Ok(None)
    }

    /// Query Caddy's loaded module inventory via `GET /modules/`.
    ///
    /// Returns the raw JSON object mapping namespace → list of module IDs.
    /// On HTTP failure, returns `Err` (caller can fall back to binary check).
    pub async fn list_modules(&self) -> Result<Value, CaddyError> {
        let url = format!("{}/modules/", self.base_url);
        let resp = self.client.get(&url).send().await?;
        if !resp.status().is_success() {
            return Err(CaddyError::Http(resp.error_for_status().unwrap_err()));
        }
        resp.json().await.map_err(CaddyError::Http)
    }

    /// Check if a DNS provider plugin is compiled into the running Caddy.
    ///
    /// Queries `GET /modules/` and checks the `dns.providers` array for `name`.
    /// On HTTP failure (admin API unreachable), falls back to the SLIP-102
    /// `caddy list-modules` binary check via `parse_caddy_modules`.
    ///
    /// Returns `Ok(true)` if found, `Ok(false)` if not found (or absent),
    /// `Err` only if both the admin API AND the binary check fail.
    pub async fn has_dns_provider(&self, name: &str) -> Result<bool, CaddyError> {
        // Try GET /modules/ first (authoritative).
        match self.list_modules().await {
            Ok(modules) => {
                if let Some(providers) = modules.get("dns.providers").and_then(|p| p.as_array()) {
                    return Ok(providers
                        .iter()
                        .any(|p| p.as_str().map(|s| s == name).unwrap_or(false)));
                }
                Ok(false)
            }
            Err(_) => {
                // Fallback: run `caddy list-modules` binary check (SLIP-102).
                let output = std::process::Command::new("caddy")
                    .args(["list-modules"])
                    .output();
                match output {
                    Ok(o) if o.status.success() => {
                        let stdout = String::from_utf8_lossy(&o.stdout);
                        let status = crate::doctor::parse_caddy_modules(&stdout, Some(name));
                        Ok(status == crate::doctor::CheckStatus::Pass)
                    }
                    Ok(_) => {
                        // Binary exists but failed — treat as "not found".
                        tracing::warn!(
                            "caddy list-modules binary check failed — \
                             cannot verify DNS plugin presence"
                        );
                        Ok(false)
                    }
                    Err(_) => {
                        // No caddy binary and no admin API — cannot verify.
                        tracing::warn!(
                            "cannot verify DNS plugin: GET /modules/ failed and \
                             `caddy` binary not found on $PATH"
                        );
                        Ok(false)
                    }
                }
            }
        }
    }

    /// Check if a certificate manager module is compiled into the running Caddy.
    ///
    /// Queries `GET /modules/` and checks the `tls.get_certificate` array for
    /// `name`. Used for the Tailscale manager (core in Caddy v2.5+, but
    /// verified for old-Caddy detection).
    pub async fn has_cert_manager(&self, name: &str) -> Result<bool, CaddyError> {
        let modules = self.list_modules().await?;
        if let Some(managers) = modules
            .get("tls.get_certificate")
            .and_then(|m| m.as_array())
        {
            Ok(managers
                .iter()
                .any(|m| m.as_str().map(|s| s == name).unwrap_or(false)))
        } else {
            Ok(false)
        }
    }

    /// Get the TLS automation policy matching a host's subjects.
    ///
    /// Matches by exact subject OR wildcard (e.g. `*.example.com` matches
    /// `foo.example.com`). Returns `Ok(Some(policy))` if found, `Ok(None)` if
    /// no matching policy.
    pub async fn get_tls_policy(&self, host: &str) -> Result<Option<Value>, CaddyError> {
        let policies_url = format!("{}/config/apps/tls/automation/policies", self.base_url);
        let resp = self.client.get(&policies_url).send().await?;
        if !resp.status().is_success() {
            return Ok(None);
        }
        let policies: Vec<Value> = resp.json().await.unwrap_or_default();
        for policy in policies {
            if let Some(subjects) = policy.get("subjects").and_then(|s| s.as_array())
                && subjects.iter().any(|s| {
                    s.as_str()
                        .map(|subj| host == subj || is_wildcard_match(subj, host))
                        .unwrap_or(false)
                })
            {
                return Ok(Some(policy));
            }
        }
        Ok(None)
    }

    /// Check if a host's TLS policy is Tailscale-managed.
    ///
    /// Returns `true` if the host's policy has a `get_certificate` entry with
    /// `via: "tailscale"`.
    pub async fn is_tailscale_managed(&self, host: &str) -> Result<bool, CaddyError> {
        if let Some(policy) = self.get_tls_policy(host).await?
            && let Some(managers) = policy.get("get_certificate").and_then(|g| g.as_array())
        {
            return Ok(managers
                .iter()
                .any(|m| m.get("via").and_then(|v| v.as_str()) == Some("tailscale")));
        }
        Ok(false)
    }

    /// Patch `renewal_window_ratio` on a host's TLS policy.
    ///
    /// Uses the stable `@id` (`slip-tls-<host>`) to PATCH by stable identity,
    /// avoiding TOCTOU on the positional policy array index.
    pub async fn patch_tls_policy_ratio(&self, host: &str, ratio: f64) -> Result<(), CaddyError> {
        // First, try to PATCH by @id (stable, no index race).
        let policy_id = tls_policy_id(host);
        let patch_by_id_url = format!("{}/id/{policy_id}", self.base_url);
        let body = json!({"renewal_window_ratio": ratio});
        let resp = self
            .client
            .patch(&patch_by_id_url)
            .json(&body)
            .send()
            .await?;
        if resp.status().is_success() {
            return Ok(());
        }
        // If the @id PATCH failed (e.g. policy created before @id support),
        // fall back to finding the policy by subjects and patching by index.
        // This is safe because the per-host renew lock serializes mutations.
        tracing::warn!(
            host = host,
            status = %resp.status(),
            "PATCH by @id failed — falling back to positional index"
        );

        let policies_url = format!("{}/config/apps/tls/automation/policies", self.base_url);
        let resp = self.client.get(&policies_url).send().await?;
        if !resp.status().is_success() {
            return Err(CaddyError::TlsConfigFailed(format!(
                "no TLS policies found for {host}"
            )));
        }
        let policies: Vec<Value> = resp.json().await.unwrap_or_default();
        let index = policies.iter().position(|p| {
            p.get("subjects")
                .and_then(|s| s.as_array())
                .map(|subjects| {
                    subjects.iter().any(|s| {
                        s.as_str()
                            .map(|subj| host == subj || is_wildcard_match(subj, host))
                            .unwrap_or(false)
                    })
                })
                .unwrap_or(false)
        });

        let Some(idx) = index else {
            return Err(CaddyError::TlsConfigFailed(format!(
                "no TLS policy found for {host} — run `slip apply` to register it"
            )));
        };

        // PATCH the specific policy to set renewal_window_ratio.
        let patch_url = format!(
            "{}/config/apps/tls/automation/policies/{idx}",
            self.base_url
        );
        let body = json!({"renewal_window_ratio": ratio});
        let resp = self.client.patch(&patch_url).json(&body).send().await?;
        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            return Err(CaddyError::TlsConfigFailed(format!(
                "PATCH {patch_url} returned {status}: {text}"
            )));
        }
        Ok(())
    }

    /// Delete the `renewal_window_ratio` field from a host's TLS policy.
    ///
    /// Used when the original ratio was absent (None) — the temporary bump
    /// must be removed, not merely set to a different value. Uses the stable
    /// `@id` for the deletion.
    pub async fn delete_tls_policy_ratio(&self, host: &str) -> Result<(), CaddyError> {
        let policy_id = tls_policy_id(host);
        let delete_url = format!("{}/id/{}/renewal_window_ratio", self.base_url, policy_id);
        let resp = self.client.delete(&delete_url).send().await?;
        if resp.status().is_success() {
            return Ok(());
        }
        // Fallback: try positional index DELETE.
        tracing::warn!(
            host = host,
            status = %resp.status(),
            "DELETE by @id failed — falling back to positional index"
        );
        let policies_url = format!("{}/config/apps/tls/automation/policies", self.base_url);
        let resp = self.client.get(&policies_url).send().await?;
        if !resp.status().is_success() {
            return Err(CaddyError::TlsConfigFailed(format!(
                "no TLS policies found for {host}"
            )));
        }
        let policies: Vec<Value> = resp.json().await.unwrap_or_default();
        let index = policies.iter().position(|p| {
            p.get("subjects")
                .and_then(|s| s.as_array())
                .map(|subjects| {
                    subjects.iter().any(|s| {
                        s.as_str()
                            .map(|subj| host == subj || is_wildcard_match(subj, host))
                            .unwrap_or(false)
                    })
                })
                .unwrap_or(false)
        });
        let Some(idx) = index else {
            return Err(CaddyError::TlsConfigFailed(format!(
                "no TLS policy found for {host} — run `slip apply` to register it"
            )));
        };
        let delete_url = format!(
            "{}/config/apps/tls/automation/policies/{idx}/renewal_window_ratio",
            self.base_url
        );
        let resp = self.client.delete(&delete_url).send().await?;
        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            return Err(CaddyError::TlsConfigFailed(format!(
                "DELETE {delete_url} returned {status}: {text}"
            )));
        }
        Ok(())
    }

    /// Verify that the `renewal_window_ratio` field has been removed or set
    /// to the expected value on a host's TLS policy.
    ///
    /// Returns `Ok(true)` if verified, `Ok(false)` if the field still has
    /// an unexpected value, or `Err` if the policy can't be read.
    pub async fn verify_ratio_restored(
        &self,
        host: &str,
        expected: Option<f64>,
    ) -> Result<bool, CaddyError> {
        let policy = self.get_tls_policy(host).await?;
        match (policy, expected) {
            (None, _) => Ok(false), // policy gone — not restored
            (Some(p), None) => {
                // Field should be absent.
                Ok(p.get("renewal_window_ratio").is_none())
            }
            (Some(p), Some(expected_ratio)) => {
                Ok(p.get("renewal_window_ratio").and_then(|r| r.as_f64()) == Some(expected_ratio))
            }
        }
    }

    /// Reload Caddy config (POST /load with current config).
    ///
    /// Triggers a config reload which causes Caddy to re-scan renewal windows.
    /// Requires a successful 2xx JSON-object GET before POST — never POSTs
    /// null/stale content.
    pub async fn reload(&self) -> Result<(), CaddyError> {
        // GET the current config — must be a successful JSON object.
        let cfg_url = format!("{}/config/", self.base_url);
        let resp = self.client.get(&cfg_url).send().await?;
        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            return Err(CaddyError::TlsConfigFailed(format!(
                "GET {cfg_url} for reload returned {status}: {text}"
            )));
        }
        let config: Value = resp.json().await.map_err(|e| {
            CaddyError::TlsConfigFailed(format!("failed to parse config JSON for reload: {e}"))
        })?;
        // Verify the config is a JSON object (not null/array).
        if !config.is_object() {
            return Err(CaddyError::TlsConfigFailed(
                "Caddy config GET returned non-object JSON — refusing to POST null/stale content"
                    .to_string(),
            ));
        }

        let load_url = format!("{}/load", self.base_url);
        let resp = self.client.post(&load_url).json(&config).send().await?;
        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            return Err(CaddyError::TlsConfigFailed(format!(
                "POST {load_url} returned {status}: {text}"
            )));
        }
        Ok(())
    }
}

/// Derive a stable Caddy `@id` for a TLS automation policy.
///
/// The subject is sanitized: `*.example.com` → `star.example.com`,
/// non-alphanumeric chars become `-`.
pub fn tls_policy_id(subject: &str) -> String {
    let sanitized = subject.replace('*', "star");
    let cleaned: String = sanitized
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '.' {
                c
            } else {
                '-'
            }
        })
        .collect();
    format!("slip-tls-{cleaned}")
}

/// Redact potential secrets (CF tokens, API keys) from Caddy/Tailscale error strings.
///
/// Scrubs the token regex `[A-Za-z0-9_-]{35,50}` from the input.
pub fn redact_external_error(input: &str) -> String {
    use regex::Regex;
    use std::sync::OnceLock;
    static TOKEN_RE: OnceLock<Regex> = OnceLock::new();
    let re = TOKEN_RE.get_or_init(|| Regex::new(r"[A-Za-z0-9_-]{35,50}").expect("valid regex"));
    re.replace_all(input, "<redacted>").to_string()
}

/// Check if a wildcard subject (e.g. `*.example.com`) matches a domain.
///
/// `*.example.com` matches `foo.example.com` but NOT `example.com` itself.
fn is_wildcard_match(wildcard: &str, domain: &str) -> bool {
    if let Some(suffix) = wildcard.strip_prefix("*.") {
        // suffix is "example.com" — domain must have at least one label
        // before it, i.e. "foo.example.com", not "example.com" itself.
        domain.ends_with(suffix) && domain.len() > suffix.len() && {
            // The char before the suffix match must be a dot.
            let prefix = &domain[..domain.len() - suffix.len()];
            prefix.ends_with('.')
        }
    } else {
        false
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

        // Pre-populate with existing policy matching what configure_tls would build.
        let existing_policy = build_tls_policy(
            &["*.preview.example.com".to_string()],
            TlsStrategy::CloudflareDns01,
            Some(&tls_config),
            Some(&tls_config.email),
            None,
        );
        state
            .lock()
            .await
            .insert("__tls_policies__".to_string(), json!([existing_policy]));

        // Should succeed without adding a new policy (idempotent — bodies match).
        client
            .configure_tls("preview.example.com", &tls_config)
            .await
            .expect("configure_tls should succeed for existing policy");

        let map = state.lock().await;
        let policies = map.get("__tls_policies__").expect("policies should exist");
        let arr = policies.as_array().expect("policies should be an array");
        // Should still be 1 policy (not 2)
        assert_eq!(
            arr.len(),
            1,
            "should not add duplicate policy when bodies match"
        );
    }

    #[tokio::test]
    async fn test_upsert_replaces_on_body_change() {
        // When the desired policy body differs from the existing policy
        // (strategy transition, reconcile repair), upsert should replace,
        // not silently no-op.
        let (port, state) = start_mock_caddy().await;
        let client = CaddyClient::new(format!("http://127.0.0.1:{port}"));

        let subjects = vec!["deploy.example.com".to_string()];

        // First, insert an internal policy.
        let internal_policy = build_tls_policy(&subjects, TlsStrategy::Internal, None, None, None);
        client
            .upsert_tls_policy(&subjects, &internal_policy)
            .await
            .expect("first upsert should succeed");

        // Now upsert an ACME policy for the same subject.
        let acme_policy = build_tls_policy(
            &subjects,
            TlsStrategy::Acme,
            None,
            Some("ops@example.com"),
            None,
        );
        client
            .upsert_tls_policy(&subjects, &acme_policy)
            .await
            .expect("second upsert (replace) should succeed");

        // The mock Caddy stores policies as an array. After replace,
        // the policy should reflect the ACME issuer (not internal).
        let map = state.lock().await;
        let policies = map
            .get("__tls_policies__")
            .and_then(|p| p.as_array())
            .expect("policies should exist");
        // There should be at least one policy with the ACME issuer.
        let has_acme = policies.iter().any(|p| {
            p.get("issuers")
                .and_then(|i| i.as_array())
                .and_then(|a| a.first())
                .and_then(|i| i.get("module"))
                .and_then(|m| m.as_str())
                == Some("acme")
        });
        assert!(
            has_acme,
            "upsert should replace internal with ACME on body change"
        );
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
            .bootstrap_deploy(
                Some("deploy.example.com"),
                &TlsStrategy::Internal,
                "127.0.0.1:7890",
                None,
                None,
                None,
            )
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
            .bootstrap_deploy(
                None,
                &TlsStrategy::Internal,
                "127.0.0.1:7890",
                None,
                None,
                None,
            )
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
            .bootstrap_deploy(
                Some("deploy.example.com"),
                &TlsStrategy::Internal,
                "127.0.0.1:7890",
                None,
                None,
                None,
            )
            .await
            .expect("first bootstrap_deploy should succeed");

        // Second call with different upstream should update it.
        client
            .bootstrap_deploy(
                Some("deploy.example.com"),
                &TlsStrategy::Internal,
                "127.0.0.1:7891",
                None,
                None,
                None,
            )
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
            .bootstrap_deploy(
                Some("deploy.example.com"),
                &TlsStrategy::Internal,
                "127.0.0.1:7890",
                None,
                None,
                None,
            )
            .await
            .expect("first bootstrap_deploy should succeed");

        // Second call should not create a duplicate TLS policy.
        client
            .bootstrap_deploy(
                Some("deploy.example.com"),
                &TlsStrategy::Internal,
                "127.0.0.1:7890",
                None,
                None,
                None,
            )
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

    // ── is_wildcard_match ──────────────────────────────────────────────────

    #[test]
    fn test_wildcard_match_exact_suffix() {
        assert!(is_wildcard_match("*.example.com", "foo.example.com"));
        assert!(is_wildcard_match("*.example.com", "bar.example.com"));
    }

    #[test]
    fn test_wildcard_match_no_match() {
        assert!(!is_wildcard_match("*.example.com", "example.org"));
        assert!(!is_wildcard_match("*.example.com", "example.com"));
    }

    #[test]
    fn test_wildcard_match_not_wildcard() {
        assert!(!is_wildcard_match("example.com", "example.com"));
    }

    // ── get_tls_issuer ─────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_get_tls_issuer_no_policies_returns_none() {
        let (port, _state) = start_mock_caddy().await;
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

        let client = CaddyClient::new(format!("http://127.0.0.1:{port}"));
        let issuer = client.get_tls_issuer("example.com").await.unwrap();
        // No policies → None (Caddy default is ACME, but we return None to
        // indicate "no explicit policy").
        assert!(issuer.is_none());
    }

    // ── build_tls_policy (Phase 2 — pure policy builder) ──────────────────

    fn dns_config_fixture(staging: bool) -> CaddyTlsConfig {
        let mut table = toml::value::Table::new();
        table.insert(
            "api_token".to_string(),
            toml::Value::String("{env.CF_API_TOKEN}".to_string()),
        );
        CaddyTlsConfig {
            email: "ops@example.com".to_string(),
            dns_provider: "cloudflare".to_string(),
            dns_provider_config: Some(table),
            propagation_delay: "2m".to_string(),
            staging,
        }
    }

    #[test]
    fn build_tls_policy_internal_exact_shape() {
        let subjects = vec!["deploy.example.com".to_string()];
        let policy = build_tls_policy(&subjects, TlsStrategy::Internal, None, None, None);
        assert_eq!(
            policy["subjects"][0], "deploy.example.com",
            "subject should be the deploy domain"
        );
        assert!(
            policy.get("issuers").is_some(),
            "internal policy must have issuers (plural, array)"
        );
        assert_eq!(policy["issuers"][0]["module"], "internal");
        // Byte-identical to the pre-refactor shape.
        let expected = json!({
            "subjects": ["deploy.example.com"],
            "issuers": [{"module": "internal"}]
        });
        assert_eq!(policy, expected, "internal policy must be byte-identical");
    }

    #[test]
    fn build_tls_policy_acme_has_email_and_ca() {
        let subjects = vec!["deploy.example.com".to_string()];
        let policy = build_tls_policy(
            &subjects,
            TlsStrategy::Acme,
            None,
            Some("ops@example.com"),
            None,
        );
        assert_eq!(policy["issuers"][0]["module"], "acme");
        assert_eq!(policy["issuers"][0]["email"], "ops@example.com");
        assert_eq!(
            policy["issuers"][0]["ca"],
            "https://acme-v02.api.letsencrypt.org/directory"
        );
        // HTTP-01 not disabled (default challenges).
        assert!(policy["issuers"][0].get("challenges").is_none());
    }

    #[test]
    fn build_tls_policy_acme_staging_ca() {
        let subjects = vec!["deploy.example.com".to_string()];
        let policy = build_tls_policy(
            &subjects,
            TlsStrategy::Acme,
            None,
            Some("ops@example.com"),
            Some("https://acme-staging-v02.api.letsencrypt.org/directory"),
        );
        assert_eq!(
            policy["issuers"][0]["ca"],
            "https://acme-staging-v02.api.letsencrypt.org/directory"
        );
    }

    #[test]
    fn build_tls_policy_cloudflare_dns01_placeholder_preserved() {
        let subjects = vec!["tailnet.example.ts.net".to_string()];
        let dns = dns_config_fixture(false);
        let policy = build_tls_policy(
            &subjects,
            TlsStrategy::CloudflareDns01,
            Some(&dns),
            Some(&dns.email),
            None,
        );
        assert_eq!(policy["issuers"][0]["module"], "acme");
        assert_eq!(policy["issuers"][0]["email"], "ops@example.com");
        // CRITICAL: the CF token must be the {env.*} placeholder, never literal.
        assert_eq!(
            policy["issuers"][0]["challenges"]["dns"]["provider"]["api_token"],
            "{env.CF_API_TOKEN}",
            "CF token must be {{env.*}} placeholder, never literal"
        );
        assert_eq!(
            policy["issuers"][0]["challenges"]["dns"]["provider"]["name"],
            "cloudflare"
        );
        assert_eq!(
            policy["issuers"][0]["challenges"]["dns"]["propagation_delay"],
            "2m"
        );
        assert_eq!(
            policy["issuers"][0]["ca"],
            "https://acme-v02.api.letsencrypt.org/directory"
        );
    }

    #[test]
    fn build_tls_policy_cloudflare_dns01_staging_ca() {
        let subjects = vec!["tailnet.example.ts.net".to_string()];
        let dns = dns_config_fixture(true);
        let policy = build_tls_policy(
            &subjects,
            TlsStrategy::CloudflareDns01,
            Some(&dns),
            Some(&dns.email),
            None,
        );
        assert_eq!(
            policy["issuers"][0]["ca"],
            "https://acme-staging-v02.api.letsencrypt.org/directory"
        );
    }

    #[test]
    fn build_tls_policy_tailscale_has_get_certificate_no_issuers() {
        let subjects = vec!["host.tailnet.ts.net".to_string()];
        let policy = build_tls_policy(&subjects, TlsStrategy::Tailscale, None, None, None);
        // CRITICAL: Tailscale is a MANAGER, not an issuer.
        assert!(
            policy.get("issuers").is_none(),
            "Tailscale policy must NOT have issuers[] — it's a get_certificate manager"
        );
        assert_eq!(
            policy["get_certificate"][0]["via"], "tailscale",
            "must use via: 'tailscale' (inline_key for tls.get_certificate namespace)"
        );
        assert_eq!(policy["subjects"][0], "host.tailnet.ts.net");
    }

    #[test]
    fn build_tls_policy_internal_byte_identical_to_pre_refactor() {
        // The pre-refactor bootstrap_deploy internal branch produced exactly:
        // {"subjects": [domain], "issuers": [{"module": "internal"}]}
        let subjects = vec!["deploy.example.com".to_string()];
        let policy = build_tls_policy(&subjects, TlsStrategy::Internal, None, None, None);
        let pre_refactor = json!({
            "subjects": ["deploy.example.com"],
            "issuers": [{"module": "internal"}]
        });
        assert_eq!(policy, pre_refactor);
    }

    // ── classify_host_tls + resolve_route_tls (Phase 3) ────────────────────

    #[test]
    fn classify_host_tls_test_tld_is_non_public() {
        assert_eq!(
            classify_host_tls("arrakeen.test"),
            TlsClassification::NonPublic
        );
    }

    #[test]
    fn classify_host_tls_internal_tld_is_non_public() {
        assert_eq!(
            classify_host_tls("host.internal"),
            TlsClassification::NonPublic
        );
    }

    #[test]
    fn classify_host_tls_public_domain_is_public() {
        assert_eq!(
            classify_host_tls("deploy.example.com"),
            TlsClassification::Public
        );
    }

    #[test]
    fn classify_host_tls_private_ip_is_non_public() {
        assert_eq!(classify_host_tls("10.0.0.1"), TlsClassification::NonPublic);
        assert_eq!(
            classify_host_tls("192.168.1.1"),
            TlsClassification::NonPublic
        );
        assert_eq!(
            classify_host_tls("172.16.0.1"),
            TlsClassification::NonPublic
        );
    }

    #[test]
    fn classify_host_tls_cgnat_ip_is_non_public() {
        assert_eq!(
            classify_host_tls("100.64.0.1"),
            TlsClassification::NonPublic
        );
    }

    #[test]
    fn classify_host_ts_net_is_public() {
        // .ts.net is never auto-internal — handled by Tailscale manager.
        assert_eq!(
            classify_host_tls("host.tailnet.ts.net"),
            TlsClassification::Public
        );
    }

    #[test]
    fn resolve_route_tls_non_public_absent_applies_internal() {
        assert_eq!(
            resolve_route_tls("arrakeen.test", None),
            RouteTlsDecision::Apply(TlsStrategy::Internal)
        );
    }

    #[test]
    fn resolve_route_tls_public_absent_leaves_default() {
        assert_eq!(
            resolve_route_tls("deploy.example.com", None),
            RouteTlsDecision::LeaveDefault
        );
    }

    #[test]
    fn resolve_route_tls_explicit_wins_over_classification() {
        assert_eq!(
            resolve_route_tls("arrakeen.test", Some(TlsStrategy::Acme)),
            RouteTlsDecision::Apply(TlsStrategy::Acme)
        );
    }

    #[test]
    fn resolve_route_tls_ts_net_explicit_tailscale_applies() {
        assert_eq!(
            resolve_route_tls("host.tailnet.ts.net", Some(TlsStrategy::Tailscale)),
            RouteTlsDecision::Apply(TlsStrategy::Tailscale)
        );
    }

    #[test]
    fn resolve_route_ts_net_absent_leaves_default() {
        // .ts.net is Public → absent TLS leaves Caddy's default (Tailscale
        // auto-detection handles it).
        assert_eq!(
            resolve_route_tls("host.tailnet.ts.net", None),
            RouteTlsDecision::LeaveDefault
        );
    }

    // ── cert_renewed / CertProbe comparison (Phase 4 — cert proof) ────────

    #[test]
    fn cert_renewed_fingerprint_change() {
        let before = CertProbe {
            fingerprint: "aaa".to_string(),
            not_after: Some("2026-08-01T00:00:00Z".to_string()),
        };
        let after = CertProbe {
            fingerprint: "bbb".to_string(),
            not_after: Some("2026-08-01T00:00:00Z".to_string()),
        };
        assert!(cert_renewed(Some(&before), Some(&after)));
    }

    #[test]
    fn cert_renewed_not_after_advanced() {
        let before = CertProbe {
            fingerprint: "aaa".to_string(),
            not_after: Some("2026-08-01T00:00:00Z".to_string()),
        };
        let after = CertProbe {
            fingerprint: "aaa".to_string(),
            not_after: Some("2026-10-30T00:00:00Z".to_string()),
        };
        assert!(cert_renewed(Some(&before), Some(&after)));
    }

    #[test]
    fn cert_renewed_absent_to_present() {
        let after = CertProbe {
            fingerprint: "aaa".to_string(),
            not_after: Some("2026-10-30T00:00:00Z".to_string()),
        };
        assert!(cert_renewed(None, Some(&after)));
    }

    #[test]
    fn cert_renewed_identical_is_false() {
        let before = CertProbe {
            fingerprint: "aaa".to_string(),
            not_after: Some("2026-08-01T00:00:00Z".to_string()),
        };
        let after = before.clone();
        assert!(!cert_renewed(Some(&before), Some(&after)));
    }

    #[test]
    fn cert_renewed_both_absent_is_false() {
        assert!(!cert_renewed(None, None));
    }

    #[test]
    fn cert_renewed_not_after_absent_to_present() {
        let before = CertProbe {
            fingerprint: "aaa".to_string(),
            not_after: None,
        };
        let after = CertProbe {
            fingerprint: "aaa".to_string(),
            not_after: Some("2026-10-30T00:00:00Z".to_string()),
        };
        assert!(cert_renewed(Some(&before), Some(&after)));
    }

    // ── TlsRenewResult JSON schema (redaction) ────────────────────────────

    #[test]
    fn tls_renew_result_has_no_secret_fields() {
        use crate::api::TlsRenewResult;
        let result = TlsRenewResult {
            schema: "slip.tls.renew/v1",
            host: "deploy.example.com".to_string(),
            before_not_after: Some("2026-08-01T00:00:00Z".to_string()),
            after_not_after: Some("2026-10-30T00:00:00Z".to_string()),
            renewed: true,
            restored: true,
            managed_by: None,
            message: None,
            elapsed_ms: 4200,
        };
        let json = serde_json::to_value(&result).unwrap();
        let obj = json.as_object().unwrap();
        assert!(!obj.contains_key("api_token"));
        assert!(!obj.contains_key("token"));
        assert!(!obj.contains_key("secret"));
        assert!(!obj.contains_key("key"));
        assert!(!obj.contains_key("password"));
        assert_eq!(obj["schema"], "slip.tls.renew/v1");
        assert_eq!(obj["renewed"], true);
        assert_eq!(obj["restored"], true);
    }

    #[test]
    fn tls_renew_result_tailscale_noop_schema() {
        use crate::api::TlsRenewResult;
        let result = TlsRenewResult {
            schema: "slip.tls.renew/v1",
            host: "host.ts.net".to_string(),
            before_not_after: None,
            after_not_after: None,
            renewed: false,
            restored: true,
            managed_by: Some("tailscale".to_string()),
            message: Some("host uses Tailscale manager".to_string()),
            elapsed_ms: 12,
        };
        let json = serde_json::to_value(&result).unwrap();
        assert_eq!(json["managed_by"], "tailscale");
        assert_eq!(json["renewed"], false);
        assert_eq!(json["restored"], true);
    }

    #[test]
    fn tls_renew_request_parses_restart_caddy() {
        use crate::api::TlsRenewRequest;
        let json = r#"{"host": "deploy.example.com", "restart_caddy": true}"#;
        let req: TlsRenewRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.host, "deploy.example.com");
        assert!(req.restart_caddy);
    }

    #[test]
    fn tls_renew_request_defaults_restart_caddy_false() {
        use crate::api::TlsRenewRequest;
        let json = r#"{"host": "deploy.example.com"}"#;
        let req: TlsRenewRequest = serde_json::from_str(json).unwrap();
        assert!(!req.restart_caddy);
    }

    // ── tls_policy_id + redact_external_error ──────────────────────────────

    #[test]
    fn tls_policy_id_exact_host() {
        assert_eq!(
            tls_policy_id("deploy.example.com"),
            "slip-tls-deploy.example.com"
        );
    }

    #[test]
    fn tls_policy_id_wildcard() {
        assert_eq!(
            tls_policy_id("*.preview.example.com"),
            "slip-tls-star.preview.example.com"
        );
    }

    #[test]
    fn tls_policy_id_sanitizes_special_chars() {
        let id = tls_policy_id("host_with_underscores.example.com");
        assert!(id.starts_with("slip-tls-"));
        assert!(
            !id.contains('_'),
            "underscores should be sanitized to dashes"
        );
    }

    #[test]
    fn redact_external_error_scrubs_token_patterns() {
        // 40-char token (within the 35-50 char range).
        let token = "AbCdEfGhIjKlMnOpQrSt1234567890AbCdEfGh";
        let input = format!("error: api_token={token} caused failure");
        let redacted = redact_external_error(&input);
        assert!(
            redacted.contains("<redacted>"),
            "token should be redacted: {redacted}"
        );
        assert!(
            !redacted.contains(token),
            "original token must not appear: {redacted}"
        );
    }

    #[test]
    fn redact_external_error_preserves_short_strings() {
        let input = "no tokens here just a short error";
        let redacted = redact_external_error(input);
        assert_eq!(
            redacted, input,
            "short strings without token patterns should pass through"
        );
    }
}
