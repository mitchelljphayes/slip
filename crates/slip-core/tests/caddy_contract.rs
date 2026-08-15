//! Real-caddy contract tests.
//!
//! These tests require a `caddy` binary on `$PATH`. They are marked `#[ignore]`
//! so they compile but are skipped by default. Run with:
//!
//!     cargo test -p slip-core --test caddy_contract -- --ignored
//!
//! Each test starts a fresh `caddy run` process with an admin-only config on a
//! free port, exercises the `CaddyClient` API, and kills the process on drop.

use std::collections::HashMap;
use std::net::TcpListener;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use slip_core::CaddyClient;
use slip_core::caddy::{Route, build_tls_policy, tls_policy_id};
use slip_core::config::{
    AppConfig, AppInfo, DeployConfig, HealthConfig, NetworkConfig, ResourceConfig, RoutingConfig,
    ServerDeployConfig, TlsStrategy,
};
use slip_core::deploy::{AppRuntimeState, AppStatus};
use slip_core::reconcile::{ReconcileContext, default_backoff, reconcile_tick};

// ── Helpers ──────────────────────────────────────────────────────────────────

/// Find a free TCP port on localhost.
fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind 127.0.0.1:0");
    let port = listener.local_addr().unwrap().port();
    // Drop the listener so the port is free for caddy.
    drop(listener);
    port
}

/// A running Caddy process that is killed on drop.
struct CaddyGuard {
    child: Child,
    base_url: String,
}

impl Drop for CaddyGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Start a fresh `caddy run` with an admin-only config on a free port.
///
/// Panics if `caddy` is not on `$PATH` or if the admin API is not reachable
/// within 5 seconds.
fn start_caddy() -> CaddyGuard {
    let port = free_port();
    let base_url = format!("http://localhost:{port}");

    // Write a minimal admin-only config (no apps block).
    let config_json = serde_json::json!({
        "admin": {
            "listen": format!("localhost:{port}")
        }
    });
    let config_str = config_json.to_string();

    let mut child = Command::new("caddy")
        .args(["run", "--config", "/dev/stdin"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("caddy binary must be on $PATH to run contract tests");

    // Write config to stdin.
    if let Some(mut stdin) = child.stdin.take() {
        use std::io::Write;
        stdin
            .write_all(config_str.as_bytes())
            .expect("write config to caddy stdin");
    }

    // Poll the admin API until it's ready (up to 5 seconds).
    // Use TcpStream to check if the port is accepting connections.
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        if std::time::Instant::now() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("Caddy admin API at {base_url} did not become ready within 5s");
        }
        if std::net::TcpStream::connect(format!("127.0.0.1:{port}")).is_ok() {
            break;
        }
        std::thread::sleep(Duration::from_millis(200));
    }

    CaddyGuard { child, base_url }
}

// ── Tests ────────────────────────────────────────────────────────────────────

/// Bootstrap on a fresh Caddy (admin only) should succeed and preserve the
/// admin block.
#[tokio::test]
#[ignore]
async fn bootstrap_succeeds_on_fresh_caddy() {
    let guard = start_caddy();
    let client = CaddyClient::new(guard.base_url.clone());

    client.bootstrap().await.expect("bootstrap should succeed");

    // The slip server block should now exist.
    let http_client = reqwest::Client::new();
    let slip_resp = http_client
        .get(format!("{}/config/apps/http/servers/slip", guard.base_url))
        .send()
        .await
        .expect("GET /config/apps/http/servers/slip");
    assert!(
        slip_resp.status().is_success(),
        "slip server block should exist after bootstrap"
    );

    // The admin block must be preserved (bootstrap must not clobber it).
    let root_resp = http_client
        .get(format!("{}/config/", guard.base_url))
        .send()
        .await
        .expect("GET /config/");
    let root: serde_json::Value = root_resp.json().await.expect("config should be valid JSON");
    assert!(
        root.get("admin").is_some(),
        "admin block must be preserved after bootstrap"
    );
}

/// Bootstrap is idempotent: calling it twice should both succeed.
#[tokio::test]
#[ignore]
async fn bootstrap_is_idempotent_on_real_caddy() {
    let guard = start_caddy();
    let client = CaddyClient::new(guard.base_url.clone());

    client
        .bootstrap()
        .await
        .expect("first bootstrap should succeed");
    client
        .bootstrap()
        .await
        .expect("second bootstrap should succeed (idempotent)");
}

/// Set routes, verify they exist via @id, then remove them and verify 404.
#[tokio::test]
#[ignore]
async fn set_and_remove_routes_on_real_caddy() {
    let guard = start_caddy();
    let client = CaddyClient::new(guard.base_url.clone());

    // Bootstrap first.
    client.bootstrap().await.expect("bootstrap should succeed");

    // Set a route for "app1".
    let routes = vec![Route {
        hostname: "a.example.com".to_string(),
        port: 8080,
    }];
    client
        .set_routes("app1", &routes)
        .await
        .expect("set_routes should succeed");

    // Verify the route exists via @id.
    let http_client = reqwest::Client::new();
    let get_resp = http_client
        .get(format!("{}/id/slip-app1-0", guard.base_url))
        .send()
        .await
        .expect("GET /id/slip-app1-0");
    assert_eq!(
        get_resp.status(),
        200,
        "route slip-app1-0 should exist after set_routes"
    );

    // Remove the route.
    client
        .remove_routes("app1", 1)
        .await
        .expect("remove_routes should succeed");

    // Verify the route is gone (404).
    let get_resp2 = http_client
        .get(format!("{}/id/slip-app1-0", guard.base_url))
        .send()
        .await
        .expect("GET /id/slip-app1-0");
    assert_eq!(
        get_resp2.status(),
        404,
        "route slip-app1-0 should be gone after remove_routes"
    );
}

// ── Chaos: reconcile self-heals after a Caddy restart ────────────────────────

/// Helper to build a minimal single-route AppConfig.
fn test_app_config(name: &str, domain: &str) -> AppConfig {
    AppConfig {
        app: AppInfo {
            name: name.to_string(),
            image: "nginx".to_string(),
            secret: None,
        },
        routing: RoutingConfig {
            domain: Some(domain.to_string()),
            port: Some(80),
            routes: vec![],
            tls: None,
        },
        health: HealthConfig::default(),
        deploy: DeployConfig::default(),
        env: HashMap::new(),
        env_file: None,
        resources: ResourceConfig::default(),
        network: NetworkConfig::default(),
        preview: None,
        volumes: vec![],
    }
}

/// Helper to build a ReconcileContext for a single running app.
fn test_context(client: CaddyClient, app: &str, domain: &str, port: u16) -> ReconcileContext {
    let mut apps = HashMap::new();
    apps.insert(app.to_string(), test_app_config(app, domain));
    let mut states = HashMap::new();
    states.insert(
        app.to_string(),
        AppRuntimeState {
            status: AppStatus::Running,
            current_port: Some(port),
            ..Default::default()
        },
    );
    ReconcileContext {
        caddy: client,
        app_states: states,
        apps,
        preview: None,
        caddy_tls: None,
        deploy: None,
        listen_addr: "127.0.0.1:7890".to_string(),
        acme_email: None,
        acme_ca: None,
    }
}

/// Assert that a route `@id` exists on the Caddy at `base_url` within
/// `timeout`. Polls every 200ms.
async fn assert_route_exists(base_url: &str, route_id: &str, timeout: Duration) {
    let http = reqwest::Client::new();
    let deadline = std::time::Instant::now() + timeout;
    loop {
        if std::time::Instant::now() > deadline {
            panic!("route {route_id} did not appear on {base_url} within {timeout:?}");
        }
        let resp = http
            .get(format!("{base_url}/id/{route_id}"))
            .send()
            .await
            .expect("GET route");
        if resp.status().is_success() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

/// The reconcile loop self-heals routes after a real Caddy restart.
///
/// This is the SLIP-99 acceptance test: kill Caddy, start a fresh instance
/// (new port, empty config), run a reconcile tick, and confirm the route
/// reappears — proving the loop converges without manual intervention.
#[tokio::test]
#[ignore]
async fn reconcile_loop_converges_after_caddy_restart() {
    // ── 1. Start Caddy, bootstrap, set an initial route ─────────────────────
    let guard = start_caddy();
    let client = CaddyClient::new(guard.base_url.clone());
    client.bootstrap().await.expect("bootstrap should succeed");

    let ctx = test_context(client, "test-app", "test.local", 8080);
    let backoff = default_backoff();
    let summary = reconcile_tick(&ctx, &backoff).await;
    assert_eq!(summary.routes_failed, 0, "initial reconcile should succeed");
    assert_route_exists(&guard.base_url, "slip-test-app-0", Duration::from_secs(5)).await;

    // ── 2. CHAOS: kill Caddy, start a fresh instance on a new port ──────────
    drop(guard);
    let guard2 = start_caddy();
    let client2 = CaddyClient::new(guard2.base_url.clone());

    // The fresh Caddy has no slip server block and no routes.
    let http = reqwest::Client::new();
    let resp = http
        .get(format!("{}/id/slip-test-app-0", guard2.base_url))
        .send()
        .await
        .expect("GET route on fresh caddy");
    assert_eq!(
        resp.status(),
        404,
        "route should be gone on fresh Caddy (simulating restart)"
    );

    // ── 3. Run a reconcile tick against the new Caddy — self-heal ───────────
    let ctx2 = test_context(client2, "test-app", "test.local", 8080);
    let summary2 = reconcile_tick(&ctx2, &backoff).await;
    assert_eq!(
        summary2.routes_failed, 0,
        "reconcile after restart should succeed"
    );

    // ── 4. Assert the route reappeared within 10s ───────────────────────────
    assert_route_exists(&guard2.base_url, "slip-test-app-0", Duration::from_secs(10)).await;
}

// ── SLIP-125: TLS policy preservation contract tests ────────────────────────

/// Fetch the current TLS automation policies array from a real Caddy.
/// Returns an empty vec if the `policies` key is absent (404).
async fn fetch_tls_policies(base_url: &str) -> Vec<serde_json::Value> {
    let http = reqwest::Client::new();
    let resp = http
        .get(format!("{base_url}/config/apps/tls/automation/policies"))
        .send()
        .await
        .expect("GET policies");
    if resp.status().is_success() {
        resp.json::<Vec<serde_json::Value>>()
            .await
            .expect("policies JSON array")
    } else {
        Vec::new()
    }
}

/// Inject a foreign (non-`slip-tls-*`) policy directly into a real Caddy
/// via the admin API (POST appends one element).
async fn inject_foreign_policy(base_url: &str, policy: &serde_json::Value) {
    let http = reqwest::Client::new();
    let resp = http
        .post(format!("{base_url}/config/apps/tls/automation/policies"))
        .json(policy)
        .send()
        .await
        .expect("POST foreign policy");
    assert!(
        resp.status().is_success(),
        "foreign policy injection failed: {}",
        resp.status()
    );
}

/// A foreign DNS-01 policy (Cloudflare, no `@id`).
fn foreign_dns01_policy() -> serde_json::Value {
    serde_json::json!({
        "subjects": ["api.example.com"],
        "issuers": [{
            "module": "acme",
            "ca": "https://acme-v02.api.letsencrypt.org/directory",
            "challenges": {
                "dns": {
                    "provider": {"name": "cloudflare", "api_token": "{env.CF_TOKEN}"}
                }
            }
        }]
    })
}

/// A foreign Tailscale `get_certificate` policy (no `@id`).
fn foreign_tailscale_policy() -> serde_json::Value {
    serde_json::json!({
        "subjects": ["arrakeen.abyssinian-lime.ts.net"],
        "get_certificate": [{"via": "tailscale"}]
    })
}

/// A foreign internal-CA policy (no `@id`).
fn foreign_internal_policy() -> serde_json::Value {
    serde_json::json!({
        "subjects": ["internal.lab.local"],
        "issuers": [{"module": "internal"}]
    })
}

/// Real-Caddy contract: foreign DNS-01 + Tailscale + internal policies
/// survive startup (`bootstrap` + `bootstrap_deploy` + `configure_tls`)
/// AND at least two periodic reconciliation cycles. Slip's own policies
/// converge once and stay stable (no duplicates). Foreign ordering and
/// exact values are preserved.
#[tokio::test]
#[ignore]
async fn tls_policies_foreign_survive_reconcile_cycles_on_real_caddy() {
    let guard = start_caddy();
    let client = CaddyClient::new(guard.base_url.clone());

    // ── 1. Seed real Caddy with three foreign policies (manual / external). ──
    inject_foreign_policy(&guard.base_url, &foreign_dns01_policy()).await;
    inject_foreign_policy(&guard.base_url, &foreign_tailscale_policy()).await;
    inject_foreign_policy(&guard.base_url, &foreign_internal_policy()).await;

    let foreign_before = fetch_tls_policies(&guard.base_url).await;
    assert_eq!(foreign_before.len(), 3, "3 foreign policies seeded");
    let foreign_dns01_before = foreign_before[0].clone();
    let foreign_ts_before = foreign_before[1].clone();
    let foreign_internal_before = foreign_before[2].clone();

    // ── 2. Startup: bootstrap + deploy + configure_tls (simulating slipd). ──
    client.bootstrap().await.expect("bootstrap should succeed");
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

    let after_startup = fetch_tls_policies(&guard.base_url).await;
    // 3 foreign + 1 slip = 4. No wipe.
    assert_eq!(
        after_startup.len(),
        4,
        "foreign policies must survive startup — no wholesale wipe"
    );
    // Foreign policies unchanged in order.
    assert_eq!(
        after_startup[0], foreign_dns01_before,
        "DNS-01 policy byte-identical after startup"
    );
    assert_eq!(
        after_startup[1], foreign_ts_before,
        "Tailscale get_certificate policy byte-identical after startup"
    );
    assert_eq!(
        after_startup[2], foreign_internal_before,
        "internal-CA policy byte-identical after startup"
    );
    // Slip policy carries expected @id.
    assert_eq!(
        after_startup[3]["@id"].as_str(),
        Some("slip-tls-deploy.example.com"),
        "Slip policy carries stable @id"
    );

    // ── 3. Two periodic reconcile cycles. ───────────────────────────────────
    let ctx = ReconcileContext {
        caddy: client.clone(),
        app_states: HashMap::new(),
        apps: HashMap::new(),
        preview: None,
        caddy_tls: None,
        deploy: Some(ServerDeployConfig {
            domain: Some("deploy.example.com".to_string()),
            tls: TlsStrategy::Internal,
            ..Default::default()
        }),
        listen_addr: "127.0.0.1:7890".to_string(),
        acme_email: None,
        acme_ca: None,
    };
    let backoff = default_backoff();

    // Cycle 1.
    reconcile_tick(&ctx, &backoff).await;
    let after_c1 = fetch_tls_policies(&guard.base_url).await;
    assert_eq!(
        after_c1.len(),
        4,
        "no new duplicates after cycle 1 — Slip converged idempotently"
    );
    assert_eq!(after_c1[0], foreign_dns01_before, "DNS-01 survives cycle 1");
    assert_eq!(after_c1[1], foreign_ts_before, "Tailscale survives cycle 1");
    assert_eq!(
        after_c1[2], foreign_internal_before,
        "internal survives cycle 1"
    );
    assert_eq!(
        after_c1[3]["@id"].as_str(),
        Some("slip-tls-deploy.example.com"),
        "Slip policy stable after cycle 1"
    );

    // Cycle 2.
    reconcile_tick(&ctx, &backoff).await;
    let after_c2 = fetch_tls_policies(&guard.base_url).await;
    assert_eq!(
        after_c2.len(),
        4,
        "no new duplicates after cycle 2 — Slip stable"
    );
    assert_eq!(after_c2[0], foreign_dns01_before, "DNS-01 survives cycle 2");
    assert_eq!(after_c2[1], foreign_ts_before, "Tailscale survives cycle 2");
    assert_eq!(
        after_c2[2], foreign_internal_before,
        "internal survives cycle 2"
    );
    assert_eq!(
        after_c2[3]["@id"].as_str(),
        Some("slip-tls-deploy.example.com"),
        "Slip policy stable after cycle 2"
    );
    assert_eq!(
        after_c2[3]["issuers"][0]["module"].as_str(),
        Some("internal"),
        "Slip policy body stable after cycle 2"
    );
}

/// Real-Caddy contract: the deploy-ingress Tailscale `get_certificate`
/// policy (`[deploy] tls = "tailscale"`) remains present across reconcile
/// cycles. A foreign policy for a different subject also survives.
#[tokio::test]
#[ignore]
async fn tls_deploy_tailscale_policy_remains_present_on_real_caddy() {
    let guard = start_caddy();
    let client = CaddyClient::new(guard.base_url.clone());

    // Seed a foreign DNS-01 policy for a different subject.
    inject_foreign_policy(&guard.base_url, &foreign_dns01_policy()).await;
    let foreign_before = fetch_tls_policies(&guard.base_url).await;
    let foreign_dns01_before = foreign_before[0].clone();

    // Startup with deploy = Tailscale.
    client.bootstrap().await.expect("bootstrap should succeed");
    let deploy_host = "arrakeen.abyssinian-lime.ts.net";
    client
        .bootstrap_deploy(
            Some(deploy_host),
            &TlsStrategy::Tailscale,
            "127.0.0.1:7890",
            None,
            None,
            None,
        )
        .await
        .expect("bootstrap_deploy Tailscale should succeed");

    let after_startup = fetch_tls_policies(&guard.base_url).await;
    assert_eq!(after_startup.len(), 2, "foreign + tailscale deploy");
    assert_eq!(
        after_startup[0], foreign_dns01_before,
        "foreign DNS-01 preserved"
    );
    assert_eq!(
        after_startup[1]["@id"].as_str(),
        Some(tls_policy_id(deploy_host).as_str()),
        "Tailscale deploy policy carries stable @id"
    );
    assert_eq!(
        after_startup[1]["get_certificate"][0]["via"].as_str(),
        Some("tailscale"),
        "Tailscale get_certificate remains present"
    );
    assert!(
        after_startup[1].get("issuers").is_none(),
        "Tailscale policy has no issuers"
    );

    // Two reconcile cycles.
    let ctx = ReconcileContext {
        caddy: client.clone(),
        app_states: HashMap::new(),
        apps: HashMap::new(),
        preview: None,
        caddy_tls: None,
        deploy: Some(ServerDeployConfig {
            domain: Some(deploy_host.to_string()),
            tls: TlsStrategy::Tailscale,
            ..Default::default()
        }),
        listen_addr: "127.0.0.1:7890".to_string(),
        acme_email: None,
        acme_ca: None,
    };
    let backoff = default_backoff();
    for cycle in 1..=2 {
        reconcile_tick(&ctx, &backoff).await;
        let after = fetch_tls_policies(&guard.base_url).await;
        assert_eq!(after.len(), 2, "no duplicates after cycle {cycle}");
        assert_eq!(
            after[0], foreign_dns01_before,
            "foreign DNS-01 preserved after cycle {cycle}"
        );
        assert_eq!(
            after[1]["get_certificate"][0]["via"].as_str(),
            Some("tailscale"),
            "Tailscale get_certificate present after cycle {cycle}"
        );
        assert!(
            after[1].get("issuers").is_none(),
            "Tailscale policy still has no issuers after cycle {cycle}"
        );
    }
}

/// Real-Caddy contract: the missing-policy-path create-only initialization
/// works. On a fresh Caddy (no `policies` key), `upsert_tls_policy` creates
/// the array via `PUT .../policies []` (create-only) and appends — without
/// ever writing the parent `automation` object.
#[tokio::test]
#[ignore]
async fn tls_upsert_initializes_absent_policies_on_real_caddy() {
    let guard = start_caddy();
    let client = CaddyClient::new(guard.base_url.clone());

    // Fresh Caddy: no policies key. GET should 404.
    let http = reqwest::Client::new();
    let resp = http
        .get(format!(
            "{}/config/apps/tls/automation/policies",
            guard.base_url
        ))
        .send()
        .await
        .expect("GET policies on fresh caddy");
    assert_eq!(
        resp.status(),
        404,
        "fresh Caddy should have no policies key (404)"
    );

    // Upsert a Slip-owned policy — should initialize the array.
    let subjects = vec!["deploy.example.com".to_string()];
    let policy = build_tls_policy(&subjects, TlsStrategy::Internal, None, None, None);
    client
        .upsert_tls_policy(&subjects, &policy)
        .await
        .expect("upsert should initialize absent policies array");

    let after = fetch_tls_policies(&guard.base_url).await;
    assert_eq!(after.len(), 1, "one policy after init");
    assert_eq!(
        after[0]["@id"].as_str(),
        Some("slip-tls-deploy.example.com"),
        "policy carries stable @id"
    );

    // The parent `automation` object should NOT have been replaced with a
    // `{"policies":[]}` body — verify the policies key exists and has our
    // one element (already asserted above), and that a second upsert is
    // idempotent (no duplicate, no wipe).
    client
        .upsert_tls_policy(&subjects, &policy)
        .await
        .expect("second upsert should be idempotent");
    let after_2 = fetch_tls_policies(&guard.base_url).await;
    assert_eq!(after_2.len(), 1, "no duplicate after idempotent upsert");
}

/// Real-Caddy contract: an unowned same-subject policy produces a
/// prescriptive conflict, not adoption or an order-dependent duplicate.
#[tokio::test]
#[ignore]
async fn tls_upsert_conflicts_on_unowned_same_subject_on_real_caddy() {
    let guard = start_caddy();
    let client = CaddyClient::new(guard.base_url.clone());

    // Seed a foreign (unowned) policy for the subject Slip will want.
    let foreign = serde_json::json!({
        "subjects": ["deploy.example.com"],
        "issuers": [{"module": "internal"}]
    });
    inject_foreign_policy(&guard.base_url, &foreign).await;

    // Attempt to upsert a Slip-owned policy for the same subject.
    let subjects = vec!["deploy.example.com".to_string()];
    let policy = build_tls_policy(&subjects, TlsStrategy::Internal, None, None, None);
    let result = client.upsert_tls_policy(&subjects, &policy).await;

    let err = result.expect_err("should refuse to adopt foreign policy");
    let msg = err.to_string();
    assert!(
        msg.contains("deploy.example.com"),
        "prescriptive error names the subject: {msg}"
    );
    assert!(
        msg.contains("slip-tls-deploy.example.com"),
        "prescriptive error names the expected @id: {msg}"
    );

    // The foreign policy is unchanged (no adoption, no duplicate).
    let after = fetch_tls_policies(&guard.base_url).await;
    assert_eq!(after.len(), 1, "no duplicate was added");
    assert_eq!(after[0], foreign, "foreign policy byte-identical");
}

/// Real-Caddy contract: replacing an owned policy via PATCH-by-ID updates
/// it in place — preserving array ordering — rather than DELETE-then-append
/// which would move it to the end. Foreign policies before and after the
/// owned entry stay in their original positions.
#[tokio::test]
#[ignore]
async fn tls_upsert_patch_in_place_preserves_ordering_on_real_caddy() {
    let guard = start_caddy();
    let client = CaddyClient::new(guard.base_url.clone());

    // Seed: foreign DNS-01, then Slip-owned internal, then foreign Tailscale.
    // The owned policy is in the MIDDLE so we can detect both forward and
    // backward position shifts.
    inject_foreign_policy(&guard.base_url, &foreign_dns01_policy()).await;
    let slip_subjects = vec!["deploy.example.com".to_string()];
    let slip_internal = build_tls_policy(&slip_subjects, TlsStrategy::Internal, None, None, None);
    inject_foreign_policy(&guard.base_url, &slip_internal).await;
    inject_foreign_policy(&guard.base_url, &foreign_tailscale_policy()).await;

    let before = fetch_tls_policies(&guard.base_url).await;
    assert_eq!(before.len(), 3, "3 policies seeded");
    let foreign_dns01_before = before[0].clone();
    let foreign_ts_before = before[2].clone();

    // Tag the owned policy with its @id so the upsert recognizes it. On a
    // real Caddy we use the admin API to PATCH the @id onto the middle
    // policy. Alternatively, just call upsert which will see an unowned
    // same-subject policy → conflict. To exercise the PATCH-in-place path,
    // we first make the policy owned by stamping its @id via a direct
    // admin-API PATCH on the element.
    let http = reqwest::Client::new();
    let mut tagged = slip_internal.clone();
    if let Some(obj) = tagged.as_object_mut() {
        obj.insert(
            "@id".to_string(),
            serde_json::Value::String(tls_policy_id("deploy.example.com")),
        );
    }
    // PATCH the element at index 1 to stamp the @id.
    let patch_resp = http
        .patch(format!(
            "{}/config/apps/tls/automation/policies/1",
            guard.base_url
        ))
        .json(&tagged)
        .send()
        .await
        .expect("PATCH element 1 to stamp @id");
    assert!(
        patch_resp.status().is_success(),
        "stamping @id on element 1 failed: {}",
        patch_resp.status()
    );

    // Now upsert an ACME policy for the same subject — the owned policy
    // (at index 1) is found by @id, bodies differ → PATCH /id/<id> in place.
    let new_policy = build_tls_policy(
        &slip_subjects,
        TlsStrategy::Acme,
        None,
        Some("ops@example.com"),
        None,
    );
    client
        .upsert_tls_policy(&slip_subjects, &new_policy)
        .await
        .expect("PATCH-in-place replace should succeed");

    let after = fetch_tls_policies(&guard.base_url).await;
    assert_eq!(after.len(), 3, "no append, no wipe — replaced in place");

    // Owned policy still at index 1 (PATCH preserved position).
    assert_eq!(
        after[1]["@id"].as_str(),
        Some("slip-tls-deploy.example.com"),
        "owned policy still at index 1 — PATCH preserved position"
    );
    assert_eq!(
        after[1]["issuers"][0]["module"].as_str(),
        Some("acme"),
        "owned policy body updated to ACME"
    );

    // Foreign policies unchanged and in their original positions.
    assert_eq!(
        after[0], foreign_dns01_before,
        "foreign DNS-01 at index 0 unchanged"
    );
    assert_eq!(
        after[2], foreign_ts_before,
        "foreign Tailscale at index 2 unchanged"
    );
}
