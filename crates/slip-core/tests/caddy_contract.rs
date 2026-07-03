//! Real-caddy contract tests.
//!
//! These tests require a `caddy` binary on `$PATH`. They are marked `#[ignore]`
//! so they compile but are skipped by default. Run with:
//!
//!     cargo test -p slip-core --test caddy_contract -- --ignored
//!
//! Each test starts a fresh `caddy run` process with an admin-only config on a
//! free port, exercises the `CaddyClient` API, and kills the process on drop.

use std::net::TcpListener;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use slip_core::CaddyClient;
use slip_core::caddy::Route;

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
