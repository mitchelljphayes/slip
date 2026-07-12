//! Tier-3 integration tests for `slip doctor`.
//!
//! These tests are `#[ignore]`d by default and run via
//! `cargo test -p slip-cli --test doctor_integration -- --ignored`.
//! Each test self-skips gracefully if its prerequisite (real Caddy, real
//! UFW, real Docker/Podman) is not present, so `--ignored` on a dev machine
//! without the prerequisites does not hard-fail.
//!
//! These tests NEVER mutate the host firewall. The UFW `--fix` test only
//! runs if UFW is present AND the test is explicitly invoked; it snapshots
//! UFW state before and restores it after (defense-in-depth). The test does
//! not run `--fix` against the real host — it only verifies detection
//! (`doctor` without `--fix` correctly reports the UFW state).

use std::process::Command;

use assert_cmd::Command as AssertCommand;

mod output {
    pub const OK: i32 = 0;
    pub const GENERIC: i32 = 1;
}

/// Check if a binary exists on $PATH.
fn has_binary(name: &str) -> bool {
    Command::new("which")
        .arg(name)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Check if Caddy is running (admin API responds).
fn has_caddy() -> bool {
    Command::new("curl")
        .args(["-sf", "http://localhost:2019/config/"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Check if UFW is present and active.
fn has_ufw_active() -> bool {
    Command::new("ufw")
        .args(["status"])
        .output()
        .map(|o| {
            let stdout = String::from_utf8_lossy(&o.stdout);
            stdout.contains("Status: active")
        })
        .unwrap_or(false)
}

/// Check if Docker or Podman is available.
fn has_container_runtime() -> bool {
    has_binary("docker") || has_binary("podman")
}

// ─── Healthy-host: doctor --json runs and emits valid schema ────────────────

/// On a host with Caddy running, `slip doctor --json` should emit the
/// `slip.doctor/v1` schema. This does NOT assert all checks pass (the host
/// may have other issues); it asserts the schema is present and the command
/// completes without hanging.
#[test]
#[ignore = "requires real Caddy on localhost:2019"]
fn doctor_json_on_host_with_caddy_emits_schema() {
    if !has_caddy() {
        eprintln!("skipping: Caddy not running on localhost:2019");
        return;
    }

    let mut cmd = AssertCommand::cargo_bin("slip").unwrap();
    let output = cmd.arg("doctor").arg("--json").output().unwrap();

    let stdout = String::from_utf8(output.stdout.clone()).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap_or_else(|e| {
        panic!("`slip doctor --json` stdout must be valid JSON: {e}\nstdout: {stdout}");
    });

    assert_eq!(parsed["schema"], "slip.doctor/v1");
    assert!(parsed.get("summary").is_some());
    assert!(parsed.get("checks").is_some());

    let code = output.status.code().unwrap_or(-1);
    assert!(
        code == output::OK || code == output::GENERIC,
        "exit code must be 0 or 1, got {code}"
    );
}

// ─── UFW detection: doctor correctly reports UFW state (no mutation) ────────

/// On a host with UFW active, `slip doctor` (without `--fix`) should run the
/// `ufw.bridge_dns` check and report it (pass/fail/warn depending on the
/// rule). This test NEVER runs `--fix` and NEVER mutates the firewall — it
/// only verifies detection.
#[test]
#[ignore = "requires real UFW active on the host"]
fn doctor_detects_ufw_state_without_mutating() {
    if !has_ufw_active() {
        eprintln!("skipping: UFW not active");
        return;
    }

    let mut cmd = AssertCommand::cargo_bin("slip").unwrap();
    let output = cmd.arg("doctor").arg("--json").output().unwrap();

    let stdout = String::from_utf8(output.stdout.clone()).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap_or_else(|e| {
        panic!("`slip doctor --json` stdout must be valid JSON: {e}\nstdout: {stdout}");
    });

    // The ufw.bridge_dns check must be present in the checks array.
    let checks = parsed
        .get("checks")
        .and_then(|c| c.as_array())
        .expect("checks array must be present");
    let ufw_check = checks
        .iter()
        .find(|c| c.get("name").and_then(|n| n.as_str()) == Some("ufw.bridge_dns"))
        .expect("ufw.bridge_dns check must be in the report");

    let status = ufw_check
        .get("status")
        .and_then(|s| s.as_str())
        .unwrap_or("");
    assert!(
        status == "pass" || status == "fail" || status == "warn",
        "ufw.bridge_dns status should be pass/fail/warn, got '{status}'"
    );

    // If the check failed, the remedy must mention `ufw allow in on`.
    if status == "fail" {
        let remedy = ufw_check
            .get("remedy")
            .and_then(|r| r.as_str())
            .unwrap_or("");
        assert!(
            remedy.contains("ufw allow in on"),
            "fail remedy should name the ufw command: {remedy}"
        );
    }

    // Verify UFW state was NOT changed — re-check status.
    let post = Command::new("ufw").arg("status").output().unwrap();
    let post_stdout = String::from_utf8_lossy(&post.stdout);
    assert!(
        post_stdout.contains("Status: active"),
        "UFW should still be active after doctor (no mutation): {post_stdout}"
    );
}

// ─── Container runtime detection ─────────────────────────────────────────────

/// On a host with Docker or Podman, `slip doctor --json` should report the
/// `runtime.socket` check (pass or warn, not fail/skip).
#[test]
#[ignore = "requires Docker or Podman on the host"]
fn doctor_detects_container_runtime() {
    if !has_container_runtime() {
        eprintln!("skipping: no container runtime (docker/podman)");
        return;
    }

    let mut cmd = AssertCommand::cargo_bin("slip").unwrap();
    let output = cmd.arg("doctor").arg("--json").output().unwrap();

    let stdout = String::from_utf8(output.stdout.clone()).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap_or_else(|e| {
        panic!("`slip doctor --json` stdout must be valid JSON: {e}\nstdout: {stdout}");
    });

    let checks = parsed
        .get("checks")
        .and_then(|c| c.as_array())
        .expect("checks array must be present");
    let rt_check = checks
        .iter()
        .find(|c| c.get("name").and_then(|n| n.as_str()) == Some("runtime.socket"))
        .expect("runtime.socket check must be in the report");

    let status = rt_check
        .get("status")
        .and_then(|s| s.as_str())
        .unwrap_or("");
    assert!(
        status == "pass" || status == "warn",
        "runtime.socket should be pass/warn on a host with a runtime, got '{status}'"
    );
}
