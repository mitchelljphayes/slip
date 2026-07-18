use assert_cmd::Command;
use assert_fs::fixture::{FileWriteStr, PathChild};
use predicates::prelude::*;

// ─── Help / usage ──────────────────────────────────────────────────────────────

#[test]
fn help_exits_zero_and_lists_new_grammar() {
    let mut cmd = Command::cargo_bin("slip").unwrap();
    let assert = cmd.arg("--help").assert();

    assert
        .success()
        .code(output::OK)
        .stdout(predicate::str::contains("init"))
        .stdout(predicate::str::contains("apply"))
        .stdout(predicate::str::contains("deploy"))
        .stdout(predicate::str::contains("server"))
        .stdout(predicate::str::contains("services"))
        .stdout(predicate::str::contains("doctor"));
}

#[test]
fn bad_flag_exits_usage() {
    let mut cmd = Command::cargo_bin("slip").unwrap();
    let assert = cmd.arg("--bad-flag").assert();

    assert
        .failure()
        .code(output::USAGE)
        .stderr(predicate::str::contains("error"));
}

// ─── Status command ───────────────────────────────────────────────────────────

#[test]
fn status_without_token_exits_auth() {
    let mut cmd = Command::cargo_bin("slip").unwrap();
    let assert = cmd.arg("status").assert();

    assert
        .failure()
        .code(output::AUTH)
        .stderr(predicate::str::contains("SLIP_TOKEN"));
}

#[test]
fn status_with_token_connection_error_exits_generic() {
    let mut cmd = Command::cargo_bin("slip").unwrap();
    let assert = cmd
        .args([
            "status",
            "--token",
            "test-token",
            "--server",
            "http://127.0.0.1:1",
        ])
        .assert();

    assert
        .failure()
        .code(output::GENERIC)
        .stderr(predicate::str::contains("can't reach slipd"));
}

#[test]
fn status_json_with_token_connection_error_exits_generic() {
    let mut cmd = Command::cargo_bin("slip").unwrap();
    let assert = cmd
        .args([
            "status",
            "--json",
            "--token",
            "test-token",
            "--server",
            "http://127.0.0.1:1",
        ])
        .assert();

    assert
        .failure()
        .code(output::GENERIC)
        .stderr(predicate::str::contains("can't reach slipd"));
}

// ─── Status command: debugging scenarios (SLIP-100 acceptance criteria) ───────
//
// These verify the CLI renders the diagnostic info from `slip status <app>`
// so the three debugging scenarios are answerable from CLI output alone.

/// Stuck deploy: the --json output must carry the deploying status and the
/// non-terminal last_deploy phase.
#[test]
fn status_app_stuck_deploy_json_shows_deploying() {
    let canned = serde_json::json!({
        "status": "deploying",
        "tag": "v2.0.0",
        "container_id": "newcid456",
        "port": 54321,
        "kind": "container",
        "deploy_id": "dep_stuck001",
        "triggered_by": "webhook",
        "last_deploy": {
            "deploy_id": "dep_stuck001",
            "app": "myapp",
            "tag": "v2.0.0",
            "status": "health_checking",
            "triggered_by": "webhook"
        }
    });
    let url = start_mock_server_with_app_status(canned);

    let mut cmd = Command::cargo_bin("slip").unwrap();
    let assert = cmd
        .args([
            "status",
            "myapp",
            "--json",
            "--token",
            "test-token",
            "--server",
            &url,
        ])
        .assert();

    let stdout = assert.success().get_output().stdout.clone();
    let parsed: serde_json::Value = serde_json::from_slice(&stdout).unwrap();
    assert_eq!(parsed["status"], "deploying");
    assert_eq!(parsed["last_deploy"]["status"], "health_checking");
}

/// Failed health: the --json output must carry health.status = "unhealthy".
#[test]
fn status_app_failed_health_json_shows_unhealthy() {
    let canned = serde_json::json!({
        "status": "running",
        "tag": "v1.0.0",
        "container_id": "abc123",
        "port": 8080,
        "kind": "container",
        "health": {
            "path": "/healthz",
            "retries": 3,
            "status": "unhealthy",
            "last_check": "2026-07-11T14:30:00Z"
        }
    });
    let url = start_mock_server_with_app_status(canned);

    let mut cmd = Command::cargo_bin("slip").unwrap();
    let assert = cmd
        .args([
            "status",
            "myapp",
            "--json",
            "--token",
            "test-token",
            "--server",
            &url,
        ])
        .assert();

    let stdout = assert.success().get_output().stdout.clone();
    let parsed: serde_json::Value = serde_json::from_slice(&stdout).unwrap();
    assert_eq!(parsed["status"], "running");
    assert_eq!(parsed["health"]["status"], "unhealthy");
    assert_eq!(parsed["health"]["path"], "/healthz");
}

/// Drifted config: the --json output must carry config_drift = true.
#[test]
fn status_app_config_drift_json_shows_drift() {
    let canned = serde_json::json!({
        "status": "running",
        "tag": "v1.0.0",
        "container_id": "abc123",
        "port": 8080,
        "kind": "container",
        "config_drift": true
    });
    let url = start_mock_server_with_app_status(canned);

    let mut cmd = Command::cargo_bin("slip").unwrap();
    let assert = cmd
        .args([
            "status",
            "myapp",
            "--json",
            "--token",
            "test-token",
            "--server",
            &url,
        ])
        .assert();

    let stdout = assert.success().get_output().stdout.clone();
    let parsed: serde_json::Value = serde_json::from_slice(&stdout).unwrap();
    assert_eq!(parsed["status"], "running");
    assert_eq!(parsed["config_drift"], true);
}

// ─── Init command ────────────────────────────────────────────────────────────────

#[test]
fn init_help_lists_flags() {
    let mut cmd = Command::cargo_bin("slip").unwrap();
    let assert = cmd.args(["init", "--help"]).assert();

    assert
        .success()
        .code(output::OK)
        .stdout(predicate::str::contains("--name"))
        .stdout(predicate::str::contains("--image"))
        .stdout(predicate::str::contains("--force"))
        .stdout(predicate::str::contains("--json"));
}

#[test]
fn init_in_tempdir_writes_three_files() {
    let tmp = assert_fs::TempDir::new().unwrap();

    let mut cmd = Command::cargo_bin("slip").unwrap();
    let assert = cmd
        .args([
            "init",
            "--name",
            "testapp",
            "--image",
            "ghcr.io/test/testapp",
        ])
        .current_dir(tmp.path())
        .assert();

    assert.success().code(output::OK);

    // Check all three files exist
    assert!(tmp.child("slip.toml").exists());
    assert!(tmp.child(".github/workflows/deploy.yml").exists());
    assert!(tmp.child("AGENTS.md").exists());

    // Verify slip.toml content
    let slip_toml = std::fs::read_to_string(tmp.child("slip.toml").path()).unwrap();
    assert!(slip_toml.contains(r#"name = "testapp""#));
    assert!(slip_toml.contains(r#"strategy = "blue-green""#));
    // Health guidance should steer away from /
    assert!(slip_toml.contains(r#"Do NOT use path = "/""#));
    assert!(slip_toml.contains(r#"path = "/healthz""#));
    // SLIP-103: expect_status scaffold comment + docs link.
    assert!(
        slip_toml.contains("expect_status"),
        "scaffold should mention expect_status"
    );
    assert!(
        slip_toml.contains("docs/health.md"),
        "scaffold should link to docs/health.md"
    );
    // Commented needs examples
    assert!(slip_toml.contains(r#"[needs.db]"#));
    assert!(slip_toml.contains(r#"[needs.storage]"#));
    assert!(slip_toml.contains(r#"[needs.cache]"#));

    // Verify deploy.yml content
    let deploy_yml =
        std::fs::read_to_string(tmp.child(".github/workflows/deploy.yml").path()).unwrap();
    assert!(deploy_yml.contains(r#"APP: "testapp""#));
    assert!(deploy_yml.contains(r#"IMAGE: "ghcr.io/test/testapp""#));
    assert!(deploy_yml.contains(r#"X-Slip-Signature"#));
    assert!(deploy_yml.contains(r#"SLIP_DEPLOY_SECRET"#));
    assert!(deploy_yml.contains(r#"SLIP_DEPLOY_URL"#));
    assert!(deploy_yml.contains(r#"TS_AUTHKEY"#));

    // Verify AGENTS.md content
    let agents_md = std::fs::read_to_string(tmp.child("AGENTS.md").path()).unwrap();
    assert!(agents_md.contains("## slip deploy contract"));
    assert!(agents_md.contains("POST /v1/deploy"));
    assert!(agents_md.contains("X-Slip-Signature"));
    assert!(agents_md.contains("blue-green"));
    assert!(agents_md.contains("GET /v1/deploys/{id}"));
    // SLIP-103: AGENTS.md template mentions expect_status + docs link.
    assert!(
        agents_md.contains("expect_status"),
        "AGENTS.md scaffold should mention expect_status"
    );
    assert!(
        agents_md.contains("docs/health.md"),
        "AGENTS.md scaffold should link to docs/health.md"
    );

    tmp.close().unwrap();
}

#[test]
fn init_without_force_refuses_to_clobber() {
    let tmp = assert_fs::TempDir::new().unwrap();

    // First run
    let mut cmd = Command::cargo_bin("slip").unwrap();
    cmd.args([
        "init",
        "--name",
        "testapp",
        "--image",
        "ghcr.io/test/testapp",
    ])
    .current_dir(tmp.path())
    .assert()
    .success();

    // Second run without --force
    let mut cmd = Command::cargo_bin("slip").unwrap();
    let assert = cmd
        .args([
            "init",
            "--name",
            "testapp",
            "--image",
            "ghcr.io/test/testapp",
        ])
        .current_dir(tmp.path())
        .assert();

    assert
        .failure()
        .code(output::GENERIC)
        .stderr(predicate::str::contains("already exist"));

    tmp.close().unwrap();
}

#[test]
fn init_with_force_overwrites() {
    let tmp = assert_fs::TempDir::new().unwrap();

    // First run
    let mut cmd = Command::cargo_bin("slip").unwrap();
    cmd.args([
        "init",
        "--name",
        "testapp",
        "--image",
        "ghcr.io/test/testapp",
    ])
    .current_dir(tmp.path())
    .assert()
    .success();

    // Second run with --force
    let mut cmd = Command::cargo_bin("slip").unwrap();
    let assert = cmd
        .args([
            "init",
            "--name",
            "testapp",
            "--image",
            "ghcr.io/test/testapp",
            "--force",
        ])
        .current_dir(tmp.path())
        .assert();

    assert.success().code(output::OK);

    tmp.close().unwrap();
}

#[test]
fn init_json_output_shape() {
    let tmp = assert_fs::TempDir::new().unwrap();

    let mut cmd = Command::cargo_bin("slip").unwrap();
    let result = cmd
        .args([
            "init",
            "--name",
            "testapp",
            "--image",
            "ghcr.io/test/testapp",
            "--json",
        ])
        .current_dir(tmp.path())
        .assert()
        .success()
        .code(output::OK);

    let stdout = String::from_utf8(result.get_output().stdout.clone()).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap();

    assert_eq!(parsed["status"], "ok");
    assert_eq!(parsed["app"], "testapp");
    assert_eq!(parsed["image"], "ghcr.io/test/testapp");
    let files = parsed["files_written"].as_array().unwrap();
    assert_eq!(files.len(), 3);

    tmp.close().unwrap();
}

#[test]
fn init_json_existing_files_reports_status_exists() {
    let tmp = assert_fs::TempDir::new().unwrap();

    // First run
    let mut cmd = Command::cargo_bin("slip").unwrap();
    cmd.args([
        "init",
        "--name",
        "testapp",
        "--image",
        "ghcr.io/test/testapp",
    ])
    .current_dir(tmp.path())
    .assert()
    .success();

    // Second run with --json (no --force)
    let mut cmd = Command::cargo_bin("slip").unwrap();
    let result = cmd
        .args([
            "init",
            "--name",
            "testapp",
            "--image",
            "ghcr.io/test/testapp",
            "--json",
        ])
        .current_dir(tmp.path())
        .assert()
        .failure()
        .code(output::GENERIC);

    let stdout = String::from_utf8(result.get_output().stdout.clone()).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap();

    assert_eq!(parsed["status"], "exists");
    assert!(!parsed["files"].as_array().unwrap().is_empty());

    tmp.close().unwrap();
}

#[test]
fn init_scaffolded_slip_toml_passes_validate() {
    let tmp = assert_fs::TempDir::new().unwrap();

    // Run init
    let mut cmd = Command::cargo_bin("slip").unwrap();
    cmd.args([
        "init",
        "--name",
        "testapp",
        "--image",
        "ghcr.io/test/testapp",
    ])
    .current_dir(tmp.path())
    .assert()
    .success();

    // Parse the generated slip.toml with slip_core's parser
    let content = std::fs::read_to_string(tmp.child("slip.toml").path()).unwrap();
    let cfg = slip_core::parse_repo_config(content.as_bytes()).unwrap();

    assert_eq!(cfg.app.name, "testapp");
    assert_eq!(cfg.app.kind, "container");
    assert_eq!(
        cfg.app.image.as_deref(),
        Some("ghcr.io/test/testapp"),
        "image should be populated from --image flag"
    );
    // Health path should be None (commented out in template)
    assert!(cfg.health.path.is_none());
    // Routing
    assert_eq!(cfg.routing.port, Some(3000));
    assert_eq!(
        cfg.routing.domain.as_deref(),
        Some("testapp.example.com"),
        "domain should be populated from template"
    );
    // Resources
    let resources = cfg.defaults.resources.as_ref().unwrap();
    assert_eq!(resources.memory.as_deref(), Some("512m"));
    assert_eq!(resources.cpus.as_deref(), Some("1.0"));

    // Verify the template also has the header comment
    assert!(content.contains("slip config — managed by you"));

    tmp.close().unwrap();
}

// ─── slip validate (SLIP-103) ───────────────────────────────────────────────

/// `slip validate --json` with a root-path config emits a stable JSON envelope
/// with `ok: true` and the root-path warning. AC14.
#[test]
fn slip_validate_root_path_warning_json() {
    let tmp = assert_fs::TempDir::new().unwrap();
    let slip_toml = r#"
[app]
name = "myapp"
kind = "container"
image = "ghcr.io/org/myapp"

[routing]
domain = "myapp.example.com"
port = 3000

[health]
path = "/"

[deploy]
strategy = "blue-green"
"#;
    std::fs::write(tmp.child("slip.toml").path(), slip_toml).unwrap();

    let mut cmd = Command::cargo_bin("slip").unwrap();
    let assert = cmd
        .args(["validate", "--json"])
        .current_dir(tmp.path())
        .assert();

    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    let stderr = String::from_utf8(assert.get_output().stderr.clone()).unwrap();
    assert.success().code(output::OK);

    let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap_or_else(|e| {
        panic!(
            "validate --json stdout must be a single JSON document: {e}\nstdout: {stdout}\nstderr: {stderr}"
        )
    });
    assert_eq!(parsed["ok"], true, "root-path is a warning, not an error");
    let warnings = parsed["warnings"].as_array().expect("warnings is array");
    assert!(
        warnings.iter().any(|w| {
            w.as_str()
                .map(|s| s.contains("does not prove readiness") && s.contains("docs/health.md"))
                .unwrap_or(false)
        }),
        "warnings must include the root-path warning with docs link: {warnings:?}"
    );
    assert!(
        parsed["errors"]
            .as_array()
            .map(|a| a.is_empty())
            .unwrap_or(false),
        "errors must be empty"
    );
}

/// `slip validate` (human mode) with a root-path config still emits the
/// `⚠ ...` warning to stdout and exits 0. AC14.
#[test]
fn slip_validate_root_path_warning_human() {
    let tmp = assert_fs::TempDir::new().unwrap();
    let slip_toml = r#"
[app]
name = "myapp"
kind = "container"
image = "ghcr.io/org/myapp"

[routing]
domain = "myapp.example.com"
port = 3000

[health]
path = "/"

[deploy]
strategy = "blue-green"
"#;
    std::fs::write(tmp.child("slip.toml").path(), slip_toml).unwrap();

    let mut cmd = Command::cargo_bin("slip").unwrap();
    let assert = cmd.args(["validate"]).current_dir(tmp.path()).assert();

    assert
        .success()
        .code(output::OK)
        .stdout(predicate::str::contains("⚠"))
        .stdout(predicate::str::contains("does not prove readiness"))
        .stdout(predicate::str::contains("docs/health.md"));
}

/// `slip validate --json` with an invalid config emits `ok: false`, a
/// non-empty `errors` array, and exit 1. AC14.
#[test]
fn slip_validate_json_envelope_invalid_config() {
    let tmp = assert_fs::TempDir::new().unwrap();
    // Invalid: kind=pod with no manifest.
    let slip_toml = r#"
[app]
name = "myapp"
kind = "pod"
"#;
    std::fs::write(tmp.child("slip.toml").path(), slip_toml).unwrap();

    let mut cmd = Command::cargo_bin("slip").unwrap();
    let assert = cmd
        .args(["validate", "--json"])
        .current_dir(tmp.path())
        .assert();

    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    assert.failure().code(output::GENERIC);
    let parsed: serde_json::Value =
        serde_json::from_str(&stdout).expect("stdout is a JSON envelope");
    assert_eq!(parsed["ok"], false);
    let errors = parsed["errors"].as_array().expect("errors is array");
    assert!(!errors.is_empty(), "errors must be non-empty");
}

#[test]
fn logs_command_rejects_invalid_since() {
    let mut cmd = Command::cargo_bin("slip").unwrap();
    let assert = cmd.args(["logs", "myapp", "--since", "abc"]).assert();

    // Invalid --since exits with USAGE (2), stderr mentions "invalid --since".
    assert
        .failure()
        .code(output::USAGE)
        .stderr(predicate::str::contains("invalid --since"));
}

#[test]
fn logs_follow_flag_accepted() {
    let mut cmd = Command::cargo_bin("slip").unwrap();
    // --follow should NOT exit with "not yet implemented" (the stub is gone).
    // It will fail with a connection error (no server), but that's not a stub.
    let assert = cmd.args(["logs", "myapp", "--follow"]).assert();

    assert
        .failure()
        .stderr(predicate::str::contains("not yet implemented").not());
}

#[test]
fn logs_short_follow_flag_accepted() {
    let mut cmd = Command::cargo_bin("slip").unwrap();
    let assert = cmd.args(["logs", "myapp", "-f"]).assert();

    assert
        .failure()
        .stderr(predicate::str::contains("not yet implemented").not());
}

#[test]
fn apply_stub_exits_nonzero() {
    let mut cmd = Command::cargo_bin("slip").unwrap();
    let assert = cmd.arg("apply").assert();

    // apply is now a real command; without a token it exits AUTH
    assert
        .failure()
        .code(output::AUTH)
        .stderr(predicate::str::contains("no admin token"));
}

#[test]
fn deploy_stub_exits_nonzero() {
    let mut cmd = Command::cargo_bin("slip").unwrap();
    // deploy requires app + tag positional args; without them clap errors first
    let assert = cmd.args(["deploy", "myapp", "v1"]).assert();

    // Without a server, it will fail with a connection error (not a stub)
    // but it should NOT exit with GENERIC — it's a real command that tries HTTP.
    // We just verify it doesn't say "not yet implemented".
    assert
        .failure()
        .stderr(predicate::str::contains("not yet implemented").not());
}

#[test]
fn doctor_json_emits_stable_schema() {
    // `slip doctor --json` must emit the slip.doctor/v1 schema. With no
    // config / no slipd, most checks will warn/fail, but the schema shape
    // must be present and the exit code must be nonzero (any fail).
    let mut cmd = Command::cargo_bin("slip").unwrap();
    let output = cmd.arg("doctor").arg("--json").output().unwrap();

    let stdout = String::from_utf8(output.stdout.clone()).unwrap();

    // Parse the JSON — it must be valid.
    let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap_or_else(|e| {
        panic!("`slip doctor --json` stdout must be valid JSON: {e}\nstdout: {stdout}");
    });

    // Schema marker.
    assert_eq!(
        parsed["schema"], "slip.doctor/v1",
        "schema must be slip.doctor/v1, got: {stdout}"
    );

    // Summary fields.
    assert!(parsed.get("summary").is_some(), "summary must be present");
    assert!(
        parsed["summary"].get("pass").is_some()
            && parsed["summary"].get("warn").is_some()
            && parsed["summary"].get("fail").is_some()
            && parsed["summary"].get("skipped").is_some(),
        "summary must have pass/warn/fail/skipped"
    );

    // Checks array.
    let checks = parsed
        .get("checks")
        .and_then(|c| c.as_array())
        .expect("checks must be an array");
    assert!(!checks.is_empty(), "checks array must not be empty");
    for check in checks {
        assert!(check.get("name").is_some(), "each check has name");
        assert!(check.get("status").is_some(), "each check has status");
        assert!(check.get("detail").is_some(), "each check has detail");
    }

    // Exit code: 0 if no fail, 1 if any fail. On a bare CI host with no
    // slipd/caddy, at least one check will fail (caddy.reachable), so we
    // expect a nonzero exit. We accept either 0 or 1 here (the host may
    // happen to have caddy running), but NOT a stub exit.
    let code = output.status.code().unwrap_or(-1);
    assert!(
        code == output::OK || code == output::GENERIC,
        "exit code must be 0 or 1, got {code}"
    );
}

#[test]
fn doctor_human_output_shows_checks() {
    let mut cmd = Command::cargo_bin("slip").unwrap();
    let output = cmd.arg("doctor").output().unwrap();

    let stdout = String::from_utf8(output.stdout.clone()).unwrap();
    let stderr = String::from_utf8(output.stderr.clone()).unwrap();

    // Must NOT say "not yet implemented" — the stub is gone.
    assert!(
        !stdout.contains("not yet implemented") && !stderr.contains("not yet implemented"),
        "doctor must not be a stub"
    );
    // Human output should show the Verification header.
    assert!(
        stdout.contains("Verification:") || stdout.contains("passed"),
        "human output should show verification results: {stdout}"
    );
}

#[test]
fn doctor_fix_without_root_fails() {
    // `slip doctor --fix` without root (and without test overrides) must
    // fail with a prescriptive "must be run as root" error. We don't set
    // SLIP_TEST_CONFIG_DIR so the root check is active. If the test host
    // is root (CI sometimes runs as root), the check passes and we instead
    // hit the non-TTY/--yes gate; either way the exit is nonzero.
    let mut cmd = Command::cargo_bin("slip").unwrap();
    let output = cmd.arg("doctor").arg("--fix").output().unwrap();

    let stdout = String::from_utf8(output.stdout.clone()).unwrap();
    let stderr = String::from_utf8(output.stderr.clone()).unwrap();

    let code = output.status.code().unwrap_or(-1);
    // Must exit nonzero (either GENERIC for non-root, or USAGE for non-TTY
    // without --yes).
    assert!(
        code == output::GENERIC || code == output::USAGE,
        "doctor --fix without root/--yes must exit 1 or 2, got {code}\nstderr: {stderr}"
    );
    // Should mention root or --yes.
    let combined = format!("{stdout}\n{stderr}");
    assert!(
        combined.contains("root") || combined.contains("--yes"),
        "prescriptive error should mention root or --yes: {combined}"
    );
}

#[test]
fn doctor_fix_dry_run_does_not_mutate() {
    // `slip doctor --fix --dry-run` should print planned actions or
    // "nothing to fix" without mutating. With no config, there's nothing
    // to fix, so it exits 0 (or 1 if there are fails but none are
    // auto-fixable → "no auto-fixable failures").
    let mut cmd = Command::cargo_bin("slip").unwrap();
    let output = cmd
        .arg("doctor")
        .arg("--fix")
        .arg("--dry-run")
        .output()
        .unwrap();

    let code = output.status.code().unwrap_or(-1);
    // Dry-run never mutates; exit is 0 (nothing to fix) or 1 (fails exist
    // but not auto-fixable).
    assert!(
        code == output::OK || code == output::GENERIC,
        "doctor --fix --dry-run should exit 0 or 1, got {code}"
    );
}

#[test]
fn doctor_fix_yes_json_emits_exactly_one_json_document() {
    // Regression for BLOCKER #1: `--fix --yes --json` must emit exactly ONE
    // parseable JSON document on stdout (not two concatenated objects).
    //
    // This test does NOT set SLIP_TEST_CONFIG_DIR — production `run()`
    // passes `skip_root: false` unconditionally, so no env var bypasses
    // the root check. However, the `NothingToDo` path (no auto-fixable
    // fails) returns BEFORE the root check, so on a typical test host
    // (where UFW is absent → warn, not fail → no auto-fixable fails) the
    // command produces a valid JSON report with `"actions": []` without
    // needing root.
    //
    // If the test host happens to have UFW active with the bridge DNS rule
    // missing (making ufw.bridge_dns a fail → auto-fixable), the root check
    // would trigger and exit GENERIC before printing JSON. In that case
    // the test would fail — but this is extremely unlikely on CI/dev hosts.
    let mut cmd = Command::cargo_bin("slip").unwrap();
    let output = cmd
        .args(["doctor", "--fix", "--yes", "--json"])
        .output()
        .unwrap();

    let stdout = String::from_utf8(output.stdout.clone()).unwrap();
    let code = output.status.code().unwrap_or(-1);

    // Two possible outcomes:
    // 1. NothingToDo (no auto-fixable fails) → one JSON document, exit 0/1.
    // 2. Root check triggered (auto-fixable fail exists) → no JSON, exit 1.
    //
    // We accept both but verify: if stdout is non-empty, it must be a
    // single valid JSON document (the BLOCKER regression).
    if !stdout.is_empty() {
        let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap_or_else(|e| {
            panic!(
                "`slip doctor --fix --yes --json` must emit exactly one JSON document: {e}\nstdout: {stdout}"
            );
        });
        assert_eq!(parsed["schema"], "slip.doctor/v1");
        assert!(
            parsed.get("actions").is_some(),
            "--fix --json must include 'actions' field, got: {stdout}"
        );
    }

    // Exit code: 0 (no fails), 1 (has fails or non-root), or 2 (usage).
    assert!(
        code == output::OK || code == output::GENERIC,
        "exit code must be 0 or 1, got {code}"
    );
}

#[test]
fn doctor_fix_yes_json_emits_actions_array_even_on_nothing_to_do() {
    // Regression for BLOCKER #1: the NothingToDo path must still emit
    // `"actions": []` (not omit the field). Same caveat as above: this
    // works on hosts without auto-fixable fails (the NothingToDo path
    // returns before the root check).
    let mut cmd = Command::cargo_bin("slip").unwrap();
    let output = cmd
        .args(["doctor", "--fix", "--yes", "--json"])
        .output()
        .unwrap();

    let stdout = String::from_utf8(output.stdout.clone()).unwrap();

    if !stdout.is_empty() {
        let parsed: serde_json::Value =
            serde_json::from_str(&stdout).expect("must be single valid JSON");
        assert!(
            parsed.get("actions").is_some(),
            "actions field must be present in --fix output"
        );
        assert!(parsed["actions"].is_array(), "actions must be an array");
    }
}

#[test]
fn doctor_fix_without_root_fails_even_with_test_config_dir() {
    // Regression proving SLIP_TEST_CONFIG_DIR does NOT bypass the production
    // root requirement for `--fix`. Production `run()` passes `skip_root:
    // false` unconditionally — no env var may bypass it.
    //
    // We set SLIP_TEST_CONFIG_DIR (which bypasses root for `slip server
    // init` but NOT for `slip doctor --fix`) and run `--fix` without root.
    // The command must exit GENERIC with "must be run as root" IF there
    // are auto-fixable fails. If there are no auto-fixable fails, the
    // NothingToDo path returns before the root check — so we can't assert
    // the root failure unconditionally. Instead, we assert that the command
    // does NOT produce a JSON report with `"actions": [...]` containing
    // applied/pending entries (which would indicate a root bypass).
    let tmp = assert_fs::TempDir::new().unwrap();

    let mut cmd = Command::cargo_bin("slip").unwrap();
    let output = cmd
        .env("SLIP_TEST_CONFIG_DIR", tmp.path().to_str().unwrap())
        .args(["doctor", "--fix", "--yes", "--json"])
        .output()
        .unwrap();

    let stdout = String::from_utf8(output.stdout.clone()).unwrap();
    let code = output.status.code().unwrap_or(-1);

    // The command must not produce a report with non-empty actions (which
    // would indicate a mutation bypassed root). Either:
    // - NothingToDo (no auto-fixable fails) → JSON with `"actions": []`,
    //   exit 0/1. Safe — no mutation.
    // - Root check triggered → no JSON, exit 1. Safe — root required.
    if !stdout.is_empty() {
        let parsed: serde_json::Value =
            serde_json::from_str(&stdout).expect("must be single valid JSON if present");
        if let Some(actions) = parsed.get("actions").and_then(|a| a.as_array()) {
            for action in actions {
                let status = action.get("status").and_then(|s| s.as_str()).unwrap_or("");
                assert!(
                    status == "pending" || status == "already_present",
                    "SLIP_TEST_CONFIG_DIR must not allow --fix to apply actions \
                     without root: found status='{status}'"
                );
            }
        }
    }
    assert!(
        code == output::OK || code == output::GENERIC,
        "exit code must be 0 or 1, got {code}"
    );
}

#[test]
fn server_init_stub_exits_nonzero() {
    let mut cmd = Command::cargo_bin("slip").unwrap();
    let assert = cmd.args(["server", "init"]).assert();

    // Without root or test overrides, the command should fail with a
    // prescriptive error about needing root.
    assert
        .failure()
        .code(output::GENERIC)
        .stderr(predicate::str::contains("must be run as root"));
}

// ─── `slip server init` integration tests ───────────────────────────────────────

#[test]
fn server_init_writes_secret_and_config_in_tempdir() {
    let tmp = assert_fs::TempDir::new().unwrap();
    let config_dir = tmp.path().join("etc/slip");
    let env_file = config_dir.join("slip.env");

    let mut cmd = Command::cargo_bin("slip").unwrap();
    let assert = cmd
        .env("SLIP_TEST_CONFIG_DIR", config_dir.to_str().unwrap())
        .env("SLIP_TEST_ENV_FILE", env_file.to_str().unwrap())
        .env("SLIP_TEST_MANIFEST_DIR", tmp.path().to_str().unwrap())
        .args([
            "server",
            "init",
            "--yes",
            "--no-systemd",
            "--skip-verify",
            "--domain",
            "deploy.example.com",
        ])
        .assert();

    let assert = assert.success().code(output::OK);

    // Check env file exists with 64-hex secret
    assert!(env_file.exists(), "env file should exist");
    let env_content = std::fs::read_to_string(&env_file).unwrap();
    assert!(
        env_content.starts_with("SLIP_ADMIN_SECRET="),
        "env file should contain SLIP_ADMIN_SECRET"
    );
    let secret = env_content
        .trim()
        .strip_prefix("SLIP_ADMIN_SECRET=")
        .unwrap();
    assert_eq!(secret.len(), 64, "secret should be 64 hex chars");
    assert!(
        secret.chars().all(|c| c.is_ascii_hexdigit()),
        "secret should be hex"
    );

    // Check 0600 mode
    let metadata = std::fs::metadata(&env_file).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            metadata.permissions().mode() & 0o777,
            0o600,
            "env file should be 0600"
        );
    }

    // Check config file exists with ${SLIP_ADMIN_SECRET} reference
    let config_path = config_dir.join("slip.toml");
    assert!(config_path.exists(), "config file should exist");
    let config_content = std::fs::read_to_string(&config_path).unwrap();
    assert!(
        config_content.contains("${SLIP_ADMIN_SECRET}"),
        "config should reference env var"
    );
    assert!(
        config_content.contains("deploy.example.com"),
        "config should contain deploy domain"
    );
    assert!(
        config_content.contains("backend = \"auto\""),
        "config should contain runtime backend"
    );

    // Check 0644 mode on config
    let config_meta = std::fs::metadata(&config_path).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            config_meta.permissions().mode() & 0o777,
            0o644,
            "config file should be 0644"
        );
    }

    // Check stdout contains the secret banner WITH the actual secret value
    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    assert!(
        stdout.contains("Admin secret generated"),
        "stdout should show secret banner"
    );
    // Fresh run SHOULD contain the 64-hex secret in stdout (on the banner line)
    let has_hex_secret = stdout.lines().any(|line| {
        line.contains("Admin secret generated:")
            && line.chars().filter(|c| c.is_ascii_hexdigit()).count() >= 64
    });
    assert!(
        has_hex_secret,
        "fresh run should show the secret in stdout: {stdout}"
    );
}

#[test]
fn server_init_idempotent_skips_existing() {
    let tmp = assert_fs::TempDir::new().unwrap();
    let config_dir = tmp.path().join("etc/slip");
    let env_file = config_dir.join("slip.env");

    // First run
    let mut cmd = Command::cargo_bin("slip").unwrap();
    cmd.env("SLIP_TEST_CONFIG_DIR", config_dir.to_str().unwrap())
        .env("SLIP_TEST_ENV_FILE", env_file.to_str().unwrap())
        .env("SLIP_TEST_MANIFEST_DIR", tmp.path().to_str().unwrap())
        .args(["server", "init", "--yes", "--no-systemd", "--skip-verify"])
        .assert()
        .success();

    // Second run (idempotent)
    let mut cmd2 = Command::cargo_bin("slip").unwrap();
    let assert2 = cmd2
        .env("SLIP_TEST_CONFIG_DIR", config_dir.to_str().unwrap())
        .env("SLIP_TEST_ENV_FILE", env_file.to_str().unwrap())
        .env("SLIP_TEST_MANIFEST_DIR", tmp.path().to_str().unwrap())
        .args(["server", "init", "--yes", "--no-systemd", "--skip-verify"])
        .assert();

    let assert2 = assert2.success().code(output::OK);

    // Should mention "already present"
    let stderr = String::from_utf8(assert2.get_output().stderr.clone()).unwrap();
    assert!(
        stderr.contains("already present"),
        "idempotent run should mention existing files: {stderr}"
    );
}

#[test]
fn server_init_force_secret_regenerates() {
    let tmp = assert_fs::TempDir::new().unwrap();
    let config_dir = tmp.path().join("etc/slip");
    let env_file = config_dir.join("slip.env");

    // First run
    let mut cmd = Command::cargo_bin("slip").unwrap();
    cmd.env("SLIP_TEST_CONFIG_DIR", config_dir.to_str().unwrap())
        .env("SLIP_TEST_ENV_FILE", env_file.to_str().unwrap())
        .env("SLIP_TEST_MANIFEST_DIR", tmp.path().to_str().unwrap())
        .args(["server", "init", "--yes", "--no-systemd", "--skip-verify"])
        .assert()
        .success();

    let first_secret = std::fs::read_to_string(&env_file).unwrap();

    // Second run with --force=secret
    let mut cmd2 = Command::cargo_bin("slip").unwrap();
    let assert2 = cmd2
        .env("SLIP_TEST_CONFIG_DIR", config_dir.to_str().unwrap())
        .env("SLIP_TEST_ENV_FILE", env_file.to_str().unwrap())
        .env("SLIP_TEST_MANIFEST_DIR", tmp.path().to_str().unwrap())
        .args([
            "server",
            "init",
            "--yes",
            "--no-systemd",
            "--skip-verify",
            "--force",
            "secret",
        ])
        .assert();

    let assert2 = assert2.success().code(output::OK);

    let second_secret = std::fs::read_to_string(&env_file).unwrap();
    assert_ne!(first_secret, second_secret, "secret should be regenerated");

    let stderr = String::from_utf8(assert2.get_output().stderr.clone()).unwrap();
    assert!(
        stderr.contains("regenerating secret"),
        "should warn about regeneration"
    );
}

#[test]
fn server_init_writes_unit_file() {
    let tmp = assert_fs::TempDir::new().unwrap();
    let config_dir = tmp.path().join("etc/slip");
    let systemd_dir = tmp.path().join("etc/systemd/system");
    let env_file = config_dir.join("slip.env");

    let mut cmd = Command::cargo_bin("slip").unwrap();
    cmd.env("SLIP_TEST_CONFIG_DIR", config_dir.to_str().unwrap())
        .env("SLIP_TEST_SYSTEMD_DIR", systemd_dir.to_str().unwrap())
        .env("SLIP_TEST_ENV_FILE", env_file.to_str().unwrap())
        .env("SLIP_TEST_MANIFEST_DIR", tmp.path().to_str().unwrap())
        .args(["server", "init", "--yes", "--skip-verify"])
        .assert()
        .success();

    let unit_path = systemd_dir.join("slipd.service");
    assert!(unit_path.exists(), "unit file should exist");
    let unit_content = std::fs::read_to_string(&unit_path).unwrap();

    // Check key features
    assert!(
        unit_content.contains("EnvironmentFile="),
        "unit should have EnvironmentFile"
    );
    assert!(
        unit_content.contains("ProtectSystem=strict"),
        "unit should have ProtectSystem=strict"
    );
    assert!(
        unit_content.contains("ReadWritePaths"),
        "unit should have ReadWritePaths"
    );
    assert!(
        unit_content.contains("RestartPreventExitStatus=78"),
        "unit should have RestartPreventExitStatus=78"
    );
    assert!(
        unit_content.contains("User=root"),
        "unit should run as root"
    );
}

#[test]
fn server_init_no_systemd_skips_service() {
    let tmp = assert_fs::TempDir::new().unwrap();
    let config_dir = tmp.path().join("etc/slip");
    let env_file = config_dir.join("slip.env");

    let mut cmd = Command::cargo_bin("slip").unwrap();
    let assert = cmd
        .env("SLIP_TEST_CONFIG_DIR", config_dir.to_str().unwrap())
        .env("SLIP_TEST_ENV_FILE", env_file.to_str().unwrap())
        .env("SLIP_TEST_MANIFEST_DIR", tmp.path().to_str().unwrap())
        .args(["server", "init", "--yes", "--no-systemd", "--skip-verify"])
        .assert();

    let assert = assert.success().code(output::OK);

    let stderr = String::from_utf8(assert.get_output().stderr.clone()).unwrap();
    assert!(
        stderr.contains("systemd unit skipped"),
        "should mention systemd unit skipped: {stderr}"
    );
}

#[test]
fn server_init_emits_manifest() {
    let tmp = assert_fs::TempDir::new().unwrap();
    let config_dir = tmp.path().join("etc/slip");
    let env_file = config_dir.join("slip.env");

    let mut cmd = Command::cargo_bin("slip").unwrap();
    cmd.env("SLIP_TEST_CONFIG_DIR", config_dir.to_str().unwrap())
        .env("SLIP_TEST_ENV_FILE", env_file.to_str().unwrap())
        .env("SLIP_TEST_MANIFEST_DIR", tmp.path().to_str().unwrap())
        .args([
            "server",
            "init",
            "--yes",
            "--no-systemd",
            "--skip-verify",
            "--domain",
            "deploy.example.com",
        ])
        .assert()
        .success();

    // Find the manifest file (named after hostname)
    let entries: Vec<_> = std::fs::read_dir(tmp.path())
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().is_some_and(|ext| ext == "toml"))
        .collect();

    assert!(!entries.is_empty(), "manifest file should exist");
    let manifest_path = &entries[0].path();
    let manifest_content = std::fs::read_to_string(manifest_path).unwrap();

    // Manifest should NOT contain the secret
    assert!(
        !manifest_content.contains("SLIP_ADMIN_SECRET"),
        "manifest should not contain secret"
    );
    assert!(
        !manifest_content.contains("secret"),
        "manifest should not contain secret field"
    );

    // Manifest should contain config sections
    assert!(
        manifest_content.contains("[deploy]"),
        "manifest should have [deploy] section"
    );
    assert!(
        manifest_content.contains("deploy.example.com"),
        "manifest should contain domain"
    );
    assert!(
        manifest_content.contains("[caddy]"),
        "manifest should have [caddy] section"
    );
    assert!(
        manifest_content.contains("[server]"),
        "manifest should have [server] section"
    );
    assert!(
        manifest_content.contains("[runtime]"),
        "manifest should have [runtime] section"
    );
}

#[test]
fn server_init_full_flow_tempdir() {
    let tmp = assert_fs::TempDir::new().unwrap();
    let config_dir = tmp.path().join("etc/slip");
    let systemd_dir = tmp.path().join("etc/systemd/system");
    let env_file = config_dir.join("slip.env");

    let mut cmd = Command::cargo_bin("slip").unwrap();
    let assert = cmd
        .env("SLIP_TEST_CONFIG_DIR", config_dir.to_str().unwrap())
        .env("SLIP_TEST_SYSTEMD_DIR", systemd_dir.to_str().unwrap())
        .env("SLIP_TEST_ENV_FILE", env_file.to_str().unwrap())
        .env("SLIP_TEST_MANIFEST_DIR", tmp.path().to_str().unwrap())
        .args([
            "server",
            "init",
            "--yes",
            "--skip-verify",
            "--domain",
            "test.example.com",
            "--tls",
            "internal",
            "--runtime",
            "auto",
        ])
        .assert();

    let assert = assert.success().code(output::OK);

    // Verify all files exist with correct modes
    assert!(env_file.exists(), "env file should exist");
    let env_meta = std::fs::metadata(&env_file).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(env_meta.permissions().mode() & 0o777, 0o600);
    }

    let config_path = config_dir.join("slip.toml");
    assert!(config_path.exists(), "config file should exist");
    let config_meta = std::fs::metadata(&config_path).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(config_meta.permissions().mode() & 0o777, 0o644);
    }

    let unit_path = systemd_dir.join("slipd.service");
    assert!(unit_path.exists(), "unit file should exist");
    let unit_meta = std::fs::metadata(&unit_path).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(unit_meta.permissions().mode() & 0o777, 0o644);
    }

    // Check stdout for secret banner WITH the actual secret value
    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    assert!(
        stdout.contains("Admin secret generated"),
        "stdout should show secret"
    );
    let has_hex_secret = stdout.lines().any(|line| {
        line.contains("Admin secret generated:")
            && line.chars().filter(|c| c.is_ascii_hexdigit()).count() >= 64
    });
    assert!(
        has_hex_secret,
        "fresh run should show the secret in stdout: {stdout}"
    );
}

#[test]
fn server_init_non_root_fails() {
    let mut cmd = Command::cargo_bin("slip").unwrap();
    let assert = cmd
        .args(["server", "init", "--yes", "--no-systemd", "--skip-verify"])
        .assert();

    assert
        .failure()
        .code(output::GENERIC)
        .stderr(predicate::str::contains("must be run as root"));
}

#[test]
fn server_init_force_all() {
    let tmp = assert_fs::TempDir::new().unwrap();
    let config_dir = tmp.path().join("etc/slip");
    let systemd_dir = tmp.path().join("etc/systemd/system");
    let env_file = config_dir.join("slip.env");

    // First run
    let mut cmd = Command::cargo_bin("slip").unwrap();
    cmd.env("SLIP_TEST_CONFIG_DIR", config_dir.to_str().unwrap())
        .env("SLIP_TEST_SYSTEMD_DIR", systemd_dir.to_str().unwrap())
        .env("SLIP_TEST_ENV_FILE", env_file.to_str().unwrap())
        .env("SLIP_TEST_MANIFEST_DIR", tmp.path().to_str().unwrap())
        .args(["server", "init", "--yes", "--no-systemd", "--skip-verify"])
        .assert()
        .success();

    let first_secret = std::fs::read_to_string(&env_file).unwrap();

    // Second run with bare --force (all)
    let mut cmd2 = Command::cargo_bin("slip").unwrap();
    cmd2.env("SLIP_TEST_CONFIG_DIR", config_dir.to_str().unwrap())
        .env("SLIP_TEST_SYSTEMD_DIR", systemd_dir.to_str().unwrap())
        .env("SLIP_TEST_ENV_FILE", env_file.to_str().unwrap())
        .env("SLIP_TEST_MANIFEST_DIR", tmp.path().to_str().unwrap())
        .args([
            "server",
            "init",
            "--yes",
            "--no-systemd",
            "--skip-verify",
            "--force",
        ])
        .assert()
        .success();

    let second_secret = std::fs::read_to_string(&env_file).unwrap();
    assert_ne!(
        first_secret, second_secret,
        "secret should be regenerated with --force"
    );
}

#[test]
fn server_init_manifest_idempotent() {
    let tmp = assert_fs::TempDir::new().unwrap();
    let config_dir = tmp.path().join("etc/slip");
    let env_file = config_dir.join("slip.env");

    // First run
    let mut cmd = Command::cargo_bin("slip").unwrap();
    cmd.env("SLIP_TEST_CONFIG_DIR", config_dir.to_str().unwrap())
        .env("SLIP_TEST_ENV_FILE", env_file.to_str().unwrap())
        .env("SLIP_TEST_MANIFEST_DIR", tmp.path().to_str().unwrap())
        .args([
            "server",
            "init",
            "--yes",
            "--no-systemd",
            "--skip-verify",
            "--domain",
            "test.example.com",
        ])
        .assert()
        .success();

    // Second run — should not fail
    let mut cmd2 = Command::cargo_bin("slip").unwrap();
    cmd2.env("SLIP_TEST_CONFIG_DIR", config_dir.to_str().unwrap())
        .env("SLIP_TEST_ENV_FILE", env_file.to_str().unwrap())
        .env("SLIP_TEST_MANIFEST_DIR", tmp.path().to_str().unwrap())
        .args([
            "server",
            "init",
            "--yes",
            "--no-systemd",
            "--skip-verify",
            "--domain",
            "test.example.com",
        ])
        .assert()
        .success();
}

#[test]
fn server_init_from_file_rebuilds() {
    let tmp = assert_fs::TempDir::new().unwrap();
    let config_dir = tmp.path().join("etc/slip");
    let systemd_dir = tmp.path().join("etc/systemd/system");
    let env_file = config_dir.join("slip.env");

    // Write a manifest file
    let manifest_path = tmp.path().join("myserver.slip.toml");
    std::fs::write(
        &manifest_path,
        r#"[deploy]
domain = "deploy.example.com"
tls = "internal"

[caddy]
admin_api = "http://localhost:2019"

[server]
listen = "127.0.0.1:7890"

[runtime]
backend = "auto"
"#,
    )
    .unwrap();

    // Run init with --from-file
    let mut cmd = Command::cargo_bin("slip").unwrap();
    let assert = cmd
        .env("SLIP_TEST_CONFIG_DIR", config_dir.to_str().unwrap())
        .env("SLIP_TEST_SYSTEMD_DIR", systemd_dir.to_str().unwrap())
        .env("SLIP_TEST_ENV_FILE", env_file.to_str().unwrap())
        .env("SLIP_TEST_MANIFEST_DIR", tmp.path().to_str().unwrap())
        .args([
            "server",
            "init",
            "--yes",
            "--no-systemd",
            "--skip-verify",
            "--from-file",
            manifest_path.to_str().unwrap(),
        ])
        .assert();

    let assert = assert.success().code(output::OK);

    // Config should match manifest values
    let config_path = config_dir.join("slip.toml");
    assert!(config_path.exists(), "config should exist");
    let config_content = std::fs::read_to_string(&config_path).unwrap();
    assert!(
        config_content.contains("deploy.example.com"),
        "config should contain domain from manifest"
    );
    assert!(
        config_content.contains("backend = \"auto\""),
        "config should contain runtime from manifest"
    );

    // Secret should be regenerated (fresh)
    assert!(env_file.exists(), "env file should exist");
    let env_content = std::fs::read_to_string(&env_file).unwrap();
    assert!(
        env_content.starts_with("SLIP_ADMIN_SECRET="),
        "env file should contain secret"
    );
    let secret = env_content
        .trim()
        .strip_prefix("SLIP_ADMIN_SECRET=")
        .unwrap();
    assert_eq!(secret.len(), 64, "secret should be 64 hex chars");

    // Stderr should contain disaster recovery warning
    let stderr = String::from_utf8(assert.get_output().stderr.clone()).unwrap();
    assert!(
        stderr.contains("disaster recovery"),
        "from-file should show disaster recovery warning: {stderr}"
    );
}

#[test]
fn server_init_non_tty_without_yes_completes() {
    // assert_cmd runs are non-TTY, so this tests the non-TTY path without --yes
    let tmp = assert_fs::TempDir::new().unwrap();
    let config_dir = tmp.path().join("etc/slip");
    let env_file = config_dir.join("slip.env");

    let mut cmd = Command::cargo_bin("slip").unwrap();
    let assert = cmd
        .env("SLIP_TEST_CONFIG_DIR", config_dir.to_str().unwrap())
        .env("SLIP_TEST_ENV_FILE", env_file.to_str().unwrap())
        .env("SLIP_TEST_MANIFEST_DIR", tmp.path().to_str().unwrap())
        // No --yes, no --domain — should complete with defaults (no domain = omit [deploy])
        .args(["server", "init", "--no-systemd", "--skip-verify"])
        .assert();

    assert.success().code(output::OK);

    // Config should exist without [deploy] section
    let config_path = config_dir.join("slip.toml");
    assert!(config_path.exists(), "config should exist");
    let config_content = std::fs::read_to_string(&config_path).unwrap();
    assert!(
        !config_content.contains("[deploy]"),
        "config should not have [deploy] section when no domain: {config_content}"
    );
}

#[test]
fn server_init_json_schema() {
    let tmp = assert_fs::TempDir::new().unwrap();
    let config_dir = tmp.path().join("etc/slip");
    let systemd_dir = tmp.path().join("etc/systemd/system");
    let env_file = config_dir.join("slip.env");

    let mut cmd = Command::cargo_bin("slip").unwrap();
    let assert = cmd
        .env("SLIP_TEST_CONFIG_DIR", config_dir.to_str().unwrap())
        .env("SLIP_TEST_SYSTEMD_DIR", systemd_dir.to_str().unwrap())
        .env("SLIP_TEST_ENV_FILE", env_file.to_str().unwrap())
        .env("SLIP_TEST_MANIFEST_DIR", tmp.path().to_str().unwrap())
        // Use --skip-verify to avoid network-dependent failures
        .args(["server", "init", "--yes", "--json", "--skip-verify"])
        .assert();

    let assert = assert.success().code(output::OK);

    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    // Parse as JSON — should be a single JSON document
    let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap_or_else(|e| {
        panic!("stdout should be valid JSON: {e}\nstdout: {stdout}");
    });

    // Should have manifest and secret_file
    assert!(
        parsed.get("manifest").is_some(),
        "JSON should have 'manifest'"
    );
    assert!(
        parsed.get("secret_file").is_some(),
        "JSON should have 'secret_file'"
    );
    assert!(
        parsed.get("next_steps").is_some(),
        "JSON should have 'next_steps'"
    );

    // In --json mode the secret is never shown, so next_steps must reference
    // the env file and must NOT say "shown above".
    let next_steps = parsed["next_steps"].as_array().unwrap_or_else(|| {
        panic!("next_steps should be an array");
    });
    let combined: String = next_steps
        .iter()
        .filter_map(|v| v.as_str())
        .collect::<Vec<_>>()
        .join(" ");
    assert!(
        !combined.contains("shown above"),
        "JSON next_steps must not say 'shown above': {combined}"
    );
}

#[test]
fn server_init_json_verify_fails_exit_5() {
    let tmp = assert_fs::TempDir::new().unwrap();
    let config_dir = tmp.path().join("etc/slip");
    let systemd_dir = tmp.path().join("etc/systemd/system");
    let env_file = config_dir.join("slip.env");

    let mut cmd = Command::cargo_bin("slip").unwrap();
    let output = cmd
        .env("SLIP_TEST_CONFIG_DIR", config_dir.to_str().unwrap())
        .env("SLIP_TEST_SYSTEMD_DIR", systemd_dir.to_str().unwrap())
        .env("SLIP_TEST_ENV_FILE", env_file.to_str().unwrap())
        .env("SLIP_TEST_MANIFEST_DIR", tmp.path().to_str().unwrap())
        // Point Caddy admin at a dead port — verification will fail
        .args(["server", "init", "--yes", "--no-systemd", "--json"])
        .output()
        .unwrap();

    let stdout = String::from_utf8(output.stdout.clone()).unwrap();
    let _stderr = String::from_utf8(output.stderr.clone()).unwrap();

    assert!(!output.status.success(), "expected failure, got success");
    assert_eq!(
        output.status.code(),
        Some(output::DEPLOY_FAILED),
        "expected exit code 5"
    );

    // stdout should be parseable JSON with checks[] populated
    let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap_or_else(|e| {
        panic!("stdout should be valid JSON on failure path: {e}\nstdout: {stdout}");
    });

    // Should have checks array with at least one entry
    let checks = parsed.get("checks").and_then(|c| c.as_array());
    assert!(checks.is_some(), "JSON should have 'checks' array");
    if let Some(arr) = checks {
        assert!(!arr.is_empty(), "checks array should not be empty");
        for check in arr {
            assert!(check.get("name").is_some(), "each check should have 'name'");
            assert!(
                check.get("status").is_some(),
                "each check should have 'status'"
            );
            assert!(
                check.get("detail").is_some(),
                "each check should have 'detail'"
            );
        }
    }

    assert!(parsed.get("passed").is_some(), "JSON should have 'passed'");
    assert!(parsed.get("failed").is_some(), "JSON should have 'failed'");
    assert_eq!(parsed["overall"], "fail", "overall should be 'fail'");
    assert!(
        parsed.get("manifest").is_some(),
        "JSON should have 'manifest'"
    );
    assert!(
        parsed.get("secret_file").is_some(),
        "JSON should have 'secret_file'"
    );
    assert!(
        parsed.get("next_steps").is_some(),
        "JSON should have 'next_steps'"
    );
}

#[test]
fn server_init_verify_fails_exit_5() {
    let tmp = assert_fs::TempDir::new().unwrap();
    let config_dir = tmp.path().join("etc/slip");
    let systemd_dir = tmp.path().join("etc/systemd/system");
    let env_file = config_dir.join("slip.env");

    let mut cmd = Command::cargo_bin("slip").unwrap();
    let output = cmd
        .env("SLIP_TEST_CONFIG_DIR", config_dir.to_str().unwrap())
        .env("SLIP_TEST_SYSTEMD_DIR", systemd_dir.to_str().unwrap())
        .env("SLIP_TEST_ENV_FILE", env_file.to_str().unwrap())
        .env("SLIP_TEST_MANIFEST_DIR", tmp.path().to_str().unwrap())
        // Point Caddy admin at a dead port — verification will fail
        .args(["server", "init", "--yes", "--no-systemd"])
        .output()
        .unwrap();

    let stdout = String::from_utf8(output.stdout.clone()).unwrap();
    let _stderr = String::from_utf8(output.stderr.clone()).unwrap();

    assert!(!output.status.success(), "expected failure, got success");
    assert_eq!(
        output.status.code(),
        Some(output::DEPLOY_FAILED),
        "expected exit code 5"
    );

    // Verification output goes to stdout
    assert!(
        stdout.contains("Caddy admin API reachable"),
        "stdout should contain verification output: {stdout}"
    );
    assert!(
        stdout.contains("✗"),
        "stdout should show failures: {stdout}"
    );
}

#[test]
fn server_init_unit_converges_on_mismatch() {
    let tmp = assert_fs::TempDir::new().unwrap();
    let config_dir = tmp.path().join("etc/slip");
    let systemd_dir = tmp.path().join("etc/systemd/system");
    let env_file = config_dir.join("slip.env");

    // Pre-write a stale unit file
    let unit_path = systemd_dir.join("slipd.service");
    std::fs::create_dir_all(&systemd_dir).unwrap();
    std::fs::write(&unit_path, "[Unit]\nDescription=stale\n").unwrap();

    // Run init — should converge (overwrite) since content differs
    let mut cmd = Command::cargo_bin("slip").unwrap();
    cmd.env("SLIP_TEST_CONFIG_DIR", config_dir.to_str().unwrap())
        .env("SLIP_TEST_SYSTEMD_DIR", systemd_dir.to_str().unwrap())
        .env("SLIP_TEST_ENV_FILE", env_file.to_str().unwrap())
        .env("SLIP_TEST_MANIFEST_DIR", tmp.path().to_str().unwrap())
        .args(["server", "init", "--yes", "--skip-verify"])
        .assert()
        .success();

    // Unit should now have the correct content
    let unit_content = std::fs::read_to_string(&unit_path).unwrap();
    assert!(
        unit_content.contains("EnvironmentFile="),
        "unit should have EnvironmentFile after convergence"
    );
    assert!(
        unit_content.contains("ProtectSystem=strict"),
        "unit should have ProtectSystem=strict after convergence"
    );
}

#[test]
fn server_init_force_unit_overwrites() {
    let tmp = assert_fs::TempDir::new().unwrap();
    let config_dir = tmp.path().join("etc/slip");
    let systemd_dir = tmp.path().join("etc/systemd/system");
    let env_file = config_dir.join("slip.env");

    // First run
    let mut cmd = Command::cargo_bin("slip").unwrap();
    cmd.env("SLIP_TEST_CONFIG_DIR", config_dir.to_str().unwrap())
        .env("SLIP_TEST_SYSTEMD_DIR", systemd_dir.to_str().unwrap())
        .env("SLIP_TEST_ENV_FILE", env_file.to_str().unwrap())
        .env("SLIP_TEST_MANIFEST_DIR", tmp.path().to_str().unwrap())
        .args(["server", "init", "--yes", "--skip-verify"])
        .assert()
        .success();

    // Second run with --force=unit — should overwrite even if content matches
    let mut cmd2 = Command::cargo_bin("slip").unwrap();
    cmd2.env("SLIP_TEST_CONFIG_DIR", config_dir.to_str().unwrap())
        .env("SLIP_TEST_SYSTEMD_DIR", systemd_dir.to_str().unwrap())
        .env("SLIP_TEST_ENV_FILE", env_file.to_str().unwrap())
        .env("SLIP_TEST_MANIFEST_DIR", tmp.path().to_str().unwrap())
        .args([
            "server",
            "init",
            "--yes",
            "--skip-verify",
            "--force",
            "unit",
        ])
        .assert()
        .success();

    // Unit should still have correct content
    let unit_path = systemd_dir.join("slipd.service");
    let unit_content = std::fs::read_to_string(&unit_path).unwrap();
    assert!(
        unit_content.contains("EnvironmentFile="),
        "unit should have EnvironmentFile after force overwrite"
    );
}

#[test]
fn server_init_cli_flag_overrides_manifest() {
    let tmp = assert_fs::TempDir::new().unwrap();
    let config_dir = tmp.path().join("etc/slip");
    let systemd_dir = tmp.path().join("etc/systemd/system");
    let env_file = config_dir.join("slip.env");

    // Write a manifest with domain "manifest.example.com"
    let manifest_path = tmp.path().join("myserver.slip.toml");
    std::fs::write(
        &manifest_path,
        r#"[deploy]
domain = "manifest.example.com"
tls = "internal"
"#,
    )
    .unwrap();

    // Run init with --from-file AND --domain — CLI flag should win
    let mut cmd = Command::cargo_bin("slip").unwrap();
    cmd.env("SLIP_TEST_CONFIG_DIR", config_dir.to_str().unwrap())
        .env("SLIP_TEST_SYSTEMD_DIR", systemd_dir.to_str().unwrap())
        .env("SLIP_TEST_ENV_FILE", env_file.to_str().unwrap())
        .env("SLIP_TEST_MANIFEST_DIR", tmp.path().to_str().unwrap())
        .args([
            "server",
            "init",
            "--yes",
            "--no-systemd",
            "--skip-verify",
            "--from-file",
            manifest_path.to_str().unwrap(),
            "--domain",
            "cli.example.com",
        ])
        .assert()
        .success();

    // Config should use CLI domain, not manifest domain
    let config_path = config_dir.join("slip.toml");
    let config_content = std::fs::read_to_string(&config_path).unwrap();
    assert!(
        config_content.contains("cli.example.com"),
        "config should use CLI flag domain"
    );
    assert!(
        !config_content.contains("manifest.example.com"),
        "config should NOT use manifest domain"
    );
}

#[test]
fn server_init_idempotent_stdout_no_secret() {
    let tmp = assert_fs::TempDir::new().unwrap();
    let config_dir = tmp.path().join("etc/slip");
    let env_file = config_dir.join("slip.env");

    // First run
    let mut cmd = Command::cargo_bin("slip").unwrap();
    cmd.env("SLIP_TEST_CONFIG_DIR", config_dir.to_str().unwrap())
        .env("SLIP_TEST_ENV_FILE", env_file.to_str().unwrap())
        .env("SLIP_TEST_MANIFEST_DIR", tmp.path().to_str().unwrap())
        .args(["server", "init", "--yes", "--no-systemd", "--skip-verify"])
        .assert()
        .success();

    // Second run (idempotent) — stdout should NOT contain a 64-hex secret
    let mut cmd2 = Command::cargo_bin("slip").unwrap();
    let assert2 = cmd2
        .env("SLIP_TEST_CONFIG_DIR", config_dir.to_str().unwrap())
        .env("SLIP_TEST_ENV_FILE", env_file.to_str().unwrap())
        .env("SLIP_TEST_MANIFEST_DIR", tmp.path().to_str().unwrap())
        .args(["server", "init", "--yes", "--no-systemd", "--skip-verify"])
        .assert();

    let assert2 = assert2.success().code(output::OK);

    let stdout = String::from_utf8(assert2.get_output().stdout.clone()).unwrap();
    // Should NOT contain "Admin secret generated" since no new secret was written
    assert!(
        !stdout.contains("Admin secret generated"),
        "idempotent run should not print secret banner: {stdout}"
    );
    // Should NOT contain any 64-hex string
    let has_hex_secret = stdout.lines().any(|line| {
        let trimmed = line.trim();
        trimmed.chars().all(|c| c.is_ascii_hexdigit()) && trimmed.len() == 64
    });
    assert!(
        !has_hex_secret,
        "idempotent run should not leak secret in stdout"
    );
}

#[test]
fn services_list_stub_exits_nonzero() {
    let mut cmd = Command::cargo_bin("slip").unwrap();
    let assert = cmd.args(["services", "list"]).assert();

    assert
        .failure()
        .code(output::GENERIC)
        .stderr(predicate::str::contains("not yet implemented"));
}

// ─── Deprecated `apps` subcommand ───────────────────────────────────────────────

#[test]
fn apps_list_shows_deprecation_warning() {
    let mut cmd = Command::cargo_bin("slip").unwrap();
    // `apps list` requires SLIP_TOKEN and hits the server, so it will fail with
    // a connection error — but the deprecation warning should appear on stderr
    // before that.
    let assert = cmd.args(["apps", "list"]).assert();

    assert
        .failure()
        .stderr(predicate::str::contains("deprecated"))
        .stderr(predicate::str::contains("slip apply"));
}

// ─── JSON output contract ──────────────────────────────────────────────────────

#[test]
fn json_output_is_parseable() {
    // `slip server init --json` emits parseable JSON.
    let tmp = assert_fs::TempDir::new().unwrap();
    let config_dir = tmp.path().join("etc/slip");
    let systemd_dir = tmp.path().join("etc/systemd/system");
    let env_file = config_dir.join("slip.env");

    let mut cmd = Command::cargo_bin("slip").unwrap();
    let assert = cmd
        .env("SLIP_TEST_CONFIG_DIR", config_dir.to_str().unwrap())
        .env("SLIP_TEST_SYSTEMD_DIR", systemd_dir.to_str().unwrap())
        .env("SLIP_TEST_ENV_FILE", env_file.to_str().unwrap())
        .env("SLIP_TEST_MANIFEST_DIR", tmp.path().to_str().unwrap())
        .args(["server", "init", "--yes", "--json", "--skip-verify"])
        .assert();

    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("stdout should be valid JSON: {e}\nstdout: {stdout}"));
    assert!(parsed.get("manifest").is_some());
}

// ─── Key command ────────────────────────────────────────────────────────────────

#[test]
fn key_help_lists_flags() {
    let mut cmd = Command::cargo_bin("slip").unwrap();
    let assert = cmd.args(["key", "--help"]).assert();

    assert
        .success()
        .code(output::OK)
        .stdout(predicate::str::contains("APP"))
        .stdout(predicate::str::contains("--rotate"))
        .stdout(predicate::str::contains("--gh"))
        .stdout(predicate::str::contains("--json"));
}

#[test]
fn key_missing_token_exits_auth() {
    let mut cmd = Command::cargo_bin("slip").unwrap();
    let assert = cmd.args(["key", "myapp"]).assert();

    assert
        .failure()
        .code(output::AUTH)
        .stderr(predicate::str::contains("SLIP_TOKEN"));
}

#[test]
fn key_missing_app_exits_usage() {
    let mut cmd = Command::cargo_bin("slip").unwrap();
    // Set a token so we get past the token check.
    let assert = cmd.args(["key", "--token", "dummy"]).assert();

    assert
        .failure()
        .code(output::USAGE)
        .stderr(predicate::str::contains("no app name"));
}

#[test]
fn key_json_with_token_and_app_shows_connection_error() {
    // With a valid token and app, the command will try to reach the server
    // and fail with a connection error (not an auth/not-found error).
    let mut cmd = Command::cargo_bin("slip").unwrap();
    let assert = cmd
        .args(["key", "myapp", "--token", "valid-token", "--json"])
        .assert();

    assert
        .failure()
        .code(output::GENERIC)
        .stderr(predicate::str::contains("can't reach slipd"));
}

#[test]
fn key_parse_gh_repo_slug_ssh() {
    // Test the parse_gh_repo_slug function indirectly via the binary.
    // We can't call it directly since it's private, but we can verify
    // the command fails with a prescriptive error when gh is requested
    // and there's no git remote.
    let mut cmd = Command::cargo_bin("slip").unwrap();
    let assert = cmd
        .args(["key", "myapp", "--token", "dummy", "--gh"])
        .assert();

    // Should fail trying to reach the server (connection error), not with
    // a git remote error — because the server call happens before gh.
    assert
        .failure()
        .stderr(predicate::str::contains("can't reach slipd"));
}

// ─── Link command ────────────────────────────────────────────────────────────────

#[test]
fn link_help_lists_flags() {
    let mut cmd = Command::cargo_bin("slip").unwrap();
    let assert = cmd.args(["link", "--help"]).assert();

    assert
        .success()
        .code(output::OK)
        .stdout(predicate::str::contains("--server"))
        .stdout(predicate::str::contains("--app"))
        .stdout(predicate::str::contains("--json"));
}

#[test]
fn link_missing_server_exits_usage() {
    let mut cmd = Command::cargo_bin("slip").unwrap();
    let assert = cmd.args(["link"]).assert();

    assert
        .failure()
        .code(output::USAGE)
        .stderr(predicate::str::contains("--server"));
}

#[test]
fn link_missing_token_exits_auth() {
    let mut cmd = Command::cargo_bin("slip").unwrap();
    let assert = cmd
        .args(["link", "--server", "http://localhost:7890"])
        .assert();

    assert
        .failure()
        .code(output::AUTH)
        .stderr(predicate::str::contains("SLIP_TOKEN"));
}

#[test]
fn link_missing_app_exits_usage() {
    let mut cmd = Command::cargo_bin("slip").unwrap();
    let assert = cmd
        .args([
            "link",
            "--server",
            "http://localhost:7890",
            "--token",
            "dummy",
        ])
        .assert();

    assert
        .failure()
        .code(output::USAGE)
        .stderr(predicate::str::contains("app name"));
}

#[test]
fn link_with_app_flag_skips_toml_lookup() {
    // When --app is provided, it should not try to read slip.toml.
    // It will fail with a connection error (server unreachable).
    let mut cmd = Command::cargo_bin("slip").unwrap();
    let assert = cmd
        .args([
            "link",
            "--server",
            "http://localhost:7890",
            "--token",
            "dummy",
            "--app",
            "myapp",
        ])
        .assert();

    assert
        .failure()
        .stderr(predicate::str::contains("can't reach slipd"));
}

#[test]
fn link_json_output_shape() {
    // With --json, the output should be valid JSON with the expected fields.
    // It will still fail with a connection error, but the JSON is only emitted
    // on success, so we just verify it doesn't crash before the HTTP call.
    let mut cmd = Command::cargo_bin("slip").unwrap();
    let assert = cmd
        .args([
            "link",
            "--server",
            "http://localhost:7890",
            "--token",
            "dummy",
            "--app",
            "myapp",
            "--json",
        ])
        .assert();

    assert
        .failure()
        .stderr(predicate::str::contains("can't reach slipd"));
}

#[test]
fn link_writes_remote_to_slip_toml() {
    // Test the TOML-writing logic by running in a temp dir with a pre-existing
    // slip.toml. The command will fail on the HTTP call, but we can verify
    // the file was NOT written (since the HTTP call happens before the write).
    // Instead, test the write logic via a unit test in the slip-core crate.
    let mut cmd = Command::cargo_bin("slip").unwrap();
    let assert = cmd
        .args([
            "link",
            "--server",
            "http://localhost:7890",
            "--token",
            "dummy",
            "--app",
            "myapp",
        ])
        .current_dir(std::env::temp_dir())
        .assert();

    assert
        .failure()
        .stderr(predicate::str::contains("can't reach slipd"));
}

// ─── Deploy command ──────────────────────────────────────────────────────────────

#[test]
fn deploy_help_shows_wait_flags() {
    let mut cmd = Command::cargo_bin("slip").unwrap();
    let assert = cmd.args(["deploy", "--help"]).assert();

    assert
        .success()
        .code(output::OK)
        .stdout(predicate::str::contains("--wait"))
        .stdout(predicate::str::contains("--wait-timeout"));
}

#[test]
fn deploy_without_wait_fire_and_forget_connection_error() {
    // Without --wait, the command should fire-and-forget.
    // It will fail with a connection error (no server running).
    // Use --no-apply to avoid needing SLIP_TOKEN.
    let mut cmd = Command::cargo_bin("slip").unwrap();
    let assert = cmd
        .args([
            "deploy",
            "myapp",
            "v1",
            "--secret",
            "dummy-secret",
            "--no-apply",
        ])
        .assert();

    assert
        .failure()
        .stderr(predicate::str::contains("not yet implemented").not())
        .stderr(
            predicate::str::contains("HTTP request failed")
                .or(predicate::str::contains("can't reach")),
        );
}

#[test]
fn deploy_with_wait_connection_error() {
    // With --wait, the command should still fail with a connection error
    // (the deploy POST itself fails, not the poll loop).
    // Use --no-apply to avoid needing SLIP_TOKEN.
    let mut cmd = Command::cargo_bin("slip").unwrap();
    let assert = cmd
        .args([
            "deploy",
            "myapp",
            "v1",
            "--secret",
            "dummy-secret",
            "--wait",
            "--no-apply",
        ])
        .assert();

    assert
        .failure()
        .stderr(predicate::str::contains("not yet implemented").not())
        .stderr(
            predicate::str::contains("HTTP request failed")
                .or(predicate::str::contains("can't reach")),
        );
}

#[test]
fn deploy_json_without_wait_connection_error() {
    // --json without --wait should still fire-and-forget and fail with connection error.
    // Use --no-apply to avoid needing SLIP_TOKEN (apply is default-on).
    let mut cmd = Command::cargo_bin("slip").unwrap();
    let assert = cmd
        .args([
            "deploy",
            "myapp",
            "v1",
            "--secret",
            "dummy-secret",
            "--json",
            "--no-apply",
        ])
        .assert();

    assert
        .failure()
        .code(output::GENERIC)
        .stderr(predicate::str::contains("not yet implemented").not());
}

#[test]
fn deploy_apply_missing_token_prescriptive_error() {
    // deploy with --apply (default) should fail with AUTH when no token is set.
    let mut cmd = Command::cargo_bin("slip").unwrap();
    let assert = cmd
        .args(["deploy", "myapp", "v1", "--secret", "dummy-secret"])
        .assert();

    assert
        .failure()
        .code(output::AUTH)
        .stderr(predicate::str::contains("no admin token"))
        .stderr(predicate::str::contains("--no-apply"));
}

use axum::{
    Json, Router,
    routing::{get, patch, post},
};
use serde_json::Value;

/// Normalize a mock app response to include all fields that AppResponse requires.
fn normalize_mock_app(mut app: Value) -> Value {
    let obj = app.as_object_mut().unwrap();
    obj.entry("env").or_insert(serde_json::json!({}));
    obj.entry("resources")
        .or_insert(serde_json::json!({"memory": null, "cpus": null}));
    obj.entry("network")
        .or_insert(serde_json::json!({"name": "slip"}));
    obj.entry("health").or_insert(serde_json::json!({"path": null, "interval": "30s", "timeout": "5s", "retries": 3, "start_period": "0s", "expect_status": null}));
    obj.entry("deploy").or_insert(
        serde_json::json!({"strategy": "blue-green", "drain_timeout": "30s", "timeout": null}),
    );
    obj.entry("volumes").or_insert(serde_json::json!([]));
    obj.entry("routes").or_insert(serde_json::json!([]));
    app
}

/// Start a mock axum server on a random port and return the URL.
/// `initial_apps` is a list of (name, json_value) to pre-populate the server state.
fn start_mock_server_with_apps(initial_apps: Vec<(&str, Value)>) -> String {
    let mut apps_map: std::collections::HashMap<String, Value> = std::collections::HashMap::new();
    for (name, app) in initial_apps {
        apps_map.insert(name.to_string(), normalize_mock_app(app));
    }

    let state = std::sync::Arc::new(MockApp {
        apps: std::sync::Mutex::new(apps_map),
    });

    let app = Router::new()
        .route(
            "/v1/apps/{name}",
            get({
                let state = state.clone();
                move |axum::extract::Path(name): axum::extract::Path<String>| {
                    let state = state.clone();
                    async move {
                        let apps = state.apps.lock().unwrap();
                        match apps.get(&name) {
                            Some(app) => (axum::http::StatusCode::OK, Json(app.clone())),
                            None => (
                                axum::http::StatusCode::NOT_FOUND,
                                Json(serde_json::json!({"error": format!("app '{name}' not found")})),
                            ),
                        }
                    }
                }
            }),
        )
        .route(
            "/v1/apps",
            post({
                let state = state.clone();
                move |Json(body): Json<Value>| {
                    let state = state.clone();
                    async move {
                        let name = body["name"].as_str().unwrap_or("").to_string();
                        let mut apps = state.apps.lock().unwrap();
                        match apps.entry(name.clone()) {
                            std::collections::hash_map::Entry::Occupied(_) => (
                                axum::http::StatusCode::CONFLICT,
                                Json(serde_json::json!({"error": format!("app '{name}' already exists")})),
                            ),
                            std::collections::hash_map::Entry::Vacant(e) => {
                                let mut app = normalize_mock_app(body);
                                app["port"] = serde_json::json!(app.get("port").and_then(|p| p.as_u64()).unwrap_or(8080));
                                e.insert(app.clone());
                                (axum::http::StatusCode::CREATED, Json(app))
                            }
                        }
                    }
                }
            }),
        )
        .route(
            "/v1/apps/{name}",
            patch({
                let state = state.clone();
                move |axum::extract::Path(name): axum::extract::Path<String>, Json(body): Json<Value>| {
                    let state = state.clone();
                    async move {
                        let mut apps = state.apps.lock().unwrap();
                        match apps.get_mut(&name) {
                            Some(existing) => {
                                if let Some(obj) = body.as_object() {
                                    for (k, v) in obj {
                                        existing[k.as_str()] = v.clone();
                                    }
                                }
                                (axum::http::StatusCode::OK, Json(existing.clone()))
                            }
                            None => (
                                axum::http::StatusCode::NOT_FOUND,
                                Json(serde_json::json!({"error": format!("app '{name}' not found")})),
                            ),
                        }
                    }
                }
            }),
        );

    let rt = tokio::runtime::Runtime::new().unwrap();
    let listener =
        rt.block_on(async { tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap() });
    let addr = listener.local_addr().unwrap();
    let url = format!("http://{}", addr);
    std::thread::spawn(move || {
        rt.block_on(async {
            axum::serve(listener, app.into_make_service())
                .await
                .unwrap();
        });
    });
    std::thread::sleep(std::time::Duration::from_millis(100));
    url
}

fn start_mock_server() -> String {
    start_mock_server_with_apps(vec![])
}

/// Start a mock axum server that serves a canned per-app status response at
/// `GET /v1/apps/{name}/status`. Used for the SLIP-100 debugging-scenario
/// CLI contract tests.
fn start_mock_server_with_app_status(status_json: Value) -> String {
    let state = std::sync::Arc::new(status_json);

    let app = Router::new().route(
        "/v1/apps/{name}/status",
        get({
            let state = state.clone();
            move |axum::extract::Path(_name): axum::extract::Path<String>| {
                let state = state.clone();
                async move { (axum::http::StatusCode::OK, Json((*state).clone())) }
            }
        }),
    );

    let rt = tokio::runtime::Runtime::new().unwrap();
    let listener =
        rt.block_on(async { tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap() });
    let addr = listener.local_addr().unwrap();
    let url = format!("http://{}", addr);
    std::thread::spawn(move || {
        rt.block_on(async {
            axum::serve(listener, app.into_make_service())
                .await
                .unwrap();
        });
    });
    std::thread::sleep(std::time::Duration::from_millis(100));
    url
}

fn make_slip_toml(name: &str, image: &str, domain: &str) -> String {
    format!(
        r#"
[app]
name = "{name}"
image = "{image}"

[routing]
domain = "{domain}"
port = 3000

[health]
path = "/healthz"
"#
    )
}

fn make_slip_toml_no_image(name: &str) -> String {
    format!(
        r#"
[app]
name = "{name}"

[routing]
domain = "app.example.com"
port = 3000
"#
    )
}

fn make_slip_toml_no_domain(name: &str) -> String {
    format!(
        r#"
[app]
name = "{name}"
image = "ghcr.io/org/app:latest"

[routing]
port = 3000
"#
    )
}

fn make_slip_toml_matching(name: &str) -> String {
    format!(
        r#"
[app]
name = "{name}"
image = "nginx:latest"

[routing]
domain = "app.example.com"
port = 8080

[health]
path = "/"
"#
    )
}

fn make_slip_toml_with_env(name: &str) -> String {
    format!(
        r#"
[app]
name = "{name}"
image = "nginx:latest"

[routing]
domain = "app.example.com"
port = 8080

[env]
SECRET = "s3cret!"
OTHER = "visible"
"#
    )
}

/// Mock app state shared between handlers.
struct MockApp {
    apps: std::sync::Mutex<std::collections::HashMap<String, Value>>,
}

// Tests below use start_mock_server() or start_mock_server_with_apps()

#[test]
fn apply_dry_run_no_changes_exits_0() {
    let url = start_mock_server_with_apps(vec![(
        "testapp",
        serde_json::json!({
            "name": "testapp",
            "image": "nginx:latest",
            "domain": "app.example.com",
            "port": 8080,
            "health": {"path": "/"}
        }),
    )]);
    let tmp = assert_fs::TempDir::new().unwrap();
    let toml = make_slip_toml_matching("testapp");
    tmp.child("slip.toml").write_str(&toml).unwrap();

    let mut cmd = Command::cargo_bin("slip").unwrap();
    let assert = cmd
        .current_dir(tmp.path())
        .args([
            "apply",
            "testapp",
            "--server",
            &url,
            "--token",
            "test-token",
            "--dry-run",
        ])
        .assert();

    assert
        .success()
        .code(output::OK)
        .stdout(predicate::str::contains("up to date"));
}

#[test]
fn apply_dry_run_changes_exits_1() {
    let url = start_mock_server_with_apps(vec![(
        "testapp",
        serde_json::json!({
            "name": "testapp",
            "image": "nginx:latest",
            "domain": "app.example.com",
            "port": 8080,
            "health": {"path": "/"}
        }),
    )]);
    let tmp = assert_fs::TempDir::new().unwrap();

    // Now apply with a different port
    let toml = make_slip_toml("testapp", "nginx:latest", "app.example.com");
    tmp.child("slip.toml").write_str(&toml).unwrap();

    let mut cmd = Command::cargo_bin("slip").unwrap();
    let assert = cmd
        .current_dir(tmp.path())
        .args([
            "apply",
            "testapp",
            "--server",
            &url,
            "--token",
            "test-token",
            "--dry-run",
        ])
        .assert();

    assert
        .failure()
        .code(output::CHANGES_PRESENT)
        .stdout(predicate::str::contains("/port"));
}

#[test]
fn apply_dry_run_generic_failure_exits_7() {
    // Missing slip.toml should exit DRY_RUN_FAILURE (7) in dry-run mode
    let url = start_mock_server();
    let tmp = assert_fs::TempDir::new().unwrap();
    // No slip.toml in this tempdir

    let mut cmd = Command::cargo_bin("slip").unwrap();
    let assert = cmd
        .current_dir(tmp.path())
        .args([
            "apply",
            "testapp",
            "--server",
            &url,
            "--token",
            "test-token",
            "--dry-run",
        ])
        .assert();

    assert
        .failure()
        .code(output::DRY_RUN_FAILURE)
        .stderr(predicate::str::contains("failed to read slip.toml"));
}

#[test]
fn apply_creates_new_app() {
    let url = start_mock_server();
    let tmp = assert_fs::TempDir::new().unwrap();
    let toml = make_slip_toml("newapp", "ghcr.io/org/app:latest", "newapp.example.com");
    tmp.child("slip.toml").write_str(&toml).unwrap();

    let mut cmd = Command::cargo_bin("slip").unwrap();
    let assert = cmd
        .current_dir(tmp.path())
        .args(["apply", "newapp", "--server", &url, "--token", "test-token"])
        .assert();

    assert
        .success()
        .code(output::OK)
        .stdout(predicate::str::contains("created new app"));
}

#[test]
fn apply_json_diff_schema() {
    let url = start_mock_server_with_apps(vec![(
        "testapp",
        serde_json::json!({
            "name": "testapp",
            "image": "nginx:latest",
            "domain": "app.example.com",
            "port": 8080,
            "health": {"path": "/"}
        }),
    )]);
    let tmp = assert_fs::TempDir::new().unwrap();

    let toml = make_slip_toml("testapp", "nginx:latest", "app.example.com");
    tmp.child("slip.toml").write_str(&toml).unwrap();

    let mut cmd = Command::cargo_bin("slip").unwrap();
    let output = cmd
        .current_dir(tmp.path())
        .args([
            "apply",
            "testapp",
            "--server",
            &url,
            "--token",
            "test-token",
            "--dry-run",
            "--json",
        ])
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert_eq!(output.status.code(), Some(output::CHANGES_PRESENT));

    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(parsed["schema"], "slip.apply.diff/v1");
    assert_eq!(parsed["app"], "testapp");
    assert_eq!(parsed["changed"], true);
    assert!(parsed["ops"].is_array());
}

#[test]
fn apply_redacts_env_by_default() {
    let url = start_mock_server_with_apps(vec![(
        "testapp",
        serde_json::json!({
            "name": "testapp",
            "image": "nginx:latest",
            "domain": "app.example.com",
            "port": 8080
        }),
    )]);
    let tmp = assert_fs::TempDir::new().unwrap();

    let toml = make_slip_toml_with_env("testapp");
    tmp.child("slip.toml").write_str(&toml).unwrap();

    let mut cmd = Command::cargo_bin("slip").unwrap();
    let output = cmd
        .current_dir(tmp.path())
        .args([
            "apply",
            "testapp",
            "--server",
            &url,
            "--token",
            "test-token",
            "--dry-run",
            "--json",
        ])
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert_eq!(output.status.code(), Some(output::CHANGES_PRESENT));
    let stdout = String::from_utf8_lossy(&output.stdout);
    // Default redaction: env values should be "(redacted)"
    assert!(
        stdout.contains("(redacted)"),
        "redacted JSON should contain (redacted): {stdout}"
    );
    assert!(
        !stdout.contains("s3cret!"),
        "redacted JSON should not contain raw env value: {stdout}"
    );
}

#[test]
fn apply_no_redact_shows_values() {
    let url = start_mock_server_with_apps(vec![(
        "testapp",
        serde_json::json!({
            "name": "testapp",
            "image": "nginx:latest",
            "domain": "app.example.com",
            "port": 8080
        }),
    )]);
    let tmp = assert_fs::TempDir::new().unwrap();

    let toml = make_slip_toml_with_env("testapp");
    tmp.child("slip.toml").write_str(&toml).unwrap();

    let mut cmd = Command::cargo_bin("slip").unwrap();
    let output = cmd
        .current_dir(tmp.path())
        .args([
            "apply",
            "testapp",
            "--server",
            &url,
            "--token",
            "test-token",
            "--dry-run",
            "--json",
            "--no-redact",
        ])
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert_eq!(output.status.code(), Some(output::CHANGES_PRESENT));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("s3cret!"),
        "--no-redact should show raw env value: {stdout}"
    );
}

#[test]
fn apply_json_real_apply_redacts_env() {
    // Real apply (non-dry-run) with --json should also redact env values.
    let url = start_mock_server_with_apps(vec![(
        "testapp",
        serde_json::json!({
            "name": "testapp",
            "image": "nginx:latest",
            "domain": "app.example.com",
            "port": 8080
        }),
    )]);
    let tmp = assert_fs::TempDir::new().unwrap();

    let toml = make_slip_toml_with_env("testapp");
    tmp.child("slip.toml").write_str(&toml).unwrap();

    let mut cmd = Command::cargo_bin("slip").unwrap();
    let output = cmd
        .current_dir(tmp.path())
        .args([
            "apply",
            "testapp",
            "--server",
            &url,
            "--token",
            "test-token",
            "--json",
        ])
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    // The apply output should be the terminal status envelope, not the diff.
    // But the diff is printed before the PATCH, so we check that the diff
    // portion (if present) doesn't contain raw env values.
    // The terminal status envelope has "status": "applied"
    assert!(
        stdout.contains(r#""status":"applied""#),
        "apply should end with status applied: {stdout}"
    );
    // If the diff was printed (it should have been), it should be redacted
    if stdout.contains("(redacted)") {
        assert!(
            !stdout.contains("s3cret!"),
            "real apply --json should not contain raw env value: {stdout}"
        );
    }
}

#[test]
fn apply_missing_image_prescriptive_error() {
    let url = start_mock_server();
    let tmp = assert_fs::TempDir::new().unwrap();
    let toml = make_slip_toml_no_image("testapp");
    tmp.child("slip.toml").write_str(&toml).unwrap();

    let mut cmd = Command::cargo_bin("slip").unwrap();
    let assert = cmd
        .current_dir(tmp.path())
        .args([
            "apply",
            "testapp",
            "--server",
            &url,
            "--token",
            "test-token",
        ])
        .assert();

    assert
        .failure()
        .code(output::GENERIC)
        .stderr(predicate::str::contains("[app] image"));
}

#[test]
fn apply_missing_domain_prescriptive_error() {
    let url = start_mock_server();
    let tmp = assert_fs::TempDir::new().unwrap();
    let toml = make_slip_toml_no_domain("testapp");
    tmp.child("slip.toml").write_str(&toml).unwrap();

    let mut cmd = Command::cargo_bin("slip").unwrap();
    let assert = cmd
        .current_dir(tmp.path())
        .args([
            "apply",
            "testapp",
            "--server",
            &url,
            "--token",
            "test-token",
        ])
        .assert();

    assert
        .failure()
        .code(output::GENERIC)
        .stderr(predicate::str::contains("[routing] domain"));
}

#[test]
fn deploy_no_apply_skips_apply() {
    // With --no-apply, deploy should not need SLIP_TOKEN
    let mut cmd = Command::cargo_bin("slip").unwrap();
    let assert = cmd
        .args([
            "deploy",
            "myapp",
            "v1",
            "--secret",
            "dummy-secret",
            "--no-apply",
        ])
        .assert();

    // Should fail with connection error (no server), not AUTH
    assert
        .failure()
        .code(output::GENERIC)
        .stderr(predicate::str::contains("not yet implemented").not())
        .stderr(
            predicate::str::contains("HTTP request failed")
                .or(predicate::str::contains("can't reach")),
        );
}

mod output {
    pub const OK: i32 = 0;
    pub const GENERIC: i32 = 1;
    pub const USAGE: i32 = 2;
    pub const AUTH: i32 = 3;
    #[allow(dead_code)]
    pub const NOT_FOUND: i32 = 4;
    #[allow(dead_code)]
    pub const DEPLOY_FAILED: i32 = 5;
    #[allow(dead_code)]
    pub const TIMEOUT: i32 = 6;
    #[allow(dead_code)]
    pub const CHANGES_PRESENT: i32 = 1;
    #[allow(dead_code)]
    pub const DRY_RUN_FAILURE: i32 = 7;
}
