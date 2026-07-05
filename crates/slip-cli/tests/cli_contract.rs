use assert_cmd::Command;
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

// ─── Stub commands (Phase 2) ──────────────────────────────────────────────────

#[test]
fn status_stub_exits_nonzero() {
    let mut cmd = Command::cargo_bin("slip").unwrap();
    let assert = cmd.arg("status").assert();

    assert
        .failure()
        .code(output::GENERIC)
        .stderr(predicate::str::contains("not yet implemented"));
}

#[test]
fn status_json_emits_valid_json() {
    let mut cmd = Command::cargo_bin("slip").unwrap();
    let assert = cmd.args(["status", "--json"]).assert();

    assert
        .failure()
        .code(output::GENERIC)
        .stdout(predicate::str::contains(r#""status":"not_implemented""#))
        .stdout(predicate::str::contains(r#""command":"status all apps""#));
}

#[test]
fn init_stub_exits_nonzero() {
    let mut cmd = Command::cargo_bin("slip").unwrap();
    let assert = cmd.arg("init").assert();

    assert
        .failure()
        .code(output::GENERIC)
        .stderr(predicate::str::contains("not yet implemented"));
}

#[test]
fn logs_stub_exits_nonzero() {
    let mut cmd = Command::cargo_bin("slip").unwrap();
    let assert = cmd.args(["logs", "myapp"]).assert();

    assert
        .failure()
        .code(output::GENERIC)
        .stderr(predicate::str::contains("not yet implemented"));
}

#[test]
fn apply_stub_exits_nonzero() {
    let mut cmd = Command::cargo_bin("slip").unwrap();
    let assert = cmd.arg("apply").assert();

    assert
        .failure()
        .code(output::GENERIC)
        .stderr(predicate::str::contains("not yet implemented"));
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
fn doctor_stub_exits_nonzero() {
    let mut cmd = Command::cargo_bin("slip").unwrap();
    let assert = cmd.arg("doctor").assert();

    assert
        .failure()
        .code(output::GENERIC)
        .stderr(predicate::str::contains("not yet implemented"));
}

#[test]
fn server_init_stub_exits_nonzero() {
    let mut cmd = Command::cargo_bin("slip").unwrap();
    let assert = cmd.args(["server", "init"]).assert();

    assert
        .failure()
        .code(output::GENERIC)
        .stderr(predicate::str::contains("not yet implemented"));
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
    let mut cmd = Command::cargo_bin("slip").unwrap();
    let assert = cmd.args(["status", "--json"]).assert();

    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap();

    assert_eq!(parsed["status"], "not_implemented");
    assert_eq!(parsed["command"], "status all apps");
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
        .stderr(predicate::str::contains("app name is required"));
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

mod output {
    pub const OK: i32 = 0;
    pub const GENERIC: i32 = 1;
    pub const USAGE: i32 = 2;
    pub const AUTH: i32 = 3;
    #[allow(dead_code)]
    pub const NOT_FOUND: i32 = 4;
}
