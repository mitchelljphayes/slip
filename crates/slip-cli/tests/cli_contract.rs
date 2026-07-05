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

// ─── Exit-code constants (mirror output.rs) ────────────────────────────────────

mod output {
    pub const OK: i32 = 0;
    pub const GENERIC: i32 = 1;
    pub const USAGE: i32 = 2;
}
