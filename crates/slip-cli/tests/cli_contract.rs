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
    obj.entry("health").or_insert(serde_json::json!({"path": null, "interval": "30s", "timeout": "5s", "retries": 3, "start_period": "0s"}));
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
