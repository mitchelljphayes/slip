use std::collections::HashMap;
use std::io::IsTerminal;

use anyhow::Context as _;
use clap::{Parser, Subcommand};
use futures_util::TryStreamExt;
use serde::{Deserialize, Serialize};
use tokio::io::AsyncBufReadExt;

#[allow(dead_code)]
mod output;

mod doctor_cmd;
mod server_init;

/// slip CLI — manage apps, deploys, secrets, and status.
#[derive(Parser)]
#[command(name = "slip", version, about)]
struct Cli {
    /// slipd server URL (default: http://localhost:7890, or [remote].server from slip.toml).
    #[arg(long, global = true)]
    server: Option<String>,

    /// Bearer token for management API (or set SLIP_TOKEN env var).
    #[arg(long, global = true)]
    token: Option<String>,

    /// Emit JSON output instead of human-readable text.
    #[arg(long, global = true)]
    json: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize slip on this machine (repo scaffold).
    Init {
        /// App name (defaults to directory name or git remote org/repo).
        #[arg(long)]
        name: Option<String>,
        /// Container image (defaults to ghcr.io/<org>/<name> from git remote).
        #[arg(long)]
        image: Option<String>,
        /// Overwrite existing files without prompting.
        #[arg(long)]
        force: bool,
    },
    /// Link a local repo to a remote slipd server.
    Link {
        /// slipd server URL (required).
        #[arg(long)]
        server: String,
        /// App name (defaults to [app].name in slip.toml).
        #[arg(long)]
        app: Option<String>,
    },
    /// Manage deploy keys.
    Key {
        /// App name (required for now; will be inferred from slip.toml in future).
        #[arg(value_name = "APP")]
        app: Option<String>,

        /// Rotate the deploy key (regenerates it).
        #[arg(long)]
        rotate: bool,

        /// Run `gh secret set` with the new key (infers repo from git remote).
        #[arg(long)]
        gh: bool,
    },
    /// Apply a slip.toml config (create or update an app).
    Apply {
        /// App name (defaults to [remote].app from slip.toml).
        app: Option<String>,
        /// Show what would change without applying (exit 0 = no changes, 1 = changes).
        #[arg(long)]
        dry_run: bool,
        /// Show environment variable values in the diff (redacted by default).
        #[arg(long)]
        no_redact: bool,
    },
    /// Trigger a deploy.
    Deploy {
        /// App name.
        app: String,
        /// Image tag to deploy.
        tag: String,
        /// Per-container image overrides (container=registry/image:tag, repeatable).
        #[arg(long = "image", value_parser = parse_key_val)]
        image: Vec<(String, String)>,
        /// App secret for HMAC signing (or set SLIP_SECRET env var).
        #[arg(long)]
        secret: Option<String>,
        /// Wait for the deploy to reach a terminal state (completed/failed).
        #[arg(long)]
        wait: bool,
        /// Max time to wait when --wait is set (e.g. "10m", "300s"). Default: 10 minutes.
        #[arg(long)]
        wait_timeout: Option<String>,
        /// Apply slip.toml config before deploying (default: on).
        #[arg(long, default_value_t = true, overrides_with = "no_apply")]
        apply: bool,
        /// Skip applying slip.toml config before deploying.
        #[arg(long)]
        no_apply: bool,
    },
    /// Show app or daemon status.
    Status {
        /// App name (omit for all apps).
        app: Option<String>,
    },
    /// Tail container logs.
    Logs {
        /// App name.
        app: String,
        /// Show logs since duration (e.g., "1h", "5m30s").
        #[arg(long)]
        since: Option<String>,
        /// Follow log output (stream new lines as they arrive).
        #[arg(long, short = 'f')]
        follow: bool,
    },
    /// Roll back to the previous version.
    Rollback {
        /// App name.
        app: String,
        /// Target tag to roll back to (defaults to previous tag).
        #[arg(long)]
        to: Option<String>,
    },
    /// Validate a repo-side slip.toml config file.
    Validate {
        /// Path to slip.toml (default: ./slip.toml).
        #[arg(default_value = "slip.toml")]
        path: String,
        /// Also validate image references in pod manifests.
        #[arg(long)]
        strict: bool,
    },
    /// Manage the slipd server.
    #[command(subcommand)]
    Server(ServerCommands),
    /// Manage registered services (postgres, s3, kv, registry).
    #[command(subcommand)]
    Services(ServicesCommands),
    /// Manage application secrets.
    #[command(subcommand)]
    Secrets(SecretsCommands),
    /// Manage preview deployments.
    #[command(subcommand)]
    Previews(PreviewsCommands),
    /// Log in to a container registry.
    #[command(subcommand)]
    Registry(RegistryCommands),
    /// Diagnose slipd health and configuration.
    Doctor {
        /// Apply safe remediations (UFW bridge DNS rule only, today).
        ///
        /// Requires root. In non-interactive / `--json` mode, also pass `--yes`.
        #[arg(long)]
        fix: bool,

        /// With `--fix`: print the exact commands that would be run and exit
        /// without mutating anything.
        #[arg(long)]
        dry_run: bool,

        /// With `--fix`: skip the interactive confirmation prompt. Required
        /// in non-TTY and `--json` mode to apply any mutation.
        #[arg(long)]
        yes: bool,

        /// Per-check timeout in seconds (default 10) and global deadline
        /// (default 60). A timed-out check is `fail`; a global timeout exits
        /// with code 6.
        #[arg(long, default_value_t = 60)]
        timeout: u64,
    },
    /// Manage applications (deprecated: use `slip apply` instead).
    #[command(subcommand, hide = true)]
    Apps(AppsCommands),
}

// ─── Noun-group subcommand enums ──────────────────────────────────────────────

#[derive(Subcommand)]
enum ServerCommands {
    /// Bootstrap slipd on a new server.
    Init {
        /// Deploy webhook domain (e.g. deploy.example.com).
        #[arg(long)]
        domain: Option<String>,
        /// TLS strategy [default: internal] [possible values: internal].
        #[arg(long, default_value = "internal")]
        tls: String,
        /// Container runtime backend [default: auto] [possible values: auto, docker, podman].
        #[arg(long, default_value = "auto")]
        runtime: String,
        /// Non-interactive: use defaults, never prompt.
        #[arg(short = 'y', long)]
        yes: bool,
        /// Force overwrite [possible values: config, secret, unit, service].
        /// Pass --force with no value to force all.
        #[arg(long, num_args = 0.., default_missing_value = "all", value_parser = clap::value_parser!(server_init::ForceTarget))]
        force: Vec<server_init::ForceTarget>,
        /// Skip systemd unit install and service start.
        #[arg(long)]
        no_systemd: bool,
        /// Skip the verification step.
        #[arg(long)]
        skip_verify: bool,
        /// Initialize from a server manifest (disaster recovery).
        #[arg(long)]
        from_file: Option<std::path::PathBuf>,
    },
    /// Show server status.
    Status,
}

#[derive(Subcommand)]
enum ServicesCommands {
    /// List registered services.
    List,
}

#[derive(Subcommand)]
enum SecretsCommands {
    /// List secret keys for an app.
    List {
        /// App name.
        app: String,
    },
    /// Set one or more secrets for an app.
    Set {
        /// App name.
        app: String,
        /// Secret key=value pairs (e.g. KEY=VALUE).
        #[arg(value_parser = parse_key_val, num_args = 1..)]
        pairs: Vec<(String, String)>,
    },
    /// Remove a secret from an app.
    Rm {
        /// App name.
        app: String,
        /// Secret key to remove.
        key: String,
    },
}

#[derive(Subcommand)]
enum PreviewsCommands {
    /// List active previews for an app.
    List {
        /// App name.
        app: String,
    },
    /// Tear down preview deployments.
    Teardown {
        /// App name.
        app: String,
        /// Preview ID to tear down.
        preview: Option<String>,
        /// Tear down all previews for the app.
        #[arg(long)]
        all: bool,
    },
}

#[derive(Subcommand)]
enum RegistryCommands {
    /// Log in to a container registry.
    Login,
}

/// Deprecated `slip apps` subcommands (hidden, still functional).
#[derive(Subcommand)]
enum AppsCommands {
    /// List all registered apps.
    List,
    /// Add a new application.
    Add {
        /// App name (lowercase alphanumeric and hyphens).
        name: String,
        /// Container image (e.g., ghcr.io/org/myapp:latest).
        image: String,
        /// Domain for the app (e.g., myapp.example.com).
        domain: String,
        /// Port the app listens on (default: 8080).
        #[arg(long, default_value = "8080")]
        port: u16,
        /// Optional secret for webhook authentication.
        #[arg(long)]
        secret: Option<String>,
        /// Environment variables (KEY=VALUE, can be repeated).
        #[arg(long, value_parser = parse_key_val)]
        env: Vec<(String, String)>,
    },
    /// Edit an existing application.
    Edit {
        /// App name.
        name: String,
        /// New container image.
        #[arg(long)]
        image: Option<String>,
        /// New domain.
        #[arg(long)]
        domain: Option<String>,
        /// New port.
        #[arg(long)]
        port: Option<u16>,
        /// New secret.
        #[arg(long)]
        secret: Option<String>,
        /// Environment variables (KEY=VALUE, can be repeated).
        #[arg(long, value_parser = parse_key_val)]
        env: Vec<(String, String)>,
    },
    /// Remove an application.
    Rm {
        /// App name.
        name: String,
        /// Skip confirmation prompt.
        #[arg(long)]
        force: bool,
    },
}

/// Parse a KEY=VALUE pair.
fn parse_key_val(s: &str) -> Result<(String, String), Box<dyn std::error::Error + Send + Sync>> {
    let pos = s
        .find('=')
        .ok_or_else(|| format!("invalid KEY=VALUE: no `=` found in `{s}`"))?;
    Ok((s[..pos].to_string(), s[pos + 1..].to_string()))
}

// ─── API response types ─────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct AppListResponse {
    apps: Vec<AppResponse>,
}

#[derive(Debug, Deserialize)]
struct AppResponse {
    name: String,
    image: String,
    domain: String,
    port: u16,
}

// ─── API request types ──────────────────────────────────────────────────────────

#[derive(Serialize)]
struct CreateAppRequest {
    name: String,
    image: String,
    domain: String,
    port: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    secret: Option<String>,
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    env: HashMap<String, String>,
}

#[derive(Serialize)]
struct UpdateAppRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    image: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    domain: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    secret: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    env: Option<HashMap<String, String>>,
}

#[derive(Serialize)]
struct RollbackRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    to: Option<String>,
}

#[derive(Debug, Deserialize)]
struct DeployResponse {
    deploy_id: String,
    app: String,
    tag: String,
    #[allow(dead_code)]
    status: String,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct DeployStatusResponse {
    deploy_id: String,
    app: String,
    tag: String,
    status: String,
    started_at: String,
    finished_at: Option<String>,
    error: Option<String>,
}

#[derive(Debug, Deserialize)]
struct SecretsListResponse {
    secrets: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct SetSecretsResponse {
    set: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct PreviewListItem {
    preview_id: String,
    tag: Option<String>,
    deployed_at: String,
    expires_at: Option<String>,
    domain: String,
    #[allow(dead_code)]
    status: String,
}

#[derive(Debug, Deserialize)]
struct TeardownAllResponse {
    torn_down: Vec<String>,
}

#[derive(Serialize)]
struct SetDeployKeyRequest {
    rotate: bool,
}

#[derive(Debug, Deserialize)]
struct SetDeployKeyResponse {
    app: String,
    key: Option<String>,
    rotated: bool,
    message: Option<String>,
}

/// One NDJSON line from the logs endpoint (text-mode parsing).
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct LogLine {
    ts: Option<String>,
    container: String,
    stream: String,
    line: String,
}

/// In-stream error event from the logs endpoint.
#[derive(Debug, Deserialize)]
struct LogErrorLine {
    error: String,
    #[serde(default)]
    container: Option<String>,
}

// ─── HTTP client helpers ──────────────────────────────────────────────────────

fn create_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .connect_timeout(std::time::Duration::from_secs(5))
        .build()
        .expect("failed to create HTTP client")
}

/// Create a reqwest client with no timeout — for streaming endpoints (logs --follow)
/// that need to stay open indefinitely.
fn create_streaming_client() -> reqwest::Client {
    reqwest::Client::builder()
        .connect_timeout(std::time::Duration::from_secs(5))
        .build()
        .expect("failed to create streaming HTTP client")
}

async fn api_request(
    client: &reqwest::Client,
    method: reqwest::Method,
    url: &str,
    token: &str,
    body: Option<&serde_json::Value>,
) -> Result<reqwest::Response, anyhow::Error> {
    let mut req = client
        .request(method, url)
        .header("Authorization", format!("Bearer {token}"));

    if let Some(b) = body {
        req = req.json(b);
    }

    let resp = req.send().await.context("HTTP request failed")?;

    if !resp.status().is_success() {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        anyhow::bail!("API error ({}): {}", status, text);
    }

    Ok(resp)
}

// ─── Apps subcommand implementations ──────────────────────────────────────────

async fn apps_list(server: &str, token: &str) -> Result<(), anyhow::Error> {
    let client = create_client();
    let url = format!("{server}/v1/apps");
    let resp = api_request(&client, reqwest::Method::GET, &url, token, None).await?;
    let data: AppListResponse = resp.json().await.context("failed to parse response")?;

    if data.apps.is_empty() {
        println!("No apps registered.");
        return Ok(());
    }

    // Print table header
    println!(
        "{:<20} {:<40} {:<30} {:<6}",
        "NAME", "IMAGE", "DOMAIN", "PORT"
    );
    println!("{}", "-".repeat(96));

    for app in data.apps {
        // Truncate long values for display
        let image = if app.image.len() > 38 {
            format!("{}...", &app.image[..35])
        } else {
            app.image.clone()
        };
        let domain = if app.domain.len() > 28 {
            format!("{}...", &app.domain[..25])
        } else {
            app.domain.clone()
        };
        println!(
            "{:<20} {:<40} {:<30} {:<6}",
            app.name, image, domain, app.port
        );
    }

    Ok(())
}

/// Arguments for `apps add` command.
struct AppsAddArgs {
    name: String,
    image: String,
    domain: String,
    port: u16,
    secret: Option<String>,
    env: Vec<(String, String)>,
}

async fn apps_add(server: &str, token: &str, args: AppsAddArgs) -> Result<(), anyhow::Error> {
    let client = create_client();
    let url = format!("{server}/v1/apps");

    let env_map: HashMap<String, String> = args.env.into_iter().collect();
    let body = CreateAppRequest {
        name: args.name,
        image: args.image,
        domain: args.domain,
        port: args.port,
        secret: args.secret,
        env: env_map,
    };

    api_request(
        &client,
        reqwest::Method::POST,
        &url,
        token,
        Some(&serde_json::to_value(&body)?),
    )
    .await?;

    println!("✓ App '{}' created", body.name);
    Ok(())
}

/// Arguments for `apps edit` command.
struct AppsEditArgs {
    name: String,
    image: Option<String>,
    domain: Option<String>,
    port: Option<u16>,
    secret: Option<String>,
    env: Vec<(String, String)>,
}

async fn apps_edit(server: &str, token: &str, args: AppsEditArgs) -> Result<(), anyhow::Error> {
    let client = create_client();
    let url = format!("{server}/v1/apps/{}", args.name);

    let env_map = if args.env.is_empty() {
        None
    } else {
        Some(args.env.into_iter().collect())
    };

    let body = UpdateAppRequest {
        image: args.image,
        domain: args.domain,
        port: args.port,
        secret: args.secret,
        env: env_map,
    };

    api_request(
        &client,
        reqwest::Method::PATCH,
        &url,
        token,
        Some(&serde_json::to_value(&body)?),
    )
    .await?;

    println!("✓ App '{}' updated", args.name);
    Ok(())
}

async fn apps_rm(server: &str, token: &str, name: &str, force: bool) -> Result<(), anyhow::Error> {
    if !force {
        println!(
            "⚠ This will remove app '{}' and stop any running containers.",
            name
        );
        println!("Type 'yes' to confirm:");
        let mut input = String::new();
        std::io::stdin()
            .read_line(&mut input)
            .context("failed to read input")?;
        if input.trim() != "yes" {
            println!("Aborted.");
            return Ok(());
        }
    }

    let client = create_client();
    let url = format!("{server}/v1/apps/{name}");

    api_request(&client, reqwest::Method::DELETE, &url, token, None).await?;

    println!("✓ App '{}' removed", name);
    Ok(())
}

/// Parse a duration string like "10m", "300s", "5m30s" into a Duration.
fn parse_duration(s: &str) -> Result<std::time::Duration, String> {
    if s.is_empty() {
        return Err("empty duration string".to_string());
    }
    let mut total_secs: u64 = 0;
    let mut current: u64 = 0;
    for ch in s.chars() {
        match ch {
            '0'..='9' => {
                current = current
                    .checked_mul(10)
                    .and_then(|v| v.checked_add((ch as u8 - b'0') as u64))
                    .ok_or_else(|| "overflow in duration".to_string())?;
            }
            's' => {
                total_secs = total_secs
                    .checked_add(current)
                    .ok_or_else(|| "overflow in duration".to_string())?;
                current = 0;
            }
            'm' => {
                total_secs = total_secs
                    .checked_add(
                        current
                            .checked_mul(60)
                            .ok_or_else(|| "overflow in duration".to_string())?,
                    )
                    .ok_or_else(|| "overflow in duration".to_string())?;
                current = 0;
            }
            'h' => {
                total_secs = total_secs
                    .checked_add(
                        current
                            .checked_mul(3600)
                            .ok_or_else(|| "overflow in duration".to_string())?,
                    )
                    .ok_or_else(|| "overflow in duration".to_string())?;
                current = 0;
            }
            _ => {
                return Err(format!(
                    "unexpected character '{ch}' in duration, expected digits followed by s/m/h"
                ));
            }
        }
    }
    if current > 0 {
        return Err("duration must have a unit suffix (s, m, or h)".to_string());
    }
    Ok(std::time::Duration::from_secs(total_secs))
}

/// Determine the exit code for a deploy status string.
/// Returns -1 if the status is not terminal (still in progress).
#[allow(dead_code)]
fn deploy_wait_exit_code(status: &str) -> i32 {
    match status {
        "completed" => output::OK,
        "failed" => output::DEPLOY_FAILED,
        _ => -1, // not terminal
    }
}

/// Terminal deploy statuses.
fn is_terminal_deploy_status(status: &str) -> bool {
    matches!(status, "completed" | "failed")
}

#[allow(clippy::too_many_arguments)]
async fn deploy(
    server: &str,
    app: &str,
    tag: &str,
    images: Vec<(String, String)>,
    secret: Option<String>,
    wait: bool,
    wait_timeout: Option<String>,
    json: bool,
) -> Result<(), anyhow::Error> {
    let client = create_client();

    // Build the images map from --image flags.
    let images_map: HashMap<String, String> = images.into_iter().collect();

    // Build the JSON payload.
    let mut body = serde_json::json!({
        "app": app,
        "tag": tag,
    });
    if !images_map.is_empty() {
        body["images"] = serde_json::to_value(&images_map)?;
    }

    let body_bytes = serde_json::to_vec(&body)?;

    // Resolve secret: --secret flag, SLIP_SECRET env var, or prompt.
    let secret = match secret {
        Some(s) => s,
        None => std::env::var("SLIP_SECRET").unwrap_or_else(|_| {
            eprintln!("No secret provided. Set --secret or SLIP_SECRET env var.");
            std::process::exit(1);
        }),
    };

    // Compute HMAC signature.
    let sig = slip_core::auth::compute_signature(&body_bytes, &secret);
    let sig_header = format!("sha256={sig}");

    let url = format!("{server}/v1/deploy");
    let resp = client
        .post(&url)
        .header("Content-Type", "application/json")
        .header("X-Slip-Signature", &sig_header)
        .body(body_bytes)
        .send()
        .await
        .context("HTTP request failed")?;

    if !resp.status().is_success() {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        anyhow::bail!("API error ({}): {}", status, text);
    }

    let deploy_resp: DeployResponse = resp.json().await.context("failed to parse response")?;

    if !wait {
        // Fire-and-forget: backwards compatible behavior.
        println!(
            "✓ Deploy accepted for '{}' → tag '{}' (deploy_id: {})",
            deploy_resp.app, deploy_resp.tag, deploy_resp.deploy_id
        );
        return Ok(());
    }

    // ── Wait mode: poll until terminal ────────────────────────────────────
    let deploy_id = &deploy_resp.deploy_id;
    let status_url = format!("{server}/v1/deploys/{deploy_id}");

    // Resolve timeout.
    let timeout_dur = match wait_timeout {
        Some(ref t) => parse_duration(t).unwrap_or_else(|e| {
            output::fail(
                output::USAGE,
                &format!("invalid --wait-timeout: {e}"),
                "use e.g. 10m, 300s, 5m",
            );
        }),
        None => std::time::Duration::from_secs(600), // 10 minutes default
    };

    let poll_interval = std::time::Duration::from_secs(2);
    let start = std::time::Instant::now();
    let mut last_status = String::new();

    if json {
        // Emit initial accepted event.
        let event = serde_json::json!({
            "event": "accepted",
            "deploy_id": deploy_id,
            "app": deploy_resp.app,
            "tag": deploy_resp.tag,
        });
        println!("{event}");
    } else {
        println!(
            "Deploy accepted for '{}' → tag '{}' (deploy_id: {}), waiting for completion...",
            deploy_resp.app, deploy_resp.tag, deploy_id
        );
    }

    loop {
        // Check timeout.
        if start.elapsed() >= timeout_dur {
            if json {
                let event = serde_json::json!({
                    "event": "timeout",
                    "deploy_id": deploy_id,
                    "timeout_secs": timeout_dur.as_secs(),
                });
                println!("{event}");
            } else {
                eprintln!(
                    "error: deploy did not reach terminal state within {}s",
                    timeout_dur.as_secs()
                );
            }
            std::process::exit(output::TIMEOUT);
        }

        // Poll the status endpoint with retries.
        let poll_resp = match client.get(&status_url).send().await {
            Ok(r) => r,
            Err(e) => {
                // Retry up to 3 times with backoff.
                let mut last_err = e;
                let mut success = false;
                let mut resp = None;
                for attempt in 1..=3 {
                    tokio::time::sleep(std::time::Duration::from_millis(500 * attempt)).await;
                    match client.get(&status_url).send().await {
                        Ok(r) => {
                            success = true;
                            resp = Some(r);
                            break;
                        }
                        Err(e2) => {
                            last_err = e2;
                        }
                    }
                }
                if !success {
                    if json {
                        let event = serde_json::json!({
                            "event": "error",
                            "deploy_id": deploy_id,
                            "error": format!("lost contact with slipd: {last_err}"),
                        });
                        println!("{event}");
                    } else {
                        eprintln!("error: lost contact with slipd: {last_err}");
                    }
                    std::process::exit(output::GENERIC);
                }
                resp.unwrap()
            }
        };

        if !poll_resp.status().is_success() {
            // Non-200 from status endpoint — retry after a short delay.
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            continue;
        }

        let status_resp: DeployStatusResponse = match poll_resp.json().await {
            Ok(s) => s,
            Err(_) => {
                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                continue;
            }
        };

        let current_status = &status_resp.status;

        // Print progress on status change.
        if *current_status != last_status {
            if json {
                let mut event = serde_json::json!({
                    "event": "status_change",
                    "deploy_id": deploy_id,
                    "status": current_status,
                });
                if let Some(ref err) = status_resp.error {
                    event["error"] = serde_json::Value::String(err.clone());
                }
                println!("{event}");
            } else {
                println!("  deploy {deploy_id}: {current_status}...");
            }
            last_status = current_status.clone();
        }

        // Check for terminal state.
        if is_terminal_deploy_status(current_status) {
            if current_status == "completed" {
                if json {
                    let event = serde_json::json!({
                        "event": "completed",
                        "deploy_id": deploy_id,
                        "app": status_resp.app,
                        "tag": status_resp.tag,
                        "status": "completed",
                        "started_at": status_resp.started_at,
                        "finished_at": status_resp.finished_at,
                    });
                    println!("{event}");
                } else {
                    println!("✓ Deploy {deploy_id} completed successfully");
                }
                std::process::exit(output::OK);
            } else {
                // failed
                let reason = status_resp
                    .error
                    .unwrap_or_else(|| "unknown error".to_string());
                if json {
                    let event = serde_json::json!({
                        "event": "failed",
                        "deploy_id": deploy_id,
                        "app": status_resp.app,
                        "tag": status_resp.tag,
                        "status": "failed",
                        "error": reason,
                        "started_at": status_resp.started_at,
                        "finished_at": status_resp.finished_at,
                    });
                    println!("{event}");
                } else {
                    eprintln!("✗ Deploy {deploy_id} failed: {reason}");
                }
                std::process::exit(output::DEPLOY_FAILED);
            }
        }

        // Wait before next poll.
        tokio::time::sleep(poll_interval).await;
    }
}

async fn rollback(
    server: &str,
    token: &str,
    app: &str,
    to: Option<String>,
) -> Result<(), anyhow::Error> {
    let client = create_client();
    let url = format!("{server}/v1/apps/{app}/rollback");

    let body = RollbackRequest { to };
    let resp = api_request(
        &client,
        reqwest::Method::POST,
        &url,
        token,
        Some(&serde_json::to_value(&body)?),
    )
    .await?;

    let deploy: DeployResponse = resp.json().await.context("failed to parse response")?;
    println!(
        "✓ Rollback initiated for '{}' → tag '{}' (deploy_id: {})",
        deploy.app, deploy.tag, deploy.deploy_id
    );

    Ok(())
}

// ─── Secrets subcommand implementations ──────────────────────────────────────────

async fn secrets_list(server: &str, token: &str, app: &str) -> Result<(), anyhow::Error> {
    let client = create_client();
    let url = format!("{server}/v1/apps/{app}/secrets");
    let resp = api_request(&client, reqwest::Method::GET, &url, token, None).await?;
    let data: SecretsListResponse = resp.json().await.context("failed to parse response")?;

    if data.secrets.is_empty() {
        println!("No secrets set for '{}'.", app);
        return Ok(());
    }

    for key in &data.secrets {
        println!("{key}");
    }

    Ok(())
}

async fn secrets_set(
    server: &str,
    token: &str,
    app: &str,
    pairs: Vec<(String, String)>,
) -> Result<(), anyhow::Error> {
    let client = create_client();
    let url = format!("{server}/v1/apps/{app}/secrets");

    let secrets: HashMap<String, String> = pairs.into_iter().collect();
    let body = serde_json::json!({ "secrets": secrets });

    let resp = api_request(&client, reqwest::Method::PUT, &url, token, Some(&body)).await?;

    let data: SetSecretsResponse = resp.json().await.context("failed to parse response")?;
    println!("✓ Set {} secret(s) for '{}'", data.set.len(), app);

    Ok(())
}

async fn secrets_rm(server: &str, token: &str, app: &str, key: &str) -> Result<(), anyhow::Error> {
    let client = create_client();
    let url = format!("{server}/v1/apps/{app}/secrets/{key}");

    api_request(&client, reqwest::Method::DELETE, &url, token, None).await?;

    println!("✓ Removed secret '{}' from '{}'", key, app);
    Ok(())
}

// ─── Previews subcommand implementations ────────────────────────────────────────

/// Format a duration as a human-readable age string.
///
/// - < 60 minutes → `"{m}m"`
/// - < 24 hours   → `"{h}h"`
/// - otherwise    → `"{d}d"`
fn format_age(deployed_at_str: &str) -> String {
    let deployed = match chrono::DateTime::parse_from_rfc3339(deployed_at_str) {
        Ok(dt) => dt.with_timezone(&chrono::Utc),
        Err(_) => return "—".to_string(),
    };
    let elapsed = chrono::Utc::now() - deployed;
    let total_mins = elapsed.num_minutes();
    if total_mins < 60 {
        format!("{total_mins}m")
    } else if total_mins < 60 * 24 {
        format!("{}h", elapsed.num_hours())
    } else {
        format!("{}d", elapsed.num_days())
    }
}

/// Format TTL (time until expiry) as a human-readable string.
///
/// - `None`       → `"—"` (no expiry)
/// - Expired      → `"expired"`
/// - Otherwise    → `"{duration} left"` using same format as age
fn format_ttl(expires_at: Option<&str>) -> String {
    let expires_str = match expires_at {
        Some(s) => s,
        None => return "—".to_string(),
    };

    let expires = match chrono::DateTime::parse_from_rfc3339(expires_str) {
        Ok(dt) => dt.with_timezone(&chrono::Utc),
        Err(_) => return "—".to_string(),
    };

    let remaining = expires - chrono::Utc::now();
    if remaining.num_seconds() <= 0 {
        return "expired".to_string();
    }

    let total_mins = remaining.num_minutes();
    if total_mins < 60 {
        format!("{}m left", remaining.num_minutes())
    } else if total_mins < 60 * 24 {
        format!("{}h left", remaining.num_hours())
    } else {
        format!("{}d left", remaining.num_days())
    }
}

async fn previews_list(server: &str, token: &str, app: &str) -> Result<(), anyhow::Error> {
    let client = create_client();
    let url = format!("{server}/v1/previews/{app}");
    let resp = api_request(&client, reqwest::Method::GET, &url, token, None).await?;
    let data: Vec<PreviewListItem> = resp.json().await.context("failed to parse response")?;

    if data.is_empty() {
        println!("No active previews for '{app}'.");
        return Ok(());
    }

    // Print table header
    println!(
        "{:<20} {:<12} {:<8} {:<14} URL",
        "PREVIEW", "TAG", "AGE", "TTL"
    );
    println!("{}", "-".repeat(70));

    for item in &data {
        let tag_display = match &item.tag {
            Some(t) if t.len() > 10 => format!("{}...", &t[..7]),
            Some(t) => t.clone(),
            None => "—".to_string(),
        };
        let age = format_age(&item.deployed_at);
        let ttl = format_ttl(item.expires_at.as_deref());
        println!(
            "{:<20} {:<12} {:<8} {:<14} {}",
            item.preview_id, tag_display, age, ttl, item.domain
        );
    }

    Ok(())
}

async fn previews_teardown(
    server: &str,
    token: &str,
    app: &str,
    preview: Option<String>,
    all: bool,
) -> Result<(), anyhow::Error> {
    if !all && preview.is_none() {
        anyhow::bail!("Specify a preview name or use --all");
    }
    if all && preview.is_some() {
        anyhow::bail!("Cannot specify both a preview name and --all");
    }

    let client = create_client();

    if all {
        let url = format!("{server}/v1/previews/{app}");
        let resp = api_request(&client, reqwest::Method::DELETE, &url, token, None).await?;
        let data: TeardownAllResponse = resp.json().await.context("failed to parse response")?;
        let n = data.torn_down.len();
        let ids = data.torn_down.join(", ");
        println!("✓ Torn down {n} preview(s) for '{app}': {ids}");
    } else {
        let preview_id = preview.as_deref().unwrap();
        let url = format!("{server}/v1/previews/{app}/{preview_id}");
        api_request(&client, reqwest::Method::DELETE, &url, token, None).await?;
        println!("✓ Torn down preview '{preview_id}' for '{app}'");
    }

    Ok(())
}

// ─── Key command implementation ────────────────────────────────────────────────

async fn key_command(
    server: &str,
    token: &str,
    app: &str,
    rotate: bool,
    gh: bool,
    json: bool,
) -> Result<(), anyhow::Error> {
    let client = create_client();
    let url = format!("{server}/v1/apps/{app}/key");

    let body = SetDeployKeyRequest { rotate };

    let resp = match api_request(
        &client,
        reqwest::Method::PUT,
        &url,
        token,
        Some(&serde_json::to_value(&body)?),
    )
    .await
    {
        Ok(r) => r,
        Err(e) => {
            let msg = format!("{e}");
            // Map known API errors to prescriptive messages.
            if msg.contains("401") || msg.contains("403") {
                output::fail(
                    output::AUTH,
                    "auth failed",
                    "check your admin token (--token or SLIP_TOKEN)",
                );
            }
            if msg.contains("404") {
                output::fail(
                    output::NOT_FOUND,
                    &format!("app '{app}' not found"),
                    "register it via POST /v1/apps or run `slip apply`",
                );
            }
            // Network/connection error (the anyhow context message).
            if msg.contains("HTTP request failed") {
                output::fail(
                    output::GENERIC,
                    &format!(
                        "can't reach slipd at {server} — is it running? did you `slip link` to the right server?"
                    ),
                    "",
                );
            }
            // Generic API error.
            output::fail(output::GENERIC, &msg, "");
        }
    };

    let data: SetDeployKeyResponse = resp.json().await.context("failed to parse response")?;

    if json {
        let out = serde_json::json!({
            "app": data.app,
            "key": data.key,
            "rotated": data.rotated,
            "gh_secret_name": "SLIP_DEPLOY_SECRET",
        });
        println!("{out}");
        return Ok(());
    }

    match data.key {
        Some(key) => {
            println!("Deploy key for {}:", data.app);
            println!("  {key}");
            println!();
            println!("Add to GitHub Actions secrets:");
            println!("  gh secret set SLIP_DEPLOY_SECRET --body '{key}'");

            if rotate {
                println!();
                println!("⚠ CI will break until the GitHub secret is updated with the new key.");
            }

            if gh {
                // Infer repo from git remote.
                let output = std::process::Command::new("git")
                    .args(["remote", "get-url", "origin"])
                    .output()
                    .context("failed to run `git remote get-url origin`")?;

                if !output.status.success() {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    output::fail(
                        output::GENERIC,
                        &format!("could not infer GitHub repo from git remote: {stderr}"),
                        "run `gh secret set SLIP_DEPLOY_SECRET --body '<key>'` manually",
                    );
                }

                let remote_url = String::from_utf8_lossy(&output.stdout).trim().to_string();
                // Parse owner/repo from common remote URL formats.
                let repo_slug = parse_gh_repo_slug(&remote_url).unwrap_or_else(|| {
                    output::fail(
                        output::GENERIC,
                        &format!("could not parse GitHub repo from remote URL: {remote_url}"),
                        "run `gh secret set SLIP_DEPLOY_SECRET --body '<key>'` manually",
                    );
                });

                // Check if `gh` is installed.
                let gh_check = std::process::Command::new("gh").arg("--version").output();
                match gh_check {
                    Ok(out) if out.status.success() => {}
                    _ => {
                        output::fail(
                            output::GENERIC,
                            "`gh` CLI is not installed or not in PATH",
                            "install it from https://cli.github.com/ or run the `gh secret set` command manually",
                        );
                    }
                }

                let gh_status = std::process::Command::new("gh")
                    .args([
                        "secret",
                        "set",
                        "SLIP_DEPLOY_SECRET",
                        "--body",
                        &key,
                        "--repo",
                        &repo_slug,
                    ])
                    .status()
                    .context("failed to run `gh secret set`")?;

                if gh_status.success() {
                    println!("✓ GitHub secret set for {repo_slug}");
                } else {
                    output::fail(
                        output::GENERIC,
                        "`gh secret set` failed",
                        &format!(
                            "run it manually: gh secret set SLIP_DEPLOY_SECRET --body '<key>' --repo {repo_slug}"
                        ),
                    );
                }
            }
        }
        None => {
            let msg = data
                .message
                .as_deref()
                .unwrap_or("deploy key already exists — pass --rotate to rotate it");
            println!("{msg}");
            // Exit 0: the command succeeded in telling the user the state.
            // No key was returned (security: never echo an existing key).
        }
    }

    Ok(())
}

/// Parse `owner/repo` from a GitHub remote URL.
///
/// Supports:
///   - git@github.com:owner/repo.git
///   - https://github.com/owner/repo.git
///   - https://github.com/owner/repo
fn parse_gh_repo_slug(url: &str) -> Option<String> {
    let url = url.strip_suffix(".git").unwrap_or(url);
    if let Some(rest) = url.strip_prefix("git@github.com:") {
        return Some(rest.to_string());
    }
    if let Some(rest) = url.strip_prefix("https://github.com/") {
        return Some(rest.to_string());
    }
    None
}

// ─── Deprecation warning helper ────────────────────────────────────────────────

fn deprecation_warning() {
    eprintln!(
        "warning: `slip apps` is deprecated; apps are now created via `slip apply` (see SLIP-94). This command still works."
    );
}

// ─── Remote resolution helpers ────────────────────────────────────────────────

/// Read `[remote]` from the repo's `slip.toml` (best-effort).
///
/// Returns `None` if the file doesn't exist or can't be parsed.
fn resolve_remote() -> Option<slip_core::RemoteConfig> {
    let content = std::fs::read_to_string("slip.toml").ok()?;
    let value: toml::Value = content.parse().ok()?;
    let remote = value.get("remote")?;
    let server = remote.get("server")?.as_str()?.to_string();
    let app = remote.get("app")?.as_str()?.to_string();
    Some(slip_core::RemoteConfig { server, app })
}

/// Resolve the server URL: explicit `--server` flag > `[remote].server` > default.
fn resolve_server(cli_server: &Option<String>) -> String {
    if let Some(s) = cli_server {
        return s.clone();
    }
    if let Some(remote) = resolve_remote()
        && !remote.server.is_empty()
    {
        return remote.server;
    }
    "http://localhost:7890".to_string()
}

/// Resolve the app name: explicit arg > `[remote].app` > error.
fn resolve_app(explicit: Option<String>) -> String {
    if let Some(app) = explicit {
        return app;
    }
    if let Some(remote) = resolve_remote()
        && !remote.app.is_empty()
    {
        return remote.app;
    }
    output::fail(
        output::USAGE,
        "no app name",
        "pass it as a positional argument, set [app].name in slip.toml, or run `slip link --server <URL> --app <name>`",
    );
}

/// Resolve the token: `--token` flag > `SLIP_TOKEN` env > error.
///
/// The error message mentions `--no-apply` as a remedy because `slip deploy`
/// now requires the admin token by default (for `--apply`). For commands that
/// don't have `--no-apply`, the mention is harmless.
fn resolve_token(cli_token: Option<String>) -> String {
    cli_token.unwrap_or_else(|| {
        output::fail(
            output::AUTH,
            "no admin token",
            "set --token or the SLIP_TOKEN env var, or use --no-apply to skip config application",
        );
    })
}

// ─── Link command implementation ───────────────────────────────────────────────

/// Response from `GET /v1/status` (minimal version used by `slip link`).
///
/// This is NOT the full `slip_core::StatusResponse` — `slip link` only needs
/// the daemon version to confirm connectivity. The full status response is
/// deserialized separately in the `slip status` command.
#[derive(Debug, Deserialize)]
struct LinkStatusResponse {
    version: String,
}

// ─── Status command implementation ────────────────────────────────────────────

/// Full daemon status response from `GET /v1/status`.
///
/// Mirrors `slip_core::StatusResponse` but we deserialize locally to keep the
/// CLI decoupled from internal crate types (only the wire schema matters).
#[derive(Debug, Serialize, Deserialize)]
struct DaemonStatusResponse {
    schema: String,
    daemon: String,
    version: String,
    uptime_seconds: i64,
    caddy: String,
    runtime: String,
    runtime_backend: Option<String>,
    app_count: usize,
    #[serde(default)]
    last_deploys: Vec<DeploySummaryJson>,
    #[serde(default)]
    apps: std::collections::HashMap<String, AppStatusJson>,
}

/// Per-app status in the daemon status response.
#[derive(Debug, Serialize, Deserialize)]
struct AppStatusJson {
    status: String,
    tag: Option<String>,
    #[serde(default)]
    deployed_at: Option<String>,
    #[serde(default)]
    container_id: Option<String>,
    #[serde(default)]
    port: Option<u16>,
    #[serde(default)]
    kind: Option<String>,
    #[serde(default)]
    deploy_id: Option<String>,
    #[serde(default)]
    triggered_by: Option<String>,
}

/// Deploy summary in the status response.
#[derive(Debug, Serialize, Deserialize)]
struct DeploySummaryJson {
    deploy_id: String,
    app: String,
    tag: String,
    status: String,
    triggered_by: String,
}

/// Detailed per-app status response from `GET /v1/apps/{name}/status`.
#[derive(Debug, Serialize, Deserialize)]
struct DetailedAppStatus {
    status: String,
    tag: Option<String>,
    #[serde(default)]
    deployed_at: Option<String>,
    #[serde(default)]
    container_id: Option<String>,
    #[serde(default)]
    port: Option<u16>,
    #[serde(default)]
    kind: Option<String>,
    #[serde(default)]
    deploy_id: Option<String>,
    #[serde(default)]
    triggered_by: Option<String>,
    #[serde(default)]
    container_state: Option<String>,
    #[serde(default)]
    health: Option<HealthStatusJson>,
    #[serde(default)]
    last_deploy: Option<DeploySummaryJson>,
    #[serde(default)]
    routes: Vec<RouteStatusJson>,
    #[serde(default)]
    secrets: Vec<String>,
    #[serde(default)]
    cert: Option<CertStatusJson>,
    #[serde(default)]
    config_drift: Option<bool>,
}

#[derive(Debug, Serialize, Deserialize)]
struct HealthStatusJson {
    #[serde(default)]
    path: Option<String>,
    retries: u32,
    status: String,
    #[serde(default)]
    last_check: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct RouteStatusJson {
    hostname: String,
    port: u16,
}

#[derive(Debug, Serialize, Deserialize)]
struct CertStatusJson {
    issuer: String,
    #[serde(default)]
    expires_at: Option<String>,
}

/// `slip status [app]` — show daemon or per-app status.
///
/// - With an app name: calls `GET /v1/apps/{name}/status` and renders a
///   detailed report (tag, container state, health, deploy, routes, cert,
///   secrets, drift).
/// - Without an app name: calls `GET /v1/status` and renders a compact table
///   of all apps.
async fn status_command(
    server: &str,
    token: &str,
    app: Option<&str>,
    json: bool,
) -> Result<(), anyhow::Error> {
    let client = create_client();

    if let Some(app_name) = app {
        // ── Per-app detailed status ─────────────────────────────────────────
        let url = format!("{server}/v1/apps/{app_name}/status");
        let resp = client
            .get(&url)
            .header("Authorization", format!("Bearer {token}"))
            .send()
            .await;

        let resp = match resp {
            Ok(r) => r,
            Err(e) => {
                if e.is_connect() || e.is_timeout() {
                    output::fail(
                        output::GENERIC,
                        &format!("can't reach slipd at {server} — is it running?"),
                        "",
                    );
                }
                anyhow::bail!("HTTP request failed: {e}");
            }
        };

        if resp.status() == reqwest::StatusCode::UNAUTHORIZED
            || resp.status() == reqwest::StatusCode::FORBIDDEN
        {
            output::fail(
                output::AUTH,
                "auth failed",
                "check your admin token (--token or SLIP_TOKEN)",
            );
        }

        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            output::fail(
                output::NOT_FOUND,
                &format!("app '{app_name}' not found"),
                "run `slip apply` to register it",
            );
        }

        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            anyhow::bail!("API error ({}): {}", status, text);
        }

        let detail: DetailedAppStatus = resp
            .json()
            .await
            .context("failed to parse app status response")?;

        if json {
            // Output the raw JSON (re-serialize for stable formatting).
            let val = serde_json::to_value(&detail).unwrap_or(serde_json::Value::Null);
            println!("{val}");
        } else {
            print_detailed_status(app_name, &detail);
        }
    } else {
        // ── Daemon-level status (all apps) ──────────────────────────────────
        let url = format!("{server}/v1/status");
        let resp = client
            .get(&url)
            .header("Authorization", format!("Bearer {token}"))
            .send()
            .await;

        let resp = match resp {
            Ok(r) => r,
            Err(e) => {
                if e.is_connect() || e.is_timeout() {
                    output::fail(
                        output::GENERIC,
                        &format!("can't reach slipd at {server} — is it running?"),
                        "",
                    );
                }
                anyhow::bail!("HTTP request failed: {e}");
            }
        };

        if resp.status() == reqwest::StatusCode::UNAUTHORIZED
            || resp.status() == reqwest::StatusCode::FORBIDDEN
        {
            output::fail(
                output::AUTH,
                "auth failed",
                "check your admin token (--token or SLIP_TOKEN)",
            );
        }

        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            anyhow::bail!("API error ({}): {}", status, text);
        }

        let status_data: DaemonStatusResponse = resp
            .json()
            .await
            .context("failed to parse status response")?;

        if json {
            let val = serde_json::to_value(&status_data).unwrap_or(serde_json::Value::Null);
            println!("{val}");
        } else {
            print_daemon_status(&status_data);
        }
    }

    Ok(())
}

/// Print a compact daemon status overview with a table of all apps.
fn print_daemon_status(status: &DaemonStatusResponse) {
    println!(
        "slipd {} (uptime: {}s)",
        status.version, status.uptime_seconds
    );
    println!(
        "  caddy: {}  runtime: {}{}  apps: {}",
        status.caddy,
        status.runtime,
        status
            .runtime_backend
            .as_ref()
            .map(|b| format!(" ({b})"))
            .unwrap_or_default(),
        status.app_count,
    );

    if status.apps.is_empty() {
        println!("\n  no apps registered");
        return;
    }

    // Sort apps by name for stable output.
    let mut app_names: Vec<&String> = status.apps.keys().collect();
    app_names.sort();

    println!();
    println!(
        "  {:<20} {:<14} {:<16} {:<8} {:<8}",
        "APP", "STATUS", "TAG", "PORT", "KIND"
    );
    println!(
        "  {:-<20} {:-<14} {:-<16} {:-<8} {:-<8}",
        "", "", "", "", ""
    );

    for name in app_names {
        let app = &status.apps[name];
        println!(
            "  {:<20} {:<14} {:<16} {:<8} {:<8}",
            name,
            app.status,
            app.tag.as_deref().unwrap_or("-"),
            app.port
                .map(|p| p.to_string())
                .unwrap_or_else(|| "-".to_string()),
            app.kind.as_deref().unwrap_or("-"),
        );
    }

    if !status.last_deploys.is_empty() {
        println!("\n  Last deploys:");
        for dep in &status.last_deploys {
            println!(
                "    {} {} {} ({})",
                dep.deploy_id, dep.app, dep.tag, dep.status
            );
        }
    }
}

// ─── Logs command implementation ──────────────────────────────────────────────

/// ANSI color codes for blue/green container prefixes.
const COLOR_BLUE: &str = "\x1b[34m";
const COLOR_GREEN: &str = "\x1b[32m";
const COLOR_RESET: &str = "\x1b[0m";

/// Stream container logs from `GET /v1/apps/{app}/logs`.
///
/// In `--json` mode, prints each NDJSON line as-is. In text mode, parses each
/// NDJSON line and prints with a colored `[container_short]` prefix (blue/green).
async fn logs_command(
    server: &str,
    token: &str,
    app: &str,
    since: Option<&str>,
    follow: bool,
    json: bool,
) -> Result<(), anyhow::Error> {
    let client = create_streaming_client();
    let url = format!("{server}/v1/apps/{app}/logs");

    // Build query params using reqwest's built-in encoding.
    let mut query: Vec<(&str, String)> =
        vec![("follow", follow.to_string()), ("json", json.to_string())];
    if let Some(s) = since {
        query.push(("since", s.to_string()));
    }

    let resp = match client
        .get(&url)
        .header("Authorization", format!("Bearer {token}"))
        .query(&query)
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            if e.is_connect() || e.is_timeout() {
                output::fail(
                    output::GENERIC,
                    &format!("can't reach slipd at {server} — is it running?"),
                    "",
                );
            }
            anyhow::bail!("HTTP request failed: {e}");
        }
    };

    // Pre-stream error handling.
    let status = resp.status();
    if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
        output::fail(
            output::AUTH,
            "auth failed",
            "check your admin token (--token or SLIP_TOKEN)",
        );
    }
    if status == reqwest::StatusCode::NOT_FOUND {
        output::fail(
            output::NOT_FOUND,
            &format!("app '{app}' not found or no running containers"),
            "run `slip apply` to register it, then `slip deploy` to start a container",
        );
    }
    if status == reqwest::StatusCode::BAD_REQUEST {
        let text = resp.text().await.unwrap_or_default();
        // Extract the error message from the JSON response.
        let msg = serde_json::from_str::<serde_json::Value>(&text)
            .ok()
            .and_then(|v| v.get("error").and_then(|e| e.as_str()).map(String::from))
            .unwrap_or(text);
        output::fail(output::USAGE, &msg, "use formats like 1h, 5m, 30s, 5m30s");
    }
    if !status.is_success() {
        let text = resp.text().await.unwrap_or_default();
        anyhow::bail!("API error ({status}): {text}");
    }

    // Consume the NDJSON stream line by line.
    let is_tty = std::io::stdout().is_terminal();

    let byte_stream = resp
        .bytes_stream()
        .map_err(|e| std::io::Error::other(e.to_string()));
    let stream_reader = tokio_util::io::StreamReader::new(byte_stream);
    let mut reader = tokio::io::BufReader::new(stream_reader);
    let mut line_buf = String::new();

    loop {
        line_buf.clear();
        let n = reader.read_line(&mut line_buf).await?;
        if n == 0 {
            break; // stream ended
        }

        let line_str = line_buf.trim_end_matches(['\n', '\r']);
        if line_str.is_empty() {
            continue;
        }

        if json {
            // In --json mode, print the NDJSON line as-is.
            println!("{line_str}");
            // Check for error lines and print to stderr.
            if let Ok(err) = serde_json::from_str::<LogErrorLine>(line_str) {
                eprintln!(
                    "error: {} (container: {})",
                    err.error,
                    err.container.unwrap_or_else(|| "?".to_string())
                );
            }
        } else {
            // Text mode: parse the NDJSON line and format with color prefix.
            match serde_json::from_str::<LogLine>(line_str) {
                Ok(log) => {
                    let container_short = log.container.split('/').next().unwrap_or(&log.container);
                    let color = if log.container.starts_with("blue") {
                        COLOR_BLUE
                    } else {
                        COLOR_GREEN
                    };
                    if is_tty {
                        println!("{color}[{container_short}]{COLOR_RESET} {}", log.line);
                    } else {
                        println!("[{container_short}] {}", log.line);
                    }
                }
                Err(_) => {
                    // Might be an error/info event — try parsing as LogErrorLine.
                    if let Ok(err) = serde_json::from_str::<LogErrorLine>(line_str) {
                        eprintln!("error: {}", err.error);
                    }
                    // Otherwise skip unparseable lines.
                }
            }
        }
    }

    Ok(())
}

/// Print a detailed per-app status report.
fn print_detailed_status(app_name: &str, detail: &DetailedAppStatus) {
    println!("app: {app_name}");
    println!("  status:       {}", detail.status);
    println!("  tag:          {}", detail.tag.as_deref().unwrap_or("-"));
    if let Some(ref cid) = detail.container_id {
        println!("  container:    {cid}");
    }
    if let Some(ref state) = detail.container_state {
        println!("  container state: {state}");
    }
    if let Some(port) = detail.port {
        println!("  port:         {port}");
    }
    if let Some(ref kind) = detail.kind {
        println!("  kind:         {kind}");
    }
    if let Some(ref at) = detail.deployed_at {
        println!("  deployed at:  {at}");
    }

    // Deploy metadata
    if let Some(ref dep) = detail.last_deploy {
        println!();
        println!("  last deploy:");
        println!("    id:          {}", dep.deploy_id);
        println!("    tag:         {}", dep.tag);
        println!("    status:      {}", dep.status);
        println!("    triggered:   {}", dep.triggered_by);
    }

    // Health
    if let Some(ref h) = detail.health {
        println!();
        println!("  health:");
        println!("    status:      {}", h.status);
        if let Some(ref path) = h.path {
            println!("    path:        {path}");
        }
        println!("    retries:     {}", h.retries);
        if let Some(ref lc) = h.last_check {
            println!("    last check:  {lc}");
        }
    }

    // Routes
    if !detail.routes.is_empty() {
        println!();
        println!("  routes:");
        for r in &detail.routes {
            println!("    {} → :{}", r.hostname, r.port);
        }
    }

    // Cert
    if let Some(ref cert) = detail.cert {
        println!();
        println!("  cert:");
        println!("    issuer:      {}", cert.issuer);
        if let Some(ref exp) = cert.expires_at {
            println!("    expires:     {exp}");
        }
    }

    // Secrets (key names only)
    if !detail.secrets.is_empty() {
        println!();
        println!("  secrets (keys only):");
        for key in &detail.secrets {
            println!("    {key}");
        }
    }

    // Config drift
    if let Some(drift) = detail.config_drift {
        println!();
        if drift {
            println!("  config drift: YES — server config differs from last `slip apply`");
        } else {
            println!("  config drift: none — up to date");
        }
    }
}

async fn link_command(
    server: &str,
    app: &str,
    token: &str,
    json: bool,
) -> Result<(), anyhow::Error> {
    let client = create_client();
    let url = format!("{server}/v1/status");

    let resp = match client
        .get(&url)
        .header("Authorization", format!("Bearer {token}"))
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            if e.is_connect() || e.is_timeout() {
                output::fail(
                    output::GENERIC,
                    &format!("can't reach slipd at {server} — is it running?"),
                    "",
                );
            }
            anyhow::bail!("HTTP request failed: {e}");
        }
    };

    if resp.status() == reqwest::StatusCode::UNAUTHORIZED
        || resp.status() == reqwest::StatusCode::FORBIDDEN
    {
        output::fail(
            output::AUTH,
            "auth failed",
            "check your admin token (--token or SLIP_TOKEN)",
        );
    }

    if !resp.status().is_success() {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        anyhow::bail!("API error ({}): {}", status, text);
    }

    let status_data: LinkStatusResponse = resp
        .json()
        .await
        .context("failed to parse status response")?;

    // Write [remote] to slip.toml using toml::Value round-trip to preserve existing content.
    let path = std::path::Path::new("slip.toml");
    let mut doc: toml::Value = if path.exists() {
        let content = std::fs::read_to_string(path).context("failed to read slip.toml")?;
        content
            .parse::<toml::Value>()
            .unwrap_or(toml::Value::Table(toml::map::Map::new()))
    } else {
        toml::Value::Table(toml::map::Map::new())
    };

    // Build the remote table
    let mut remote_table = toml::map::Map::new();
    remote_table.insert(
        "server".to_string(),
        toml::Value::String(server.to_string()),
    );
    remote_table.insert("app".to_string(), toml::Value::String(app.to_string()));

    doc.as_table_mut()
        .expect("doc is a table")
        .insert("remote".to_string(), toml::Value::Table(remote_table));

    let output = toml::to_string(&doc).context("failed to serialize slip.toml")?;
    std::fs::write(path, &output).context("failed to write slip.toml")?;

    let action = if path.exists() { "updated" } else { "created" };

    if json {
        let out = serde_json::json!({
            "server": server,
            "app": app,
            "slipd_version": status_data.version,
            "slip_toml": action,
        });
        println!("{out}");
    } else {
        println!(
            "Linked {} → {} (app: {}, slipd {})",
            std::env::current_dir()
                .ok()
                .and_then(|p| p.file_name().map(|n| n.to_string_lossy().to_string()))
                .unwrap_or_else(|| ".".to_string()),
            server,
            app,
            status_data.version,
        );
    }

    Ok(())
}

// ─── Apply command implementation ─────────────────────────────────────────────

/// Apply a slip.toml config: validate, fetch server state, diff, and push.
async fn apply_command(
    server: &str,
    token: &str,
    app: &str,
    dry_run: bool,
    no_redact: bool,
    json: bool,
) -> Result<(), anyhow::Error> {
    let client = create_client();

    // 1. Read slip.toml
    let content = match std::fs::read_to_string("slip.toml") {
        Ok(c) => c,
        Err(e) => {
            let exit_code = if dry_run {
                output::DRY_RUN_FAILURE
            } else {
                output::GENERIC
            };
            output::fail(
                exit_code,
                &format!("failed to read slip.toml: {e}"),
                "run `slip init` to create one, or ensure you're in the repo root",
            );
        }
    };

    // 2. Parse and validate
    let base_dir = std::path::Path::new(".").to_path_buf();
    let (config, result) = slip_core::validate::parse_and_validate(&content, &base_dir, false);

    // Print warnings
    for warning in &result.warnings {
        if json {
            let w = serde_json::json!({"warning": warning});
            eprintln!("{w}");
        } else {
            eprintln!("⚠ {warning}");
        }
    }

    if !result.is_valid() {
        if json {
            println!("{}", serde_json::to_string(&result).unwrap());
        } else {
            for error in &result.errors {
                eprintln!("✗ {error}");
            }
        }
        let exit_code = if dry_run {
            output::DRY_RUN_FAILURE
        } else {
            output::GENERIC
        };
        std::process::exit(exit_code);
    }

    let repo_config = config.expect("valid config should be present");

    // 3. GET /v1/apps/{app} — use reqwest directly to distinguish status codes
    let get_url = format!("{server}/v1/apps/{app}");
    let get_resp = client
        .get(&get_url)
        .header("Authorization", format!("Bearer {token}"))
        .send()
        .await
        .context("HTTP request failed")?;

    let status = get_resp.status();

    if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
        output::fail(
            output::AUTH,
            "authentication failed — invalid or expired token",
            "check your --token flag or SLIP_TOKEN env var",
        );
    }

    if status == reqwest::StatusCode::NOT_FOUND {
        // 4. App doesn't exist — create it
        if dry_run {
            let out = slip_core::diff::ApplyDiff {
                schema: "slip.apply.diff/v1".to_string(),
                app: app.to_string(),
                changed: true,
                ops: vec![],
                create: Some(true),
                message: Some(format!("would create new app '{app}'")),
                status: None,
            };
            if json {
                println!("{}", serde_json::to_string(&out).unwrap());
            } else {
                println!("{}", out.message.as_deref().unwrap_or(""));
            }
            std::process::exit(output::CHANGES_PRESENT);
        }

        let create_payload =
            slip_core::diff::build_create_payload(&repo_config).unwrap_or_else(|e| {
                let exit_code = if dry_run {
                    output::DRY_RUN_FAILURE
                } else {
                    output::GENERIC
                };
                output::fail(
                    exit_code,
                    &e,
                    "add the missing field(s) to slip.toml, or register the app first via the API",
                );
            });

        let create_url = format!("{server}/v1/apps");
        let create_resp = client
            .post(&create_url)
            .header("Authorization", format!("Bearer {token}"))
            .json(&create_payload)
            .send()
            .await
            .context("HTTP request failed")?;

        if create_resp.status() == reqwest::StatusCode::CONFLICT {
            // TOCTOU: app was created between our GET and POST — re-fetch and proceed as update
            let re_get_resp = client
                .get(&get_url)
                .header("Authorization", format!("Bearer {token}"))
                .send()
                .await
                .context("HTTP request failed")?;
            if !re_get_resp.status().is_success() {
                let status_code = re_get_resp.status();
                let text = re_get_resp.text().await.unwrap_or_default();
                anyhow::bail!("API error ({}): {}", status_code, text);
            }
            let body_bytes = re_get_resp
                .bytes()
                .await
                .context("failed to read response body")?;
            let server_response: slip_core::api::AppResponse =
                serde_json::from_slice(&body_bytes).context("failed to parse server response")?;

            let diff = slip_core::diff::compute_diff(&repo_config, &server_response)
                .context("failed to compute diff")?;
            if !diff.changed {
                if json {
                    println!("{}", serde_json::to_string(&diff).unwrap());
                } else {
                    println!("✓ up to date");
                }
                return Ok(());
            }
            // Fall through to apply the diff below
            return apply_diff(&client, server, token, app, &diff, &repo_config, json).await;
        } else if !create_resp.status().is_success() {
            let status_code = create_resp.status();
            let text = create_resp.text().await.unwrap_or_default();
            if status_code == reqwest::StatusCode::UNAUTHORIZED {
                output::fail(output::AUTH, "authentication failed", "check your token");
            }
            anyhow::bail!("API error ({}): {}", status_code, text);
        } else {
            let out = slip_core::diff::ApplyDiff {
                schema: "slip.apply.diff/v1".to_string(),
                app: app.to_string(),
                changed: false,
                ops: vec![],
                create: None,
                message: None,
                status: Some("created".to_string()),
            };
            if json {
                println!("{}", serde_json::to_string(&out).unwrap());
            } else {
                println!("+ created new app '{app}'");
            }
            return Ok(());
        }
    }

    // 5. Parse server response
    let body_bytes = get_resp
        .bytes()
        .await
        .context("failed to read response body")?;
    let server_response: slip_core::api::AppResponse =
        serde_json::from_slice(&body_bytes).context("failed to parse server response")?;

    // 6. Compute diff
    let diff = slip_core::diff::compute_diff(&repo_config, &server_response)
        .context("failed to compute diff")?;

    if !diff.changed {
        if json {
            println!("{}", serde_json::to_string(&diff).unwrap());
        } else {
            println!("✓ up to date");
        }
        return Ok(());
    }

    // 7. Dry-run: render diff and exit
    if dry_run {
        let display_diff = if !no_redact { diff.redacted() } else { diff };
        if json {
            println!("{}", serde_json::to_string(&display_diff).unwrap());
        } else {
            println!(
                "{}",
                slip_core::diff::render_human_diff(&display_diff, false)
            );
        }
        std::process::exit(output::CHANGES_PRESENT);
    }

    // 8. Apply: print diff summary, then PATCH
    apply_diff(&client, server, token, app, &diff, &repo_config, json).await
}

/// Apply a computed diff via PATCH.
async fn apply_diff(
    client: &reqwest::Client,
    server: &str,
    token: &str,
    app: &str,
    diff: &slip_core::diff::ApplyDiff,
    repo_config: &slip_core::RepoConfig,
    json: bool,
) -> Result<(), anyhow::Error> {
    if json {
        println!("{}", serde_json::to_string(&diff.redacted()).unwrap());
    } else {
        println!("{}", slip_core::diff::render_human_diff(diff, true));
    }

    let update_payload = slip_core::diff::build_update_payload(repo_config);
    let patch_url = format!("{server}/v1/apps/{app}");
    let patch_resp = client
        .patch(&patch_url)
        .header("Authorization", format!("Bearer {token}"))
        .json(&update_payload)
        .send()
        .await
        .context("HTTP request failed")?;

    if !patch_resp.status().is_success() {
        let status_code = patch_resp.status();
        let text = patch_resp.text().await.unwrap_or_default();
        match status_code {
            reqwest::StatusCode::UNAUTHORIZED => {
                output::fail(output::AUTH, "authentication failed", "check your token");
            }
            reqwest::StatusCode::NOT_FOUND => {
                output::fail(
                    output::NOT_FOUND,
                    &format!("app '{app}' not found"),
                    "it may have been deleted; run `slip apply` again to recreate it",
                );
            }
            _ => {
                anyhow::bail!("API error ({}): {}", status_code, text);
            }
        }
    }

    let out = slip_core::diff::ApplyDiff {
        schema: "slip.apply.diff/v1".to_string(),
        app: app.to_string(),
        changed: false,
        ops: vec![],
        create: None,
        message: None,
        status: Some("applied".to_string()),
    };
    if json {
        println!("{}", serde_json::to_string(&out).unwrap());
    } else {
        println!("✓ applied");
    }

    Ok(())
}

// ─── Init command implementation ──────────────────────────────────────────────

/// Infer the app name from: --name flag > git remote origin org/repo > dir name.
fn infer_name(explicit: Option<String>) -> String {
    if let Some(name) = explicit {
        return name;
    }
    // Try git remote origin
    if let Ok(output) = std::process::Command::new("git")
        .args(["remote", "get-url", "origin"])
        .output()
        && output.status.success()
    {
        let url = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if let Some(slug) = parse_gh_repo_slug(&url) {
            // slug is "org/repo" — use the repo part
            if let Some(repo) = slug.split('/').nth(1) {
                return repo.to_string();
            }
        }
    }
    // Fall back to current directory name
    std::env::current_dir()
        .ok()
        .and_then(|p| p.file_name().map(|n| n.to_string_lossy().to_string()))
        .unwrap_or_else(|| "myapp".to_string())
}

/// Infer the image from: --image flag > ghcr.io/<org>/<name> from git remote > ghcr.io/<dir-name>.
fn infer_image(explicit: Option<String>, name: &str) -> String {
    if let Some(image) = explicit {
        return image;
    }
    // Try git remote origin for org
    if let Ok(output) = std::process::Command::new("git")
        .args(["remote", "get-url", "origin"])
        .output()
        && output.status.success()
    {
        let url = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if let Some(slug) = parse_gh_repo_slug(&url) {
            // slug is "org/repo"
            if let Some(org) = slug.split('/').next() {
                return format!("ghcr.io/{org}/{name}");
            }
        }
    }
    format!("ghcr.io/{name}")
}

/// Files that `slip init` generates.
const INIT_FILES: &[&str] = &["slip.toml", ".github/workflows/deploy.yml", "AGENTS.md"];

/// Check which files already exist (for idempotent re-run).
fn check_existing_files() -> Vec<String> {
    let mut existing = Vec::new();
    for f in INIT_FILES {
        if std::path::Path::new(f).exists() {
            existing.push(f.to_string());
        }
    }
    existing
}

/// Render the slip.toml template with the given name and image.
fn render_slip_toml(name: &str, image: &str) -> String {
    let template = include_str!("../templates/slip.toml");
    template.replace("{NAME}", name).replace("{IMAGE}", image)
}

/// Render the deploy.yml template with the given name and image.
fn render_deploy_yml(name: &str, image: &str) -> String {
    let template = include_str!("../templates/deploy.yml");
    template.replace("{NAME}", name).replace("{IMAGE}", image)
}

/// Render the AGENTS.md section template.
fn render_agents_md() -> String {
    include_str!("../templates/AGENTS.md").to_string()
}

/// Write a file, creating parent directories as needed.
fn write_file(path: &str, content: &str) -> Result<(), anyhow::Error> {
    let p = std::path::Path::new(path);
    if let Some(parent) = p.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed to create directory: {}", parent.display()))?;
    }
    std::fs::write(p, content).with_context(|| format!("failed to write: {path}"))?;
    Ok(())
}

fn init_command(name: Option<String>, image: Option<String>, force: bool, json: bool) -> ! {
    let app_name = infer_name(name);

    // Warn if no git remote was found
    let has_remote = std::process::Command::new("git")
        .args(["remote", "get-url", "origin"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    if !has_remote {
        eprintln!(
            "warning: no git remote 'origin' found — using directory name for image inference"
        );
    }

    let image_name = infer_image(image, &app_name);

    // Check for existing files
    let existing = check_existing_files();
    if !existing.is_empty() && !force {
        if json {
            let out = serde_json::json!({
                "status": "exists",
                "files": existing,
                "app": app_name,
                "image": image_name,
            });
            println!("{out}");
        } else {
            eprintln!("error: the following files already exist:");
            for f in &existing {
                eprintln!("  {f}");
            }
            eprintln!("  → use --force to overwrite");
        }
        std::process::exit(output::GENERIC);
    }

    // Render and write files
    let slip_toml = render_slip_toml(&app_name, &image_name);
    let deploy_yml = render_deploy_yml(&app_name, &image_name);
    let agents_md = render_agents_md();

    let mut files_written = Vec::new();

    if let Err(e) = write_file("slip.toml", &slip_toml) {
        output::fail(
            output::GENERIC,
            &format!("failed to write slip.toml: {e}"),
            "",
        );
    }
    files_written.push("slip.toml".to_string());

    if let Err(e) = write_file(".github/workflows/deploy.yml", &deploy_yml) {
        output::fail(
            output::GENERIC,
            &format!("failed to write .github/workflows/deploy.yml: {e}"),
            "",
        );
    }
    files_written.push(".github/workflows/deploy.yml".to_string());

    // AGENTS.md: append section or create file
    let agents_path = std::path::Path::new("AGENTS.md");
    let final_agents = if agents_path.exists() {
        let existing_content = std::fs::read_to_string(agents_path).unwrap_or_default();
        // Check if the slip section already exists
        if existing_content.contains("## slip deploy contract") {
            existing_content
        } else {
            format!("{}\n\n{}", existing_content.trim_end(), agents_md)
        }
    } else {
        agents_md.clone()
    };
    if let Err(e) = write_file("AGENTS.md", &final_agents) {
        output::fail(
            output::GENERIC,
            &format!("failed to write AGENTS.md: {e}"),
            "",
        );
    }
    files_written.push("AGENTS.md".to_string());

    if json {
        let out = serde_json::json!({
            "status": "ok",
            "files_written": files_written,
            "app": app_name,
            "image": image_name,
        });
        println!("{out}");
    } else {
        println!("✓ Initialized slip project '{}'", app_name);
        println!("  image: {}", image_name);
        for f in &files_written {
            println!("  created: {f}");
        }
        println!();
        println!("Next steps:");
        println!("  1. Edit slip.toml — set your domain, health check path, and resources");
        println!(
            "  2. Run `slip link --server <URL> --app {app_name}` to bind this repo to a slipd server"
        );
        println!("  3. Run `slip key --gh` to generate a deploy key and set it as a GitHub secret");
        println!("  4. Push to main to trigger your first deploy");
    }

    std::process::exit(output::OK);
}

// ─── Main entry point ──────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // Resolve server from flag > [remote] > default.
    let server = resolve_server(&cli.server);

    match cli.command {
        // ── Init ───────────────────────────────────────────────────────────
        Commands::Init { name, image, force } => {
            init_command(name, image, force, cli.json);
        }
        Commands::Link {
            server: link_server,
            app: link_app,
        } => {
            let token = resolve_token(cli.token);

            // Resolve app: --app flag > [app].name from slip.toml > error.
            let app = match link_app {
                Some(a) => a,
                None => {
                    // Try reading [app].name from slip.toml
                    let content = std::fs::read_to_string("slip.toml").ok();
                    let app_name = content
                        .as_ref()
                        .and_then(|c| c.parse::<toml::Value>().ok())
                        .and_then(|v| {
                            v.get("app")
                                .and_then(|a| a.get("name"))
                                .and_then(|n| n.as_str().map(|s| s.to_string()))
                        });
                    match app_name {
                        Some(name) if !name.is_empty() => name,
                        _ => output::fail(
                            output::USAGE,
                            "no app name",
                            "pass --app or set [app].name in slip.toml",
                        ),
                    }
                }
            };

            link_command(&link_server, &app, &token, cli.json).await?;
        }
        Commands::Key { app, rotate, gh } => {
            let token = resolve_token(cli.token);
            let app = resolve_app(app);
            key_command(&server, &token, &app, rotate, gh, cli.json).await?;
        }
        Commands::Apply {
            app,
            dry_run,
            no_redact,
        } => {
            let token = resolve_token(cli.token);
            let app = resolve_app(app);
            apply_command(&server, &token, &app, dry_run, no_redact, cli.json).await?;
        }
        Commands::Status { app } => {
            let token = resolve_token(cli.token);
            let app = app.or_else(|| {
                // Try [remote].app as a fallback
                resolve_remote()
                    .filter(|r| !r.app.is_empty())
                    .map(|r| r.app)
            });
            status_command(&server, &token, app.as_deref(), cli.json).await?;
        }
        Commands::Logs { app, since, follow } => {
            // Validate --since before requiring the token — fails fast on bad input.
            if let Some(ref s) = since
                && parse_duration(s).is_err()
            {
                output::fail(
                    output::USAGE,
                    &format!("invalid --since '{s}'"),
                    "use formats like 1h, 5m, 30s, 5m30s",
                );
            }
            let token = resolve_token(cli.token);
            logs_command(&server, &token, &app, since.as_deref(), follow, cli.json).await?;
        }
        Commands::Server(command) => match command {
            ServerCommands::Init {
                domain,
                tls,
                runtime,
                yes,
                force,
                no_systemd,
                skip_verify,
                from_file,
            } => {
                let force_all = force
                    .iter()
                    .any(|f| matches!(f, server_init::ForceTarget::All));
                let force_targets: Vec<server_init::ForceTarget> = force
                    .into_iter()
                    .filter(|f| !matches!(f, server_init::ForceTarget::All))
                    .collect();
                let opts = server_init::ServerInitOpts {
                    domain,
                    tls,
                    runtime,
                    yes,
                    force: force_targets,
                    force_all,
                    no_systemd,
                    skip_verify,
                    from_file,
                    json: cli.json,
                };
                server_init::run(opts);
            }
            ServerCommands::Status => {
                output::not_implemented("server status", cli.json);
            }
        },
        Commands::Services(command) => match command {
            ServicesCommands::List => {
                output::not_implemented("services list", cli.json);
            }
        },
        Commands::Registry(command) => match command {
            RegistryCommands::Login => {
                output::not_implemented("registry login", cli.json);
            }
        },
        Commands::Doctor {
            fix,
            dry_run,
            yes,
            timeout,
        } => {
            doctor_cmd::run(doctor_cmd::DoctorArgs {
                json: cli.json,
                fix,
                dry_run,
                yes,
                timeout,
                server: resolve_server(&cli.server),
                token: cli.token.clone(),
            })
            .await;
        }

        // ── Working commands ────────────────────────────────────────────────
        Commands::Deploy {
            app,
            tag,
            image,
            secret,
            wait,
            wait_timeout,
            apply,
            no_apply,
        } => {
            let effective_apply = apply && !no_apply;
            if effective_apply {
                let token = resolve_token(cli.token);
                let app_name = resolve_app(Some(app.clone()));
                apply_command(&server, &token, &app_name, false, false, cli.json).await?;
            }
            deploy(
                &server,
                &app,
                &tag,
                image,
                secret,
                wait,
                wait_timeout,
                cli.json,
            )
            .await?;
        }
        Commands::Rollback { app, to } => {
            let token = resolve_token(cli.token);
            rollback(&server, &token, &app, to).await?;
        }
        Commands::Validate { path, strict } => {
            let content = match std::fs::read_to_string(&path) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("✗ Failed to read '{}': {}", path, e);
                    std::process::exit(1);
                }
            };

            let base_dir = std::path::Path::new(&path)
                .parent()
                .unwrap_or(std::path::Path::new("."))
                .to_path_buf();

            let (config, result) =
                slip_core::validate::parse_and_validate(&content, &base_dir, strict);

            // Print warnings
            for warning in &result.warnings {
                println!("⚠ {}", warning);
            }

            // Print errors
            for error in &result.errors {
                eprintln!("✗ {}", error);
            }

            // Exit if errors
            if !result.is_valid() {
                std::process::exit(1);
            }

            // Print success summary
            if let Some(cfg) = config {
                println!("✓ Valid repo config");
                println!("  app:  {}", cfg.app.name);
                println!("  kind: {}", cfg.app.kind);

                if let Some(ref manifest) = cfg.app.manifest {
                    println!("  manifest: {}", manifest);
                }

                if let Some(ref preview) = cfg.preview {
                    println!(
                        "  preview: {}",
                        if preview.enabled {
                            "enabled"
                        } else {
                            "disabled"
                        }
                    );
                }
            }
        }
        Commands::Secrets(command) => {
            let token = resolve_token(cli.token);
            match command {
                SecretsCommands::List { app } => {
                    secrets_list(&server, &token, &app).await?;
                }
                SecretsCommands::Set { app, pairs } => {
                    secrets_set(&server, &token, &app, pairs).await?;
                }
                SecretsCommands::Rm { app, key } => {
                    secrets_rm(&server, &token, &app, &key).await?;
                }
            }
        }
        Commands::Previews(command) => {
            let token = resolve_token(cli.token);
            match command {
                PreviewsCommands::List { app } => {
                    previews_list(&server, &token, &app).await?;
                }
                PreviewsCommands::Teardown { app, preview, all } => {
                    previews_teardown(&server, &token, &app, preview, all).await?;
                }
            }
        }

        // ── Deprecated aliases ──────────────────────────────────────────────
        Commands::Apps(command) => {
            deprecation_warning();
            let token = resolve_token(cli.token);
            match command {
                AppsCommands::List => {
                    apps_list(&server, &token).await?;
                }
                AppsCommands::Add {
                    name,
                    image,
                    domain,
                    port,
                    secret,
                    env,
                } => {
                    apps_add(
                        &server,
                        &token,
                        AppsAddArgs {
                            name,
                            image,
                            domain,
                            port,
                            secret,
                            env,
                        },
                    )
                    .await?;
                }
                AppsCommands::Edit {
                    name,
                    image,
                    domain,
                    port,
                    secret,
                    env,
                } => {
                    apps_edit(
                        &server,
                        &token,
                        AppsEditArgs {
                            name,
                            image,
                            domain,
                            port,
                            secret,
                            env,
                        },
                    )
                    .await?;
                }
                AppsCommands::Rm { name, force } => {
                    apps_rm(&server, &token, &name, force).await?;
                }
            }
        }
    }

    Ok(())
}

// ─── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deploy_wait_exit_code_completed() {
        assert_eq!(deploy_wait_exit_code("completed"), output::OK);
    }

    #[test]
    fn test_deploy_wait_exit_code_failed() {
        assert_eq!(deploy_wait_exit_code("failed"), output::DEPLOY_FAILED);
    }

    #[test]
    fn test_deploy_wait_exit_code_in_progress() {
        assert_eq!(deploy_wait_exit_code("accepted"), -1);
        assert_eq!(deploy_wait_exit_code("pulling"), -1);
        assert_eq!(deploy_wait_exit_code("starting"), -1);
        assert_eq!(deploy_wait_exit_code("health_checking"), -1);
        assert_eq!(deploy_wait_exit_code("switching"), -1);
        assert_eq!(deploy_wait_exit_code("configuring"), -1);
        assert_eq!(deploy_wait_exit_code("stopping_old"), -1);
        assert_eq!(deploy_wait_exit_code("removing_route"), -1);
        assert_eq!(deploy_wait_exit_code("restarting_old"), -1);
    }

    #[test]
    fn test_is_terminal_deploy_status() {
        assert!(is_terminal_deploy_status("completed"));
        assert!(is_terminal_deploy_status("failed"));
        assert!(!is_terminal_deploy_status("accepted"));
        assert!(!is_terminal_deploy_status("pulling"));
        assert!(!is_terminal_deploy_status("starting"));
        assert!(!is_terminal_deploy_status("health_checking"));
        assert!(!is_terminal_deploy_status("switching"));
        assert!(!is_terminal_deploy_status("configuring"));
        assert!(!is_terminal_deploy_status("stopping_old"));
        assert!(!is_terminal_deploy_status("removing_route"));
        assert!(!is_terminal_deploy_status("restarting_old"));
        assert!(!is_terminal_deploy_status("unknown"));
    }

    #[test]
    fn test_parse_duration_seconds() {
        let d = parse_duration("30s").unwrap();
        assert_eq!(d.as_secs(), 30);
    }

    #[test]
    fn test_parse_duration_minutes() {
        let d = parse_duration("10m").unwrap();
        assert_eq!(d.as_secs(), 600);
    }

    #[test]
    fn test_parse_duration_hours() {
        let d = parse_duration("2h").unwrap();
        assert_eq!(d.as_secs(), 7200);
    }

    #[test]
    fn test_parse_duration_combined() {
        let d = parse_duration("5m30s").unwrap();
        assert_eq!(d.as_secs(), 330);
    }

    #[test]
    fn test_parse_duration_invalid_no_unit() {
        assert!(parse_duration("30").is_err());
    }

    #[test]
    fn test_parse_duration_invalid_char() {
        assert!(parse_duration("10x").is_err());
    }

    #[test]
    fn test_parse_duration_empty() {
        assert!(parse_duration("").is_err());
    }
}
