use std::collections::HashMap;

use anyhow::Context as _;
use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};

/// slip CLI — manage apps, deploys, secrets, and status.
#[derive(Parser)]
#[command(name = "slip", version, about)]
struct Cli {
    /// slipd server URL.
    #[arg(long, default_value = "http://localhost:7890", global = true)]
    server: String,

    /// Bearer token for management API (or set SLIP_TOKEN env var).
    #[arg(long, global = true)]
    token: Option<String>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Manage applications.
    #[command(subcommand)]
    Apps(AppsCommands),
    /// Show app or daemon status.
    Status {
        /// App name (omit for all apps).
        app: Option<String>,
    },
    /// Trigger a deploy.
    Deploy {
        /// App name.
        app: String,
        /// Image tag to deploy.
        tag: String,
    },
    /// Roll back to the previous version.
    Rollback {
        /// App name.
        app: String,
        /// Target tag to roll back to (defaults to previous tag).
        #[arg(long)]
        to: Option<String>,
    },
    /// Tail container logs.
    Logs {
        /// App name.
        app: String,
        /// Show logs since duration (e.g., "1h").
        #[arg(long)]
        since: Option<String>,
    },
    /// Initialize slip on a new server.
    Init,
    /// Validate a repo-side slip.toml config file.
    Validate {
        /// Path to slip.toml (default: ./slip.toml).
        #[arg(default_value = "slip.toml")]
        path: String,
        /// Also validate image references in pod manifests.
        #[arg(long)]
        strict: bool,
    },
}

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

// ─── HTTP client helpers ──────────────────────────────────────────────────────

fn create_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .connect_timeout(std::time::Duration::from_secs(5))
        .build()
        .expect("failed to create HTTP client")
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

// ─── Main entry point ──────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Apps(command) => {
            let token = cli.token.context(
                "SLIP_TOKEN is required for apps commands. Set --token or SLIP_TOKEN env var.",
            )?;
            match command {
                AppsCommands::List => {
                    apps_list(&cli.server, &token).await?;
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
                        &cli.server,
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
                        &cli.server,
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
                    apps_rm(&cli.server, &token, &name, force).await?;
                }
            }
        }
        Commands::Status { app } => {
            let target = app.as_deref().unwrap_or("all apps");
            println!("slip status {target} — not yet implemented (Phase 2)");
        }
        Commands::Deploy { app, tag } => {
            println!("slip deploy {app} {tag} — not yet implemented (Phase 2)");
        }
        Commands::Rollback { app, to } => {
            let token = cli.token.context(
                "SLIP_TOKEN is required for rollback. Set --token or SLIP_TOKEN env var.",
            )?;
            rollback(&cli.server, &token, &app, to).await?;
        }
        Commands::Logs { app, since } => {
            let since_str = since.as_deref().unwrap_or("now");
            println!("slip logs {app} --since {since_str} — not yet implemented (Phase 2)");
        }
        Commands::Init => {
            println!("slip init — not yet implemented (Phase 2)");
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
    }

    Ok(())
}
