use clap::{Parser, Subcommand};

/// slip CLI — manage apps, deploys, secrets, and status.
#[derive(Parser)]
#[command(name = "slip", version, about)]
struct Cli {
    /// slipd server URL.
    #[arg(long, default_value = "http://localhost:7890", global = true)]
    server: String,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// List registered apps.
    Apps,
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
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Apps => {
            println!("slip apps — not yet implemented (Phase 2)");
        }
        Commands::Status { app } => {
            let target = app.as_deref().unwrap_or("all apps");
            println!("slip status {target} — not yet implemented (Phase 2)");
        }
        Commands::Deploy { app, tag } => {
            println!("slip deploy {app} {tag} — not yet implemented (Phase 2)");
        }
        Commands::Rollback { app } => {
            println!("slip rollback {app} — not yet implemented (Phase 2)");
        }
        Commands::Logs { app, since } => {
            let since_str = since.as_deref().unwrap_or("now");
            println!("slip logs {app} --since {since_str} — not yet implemented (Phase 2)");
        }
        Commands::Init => {
            println!("slip init — not yet implemented (Phase 2)");
        }
    }

    Ok(())
}
