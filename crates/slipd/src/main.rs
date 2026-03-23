use clap::Parser;

/// slip deploy daemon — receives webhooks, manages zero-downtime container deploys.
#[derive(Parser)]
#[command(name = "slipd", version, about)]
struct Args {
    /// Path to the slip configuration directory.
    #[arg(long, default_value = "/etc/slip")]
    config: String,

    /// Validate configuration and exit.
    #[arg(long)]
    check: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    // Initialize structured logging
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    tracing::info!(
        config_path = %args.config,
        version = env!("CARGO_PKG_VERSION"),
        "slipd starting"
    );

    if args.check {
        tracing::info!("config check mode — validating and exiting");
        // TODO: load and validate config, exit
        return Ok(());
    }

    // TODO: load config
    // TODO: connect to Docker
    // TODO: connect to Caddy
    // TODO: bootstrap (network, Caddy server block)
    // TODO: load persisted state
    // TODO: reconcile Caddy routes
    // TODO: start HTTP server

    tracing::info!("slipd is not yet implemented — see SLIP-2 through SLIP-11");

    Ok(())
}
