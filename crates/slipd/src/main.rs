use std::path::Path;
use std::sync::Arc;

use clap::Parser;
use slip_core::{AppState, build_router, load_config};

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

    let config_path = Path::new(&args.config);

    // ── Config check mode ────────────────────────────────────────────────────
    if args.check {
        tracing::info!("config check mode — validating and exiting");
        match load_config(config_path) {
            Ok((cfg, apps)) => {
                tracing::info!(
                    listen = %cfg.server.listen,
                    app_count = apps.len(),
                    "config is valid"
                );
            }
            Err(e) => {
                tracing::error!(error = %e, "config validation failed");
                std::process::exit(1);
            }
        }
        return Ok(());
    }

    // ── Load configuration ───────────────────────────────────────────────────
    let (slip_config, apps) = load_config(config_path).map_err(|e| {
        tracing::error!(error = %e, "failed to load configuration");
        anyhow::anyhow!("config error: {e}")
    })?;

    let listen_addr = slip_config.server.listen;

    tracing::info!(
        listen = %listen_addr,
        app_count = apps.len(),
        "config loaded"
    );

    // ── Build application state ──────────────────────────────────────────────
    let state = Arc::new(AppState {
        config: slip_config,
        apps,
        deploy_locks: dashmap::DashMap::new(),
    });

    // ── Build router ─────────────────────────────────────────────────────────
    let router = build_router(state);

    // TODO: connect to Docker  (SLIP-8)
    // TODO: connect to Caddy   (SLIP-7)
    // TODO: bootstrap (network, Caddy server block)
    // TODO: load persisted state
    // TODO: reconcile Caddy routes

    // ── Start HTTP server ────────────────────────────────────────────────────
    tracing::info!(%listen_addr, "slipd listening");
    let listener = tokio::net::TcpListener::bind(listen_addr).await?;
    axum::serve(listener, router).await?;

    Ok(())
}
