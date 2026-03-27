use std::path::Path;
use std::sync::Arc;

use chrono::Utc;
use clap::Parser;
use dashmap::DashMap;
use slip_core::{
    AppState, CaddyClient, DockerClient, HealthChecker, build_router, load_app_states, load_config,
    reconcile_routes, verify_containers,
};
use tokio::sync::RwLock;

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
        match load_config(config_path) {
            Ok((cfg, apps)) => {
                println!(
                    "✓ Configuration is valid ({} apps, listening on {})",
                    apps.len(),
                    cfg.server.listen
                );
            }
            Err(e) => {
                eprintln!("✗ Configuration validation failed: {e}");
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

    // ── Connect to Docker ────────────────────────────────────────────────────
    let docker = DockerClient::new().map_err(|e| {
        tracing::error!(error = %e, "failed to connect to Docker daemon");
        anyhow::anyhow!("Docker connection error: {e}")
    })?;

    // Verify Docker is reachable (fail fast if not)
    docker.ping().await.map_err(|e| {
        tracing::error!(error = %e, "Docker daemon is not responding");
        anyhow::anyhow!("Docker ping error: {e}")
    })?;

    // ── Connect to Caddy ─────────────────────────────────────────────────────
    let caddy = CaddyClient::new(slip_config.caddy.admin_api.clone());

    // ── Bootstrap infrastructure (before state reconciliation) ───────────────
    docker.ensure_network("slip").await.map_err(|e| {
        tracing::error!(error = %e, "failed to create Docker network");
        anyhow::anyhow!("Docker network error: {e}")
    })?;

    caddy.bootstrap().await.map_err(|e| {
        tracing::error!(error = %e, "failed to bootstrap Caddy");
        anyhow::anyhow!("Caddy bootstrap error: {e}")
    })?;

    tracing::info!("infrastructure bootstrap complete");

    // ── Load and reconcile persisted state ───────────────────────────────────
    let state_dir = slip_config.storage.path.join("state");
    let raw_states = load_app_states(&state_dir).unwrap_or_default();
    let verified_states = verify_containers(&docker, raw_states).await;

    if let Err(e) = reconcile_routes(&caddy, &verified_states, &apps).await {
        tracing::warn!(error = %e, "caddy route reconciliation failed on startup (non-fatal)");
    }

    // ── Build application state ──────────────────────────────────────────────
    let state = Arc::new(AppState {
        config: slip_config,
        apps,
        deploy_locks: DashMap::new(),
        docker,
        caddy,
        health: HealthChecker::new(),
        app_states: RwLock::new(verified_states),
        deploys: DashMap::new(),
        started_at: Utc::now(),
    });

    // ── Build router ─────────────────────────────────────────────────────────
    let router = build_router(state);

    // ── Start HTTP server with graceful shutdown ───────────────────────────────
    tracing::info!(%listen_addr, "slipd listening");

    let shutdown_signal = async {
        let ctrl_c = async {
            tokio::signal::ctrl_c()
                .await
                .expect("failed to install Ctrl+C handler");
        };

        #[cfg(unix)]
        let terminate = async {
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .expect("failed to install signal handler")
                .recv()
                .await;
        };

        #[cfg(not(unix))]
        let terminate = std::future::pending::<()>();

        tokio::select! {
            _ = ctrl_c => {},
            _ = terminate => {},
        }
        tracing::info!("shutdown signal received, stopping server");
    };

    let listener = tokio::net::TcpListener::bind(listen_addr).await?;
    axum::serve(listener, router)
        .with_graceful_shutdown(shutdown_signal)
        .await?;

    tracing::info!("slipd stopped");

    Ok(())
}
