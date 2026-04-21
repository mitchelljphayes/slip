use std::path::Path;
use std::sync::Arc;

use chrono::Utc;
use clap::Parser;
use dashmap::DashMap;
use slip_core::preview::preview_reaper;
use slip_core::runtime::RuntimeBackend;
use slip_core::{
    AppState, CaddyClient, DockerClient, HealthChecker, PodmanBackend, build_router,
    load_app_states, load_config, load_preview_states, reconcile_preview_routes, reconcile_routes,
    verify_containers,
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

    // ── Connect to container runtime ─────────────────────────────────────────
    let runtime: Arc<dyn RuntimeBackend> = match slip_config.runtime.backend.as_str() {
        "docker" => Arc::new(DockerClient::new().map_err(|e| {
            tracing::error!(error = %e, "failed to connect to Docker daemon");
            anyhow::anyhow!("Docker connection error: {e}")
        })?),
        "podman" => Arc::new(PodmanBackend::new().map_err(|e| {
            tracing::error!(error = %e, "failed to connect to Podman");
            anyhow::anyhow!("Podman connection error: {e}")
        })?),
        "auto" => {
            // Try Podman first, then Docker
            if let Ok(podman) = PodmanBackend::new() {
                if podman.ping().await.is_ok() {
                    tracing::info!("auto-detected Podman runtime");
                    Arc::new(podman)
                } else if let Ok(docker) = DockerClient::new() {
                    tracing::info!("auto-detected Docker runtime");
                    Arc::new(docker)
                } else {
                    tracing::error!("no container runtime found (tried Podman and Docker)");
                    return Err(anyhow::anyhow!(
                        "no container runtime found (tried Podman and Docker)"
                    ));
                }
            } else if let Ok(docker) = DockerClient::new() {
                tracing::info!("auto-detected Docker runtime");
                Arc::new(docker)
            } else {
                tracing::error!("no container runtime found");
                return Err(anyhow::anyhow!("no container runtime found"));
            }
        }
        other => {
            return Err(anyhow::anyhow!(
                "unknown runtime backend '{other}': valid values are \"docker\", \"podman\", \"auto\""
            ));
        }
    };

    // Verify runtime is reachable (fail fast if not)
    runtime.ping().await.map_err(|e| {
        tracing::error!(error = %e, "runtime daemon is not responding");
        anyhow::anyhow!("runtime ping error: {e}")
    })?;

    tracing::info!(backend = runtime.name(), "runtime connected");

    // ── Connect to Caddy ─────────────────────────────────────────────────────
    let caddy = CaddyClient::new(slip_config.caddy.admin_api.clone());

    // ── Bootstrap infrastructure (before state reconciliation) ───────────────
    runtime.ensure_network("slip").await.map_err(|e| {
        tracing::error!(error = %e, "failed to create network");
        anyhow::anyhow!("network error: {e}")
    })?;

    caddy.bootstrap().await.map_err(|e| {
        tracing::error!(error = %e, "failed to bootstrap Caddy");
        anyhow::anyhow!("Caddy bootstrap error: {e}")
    })?;

    // ── Configure TLS for preview wildcard certificates ────────────────────────
    if let (Some(preview_config), Some(tls_config)) = (&slip_config.preview, &slip_config.caddy.tls)
    {
        match caddy
            .configure_tls(&preview_config.domain, tls_config)
            .await
        {
            Ok(()) => {
                tracing::info!(
                    domain = %preview_config.domain,
                    "configured TLS for wildcard preview certificates"
                );
            }
            Err(e) => {
                tracing::error!(error = %e, "failed to configure TLS for preview domain");
                return Err(anyhow::anyhow!("TLS configuration error: {e}"));
            }
        }
    } else if slip_config.preview.is_some() && slip_config.caddy.tls.is_none() {
        tracing::warn!(
            "preview deployments configured but no TLS config found; \
             preview domains will use Caddy's default HTTP-01 challenge"
        );
    }

    tracing::info!("infrastructure bootstrap complete");

    // ── Load and reconcile persisted state ───────────────────────────────────
    let state_dir = slip_config.storage.path.join("state");
    let raw_states = load_app_states(&state_dir).unwrap_or_default();
    let verified_states = verify_containers(runtime.as_ref(), raw_states).await;

    if let Err(e) = reconcile_routes(&caddy, &verified_states, &apps).await {
        tracing::warn!(error = %e, "caddy route reconciliation failed on startup (non-fatal)");
    }

    // ── Load persisted preview states ────────────────────────────────────────
    let persisted_previews = load_preview_states(&state_dir);
    if !persisted_previews.is_empty() {
        tracing::info!(
            count = persisted_previews.len(),
            "loaded persisted preview states"
        );
    }
    let preview_states: Arc<DashMap<String, slip_core::PreviewState>> =
        Arc::new(persisted_previews.into_iter().collect());

    // ── Reconcile preview Caddy routes ───────────────────────────────────────
    if let Err(e) = reconcile_preview_routes(&caddy, &preview_states).await {
        tracing::warn!(
            error = %e,
            "preview caddy route reconciliation failed on startup (non-fatal)"
        );
    }

    // ── Build application state ──────────────────────────────────────────────
    let secrets_store = slip_core::SecretsStore::new(slip_config.storage.path.join("secrets"))
        .map_err(|e| {
            tracing::error!(error = %e, "failed to initialize secrets store");
            anyhow::anyhow!("secrets store error: {e}")
        })?;

    let state = Arc::new(AppState {
        config: slip_config,
        apps: RwLock::new(apps),
        config_dir: config_path.to_path_buf(),
        deploy_locks: DashMap::new(),
        runtime,
        caddy,
        health: HealthChecker::new(),
        app_states: RwLock::new(verified_states),
        deploys: DashMap::new(),
        started_at: Utc::now(),
        preview_states,
        preview_locks: DashMap::new(),
        secrets_store,
    });

    // ── Spawn background tasks ────────────────────────────────────────────────
    tokio::spawn(preview_reaper(state.clone()));

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
