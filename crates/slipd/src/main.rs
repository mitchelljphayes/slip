use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use clap::Parser;
use dashmap::DashMap;
use slip_core::preview::preview_reaper;
use slip_core::reconcile::reconcile_loop;
use slip_core::runtime::RuntimeBackend;
use slip_core::{
    AppState, CaddyClient, Db, DockerClient, HealthChecker, PodmanBackend, build_router,
    load_app_states, load_config, load_config_check, load_preview_states, parse_env_file,
    reconcile_preview_routes, verify_containers,
};
use tokio::sync::RwLock;

/// slip deploy daemon — receives webhooks, manages zero-downtime container deploys.
#[derive(Parser)]
#[command(name = "slipd", version, about)]
struct Args {
    /// Path to the slip configuration directory.
    #[arg(long, default_value = "/etc/slip")]
    config: String,

    /// Validate configuration and exit (warn-mode: unresolved ${ENV} → warning, exit 0).
    #[arg(long)]
    check: bool,

    /// Path to a systemd-style EnvironmentFile (`KEY=value`) to pre-populate
    /// the process env before resolving config `${VAR}` placeholders in
    /// `--check` mode. Use with `--check` so unresolved env vars clear.
    #[arg(long)]
    env_file: Option<String>,
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

    // ── --env-file without --check is a no-op (warn, don't error) ───────────
    // --env-file pre-populates env vars before resolving config placeholders,
    // which only matters in --check mode (the running daemon gets its env vars
    // from its systemd unit). Without --check, the file is parsed but never
    // used — flag that so an operator doesn't silently expect it to apply.
    if args.env_file.is_some() && !args.check {
        tracing::warn!(
            env_file = %args.env_file.as_deref().unwrap_or(""),
            "--env-file is ignored without --check (the running daemon reads env vars \
             from its systemd unit EnvironmentFile, not from --env-file); \
             did you mean to pass --check?"
        );
        eprintln!(
            "⚠ --env-file is ignored without --check (the running daemon reads env vars \
             from its systemd unit EnvironmentFile, not from --env-file); \
             did you mean to pass --check?"
        );
    }

    // ── Config check mode ────────────────────────────────────────────────────
    if args.check {
        // Pre-populate env from --env-file (systemd EnvironmentFile format) so
        // ${VAR} placeholders resolve. This lets `--check --env-file` fully
        // resolve and exit 0 clean, matching the running daemon's behaviour
        // (which gets the same vars from the systemd unit's EnvironmentFile).
        if let Some(env_file_path) = &args.env_file {
            match parse_env_file(Path::new(env_file_path)) {
                Ok(vars) => {
                    for (key, value) in vars {
                        // SAFETY: --check is a single-process invocation that
                        // exits before any concurrent work; env mutation is safe.
                        unsafe { std::env::set_var(&key, &value) };
                    }
                }
                Err(e) => {
                    eprintln!("✗ Failed to parse --env-file '{env_file_path}': {e}");
                    std::process::exit(1);
                }
            }
        }

        // Warn-mode: unresolved ${ENV} → warning, exit 0 (the running daemon
        // gets these from its systemd EnvironmentFile; a manual --check
        // without --env-file should warn, not error — FR §3.10).
        match load_config_check(config_path) {
            Ok((cfg, apps, warnings)) => {
                for w in &warnings {
                    eprintln!("⚠ {w} (set via EnvironmentFile or systemd unit)");
                }
                if warnings.is_empty() {
                    println!(
                        "✓ Configuration is valid ({} apps, listening on {})",
                        apps.len(),
                        cfg.server.listen
                    );
                } else {
                    println!(
                        "✓ Configuration is structurally valid ({} apps, listening on {}); \
                         {} unresolved env warning(s) — see above",
                        apps.len(),
                        cfg.server.listen,
                        warnings.len()
                    );
                }
            }
            Err(e) => {
                eprintln!("✗ Configuration validation failed: {e}");
                std::process::exit(1);
            }
        }
        return Ok(());
    }

    // ── Load configuration ───────────────────────────────────────────────────
    let (slip_config, mut apps) = load_config(config_path).map_err(|e| {
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

    match caddy.bootstrap().await {
        Ok(()) => {}
        Err(slip_core::CaddyError::ListenerConflict { server, listener }) => {
            // SLIP-88: Listener conflict is a configuration error, not a transient
            // failure. Exit with code 78 (EX_CONFIG — sysexits.h) so systemd's
            // Restart=on-failure does NOT restart (the unit sets
            // RestartPreventExitStatus=78). The user must fix their Caddyfile and
            // restart slipd manually. Using a distinct non-zero code (rather than
            // exit(0)) keeps the exit status semantically honest: a config error
            // is a failure, not a success.
            tracing::error!(
                server = %server,
                listener = %listener,
                "Caddyfile site block conflicts with slip's server. \
                 Remove site blocks from the Caddyfile — use [deploy] for the webhook \
                 and 'slip services expose' / static routes for other hosts."
            );
            std::process::exit(78);
        }
        Err(e) => {
            tracing::error!(error = %e, "failed to bootstrap Caddy");
            return Err(anyhow::anyhow!("Caddy bootstrap error: {e}"));
        }
    }

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

    // ── SLIP-87: Bootstrap deploy-webhook ingress ─────────────────────────────
    if let Some(deploy_cfg) = &slip_config.deploy {
        let upstream = slip_config.server.listen.to_string();
        let acme_email = slip_core::config::resolve_acme_email(&slip_config);
        let ca_url = slip_config.caddy.acme_ca.as_deref();
        let dns_config = slip_config.caddy.tls.as_ref();
        match caddy
            .bootstrap_deploy(
                deploy_cfg.domain.as_deref(),
                &deploy_cfg.tls,
                &upstream,
                acme_email.as_deref(),
                dns_config,
                ca_url,
            )
            .await
        {
            Ok(()) => {
                if let Some(ref domain) = deploy_cfg.domain {
                    tracing::info!(
                        domain = %domain,
                        tls = %deploy_cfg.tls,
                        "configured deploy-webhook ingress"
                    );
                }
            }
            Err(e) => {
                tracing::error!(error = %e, "failed to bootstrap deploy-webhook ingress");
                return Err(anyhow::anyhow!("deploy-webhook bootstrap error: {e}"));
            }
        }
    }

    tracing::info!("infrastructure bootstrap complete");

    // ── Load and reconcile persisted state ───────────────────────────────────
    let state_dir = slip_config.storage.path.join("state");
    let raw_states = load_app_states(&state_dir).unwrap_or_default();
    let verified_states = verify_containers(runtime.as_ref(), raw_states).await;

    // Reconcile app routes on startup using the new collect-and-continue
    // reconcile (per-route retry with backoff, structured app/route_id logging).
    // The old `reconcile_routes()` fail-fast bug (HE #6) is fixed by routing
    // through `reconcile_app_routes` instead.
    {
        let backoff = slip_core::reconcile::default_backoff();
        let summary =
            slip_core::reconcile::reconcile_app_routes(&caddy, &verified_states, &apps, &backoff)
                .await;
        if summary.routes_failed > 0 {
            tracing::warn!(
                ok = summary.routes_ok,
                failed = summary.routes_failed,
                total = summary.routes_total,
                "caddy route reconciliation completed with partial failures on startup (non-fatal)"
            );
        } else {
            tracing::info!(
                routes = summary.routes_total,
                "caddy routes reconciled on startup"
            );
        }
    }

    // ── Initialize SQLite deploy history ──────────────────────────────────────
    let db_path = slip_config.storage.path.join("slip.db");
    let db = Db::open(&db_path)
        .map_err(|e| anyhow::anyhow!("failed to open database at {}: {e}", db_path.display()))?;
    tracing::info!(path = %db_path.display(), "deploy history database opened");

    // ── Initialize service controller (SLIP-106 Part 3) ──────────────────────
    let installation_id = {
        let db_clone = db.clone();
        slip_core::services::ServiceRepository::ensure_installation_id_via_db(&db_clone)
            .map_err(|e| anyhow::anyhow!("failed to ensure installation_id: {e}"))?
    };

    let services_root = slip_config.storage.path.join("services");
    let runtime_clone = runtime.clone();

    #[cfg(target_os = "linux")]
    let service_storage = {
        match slip_core::services::ServiceStorage::new(&services_root) {
            Ok(s) => Some(s),
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    path = %services_root.display(),
                    "service storage initialization failed (services will be unavailable)"
                );
                None
            }
        }
    };

    let apps_snapshot = apps.clone();
    let usage = std::sync::Arc::new(slip_core::services::AppConfigUsageReader::new(
        std::sync::Arc::new(tokio::sync::RwLock::new(apps_snapshot)),
    ));

    let service_controller = std::sync::Arc::new(slip_core::services::ServiceController::new(
        db.clone(),
        runtime_clone,
        services_root.clone(),
        "slip".to_string(),
        installation_id,
        usage,
        #[cfg(target_os = "linux")]
        service_storage,
    ));

    // Check if runtime is rootful for service support.
    let svc_rootful = service_controller.is_rootful().await;
    if !svc_rootful {
        tracing::warn!(
            "service framework: runtime is not rootful — service operations will fail closed"
        );
    } else {
        tracing::info!("service framework: rootful runtime detected");
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

    // ── Migrate deprecated [app] secret from TOML to secrets store ──────────
    // This runs once at daemon startup.  The TOML field remains readable as a
    // fallback during the migration window.
    slip_core::config::migrate_app_secrets(&mut apps, &secrets_store);

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
        db,
        started_at: Utc::now(),
        preview_states,
        preview_locks: DashMap::new(),
        renew_locks: DashMap::new(),
        secrets_store,
        services: Some(service_controller.clone()),
    });

    // ── Populate in-memory deploy cache from SQLite ──────────────────────────
    match state.db.get_latest_deploys_per_app() {
        Ok(latest) => {
            for (app, ctx) in latest {
                state.deploys.insert(app, ctx);
            }
            tracing::info!(
                count = state.deploys.len(),
                "loaded deploy history from SQLite"
            );
        }
        Err(e) => {
            tracing::warn!(
                error = %e,
                "failed to load deploy history from SQLite (starting with empty cache)"
            );
        }
    }

    // ── Spawn background tasks ────────────────────────────────────────────────
    tokio::spawn(preview_reaper(state.clone()));

    // Service startup ensure (SLIP-106 Part 3) — bounded, non-blocking.
    // Runs a single ensure pass over all services after startup; the periodic
    // reconcile loop handles ongoing convergence.
    if let Some(ctrl) = &state.services {
        let ctrl_clone = ctrl.clone();
        tokio::spawn(async move {
            ctrl_clone.startup_ensure().await;
        });
        tracing::info!("service startup ensure spawned (bounded, non-blocking)");
    }

    // Caddy reconcile loop — self-heals routes, deploy-webhook, and TLS after
    // a Caddy restart or missed webhook. Safety net, not the primary update
    // path. Gated behind [caddy.reconcile] (default-on, harmless when no
    // drift). Cancelled via oneshot alongside the HTTP server's graceful
    // shutdown.
    let (reconcile_shutdown_tx, reconcile_shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let reconcile_interval = state.config.caddy.reconcile.interval;
    let reconcile_handle = tokio::spawn(reconcile_loop(
        state.clone(),
        reconcile_shutdown_rx,
        reconcile_interval,
    ));
    tracing::info!(interval = ?reconcile_interval, "caddy reconcile loop started");

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
        // Signal the reconcile loop to shut down before we stop the server.
        let _ = reconcile_shutdown_tx.send(());
        tracing::info!("shutdown signal received, stopping server");
    };

    let listener = tokio::net::TcpListener::bind(listen_addr).await?;
    axum::serve(listener, router)
        .with_graceful_shutdown(shutdown_signal)
        .await?;

    // Wait for the reconcile loop to finish (bounded — it should exit promptly
    // once the shutdown oneshot fires, but we cap at 10s to avoid hanging).
    match tokio::time::timeout(Duration::from_secs(10), reconcile_handle).await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => tracing::warn!(error = %e, "reconcile loop task panicked"),
        Err(_) => tracing::warn!("reconcile loop did not shut down within 10s, dropping"),
    }

    tracing::info!("slipd stopped");

    Ok(())
}
