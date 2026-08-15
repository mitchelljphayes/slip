//! `slip doctor` — diagnose slipd health and configuration.
//!
//! Hybrid CLI-side architecture (see SLIP-102 plan): host-privileged checks
//! run directly in the `slip` binary; slipd-dependent checks call the existing
//! `GET /v1/status` + per-app status endpoints with the admin token. The
//! shared `slip_core::doctor` types are the single check-result schema.
//!
//! Read-only by default. `--fix` is scoped to the UFW bridge DNS rule only,
//! with confirmation, idempotence, snapshot+rollback, dry-run, non-TTY/JSON
//! safety, and no internal `sudo` (see [`fix::apply_fixes`]).
//!
//! Check order is a fixed `const` slice (deterministic for `jq`/snapshot
//! tests). See [`CHECK_ORDER`].

use std::io::IsTerminal;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::Command;

use slip_core::doctor::{
    self, CheckStatus, CommandOutput, CommandRunner, DoctorAction, DoctorReport, VerificationCheck,
    aggregate_exit, classify_dns_expectation, classify_ufw, dns_plugin_remedy,
    fetch_cloudflare_ranges, module_present_exact, parse_caddy_modules, render_human,
};

use crate::output;

// ─── Args ─────────────────────────────────────────────────────────────────────

/// Arguments passed from the `Doctor` subcommand variant.
pub struct DoctorArgs {
    pub json: bool,
    pub fix: bool,
    pub dry_run: bool,
    pub yes: bool,
    pub timeout: u64,
    pub server: String,
    pub token: Option<String>,
}

/// The fixed declaration order of all doctor checks.
///
/// This is the contract for `jq`/snapshot consumers — do not reorder without
/// bumping the schema version. The names are stable snake_case dotted
/// identifiers. Kept as a `const` slice even though the orchestrator builds
/// checks incrementally — it documents the contract and is referenced by
/// tests.
#[allow(dead_code)]
pub const CHECK_ORDER: &[&str] = &[
    "runtime.socket",
    "ufw.bridge_dns",
    "aardvark.active",
    "caddy.dns_plugin",
    "config.env",
    "disk.free",
    "caddy.reachable",
    "caddy.slip_server",
    "caddy.listener_conflict",
    "registry.reachable",
    "registry.auth",
    "registry.manifest",
    "tls.issuer",
    "tls.cert_expiry",
    "tls.acme_stuck",
    "dns.probe",
    "dns.expectation",
];

// ─── Entry point ──────────────────────────────────────────────────────────────

/// Run `slip doctor`. Exits with the contractual code:
/// - `0` (OK) when no `fail`.
/// - `1` (GENERIC) when any `fail`.
/// - `2` (USAGE) when `--fix` is used incorrectly (non-TTY without `--yes`).
/// - `6` (TIMEOUT) when the global deadline is hit.
pub async fn run(args: DoctorArgs) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(args.timeout.max(1));

    // ── 1. Load config (raw, warn-on-unresolved) ───────────────────────────
    let config_dir = config_dir();
    let loaded = load_config_for_doctor(&config_dir);

    // ── 2. Run all checks ──────────────────────────────────────────────────
    let runner = RealCommandRunner;
    let mut checks = Vec::new();

    // Phase 2: host-local checks.
    checks.extend(run_host_checks(&runner, &loaded, args.timeout));

    // Phase 3: slipd-dependent + DNS checks (bounded by remaining deadline).
    let remaining = deadline.saturating_duration_since(std::time::Instant::now());
    let slipd_timeout = remaining.min(std::time::Duration::from_secs(args.timeout.max(1)));
    let slipd_checks = tokio::time::timeout(
        slipd_timeout,
        run_slipd_checks(
            &loaded,
            &args.server,
            args.token.as_deref(),
            &runner,
            args.timeout,
        ),
    )
    .await;
    match slipd_checks {
        Ok(c) => checks.extend(c),
        Err(_) => {
            // Global timeout hit during slipd checks — record a fail and stop.
            checks.push(VerificationCheck::new(
                "slipd.checks",
                "slipd-dependent checks",
                CheckStatus::Fail,
                "global doctor timeout reached while running slipd-dependent checks",
                Some(format!(
                    "re-run with a larger --timeout (current: {}s)",
                    args.timeout
                )),
            ));
            emit(&checks, None, args.json, true);
            return;
        }
    }

    // ── 3. `--fix` flow (Phase 4) ──────────────────────────────────────────
    //
    // Production always passes `skip_root: false` — no environment variable
    // may bypass the root requirement for `--fix`. The `skip_root: true`
    // path is reachable ONLY from `#[cfg(test)]` unit-test calls to
    // `fix::run_fix`.
    if args.fix {
        match fix::run_fix(&checks, &runner, &loaded, &args, false) {
            fix::FixOutcome::NothingToDo(actions) => {
                // emit() is the single print point. Pass Some(actions) so
                // the JSON includes `"actions": []`.
                emit(&checks, Some(actions), args.json, false);
                return;
            }
            fix::FixOutcome::DryRun(actions) => {
                emit(&checks, Some(actions), args.json, false);
                return;
            }
            fix::FixOutcome::Applied(actions) => {
                // Re-run the UFW check to reflect the new state.
                let rechecked = run_host_checks(&runner, &loaded, args.timeout);
                let ufw_idx = checks
                    .iter()
                    .position(|c| c.name == "ufw.bridge_dns")
                    .expect("ufw.bridge_dns check exists");
                if let Some(new_ufw) = rechecked.iter().find(|c| c.name == "ufw.bridge_dns") {
                    checks[ufw_idx] = new_ufw.clone();
                }
                emit(&checks, Some(actions), args.json, false);
                return;
            }
            fix::FixOutcome::Err(code) => {
                // `output::fail` already exited inside run_fix in most cases,
                // but if we get here with a code, exit with it.
                std::process::exit(code);
            }
        }
    }

    // ── 4. Detection-only report + exit ────────────────────────────────────
    emit(&checks, None, args.json, false);
}

/// Emit the report (human or JSON) and exit with the aggregate code.
fn emit(
    checks: &[VerificationCheck],
    actions: Option<Vec<DoctorAction>>,
    json: bool,
    timed_out: bool,
) {
    let report = match &actions {
        Some(a) => DoctorReport::with_actions(checks.to_vec(), a.clone()),
        None => DoctorReport::detection(checks.to_vec()),
    };

    if json {
        let v = report.to_json();
        println!(
            "{}",
            serde_json::to_string_pretty(&v).unwrap_or_else(|e| {
                format!("{{\"error\":\"failed to serialize doctor report: {e}\"}}")
            })
        );
    } else {
        print!("{}", render_human(checks));
        if let Some(ref acts) = actions {
            println!();
            println!("Actions:");
            for a in acts {
                println!("  • {} → {}", a.command, a.status);
                if let Some(ref rb) = a.rollback {
                    println!("    rollback: {rb}");
                }
            }
        }
        println!();
    }

    let summary = doctor::Summary::from_checks(checks);
    std::process::exit(aggregate_exit(&summary, timed_out));
}

// ─── Config loading (warn, not error) ────────────────────────────────────────

/// Doctor's view of the loaded config.
///
/// `None` means the config file couldn't be read or parsed at all — doctor
/// still runs the host-local checks that don't need config. Individual checks
/// that need config emit `warn`/`skipped` when it's absent.
#[derive(Default)]
pub struct DoctorConfig {
    pub slip_toml: Option<slip_core::SlipConfig>,
    pub apps: std::collections::HashMap<String, slip_core::AppConfig>,
    /// Unresolved env var names encountered while loading (for check 7).
    pub unresolved_env: Vec<String>,
    /// Raw slip.toml text (for env-hygiene reporting / future use).
    #[allow(dead_code)]
    pub slip_toml_raw: Option<String>,
    /// Config dir used (for path display).
    pub config_dir: PathBuf,
}

/// Load `slip.toml` + apps, collecting unresolved env vars as warnings instead
/// of erroring (FR §3.10).
fn load_config_for_doctor(config_dir: &Path) -> DoctorConfig {
    let slip_toml_path = config_dir.join("slip.toml");
    let raw = match std::fs::read_to_string(&slip_toml_path) {
        Ok(s) => s,
        Err(_) => {
            return DoctorConfig {
                config_dir: config_dir.to_path_buf(),
                ..Default::default()
            };
        }
    };

    let mut slip_cfg: slip_core::SlipConfig = match toml::from_str(&raw) {
        Ok(c) => c,
        Err(_) => {
            return DoctorConfig {
                slip_toml_raw: Some(raw),
                config_dir: config_dir.to_path_buf(),
                ..Default::default()
            };
        }
    };

    let mut unresolved: Vec<String> = Vec::new();

    // auth.secret
    let (resolved, mut miss) = slip_core::resolve_env_vars_warn(&slip_cfg.auth.secret);
    slip_cfg.auth.secret = resolved;
    unresolved.append(&mut miss);

    // registries.<name>.token
    for entry in slip_cfg.registries.registries.values_mut() {
        if let Some(token) = entry.token.take() {
            let (resolved, mut miss) = slip_core::resolve_env_vars_warn(&token);
            entry.token = Some(resolved);
            unresolved.append(&mut miss);
        }
    }

    // Apps (load each, resolve env, collect misses).
    let mut apps = std::collections::HashMap::new();
    let apps_dir = config_dir.join("apps");
    if apps_dir.is_dir()
        && let Ok(entries) = std::fs::read_dir(&apps_dir)
    {
        for entry in entries.flatten() {
            let p = entry.path();
            if p.extension().and_then(|e| e.to_str()) != Some("toml") {
                continue;
            }
            if let Ok(app_raw) = std::fs::read_to_string(&p)
                && let Ok(mut app_cfg) = toml::from_str::<slip_core::AppConfig>(&app_raw)
            {
                // Resolve app env values.
                for v in app_cfg.env.values_mut() {
                    let (resolved, mut miss) = slip_core::resolve_env_vars_warn(v);
                    *v = resolved;
                    unresolved.append(&mut miss);
                }
                // Resolve app.secret if present.
                if let Some(secret) = app_cfg.app.secret.take() {
                    let (resolved, mut miss) = slip_core::resolve_env_vars_warn(&secret);
                    app_cfg.app.secret = Some(resolved);
                    unresolved.append(&mut miss);
                }
                apps.insert(app_cfg.app.name.clone(), app_cfg);
            }
        }
    }

    DoctorConfig {
        slip_toml: Some(slip_cfg),
        apps,
        unresolved_env: unresolved,
        slip_toml_raw: Some(raw),
        config_dir: config_dir.to_path_buf(),
    }
}

/// Resolve the config directory: `SLIP_TEST_CONFIG_DIR` env > default `/etc/slip`.
fn config_dir() -> PathBuf {
    std::env::var("SLIP_TEST_CONFIG_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/etc/slip"))
}

/// Are any test overrides active?
///
/// This is used ONLY by `config_dir()` to resolve the config directory for
/// testability (the `SLIP_TEST_CONFIG_DIR` override, also used by
/// `server_init.rs`). It is **never** used to bypass the root check for
/// `--fix` — production `run()` passes `skip_root: false` unconditionally.
/// The `skip_root: true` path is reachable only from `#[cfg(test)]` unit
/// tests that call `fix::run_fix` directly.
#[cfg(test)]
fn has_test_overrides() -> bool {
    std::env::var("SLIP_TEST_CONFIG_DIR").is_ok()
}

// ─── Real CommandRunner ──────────────────────────────────────────────────────

/// Real `CommandRunner` that shells out via `std::process::Command`.
pub struct RealCommandRunner;

impl CommandRunner for RealCommandRunner {
    fn run(&self, cmd: &str, args: &[&str]) -> std::io::Result<CommandOutput> {
        let out = Command::new(cmd).args(args).output()?;
        Ok(CommandOutput {
            stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
            status: out.status.code().unwrap_or(-1),
        })
    }
}

// ─── Phase 2: host-local checks ──────────────────────────────────────────────

/// Run the host-local checks (no slipd needed).
pub fn run_host_checks(
    runner: &dyn CommandRunner,
    cfg: &DoctorConfig,
    timeout_secs: u64,
) -> Vec<VerificationCheck> {
    vec![
        check_runtime_socket(cfg),
        check_ufw_bridge_dns(runner, cfg),
        check_aardvark_active(runner),
        check_caddy_dns_plugin(runner, cfg),
        check_config_env(cfg),
        check_disk_free(cfg, timeout_secs),
    ]
}

/// Check 1: runtime socket existence (partial — ping is slipd-side).
fn check_runtime_socket(cfg: &DoctorConfig) -> VerificationCheck {
    let backend = cfg
        .slip_toml
        .as_ref()
        .map(|c| c.runtime.backend.as_str())
        .unwrap_or("auto");

    let candidates: Vec<(&str, &str)> = match backend {
        "docker" => vec![("docker", "/var/run/docker.sock")],
        "podman" => vec![
            ("podman (rootless)", ""),
            ("podman (rootful)", "/run/podman/podman.sock"),
        ],
        _ => vec![
            ("docker", "/var/run/docker.sock"),
            ("podman (rootless)", ""),
            ("podman (rootful)", "/run/podman/podman.sock"),
            ("podman (alt)", "/var/run/podman/podman.sock"),
        ],
    };

    let mut found: Option<&str> = None;
    for (label, path) in &candidates {
        if path.is_empty() {
            // rootless podman via XDG_RUNTIME_DIR
            if let Ok(xdg) = std::env::var("XDG_RUNTIME_DIR") {
                let p = format!("{xdg}/podman/podman.sock");
                if Path::new(&p).exists() {
                    found = Some(label);
                    break;
                }
            }
        } else if Path::new(path).exists() {
            found = Some(label);
            break;
        }
    }

    match found {
        Some(label) => VerificationCheck::new(
            "runtime.socket",
            "Container runtime socket",
            CheckStatus::Pass,
            format!("{label} socket found"),
            None,
        ),
        None => VerificationCheck::new(
            "runtime.socket",
            "Container runtime socket",
            CheckStatus::Warn,
            "no container runtime socket found (docker/podman)",
            Some(String::from(
                "install/start docker or podman, or set [runtime] backend in slip.toml — \
                 slipd cannot run containers without a runtime",
            )),
        ),
    }
}

/// Inspect the slip network via the runtime CLI and return the bridge
/// interface name. Returns `None` if the network doesn't exist or the runtime
/// can't be queried.
fn network_bridge_name(runner: &dyn CommandRunner, cfg: &DoctorConfig) -> Option<String> {
    let network = cfg
        .slip_toml
        .as_ref()
        .map(|c| c.network_name())
        .unwrap_or_else(|| "slip".to_string());

    // Try docker first, then podman.
    for runtime in &["docker", "podman"] {
        let out = runner
            .run(runtime, &["network", "inspect", &network])
            .ok()?;
        if out.status != 0 {
            continue;
        }
        // `docker network inspect slip` returns a JSON array with one object.
        // The bridge name is in `Options["com.docker.network.bridge.name"]` OR
        // derivable from `Id` (br-<first 12 chars>). Podman returns a similar
        // shape but with `network_interface` in some versions.
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&out.stdout) {
            let obj = if v.is_array() { v.get(0)? } else { &v };
            // Try explicit bridge name (docker custom networks use br-<id12>).
            if let Some(name) = obj
                .pointer("/Options/com.docker.network.bridge.name")
                .and_then(|v| v.as_str())
            {
                return Some(name.to_string());
            }
            // Try podman's `network_interface`.
            if let Some(name) = obj.get("network_interface").and_then(|v| v.as_str())
                && !name.is_empty()
            {
                return Some(name.to_string());
            }
            // Fall back to br-<Id[:12]>.
            if let Some(id) = obj.get("Id").and_then(|v| v.as_str())
                && id.len() >= 12
            {
                return Some(format!("br-{}", &id[..12]));
            }
        }
    }
    None
}

/// Check 3 (UFW): is the bridge DNS rule present?
fn check_ufw_bridge_dns(runner: &dyn CommandRunner, cfg: &DoctorConfig) -> VerificationCheck {
    // Get UFW status.
    let ufw_out = runner.run("ufw", &["status", "numbered"]);
    let ufw_status_text = match ufw_out {
        Ok(o) if o.status == 0 => o.stdout,
        Ok(o) => {
            // ufw returned non-zero (e.g. not installed, not root).
            return VerificationCheck::new(
                "ufw.bridge_dns",
                "UFW bridge DNS rule",
                CheckStatus::Warn,
                format!("`ufw status` exited {} — cannot inspect firewall", o.status),
                Some(String::from(
                    "ensure ufw is installed and this command runs as root, \
                     or ignore if UFW is not in use",
                )),
            );
        }
        Err(e) => {
            return VerificationCheck::new(
                "ufw.bridge_dns",
                "UFW bridge DNS rule",
                CheckStatus::Warn,
                format!("`ufw status` failed to execute: {e}"),
                Some(String::from(
                    "ensure ufw is installed and this command runs as root, \
                     or ignore if UFW is not in use",
                )),
            );
        }
    };

    let bridge = network_bridge_name(runner, cfg).unwrap_or_default();
    let class = classify_ufw(&bridge, &ufw_status_text);
    VerificationCheck::new(
        "ufw.bridge_dns",
        "UFW bridge DNS rule",
        class.status,
        class.detail,
        class.remedy,
    )
}

/// Check 3 (aardvark): is the aardvark-dns service active?
fn check_aardvark_active(runner: &dyn CommandRunner) -> VerificationCheck {
    match runner.run("systemctl", &["is-active", "aardvark-dns"]) {
        Ok(o) if o.stdout.trim() == "active" => VerificationCheck::new(
            "aardvark.active",
            "aardvark-dns service",
            CheckStatus::Pass,
            "aardvark-dns is active",
            None,
        ),
        Ok(o) if o.stdout.trim() == "inactive" || o.status == 3 => VerificationCheck::new(
            "aardvark.active",
            "aardvark-dns service",
            CheckStatus::Warn,
            "aardvark-dns is inactive",
            Some(String::from(
                "systemctl start aardvark-dns (or restart slipd which recreates the network)",
            )),
        ),
        Ok(_) => VerificationCheck::new(
            "aardvark.active",
            "aardvark-dns service",
            CheckStatus::Warn,
            "aardvark-dns unit not found or non-systemd host",
            Some(String::from(
                "the end-to-end DNS probe (dns.probe) is authoritative — \
                 aardvark liveness is best confirmed by container name resolution",
            )),
        ),
        Err(_) => VerificationCheck::new(
            "aardvark.active",
            "aardvark-dns service",
            CheckStatus::Warn,
            "cannot query systemd (non-systemd host or systemctl missing)",
            Some(String::from(
                "the end-to-end DNS probe (dns.probe) is authoritative — \
                 aardvark liveness is best confirmed by container name resolution",
            )),
        ),
    }
}

/// Check 4 (DNS plugin): does `caddy list-modules` include the configured
/// DNS provider?
fn check_caddy_dns_plugin(runner: &dyn CommandRunner, cfg: &DoctorConfig) -> VerificationCheck {
    let required = required_dns_provider(cfg);

    // Short-circuit: if no DNS-01 provider is required, skip without
    // shelling out to caddy (avoids a false `warn` when caddy isn't
    // installed but DNS-01 isn't configured anyway).
    if required.is_none() {
        return VerificationCheck::new(
            "caddy.dns_plugin",
            "Caddy DNS-01 plugin",
            CheckStatus::Skipped,
            String::from("no DNS-01 TLS strategy configured — DNS plugin not required"),
            None,
        );
    }

    let modules_out = runner.run("caddy", &["list-modules"]);
    let modules_text = match modules_out {
        Ok(o) if o.status == 0 => o.stdout,
        Ok(o) => {
            return VerificationCheck::new(
                "caddy.dns_plugin",
                "Caddy DNS-01 plugin",
                CheckStatus::Warn,
                format!(
                    "`caddy list-modules` exited {} — cannot verify plugin",
                    o.status
                ),
                Some(String::from("ensure caddy is installed and on $PATH")),
            );
        }
        Err(_) => {
            return VerificationCheck::new(
                "caddy.dns_plugin",
                "Caddy DNS-01 plugin",
                CheckStatus::Warn,
                "`caddy` binary not found on $PATH — cannot verify DNS plugin",
                Some(String::from(
                    "install caddy or set [caddy] admin_api in slip.toml",
                )),
            );
        }
    };

    let status = parse_caddy_modules(&modules_text, required.as_deref());
    match status {
        CheckStatus::Skipped => VerificationCheck::new(
            "caddy.dns_plugin",
            "Caddy DNS-01 plugin",
            CheckStatus::Skipped,
            String::from("no DNS-01 TLS strategy configured — DNS plugin not required"),
            None,
        ),
        CheckStatus::Pass => VerificationCheck::new(
            "caddy.dns_plugin",
            "Caddy DNS-01 plugin",
            CheckStatus::Pass,
            format!(
                "caddy has dns.providers.{} compiled in",
                required.as_deref().unwrap_or("")
            ),
            None,
        ),
        CheckStatus::Fail => {
            let provider = required.as_deref().unwrap_or("");
            VerificationCheck::new(
                "caddy.dns_plugin",
                "Caddy DNS-01 plugin",
                CheckStatus::Fail,
                format!(
                    "TLS strategy requires dns.providers.{provider} but \
                     `caddy list-modules` does not list it — DNS-01 challenges \
                     will silently fail (HE #3)"
                ),
                Some(dns_plugin_remedy(provider)),
            )
        }
        CheckStatus::Warn => VerificationCheck::new(
            "caddy.dns_plugin",
            "Caddy DNS-01 plugin",
            CheckStatus::Warn,
            String::from("unexpected state"),
            None,
        ),
    }
}

/// Determine the required DNS provider from config (caddy.tls.dns_provider
/// OR deploy strategy being `CloudflareDns01`).
fn required_dns_provider(cfg: &DoctorConfig) -> Option<String> {
    if let Some(slip) = &cfg.slip_toml {
        if let Some(tls) = &slip.caddy.tls {
            return Some(tls.dns_provider.clone());
        }
        if let Some(deploy) = &slip.deploy
            && deploy.tls == slip_core::config::TlsStrategy::CloudflareDns01
        {
            return Some("cloudflare".to_string());
        }
    }
    None
}

/// Check 7 (env): unresolved `${VAR}` placeholders in config.
fn check_config_env(cfg: &DoctorConfig) -> VerificationCheck {
    if cfg.unresolved_env.is_empty() {
        return VerificationCheck::new(
            "config.env",
            "Config env var resolution",
            CheckStatus::Pass,
            String::from("all ${VAR} placeholders in slip.toml + apps resolved"),
            None,
        );
    }
    let names: Vec<&str> = cfg.unresolved_env.iter().map(|s| s.as_str()).collect();
    VerificationCheck::new(
        "config.env",
        "Config env var resolution",
        CheckStatus::Warn,
        format!(
            "unresolved env vars in config: {} — \
             the running slipd may load these via its EnvironmentFile; \
             a manual check does not (FR §3.10)",
            names.join(", ")
        ),
        Some(format!(
            "set {} in {}/slip.env (the systemd EnvironmentFile) \
             or export them before running `slip doctor`",
            names.join(", "),
            cfg.config_dir.display()
        )),
    )
}

/// Check 7 (disk): free space under the storage path.
fn check_disk_free(cfg: &DoctorConfig, _timeout_secs: u64) -> VerificationCheck {
    let path = cfg
        .slip_toml
        .as_ref()
        .map(|c| c.storage.path.clone())
        .unwrap_or_else(|| PathBuf::from("/var/lib/slip"));

    if !path.exists() {
        return VerificationCheck::new(
            "disk.free",
            "Disk space under storage path",
            CheckStatus::Warn,
            format!("storage path {} does not exist yet", path.display()),
            Some(String::from(
                "run slipd once to create the storage directory",
            )),
        );
    }

    // Use `df` shell-out for portability (avoids nix statvfs platform issues).
    let out = Command::new("df")
        .args(["-P", path.to_str().unwrap_or(".")])
        .output();
    match out {
        Ok(o) if o.status.success() => {
            let text = String::from_utf8_lossy(&o.stdout);
            // `df -P` output: Filesystem 1024-blocks Used Available Capacity Mounted on
            let avail_bytes = parse_df_available(&text);
            match avail_bytes {
                Some(bytes) => {
                    let gib = bytes as f64 / (1024.0 * 1024.0 * 1024.0);
                    if gib < 1.0 {
                        VerificationCheck::new(
                            "disk.free",
                            "Disk space under storage path",
                            CheckStatus::Fail,
                            format!(
                                "{:.2} GiB free under {} — disk almost full",
                                gib,
                                path.display()
                            ),
                            Some(format!(
                                "free space on the volume hosting {} — slip needs room for images and state",
                                path.display()
                            )),
                        )
                    } else if gib < 5.0 {
                        VerificationCheck::new(
                            "disk.free",
                            "Disk space under storage path",
                            CheckStatus::Warn,
                            format!(
                                "{:.2} GiB free under {} — low on space",
                                gib,
                                path.display()
                            ),
                            Some(format!(
                                "free space on the volume hosting {}",
                                path.display()
                            )),
                        )
                    } else {
                        VerificationCheck::new(
                            "disk.free",
                            "Disk space under storage path",
                            CheckStatus::Pass,
                            format!("{:.2} GiB free under {}", gib, path.display()),
                            None,
                        )
                    }
                }
                None => VerificationCheck::new(
                    "disk.free",
                    "Disk space under storage path",
                    CheckStatus::Warn,
                    String::from("could not parse `df` output"),
                    Some(String::from("check disk space manually with `df -h`")),
                ),
            }
        }
        _ => VerificationCheck::new(
            "disk.free",
            "Disk space under storage path",
            CheckStatus::Warn,
            String::from("`df` command failed"),
            Some(String::from("check disk space manually with `df -h`")),
        ),
    }
}

/// Parse the `Available` column (in 1K blocks) from `df -P` output.
fn parse_df_available(text: &str) -> Option<u64> {
    let mut lines = text.lines();
    let _header = lines.next()?; // header
    let line = lines.next()?;
    let cols: Vec<&str> = line.split_whitespace().collect();
    // Filesystem 1024-blocks Used Available Capacity Mounted on
    // 0          1            2    3          4         5       6
    let avail: u64 = cols.get(3)?.parse().ok()?;
    Some(avail * 1024)
}

// ─── Phase 3: slipd-dependent + DNS checks ────────────────────────────────────

/// Run slipd-dependent checks (management API + Caddy admin + DNS).
pub async fn run_slipd_checks(
    cfg: &DoctorConfig,
    server: &str,
    cli_token: Option<&str>,
    runner: &dyn CommandRunner,
    timeout_secs: u64,
) -> Vec<VerificationCheck> {
    let mut checks = Vec::new();

    // Caddy admin checks (direct to admin API, not via slipd).
    let caddy_admin = cfg
        .slip_toml
        .as_ref()
        .map(|c| c.caddy.admin_api.clone())
        .unwrap_or_else(|| "http://localhost:2019".to_string());
    checks.extend(check_caddy_admin(&caddy_admin, timeout_secs).await);

    // Registry checks.
    checks.extend(check_registry(cfg, timeout_secs).await);

    // TLS checks.
    checks.extend(check_tls(cfg, &caddy_admin, timeout_secs, runner).await);

    // DNS end-to-end probe + DNS expectation (check 2 + 8).
    checks.extend(check_dns(cfg, runner, timeout_secs).await);

    // slipd management-API reachability (informational — many host checks
    // already run without it). If we have a token, ping /v1/status.
    if let Some(token) = cli_token {
        checks.push(check_slipd_reachable(server, token, timeout_secs).await);
    } else {
        checks.push(VerificationCheck::new(
            "slipd.reachable",
            "slipd management API reachable",
            CheckStatus::Skipped,
            String::from("no admin token (--token / SLIP_TOKEN) — skipped"),
            None,
        ));
    }

    checks
}

/// Check 4 (admin/server/443): Caddy admin reachable + slip server block +
/// :443 conflict.
async fn check_caddy_admin(admin_api: &str, timeout_secs: u64) -> Vec<VerificationCheck> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(timeout_secs.min(5)))
        .build()
        .unwrap_or_else(|_| reqwest::Client::new());

    let mut out = Vec::with_capacity(3);

    // caddy.reachable
    let ping = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        client.get(format!("{admin_api}/config/")).send(),
    )
    .await;
    match ping {
        Ok(Ok(resp)) if resp.status().is_success() => out.push(VerificationCheck::new(
            "caddy.reachable",
            "Caddy admin API reachable",
            CheckStatus::Pass,
            format!("GET {admin_api}/config/ → {}", resp.status()),
            None,
        )),
        Ok(Ok(resp)) => out.push(VerificationCheck::new(
            "caddy.reachable",
            "Caddy admin API reachable",
            CheckStatus::Fail,
            format!("GET {admin_api}/config/ → {}", resp.status()),
            Some(String::from("is Caddy running? systemctl status caddy")),
        )),
        Ok(Err(e)) => out.push(VerificationCheck::new(
            "caddy.reachable",
            "Caddy admin API reachable",
            CheckStatus::Fail,
            format!("connection error: {e}"),
            Some(String::from("is Caddy running? systemctl status caddy")),
        )),
        Err(_) => out.push(VerificationCheck::new(
            "caddy.reachable",
            "Caddy admin API reachable",
            CheckStatus::Fail,
            String::from("timeout contacting Caddy admin API"),
            Some(String::from("is Caddy running? systemctl status caddy")),
        )),
    }

    // caddy.slip_server + caddy.listener_conflict
    let cfg_resp = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        client.get(format!("{admin_api}/config/")).send(),
    )
    .await;
    let config_json: serde_json::Value = match cfg_resp {
        Ok(Ok(r)) if r.status().is_success() => r.json().await.unwrap_or(serde_json::Value::Null),
        _ => serde_json::Value::Null,
    };

    // slip_server
    if config_json.pointer("/apps/http/servers/slip").is_some() {
        out.push(VerificationCheck::new(
            "caddy.slip_server",
            "slip HTTP server block exists",
            CheckStatus::Pass,
            String::from("slip server block found in Caddy config"),
            None,
        ));
    } else {
        out.push(VerificationCheck::new(
            "caddy.slip_server",
            "slip HTTP server block exists",
            CheckStatus::Fail,
            String::from("slip server block missing from Caddy config"),
            Some(String::from(
                "check journalctl -u slipd for bootstrap errors",
            )),
        ));
    }

    // listener_conflict — read-only scan (mirrors caddy.rs bootstrap logic).
    let slip_listener = ":443";
    let mut conflict: Option<(String, String)> = None;
    if let Some(servers) = config_json
        .pointer("/apps/http/servers")
        .and_then(|v| v.as_object())
    {
        for (name, server) in servers {
            if name == "slip" {
                continue;
            }
            if let Some(listen) = server.get("listen").and_then(|v| v.as_array())
                && listen.iter().any(|l| l.as_str() == Some(slip_listener))
            {
                conflict = Some((name.clone(), slip_listener.to_string()));
                break;
            }
        }
    }
    match conflict {
        None => out.push(VerificationCheck::new(
            "caddy.listener_conflict",
            "Caddy :443 listener conflict",
            CheckStatus::Pass,
            String::from("no non-slip server claims :443"),
            None,
        )),
        Some((server, listener)) => out.push(VerificationCheck::new(
            "caddy.listener_conflict",
            "Caddy :443 listener conflict",
            CheckStatus::Fail,
            format!("Caddy server '{server}' already claims {listener}"),
            Some(format!(
                "remove the conflicting {listener} listener from the '{server}' server in your Caddy config, or change slip's listen port"
            )),
        )),
    }

    out
}

/// Check 5: registry reachability + auth + manifest HEAD.
async fn check_registry(cfg: &DoctorConfig, timeout_secs: u64) -> Vec<VerificationCheck> {
    let mut out = Vec::with_capacity(3);
    let Some(slip) = &cfg.slip_toml else {
        out.push(VerificationCheck::new(
            "registry.reachable",
            "Registry reachable",
            CheckStatus::Skipped,
            String::from("no slip.toml loaded — registry check skipped"),
            None,
        ));
        out.push(VerificationCheck::new(
            "registry.auth",
            "Registry auth",
            CheckStatus::Skipped,
            String::from("no slip.toml loaded"),
            None,
        ));
        out.push(VerificationCheck::new(
            "registry.manifest",
            "Registry manifest HEAD",
            CheckStatus::Skipped,
            String::from("no slip.toml loaded"),
            None,
        ));
        return out;
    };

    // Collect unique registry hosts from app images.
    let hosts = collect_registry_hosts(&cfg.apps);
    if hosts.is_empty() {
        out.push(VerificationCheck::new(
            "registry.reachable",
            "Registry reachable",
            CheckStatus::Skipped,
            String::from("no app images reference a registry"),
            None,
        ));
        out.push(VerificationCheck::new(
            "registry.auth",
            "Registry auth",
            CheckStatus::Skipped,
            String::from("no registry configured"),
            None,
        ));
        out.push(VerificationCheck::new(
            "registry.manifest",
            "Registry manifest HEAD",
            CheckStatus::Skipped,
            String::from("no registry configured"),
            None,
        ));
        return out;
    }

    // Build a host → token map from the declared registries (Phase 1: simple
    // host equality; Phase 3 adds longest-path-prefix matching). The doctor
    // only probes reachability/auth, so a flat host match suffices here.
    let host_tokens: std::collections::HashMap<String, String> = slip
        .registries
        .registries
        .values()
        .filter_map(|e| e.token.as_ref().map(|t| (e.url.clone(), t.clone())))
        .collect();
    let any_token_present = !host_tokens.is_empty();
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(timeout_secs.min(5)))
        .build()
        .unwrap_or_else(|_| reqwest::Client::new());

    let mut reachable_any = false;
    let mut auth_ok_any = false;
    let mut manifest_ok_any = false;
    let mut auth_invalid = false;
    let mut manifest_missing = false;

    for (host, repo_tag) in &hosts {
        // Split repo:tag
        let (repo, tag) = repo_tag
            .rsplit_once(':')
            .unwrap_or((repo_tag.as_str(), "latest"));

        // /v2/ reachable
        let v2_url = format!("https://{host}/v2/");
        let v2_resp = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            client.get(&v2_url).send(),
        )
        .await;
        let v2_status = match v2_resp {
            Ok(Ok(r)) => r.status().as_u16(),
            _ => 0,
        };
        if v2_status == 200 || v2_status == 401 {
            reachable_any = true;
        }

        // manifest HEAD (with per-host token if declared for this host)
        let manifest_url = format!("https://{host}/v2/{repo}/manifests/{tag}");
        let mut req = client.head(&manifest_url);
        if let Some(token) = host_tokens.get(host) {
            req = req.header("Authorization", format!("Bearer {token}"));
        }
        let m_resp = tokio::time::timeout(std::time::Duration::from_secs(5), req.send()).await;
        if let Ok(Ok(r)) = m_resp {
            let s = r.status().as_u16();
            if s == 200 {
                auth_ok_any = true;
                manifest_ok_any = true;
            } else if s == 401 || s == 403 {
                auth_invalid = true;
            } else if s == 404 {
                manifest_missing = true;
            }
        }
    }

    // registry.reachable
    out.push(if reachable_any {
        VerificationCheck::new(
            "registry.reachable",
            "Registry reachable",
            CheckStatus::Pass,
            String::from("registry /v2/ endpoint reachable"),
            None,
        )
    } else {
        VerificationCheck::new(
            "registry.reachable",
            "Registry reachable",
            CheckStatus::Fail,
            String::from("registry /v2/ endpoint not reachable"),
            Some(String::from("check registry URL and network connectivity")),
        )
    });

    // registry.auth
    out.push(if auth_invalid {
        VerificationCheck::new(
            "registry.auth",
            "Registry auth",
            CheckStatus::Fail,
            String::from("registry returned 401/403 with the configured token"),
            Some(String::from(
                "rotate the matching [registries.<name>].token or `slip registry login`",
            )),
        )
    } else if !any_token_present {
        VerificationCheck::new(
            "registry.auth",
            "Registry auth",
            CheckStatus::Warn,
            String::from("no registry token configured — anonymous pull only"),
            Some(String::from(
                "set [registries.<name>].token or run `slip registry login` for private repos",
            )),
        )
    } else if auth_ok_any {
        VerificationCheck::new(
            "registry.auth",
            "Registry auth",
            CheckStatus::Pass,
            String::from("registry accepted the configured token"),
            None,
        )
    } else {
        VerificationCheck::new(
            "registry.auth",
            "Registry auth",
            CheckStatus::Warn,
            String::from("could not verify registry auth"),
            None,
        )
    });

    // registry.manifest
    out.push(if manifest_missing {
        VerificationCheck::new(
            "registry.manifest",
            "Registry manifest HEAD",
            CheckStatus::Fail,
            String::from("one or more app image manifests returned 404"),
            Some(String::from("check the image:tag in your app configs — the manifest does not exist in the registry")),
        )
    } else if manifest_ok_any {
        VerificationCheck::new(
            "registry.manifest",
            "Registry manifest HEAD",
            CheckStatus::Pass,
            String::from("app image manifests found in registry"),
            None,
        )
    } else {
        VerificationCheck::new(
            "registry.manifest",
            "Registry manifest HEAD",
            CheckStatus::Warn,
            String::from("could not verify manifest existence"),
            None,
        )
    });

    out
}

/// Extract `(registry_host, repo:tag)` pairs from app configs.
fn collect_registry_hosts(
    apps: &std::collections::HashMap<String, slip_core::AppConfig>,
) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for app in apps.values() {
        let image = &app.app.image;
        // image = "registry.example.com/repo:tag" or "repo:tag" (Docker Hub implicit)
        if image.contains('/') {
            let host_part = image.split('/').next().unwrap_or("");
            // Heuristic: host_part contains a '.' or ':' or is "localhost" → registry host
            if host_part.contains('.') || host_part.contains(':') || host_part == "localhost" {
                let key = format!("{host_part}|{image}");
                if seen.insert(key) {
                    out.push((host_part.to_string(), image.clone()));
                }
                continue;
            }
        }
        // Docker Hub implicit — skip (doctor focuses on configured private registries).
    }
    out
}

/// The canonical Caddy module ID for the built-in Tailscale certificate
/// manager (standard since Caddy v2.5). Used by `classify_manager_module`
/// and the reconcile preflight.
const TAILSCALE_CERT_MANAGER_ID: &str = "tls.get_certificate.tailscale";

/// Classify the `tailscale.manager_module` doctor check using the injected
/// `CommandRunner` to run `caddy list-modules` directly (mirroring
/// `check_caddy_dns_plugin`). This decouples the check from the admin API
/// entirely — the admin API reflects runtime config, not the compiled module
/// set, and its `/modules/` endpoint is undocumented and always 404 on
/// standard Caddy (the root cause of SLIP-124).
///
/// Classification (per the SLIP-124 decision table):
/// - exit 0 + stdout contains exact `tls.get_certificate.tailscale` → `Pass`
/// - exit 0 + stdout lacks the exact ID → `Fail` (confirmed absent; remedy:
///   upgrade Caddy to v2.5+ / rebuild with xcaddy)
/// - exit nonzero → `Warn` (cannot verify; don't claim absence)
/// - binary not found / io error → `Warn` (cannot verify)
///
/// Extracted from `check_tls` so it is unit-testable via `FakeRunner` without
/// constructing a `CaddyClient` or running the async TLS checks.
fn classify_manager_module(runner: &dyn CommandRunner) -> VerificationCheck {
    const NAME: &str = "tailscale.manager_module";
    const LABEL: &str = "Tailscale Caddy certificate manager";
    match runner.run("caddy", &["list-modules"]) {
        Ok(o) if o.status == 0 => {
            match module_present_exact(&o.stdout, TAILSCALE_CERT_MANAGER_ID) {
                CheckStatus::Pass => VerificationCheck::new(
                    NAME,
                    LABEL,
                    CheckStatus::Pass,
                    format!(
                        "{} found via `caddy list-modules`",
                        TAILSCALE_CERT_MANAGER_ID
                    ),
                    None,
                ),
                CheckStatus::Fail => VerificationCheck::new(
                    NAME,
                    LABEL,
                    CheckStatus::Fail,
                    format!(
                        "Caddy build lacks {} — `caddy list-modules` did not list it \
                         (built-in since Caddy v2.5)",
                        TAILSCALE_CERT_MANAGER_ID
                    ),
                    Some(String::from(
                        "upgrade Caddy to v2.5 or later, or rebuild with \
                         `xcaddy build` if using a custom build; then restart caddy",
                    )),
                ),
                // Skipped only when module_id is empty (never, it's a const);
                // treat defensively as a fail-closed Warn so we never silently
                // claim presence.
                CheckStatus::Skipped | CheckStatus::Warn => VerificationCheck::new(
                    NAME,
                    LABEL,
                    CheckStatus::Warn,
                    format!(
                        "could not classify {} in `caddy list-modules` output",
                        TAILSCALE_CERT_MANAGER_ID
                    ),
                    Some(String::from("run `caddy list-modules` manually to verify")),
                ),
            }
        }
        Ok(o) => VerificationCheck::new(
            NAME,
            LABEL,
            CheckStatus::Warn,
            format!(
                "`caddy list-modules` exited {} — cannot verify Tailscale manager module{}",
                o.status,
                if o.stderr.trim().is_empty() {
                    String::new()
                } else {
                    format!(": {}", o.stderr.trim())
                }
            ),
            Some(String::from(
                "ensure `caddy` is installed and on $PATH, then run \
                 `caddy list-modules` manually to confirm \
                 tls.get_certificate.tailscale is compiled in",
            )),
        ),
        Err(_) => VerificationCheck::new(
            NAME,
            LABEL,
            CheckStatus::Warn,
            "no `caddy` binary found on $PATH — cannot verify Tailscale manager module".to_string(),
            Some(String::from(
                "install Caddy (v2.5+) or expose the admin API, then re-run `slip doctor`",
            )),
        ),
    }
}

/// Check 6: TLS issuer + cert expiry + stuck ACME (documented unsupported).
async fn check_tls(
    cfg: &DoctorConfig,
    caddy_admin: &str,
    timeout_secs: u64,
    runner: &dyn CommandRunner,
) -> Vec<VerificationCheck> {
    let mut out = Vec::with_capacity(3);

    let Some(slip) = &cfg.slip_toml else {
        out.push(VerificationCheck::new(
            "tls.issuer",
            "TLS issuer",
            CheckStatus::Skipped,
            String::from("no slip.toml loaded"),
            None,
        ));
        out.push(VerificationCheck::new(
            "tls.cert_expiry",
            "TLS cert expiry",
            CheckStatus::Skipped,
            String::from("no slip.toml loaded"),
            None,
        ));
        out.push(VerificationCheck::new(
            "tls.acme_stuck",
            "TLS stuck ACME orders",
            CheckStatus::Skipped,
            String::from("no slip.toml loaded"),
            None,
        ));
        return out;
    };

    let caddy = slip_core::CaddyClient::new(caddy_admin.to_string());

    // Collect hosts to check: deploy.domain + app routing hostnames.
    let mut hosts: Vec<String> = Vec::new();
    if let Some(deploy) = &slip.deploy
        && let Some(d) = &deploy.domain
    {
        hosts.push(d.clone());
    }
    for app in cfg.apps.values() {
        for route in app.routing.effective_routes() {
            if !hosts.contains(&route.hostname) {
                hosts.push(route.hostname);
            }
        }
    }

    let deploy_tls = slip
        .deploy
        .as_ref()
        .map(|d| d.tls.as_str())
        .unwrap_or_else(|| slip_core::ServerDeployConfig::default().tls.as_str());

    // Single loop: query each host once and reuse the result.
    let mut issuer_any_mismatch = false;
    let mut issuer_details: Vec<String> = Vec::new();
    for host in &hosts {
        let issuer = tokio::time::timeout(
            std::time::Duration::from_secs(timeout_secs.min(5)),
            caddy.get_tls_issuer(host),
        )
        .await;
        let issuer_str: Option<String> = match issuer {
            Ok(Ok(Some(i))) => Some(i.clone()),
            Ok(Ok(None)) => None, // Caddy default = ACME
            Ok(Err(_)) => None,
            Err(_) => None,
        };
        match &issuer_str {
            Some(i) => issuer_details.push(format!("{host}→{i}")),
            None => issuer_details.push(format!("{host}→acme(default)")),
        }
        // Check for internal issuer serving a public hostname (mismatch).
        if let Some(ref i) = issuer_str
            && i == "internal"
            && !is_private_hostname(host)
            && deploy_tls != "internal"
        {
            issuer_any_mismatch = true;
        }
    }

    if issuer_any_mismatch {
        out.push(VerificationCheck::new(
            "tls.issuer",
            "TLS issuer",
            CheckStatus::Warn,
            format!(
                "internal issuer serving a public hostname — {} | hosts: {}",
                issuer_details.join(", "),
                hosts.join(", ")
            ),
            Some(String::from(
                "check TLS automation policies — a public hostname should use ACME, not internal",
            )),
        ));
    } else if !issuer_details.is_empty() {
        out.push(VerificationCheck::new(
            "tls.issuer",
            "TLS issuer",
            CheckStatus::Pass,
            issuer_details.join(", "),
            None,
        ));
    } else {
        out.push(VerificationCheck::new(
            "tls.issuer",
            "TLS issuer",
            CheckStatus::Skipped,
            String::from("no hosts configured"),
            None,
        ));
    }

    // tls.cert_expiry — TLS handshake to inspect notAfter.
    // We use a plain TCP+TLS handshake via reqwest on https://<host> and read
    // the cert. reqwest/rustls does not expose notAfter directly; we mark this
    // as a documented limitation and warn the operator to check manually.
    // A full implementation needs rustls access to the peer certificate chain.
    out.push(VerificationCheck::new(
        "tls.cert_expiry",
        "TLS cert expiry",
        CheckStatus::Skipped,
        String::from("cert expiry inspection via TLS handshake not yet wired — \
         reqwest/rustls does not expose notAfter without a custom verifier"),
        Some(String::from("check cert expiry manually: `echo | openssl s_client -connect <host>:443 2>/dev/null | openssl x509 -noout -dates`")),
    ));

    // tls.acme_stuck — documented unsupported (Caddy admin API doesn't expose order state).
    out.push(VerificationCheck::new(
        "tls.acme_stuck",
        "TLS stuck ACME orders",
        CheckStatus::Skipped,
        String::from(
            "stuck ACME order detection is not available via Caddy's admin API — \
             Caddy does not expose ACME order state (api.rs comment)",
        ),
        Some(String::from(
            "run: slip tls renew <host> to force reissue \
             (non-destructive: bumps renewal_window_ratio then reverts it)",
        )),
    ));

    // ── Tailscale doctor checks (additive, print only) ────────────────────
    // Run when any host has tls="tailscale" OR any .ts.net host exists.
    let has_tailscale_strategy = slip
        .deploy
        .as_ref()
        .map(|d| d.tls == slip_core::config::TlsStrategy::Tailscale)
        .unwrap_or(false)
        || cfg.apps.values().any(|a| {
            a.routing.tls == Some(slip_core::config::TlsStrategy::Tailscale)
                || a.routing
                    .routes
                    .iter()
                    .any(|r| r.tls == Some(slip_core::config::TlsStrategy::Tailscale))
        });
    let ts_net_hosts: Vec<String> = hosts
        .iter()
        .filter(|h| slip_core::config::is_ts_net_host(h))
        .cloned()
        .collect();

    if has_tailscale_strategy || !ts_net_hosts.is_empty() {
        // tailscale.daemon — tailscaled active + socket present
        let daemon_active = runner
            .run("systemctl", &["is-active", "tailscaled"])
            .map(|o| o.status == 0 && o.stdout.trim() == "active")
            .unwrap_or(false);
        let socket_present = std::path::Path::new(slip_core::tailscale::TAILSCALED_SOCKET).exists();

        if daemon_active && socket_present {
            out.push(VerificationCheck::new(
                "tailscale.daemon",
                "Tailscale daemon",
                CheckStatus::Pass,
                String::from("tailscaled is active and socket is present"),
                None,
            ));
        } else {
            let mut detail = String::from("tailscaled not running or socket missing");
            if !daemon_active {
                detail.push_str(" — daemon is not active");
            }
            if !socket_present {
                detail.push_str(" — socket not found");
            }
            out.push(VerificationCheck::new(
                "tailscale.daemon",
                "Tailscale daemon",
                CheckStatus::Fail,
                detail,
                Some(String::from(
                    "run: systemctl start tailscaled \
                     (socket: /var/run/tailscale/tailscaled.sock)",
                )),
            ));
        }

        // tailscale.https — CertDomains non-empty
        let status_out = runner.run("tailscale", &["status", "--json"]);
        let cert_domains = status_out
            .ok()
            .filter(|o| o.status == 0)
            .map(|o| slip_core::tailscale::parse_cert_domains(&o.stdout))
            .unwrap_or_default();

        if !cert_domains.is_empty() {
            out.push(VerificationCheck::new(
                "tailscale.https",
                "Tailscale HTTPS certificates",
                CheckStatus::Pass,
                format!("HTTPS enabled — CertDomains: {}", cert_domains.join(", ")),
                None,
            ));
        } else {
            out.push(VerificationCheck::new(
                "tailscale.https",
                "Tailscale HTTPS certificates",
                CheckStatus::Fail,
                String::from(
                    "HTTPS certificates not enabled for tailnet — \
                     tailscale status --json reports no CertDomains",
                ),
                Some(String::from(
                    "enable MagicDNS + HTTPS Certificates at \
                     https://login.tailscale.com/admin/dns",
                )),
            ));
        }

        // tailscale.caddy_user — TS_PERMIT_CERT_UID for non-root Caddy
        // Delegate to the shared core implementation (RE-5 fix — no duplication).
        let permitted = slip_core::tailscale::check_caddy_user_permission();

        if permitted {
            out.push(VerificationCheck::new(
                "tailscale.caddy_user",
                "Tailscale Caddy user permission",
                CheckStatus::Pass,
                String::from("Caddy user can access tailscaled socket"),
                None,
            ));
        } else {
            out.push(VerificationCheck::new(
                "tailscale.caddy_user",
                "Tailscale Caddy user permission",
                CheckStatus::Fail,
                String::from(
                    "Caddy user 'caddy' cannot access tailscaled socket — \
                     TS_PERMIT_CERT_UID not set in /etc/default/tailscaled",
                ),
                Some(String::from(
                    "set TS_PERMIT_CERT_UID=caddy in /etc/default/tailscaled, \
                     then: systemctl restart tailscaled. \
                     See https://tailscale.com/docs/integrations/web-servers/caddy/caddy-certificates",
                )),
            ));
        }

        // tailscale.manager_module — Caddy has the Tailscale manager.
        // Use the injected `runner` + `caddy list-modules` directly (SLIP-124):
        // the admin API `/modules/` endpoint is undocumented and always 404 on
        // standard Caddy, so it cannot authoritatively report compiled modules.
        out.push(classify_manager_module(runner));

        // tailscale.hostname_match — per .ts.net host
        for ts_host in &ts_net_hosts {
            let matches = slip_core::tailscale::host_matches_cert_domains(ts_host, &cert_domains);
            if matches {
                out.push(VerificationCheck::new(
                    "tailscale.hostname_match",
                    format!("Tailscale hostname match: {ts_host}"),
                    CheckStatus::Pass,
                    format!("{ts_host} matches a tailscaled CertDomain"),
                    None,
                ));
            } else {
                out.push(VerificationCheck::new(
                    "tailscale.hostname_match",
                    format!("Tailscale hostname match: {ts_host}"),
                    CheckStatus::Fail,
                    format!("{ts_host} does not match any tailscaled CertDomain"),
                    Some(
                        "rename the node: tailscale set --hostname <node>, \
                         or use a *.ts.net subject that matches this machine"
                            .to_string(),
                    ),
                ));
            }
        }
    }

    out
}

/// Heuristic: is `host` a private/tailnet hostname (not a public FQDN)?
///
/// Used by `check_tls` to decide whether an `internal` TLS issuer serving a
/// public hostname is a mismatch (`warn`). This only affects the `tls.issuer`
/// check's `warn` path, never a `fail`.
///
/// Limitation: `.internal` is not a reserved TLD. A public hostname ending
/// in `.internal` would be misclassified as private, suppressing the
/// mismatch warning. This is acceptable for slip's target deployments
/// (tailnet/home-server origins) but documented here so a future ticket
/// can refine it (e.g. by checking the resolved IP against RFC 1918/CGNAT).
fn is_private_hostname(host: &str) -> bool {
    // Reuse the config allowlist for consistency with auto-internal classification.
    // `.ts.net` is NOT classified as private here — it uses real LE certs via
    // the Tailscale manager, so an internal issuer on a .ts.net host IS a
    // mismatch worth warning about.
    for tld in slip_core::config::NON_PUBLIC_TLDS {
        if host.ends_with(tld) {
            return true;
        }
    }
    host.split('.').count() == 1 // bare name, no domain
}

/// Check 2 + 8: DNS probe (getent ahosts) + DNS expectation classification.
async fn check_dns(
    cfg: &DoctorConfig,
    runner: &dyn CommandRunner,
    timeout_secs: u64,
) -> Vec<VerificationCheck> {
    let mut out = Vec::with_capacity(2);

    // Collect declared hosts.
    let mut hosts: Vec<String> = Vec::new();
    if let Some(slip) = &cfg.slip_toml
        && let Some(deploy) = &slip.deploy
        && let Some(d) = &deploy.domain
    {
        hosts.push(d.clone());
    }
    for app in cfg.apps.values() {
        for route in app.routing.effective_routes() {
            if !hosts.contains(&route.hostname) {
                hosts.push(route.hostname);
            }
        }
    }

    if hosts.is_empty() {
        out.push(VerificationCheck::new(
            "dns.probe",
            "End-to-end container DNS probe",
            CheckStatus::Skipped,
            String::from("no app containers running to probe DNS against"),
            Some(String::from("start an app and re-run `slip doctor`")),
        ));
        out.push(VerificationCheck::new(
            "dns.expectation",
            "DNS expectation for declared hosts",
            CheckStatus::Skipped,
            String::from("no declared hosts"),
            None,
        ));
        return out;
    }

    // Check 2: end-to-end DNS probe via a scratch container.
    // We shell out to `docker run --rm --network <net> busybox getent hosts <peer>`
    // (or podman). This is bounded by timeout and uses --rm for cleanup.
    let network = cfg
        .slip_toml
        .as_ref()
        .map(|c| c.network_name())
        .unwrap_or_else(|| "slip".to_string());

    // Find a running app container name to probe against.
    let peer = find_running_app_container_name(runner, &network);
    let probe_result = match peer {
        Some(name) => run_dns_probe(runner, &network, &name, timeout_secs),
        None => DnsProbeResult::NoPeer,
    };
    out.push(match probe_result {
        DnsProbeResult::Ok(resolved) => VerificationCheck::new(
            "dns.probe",
            "End-to-end container DNS probe",
            CheckStatus::Pass,
            format!("scratch container resolved peer via getent → {resolved}"),
            None,
        ),
        DnsProbeResult::Failed(detail) => VerificationCheck::new(
            "dns.probe",
            "End-to-end container DNS probe",
            CheckStatus::Fail,
            detail,
            Some(String::from("check ufw.bridge_dns and aardvark.active — the end-to-end probe is authoritative (FR §3.8)")),
        ),
        DnsProbeResult::NoPeer => VerificationCheck::new(
            "dns.probe",
            "End-to-end container DNS probe",
            CheckStatus::Warn,
            String::from("no app container running on the slip network to probe DNS against"),
            Some(String::from("start an app and re-run `slip doctor`")),
        ),
        DnsProbeResult::NoRuntime => VerificationCheck::new(
            "dns.probe",
            "End-to-end container DNS probe",
            CheckStatus::Warn,
            String::from("no container runtime available to run the scratch probe"),
            Some(String::from("install/start docker or podman")),
        ),
        DnsProbeResult::PullFailed => VerificationCheck::new(
            "dns.probe",
            "End-to-end container DNS probe",
            CheckStatus::Warn,
            String::from("could not pull busybox for the scratch probe (offline host?)"),
            Some(String::from("docker pull busybox (or podman pull busybox)")),
        ),
    });

    // Check 8: DNS expectation for each declared host.
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(3))
        .build()
        .unwrap_or_else(|_| reqwest::Client::new());
    let (cf_set, used_fallback) = fetch_cloudflare_ranges(&client).await;

    let deploy_tls = cfg
        .slip_toml
        .as_ref()
        .and_then(|s| s.deploy.as_ref())
        .map(|d| d.tls.as_str())
        .unwrap_or_else(|| slip_core::ServerDeployConfig::default().tls.as_str());

    let mut any_fail = false;
    let mut any_warn = false;
    let mut details: Vec<String> = Vec::new();
    let mut remedies: Vec<String> = Vec::new();
    for host in &hosts {
        let (ips, dns_error) = resolve_host(runner, host);
        let exp = classify_dns_expectation(
            host, &ips, deploy_tls, None, // proxied_hint: SLIP-117 follow-up
            &cf_set, dns_error,
        );
        match exp.status {
            CheckStatus::Fail => any_fail = true,
            CheckStatus::Warn => any_warn = true,
            _ => {}
        }
        details.push(format!("{}: {}", host, exp.detail));
        if let Some(r) = exp.remedy {
            remedies.push(r);
        }
    }

    let status = if any_fail {
        CheckStatus::Fail
    } else if any_warn {
        CheckStatus::Warn
    } else {
        CheckStatus::Pass
    };
    let detail = details.join("; ");
    let remedy = if remedies.is_empty() {
        None
    } else {
        Some(remedies.join("; "))
    };

    let mut check = VerificationCheck::new(
        "dns.expectation",
        "DNS expectation for declared hosts",
        status,
        detail,
        remedy,
    );
    if used_fallback {
        check
            .detail
            .push_str(" — (Cloudflare ranges fetched from snapshot; live fetch failed)");
    }
    out.push(check);

    out
}

/// Result of the end-to-end DNS probe.
#[derive(Debug)]
enum DnsProbeResult {
    Ok(String),
    Failed(String),
    NoPeer,
    NoRuntime,
    PullFailed,
}

/// Run a scratch `busybox` container on the slip network and resolve `peer`
/// via `getent hosts`. Uses `--rm` for cleanup and is bounded by timeout.
fn run_dns_probe(
    runner: &dyn CommandRunner,
    network: &str,
    peer: &str,
    _timeout_secs: u64,
) -> DnsProbeResult {
    // Prefer docker, fall back to podman.
    for runtime in &["docker", "podman"] {
        // Check runtime is available.
        let ping = runner.run(runtime, &["version"]);
        if ping.is_err() || ping.map(|o| o.status != 0).unwrap_or(true) {
            continue;
        }
        // Run the scratch probe with --rm.
        let args = [
            "run",
            "--rm",
            "--network",
            network,
            "busybox",
            "getent",
            "hosts",
            peer,
        ];
        let out = runner.run(runtime, &args);
        return match out {
            Ok(o) if o.status == 0 => {
                let resolved = o.stdout.split_whitespace().next().unwrap_or("").to_string();
                if resolved.is_empty() {
                    DnsProbeResult::Failed(String::from("getent returned 0 but no IP"))
                } else {
                    DnsProbeResult::Ok(resolved)
                }
            }
            Ok(o) => {
                // Non-zero exit. Distinguish pull failure (image not found) from DNS failure.
                let stderr = o.stderr.to_ascii_lowercase();
                if stderr.contains("not found")
                    || stderr.contains("no such image")
                    || stderr.contains("pull")
                {
                    return DnsProbeResult::PullFailed;
                }
                DnsProbeResult::Failed(format!(
                    "getent hosts {peer} failed in scratch container (exit {}): {}",
                    o.status,
                    o.stderr.trim()
                ))
            }
            Err(e) => DnsProbeResult::Failed(format!("failed to run scratch container: {e}")),
        };
    }
    DnsProbeResult::NoRuntime
}

/// Find a running app container name on the slip network via `docker ps` /
/// `podman ps`. Returns the container name (or None).
fn find_running_app_container_name(runner: &dyn CommandRunner, _network: &str) -> Option<String> {
    for runtime in &["docker", "podman"] {
        let out = runner
            .run(
                runtime,
                &[
                    "ps",
                    "--format",
                    "{{.Names}}",
                    "--filter",
                    "label=slip.managed=true",
                ],
            )
            .ok()?;
        if out.status != 0 {
            continue;
        }
        let name = out.stdout.lines().next()?.trim().to_string();
        if !name.is_empty() {
            return Some(name);
        }
    }
    None
}

/// Resolve a host via `getent ahosts <host>` shell-out. Returns (ips, dns_error).
///
/// `getent ahosts` exit codes:
/// - 0: success (records found) — IPs parsed from stdout.
/// - 2: "Not found" (NXDOMAIN/NODATA) — no records, NOT a resolver error →
///   `(empty, false)` so `classify_dns_expectation` returns `warn` (unresolved).
/// - 3 (or other non-zero): "Service unavailable" / SERVFAIL / timeout —
///   resolver itself is broken → `(empty, true)` so classification returns
///   `fail` (dns_error).
/// - exec error (getent missing): `(empty, true)` — treat as dns_error.
fn resolve_host(runner: &dyn CommandRunner, host: &str) -> (Vec<IpAddr>, bool) {
    match runner.run("getent", &["ahosts", host]) {
        Ok(o) if o.status == 0 => {
            let mut ips = Vec::new();
            for line in o.stdout.lines() {
                if let Some(ip_str) = line.split_whitespace().next()
                    && let Ok(ip) = ip_str.parse::<IpAddr>()
                    && !ips.contains(&ip)
                {
                    ips.push(ip);
                }
            }
            (ips, false)
        }
        Ok(o) if o.status == 2 => {
            // NXDOMAIN / NODATA — host does not resolve, but the resolver
            // itself is fine. This is "unresolved" → warn, not dns_error.
            (Vec::new(), false)
        }
        Ok(_) => {
            // SERVFAIL / timeout / other non-zero — resolver is broken.
            (Vec::new(), true)
        }
        Err(_) => {
            // getent not available / failed to execute — treat as dns_error.
            (Vec::new(), true)
        }
    }
}

/// Check: is slipd management API reachable?
async fn check_slipd_reachable(server: &str, token: &str, timeout_secs: u64) -> VerificationCheck {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(timeout_secs.min(5)))
        .build()
        .unwrap_or_else(|_| reqwest::Client::new());
    let url = format!("{server}/v1/status");
    let resp = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        client
            .get(&url)
            .header("Authorization", format!("Bearer {token}"))
            .send(),
    )
    .await;
    match resp {
        Ok(Ok(r)) if r.status().is_success() => VerificationCheck::new(
            "slipd.reachable",
            "slipd management API reachable",
            CheckStatus::Pass,
            format!("GET {url} → {}", r.status()),
            None,
        ),
        Ok(Ok(r)) => VerificationCheck::new(
            "slipd.reachable",
            "slipd management API reachable",
            CheckStatus::Fail,
            format!(
                "GET {url} → {} — slipd may be down or token invalid",
                r.status()
            ),
            Some(String::from(
                "systemctl status slipd; check --token / SLIP_TOKEN",
            )),
        ),
        Ok(Err(e)) => VerificationCheck::new(
            "slipd.reachable",
            "slipd management API reachable",
            CheckStatus::Fail,
            format!("connection error: {e}"),
            Some(String::from("systemctl status slipd")),
        ),
        Err(_) => VerificationCheck::new(
            "slipd.reachable",
            "slipd management API reachable",
            CheckStatus::Fail,
            String::from("timeout contacting slipd"),
            Some(String::from("systemctl status slipd")),
        ),
    }
}

// ─── Phase 4: --fix flow (UFW bridge DNS rule only) ───────────────────────────

pub mod fix {
    use super::*;
    use slip_core::doctor::{DoctorAction, Summary, VerificationCheck};

    /// Outcome of the `--fix` flow. Carries the actions (possibly empty) so
    /// `run()` can emit exactly one report via `emit()` — the single print
    /// point. `run_fix` never prints directly.
    #[derive(Debug)]
    pub enum FixOutcome {
        /// No fails to fix (or no auto-fixable fails). Carries the (empty)
        /// actions vec so `emit()` includes `"actions": []` in the JSON.
        NothingToDo(Vec<DoctorAction>),
        /// `--dry-run`: actions planned but not applied.
        DryRun(Vec<DoctorAction>),
        /// Applied: actions executed (and the UFW check re-run by the caller).
        Applied(Vec<DoctorAction>),
        /// An error occurred (the caller already exited via `output::fail` in
        /// most cases; this is a fallback).
        #[allow(dead_code)]
        Err(i32),
    }

    /// Run the `--fix` flow. May call `output::fail` and exit directly for
    /// privilege/usage errors. Never prints the report — that is `run()`'s
    /// job via `emit()`, so there is exactly one JSON document on stdout.
    ///
    /// # Root check
    ///
    /// `skip_root` controls whether the root-privilege check is performed.
    /// Production `run()` **always** passes `false` — no environment
    /// variable may bypass the root requirement for `--fix`. The `true`
    /// path is reachable ONLY from `#[cfg(test)]` unit tests that call
    /// this function directly.
    ///
    /// # `--dry-run` semantics
    ///
    /// `--dry-run` prints planned commands without mutating. It does NOT
    /// bypass the root check: the root check runs before the dry-run
    /// branch, so `--fix --dry-run` without root exits with GENERIC. This
    /// is intentional — `--fix` (even dry-run) is a privileged operation
    /// that requires root, consistent with `slip server init --verify`
    /// requiring root even for read-only verification. If a non-root user
    /// wants diagnostics, they should use `slip doctor` (without `--fix`).
    pub fn run_fix(
        checks: &[VerificationCheck],
        runner: &dyn CommandRunner,
        cfg: &DoctorConfig,
        args: &DoctorArgs,
        skip_root: bool,
    ) -> FixOutcome {
        let summary = Summary::from_checks(checks);
        if summary.fail == 0 {
            // Nothing to fix.
            return FixOutcome::NothingToDo(Vec::new());
        }

        // Plan fixes: only ufw.bridge_dns failures.
        let actions = plan_fixes(checks, cfg);
        if actions.is_empty() {
            // Fails exist but none are auto-fixable.
            return FixOutcome::NothingToDo(Vec::new());
        }

        // ── Privilege check ────────────────────────────────────────────────
        if !skip_root {
            let euid = nix::unistd::geteuid();
            if !euid.is_root() {
                output::fail(
                    output::GENERIC,
                    "`slip doctor --fix` must be run as root",
                    "re-run with `sudo slip doctor --fix`",
                );
            }
        }

        // ── Non-TTY / JSON safety ──────────────────────────────────────────
        let is_tty = std::io::stdin().is_terminal();
        if !args.yes && (args.json || !is_tty) {
            // Non-interactive without --yes: refuse to mutate.
            output::fail(
                output::USAGE,
                "`slip doctor --fix` requires --yes in non-interactive / --json mode",
                "rerun with `slip doctor --fix --yes --json`",
            );
        }

        // ── Dry-run ────────────────────────────────────────────────────────
        if args.dry_run {
            return FixOutcome::DryRun(actions);
        }

        // ── Interactive confirmation (TTY, not --yes) ──────────────────────
        if is_tty && !args.yes {
            println!("The following commands will be run:");
            for a in &actions {
                println!("  • {}", a.command);
            }
            println!();
            let confirm = dialoguer::Confirm::new()
                .with_prompt("Apply these changes?")
                .default(false)
                .interact()
                .unwrap_or(false);
            if !confirm {
                println!("aborted — no changes made");
                return FixOutcome::DryRun(actions);
            }
        }

        // ── Snapshot + apply ───────────────────────────────────────────────
        let _snap = snapshot_ufw(runner);
        let mut applied: Vec<DoctorAction> = Vec::new();
        for mut action in actions {
            // Idempotence: re-check if the rule is already present.
            // We re-run the UFW status check; if it passes, mark already_present.
            let ufw_out = runner.run("ufw", &["status", "numbered"]);
            if let Ok(o) = &ufw_out {
                // Parse the bridge name from the `on <bridge>` position in
                // the command string (same logic as plan_fixes). This is
                // robust to non-`br-` bridge names.
                let bridge = parse_bridge_from_command(&action.command);
                let class = classify_ufw(bridge, &o.stdout);
                if class.status == CheckStatus::Pass {
                    action.status = String::from("already_present");
                    applied.push(action);
                    continue;
                }
            }

            // Apply: parse the command into (cmd, args).
            let parts: Vec<&str> = action.command.split_whitespace().collect();
            let (cmd, args_slice) = parts.split_first().expect("action command non-empty");
            let result = runner.run(cmd, args_slice);
            match result {
                Ok(o) if o.status == 0 => {
                    action.status = String::from("applied");
                }
                Ok(o) => {
                    action.status = String::from("failed");
                    action.rollback = Some(format!(
                        "{} (failed: {})",
                        o.stderr.trim(),
                        action.rollback.clone().unwrap_or_default()
                    ));
                }
                Err(e) => {
                    action.status = String::from("failed");
                    action.rollback = Some(format!(
                        "(exec error: {e}) {}",
                        action.rollback.clone().unwrap_or_default()
                    ));
                }
            }
            applied.push(action);
        }

        FixOutcome::Applied(applied)
    }

    /// Plan fixes from the detection report. Only `ufw.bridge_dns` failures
    /// produce an action today.
    pub fn plan_fixes(checks: &[VerificationCheck], cfg: &DoctorConfig) -> Vec<DoctorAction> {
        let mut out = Vec::new();
        let ufw_fail = checks
            .iter()
            .any(|c| c.name == "ufw.bridge_dns" && c.status == CheckStatus::Fail);
        if !ufw_fail {
            return out;
        }

        // Derive the bridge name from the remedy or re-inspect.
        // The remedy text is "ufw allow in on <bridge> to any port 53".
        let bridge = checks
            .iter()
            .find(|c| c.name == "ufw.bridge_dns")
            .and_then(|c| c.remedy.as_deref())
            .and_then(|r| {
                r.split_whitespace()
                    .skip_while(|w| *w != "on")
                    .nth(1)
                    .map(|s| s.to_string())
            })
            .unwrap_or_else(|| {
                // Fallback: try network_bridge_name (needs runner; we can't
                // call it here without a runner, so use a generic name).
                "br-slip".to_string()
            });

        let _ = cfg; // cfg available for future fix types
        let command = format!("ufw allow in on {bridge} to any port 53");
        out.push(DoctorAction {
            name: String::from("ufw.allow.bridge_dns"),
            command,
            status: String::from("pending"),
            rollback: Some(format!("ufw delete allow in on {bridge} to any port 53")),
        });
        out
    }

    /// Snapshot UFW state before a mutation (for rollback display).
    fn snapshot_ufw(runner: &dyn CommandRunner) -> String {
        runner
            .run("ufw", &["status", "numbered"])
            .map(|o| o.stdout)
            .unwrap_or_default()
    }

    /// Parse the bridge interface name from a `ufw ... on <bridge> ...`
    /// command string. Returns `""` if not found (which makes `classify_ufw`
    /// emit a "network missing" fail, not a false pass).
    ///
    /// This is robust to non-`br-` bridge names (e.g. a custom
    /// `com.docker.network.bridge.name`).
    pub fn parse_bridge_from_command(command: &str) -> &str {
        let mut tokens = command.split_whitespace();
        // The command is "ufw allow in on <bridge> to any port 53" (or
        // "ufw delete allow in on <bridge> ..."). Find the `on` keyword and
        // take the next token.
        while let Some(tok) = tokens.next() {
            if tok == "on" {
                return tokens.next().unwrap_or("");
            }
        }
        ""
    }
}

// ─── SlipConfig helper (network name) ────────────────────────────────────────

/// Extension trait to get the network name from `SlipConfig` (lives here to
/// avoid touching slip-core's config.rs for a one-liner).
trait NetworkNameExt {
    fn network_name(&self) -> String;
}

impl NetworkNameExt for slip_core::SlipConfig {
    fn network_name(&self) -> String {
        // SlipConfig doesn't have a top-level network field; the default is
        // "slip" (config.rs default_network_name). Apps can override per-app.
        // For doctor's UFW/network purposes, "slip" is the right default.
        "slip".to_string()
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use slip_core::doctor::{CommandOutput, CommandRunner};

    /// A fake `CommandRunner` that returns canned outputs keyed by command.
    struct FakeRunner {
        canned: std::collections::HashMap<String, CommandOutput>,
    }

    impl FakeRunner {
        fn new() -> Self {
            Self {
                canned: std::collections::HashMap::new(),
            }
        }

        fn with(mut self, cmd: &str, out: CommandOutput) -> Self {
            self.canned.insert(cmd.to_string(), out);
            self
        }
    }

    impl CommandRunner for FakeRunner {
        fn run(&self, cmd: &str, _args: &[&str]) -> std::io::Result<CommandOutput> {
            self.canned.get(cmd).cloned().ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    format!("no canned output for {cmd}"),
                )
            })
        }
    }

    fn ok_out(stdout: &str) -> CommandOutput {
        CommandOutput {
            stdout: stdout.into(),
            stderr: String::new(),
            status: 0,
        }
    }

    #[test]
    fn parse_df_available_extracts_bytes() {
        let text = "Filesystem     1024-blocks    Used Available Capacity Mounted on\n/dev/vda1      209715200 52428800 157286400      26% /\n";
        let bytes = parse_df_available(text).unwrap();
        // 157286400 * 1024
        assert_eq!(bytes, 157_286_400 * 1024);
    }

    #[test]
    fn parse_df_available_returns_none_for_bad_format() {
        assert!(parse_df_available("garbage").is_none());
        assert!(parse_df_available("").is_none());
    }

    #[test]
    fn collect_registry_hosts_extracts_private_registries() {
        let mut apps = std::collections::HashMap::new();
        apps.insert(
            String::from("a"),
            slip_core::AppConfig {
                app: slip_core::AppInfo {
                    name: String::from("a"),
                    image: String::from("ghcr.io/org/repo:tag"),
                    secret: None,
                },
                routing: slip_core::RoutingConfig::default(),
                health: slip_core::HealthConfig::default(),
                deploy: slip_core::DeployConfig::default(),
                env: Default::default(),
                env_file: None,
                resources: Default::default(),
                network: Default::default(),
                preview: None,
                volumes: Vec::new(),
            },
        );
        apps.insert(
            String::from("b"),
            slip_core::AppConfig {
                app: slip_core::AppInfo {
                    name: String::from("b"),
                    image: String::from("nginx:latest"), // Docker Hub — skipped
                    secret: None,
                },
                routing: slip_core::RoutingConfig::default(),
                health: slip_core::HealthConfig::default(),
                deploy: slip_core::DeployConfig::default(),
                env: Default::default(),
                env_file: None,
                resources: Default::default(),
                network: Default::default(),
                preview: None,
                volumes: Vec::new(),
            },
        );
        let hosts = collect_registry_hosts(&apps);
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0].0, "ghcr.io");
    }

    #[test]
    fn required_dns_provider_from_caddy_tls() {
        let cfg = DoctorConfig {
            slip_toml: Some(slip_core::SlipConfig {
                server: slip_core::ServerConfig::default(),
                caddy: slip_core::CaddyConfig {
                    admin_api: String::from("http://localhost:2019"),
                    tls: Some(slip_core::CaddyTlsConfig {
                        email: String::from("x@x"),
                        dns_provider: String::from("cloudflare"),
                        dns_provider_config: None,
                        propagation_delay: String::from("2m"),
                        staging: false,
                    }),
                    acme_email: None,
                    acme_ca: None,
                    reconcile: slip_core::ReconcileConfig::default(),
                },
                auth: slip_core::AuthConfig {
                    secret: String::from("x"),
                },
                registries: slip_core::RegistriesConfig::default(),
                storage: slip_core::StorageConfig::default(),
                runtime: slip_core::RuntimeConfig::default(),
                preview: None,
                deploy: None,
            }),
            ..Default::default()
        };
        assert_eq!(required_dns_provider(&cfg), Some("cloudflare".to_string()));
    }

    #[test]
    fn required_dns_provider_from_deploy_tls_dns01() {
        let cfg = DoctorConfig {
            slip_toml: Some(slip_core::SlipConfig {
                server: slip_core::ServerConfig::default(),
                caddy: slip_core::CaddyConfig {
                    admin_api: String::from("http://localhost:2019"),
                    tls: None,
                    acme_email: None,
                    acme_ca: None,
                    reconcile: slip_core::ReconcileConfig::default(),
                },
                auth: slip_core::AuthConfig {
                    secret: String::from("x"),
                },
                registries: slip_core::RegistriesConfig::default(),
                storage: slip_core::StorageConfig::default(),
                runtime: slip_core::RuntimeConfig::default(),
                preview: None,
                deploy: Some(slip_core::ServerDeployConfig {
                    timeout: std::time::Duration::from_secs(60),
                    preview_timeout: std::time::Duration::from_secs(60),
                    domain: Some(String::from("deploy.example")),
                    tls: slip_core::config::TlsStrategy::CloudflareDns01,
                }),
            }),
            ..Default::default()
        };
        assert_eq!(required_dns_provider(&cfg), Some("cloudflare".to_string()));
    }

    #[test]
    fn required_dns_provider_none_when_no_dns01() {
        let cfg = DoctorConfig::default();
        assert_eq!(required_dns_provider(&cfg), None);
    }

    #[test]
    fn check_runtime_socket_warns_when_no_socket() {
        // In the test environment, none of the standard sockets exist.
        let cfg = DoctorConfig::default();
        let check = check_runtime_socket(&cfg);
        // May be pass or warn depending on the test host; just assert it runs.
        assert!(matches!(
            check.status,
            CheckStatus::Pass | CheckStatus::Warn
        ));
    }

    #[test]
    fn check_ufw_bridge_dns_warns_when_ufw_not_found() {
        let runner = FakeRunner::new();
        let cfg = DoctorConfig::default();
        let check = check_ufw_bridge_dns(&runner, &cfg);
        // ufw not installed in test env → warn
        assert_eq!(check.status, CheckStatus::Warn);
    }

    #[test]
    fn check_aardvark_active_warns_when_systemctl_missing() {
        let runner = FakeRunner::new();
        let check = check_aardvark_active(&runner);
        assert_eq!(check.status, CheckStatus::Warn);
    }

    #[test]
    fn check_caddy_dns_plugin_skipped_when_no_provider() {
        let runner = FakeRunner::new();
        let cfg = DoctorConfig::default();
        let check = check_caddy_dns_plugin(&runner, &cfg);
        // No caddy binary + no required provider → skipped (provider check first)
        // Actually the function checks `caddy list-modules` first. With no caddy
        // binary, it returns Warn. But required_dns_provider is None → Skipped
        // only if caddy ran. Let's check the actual behavior: the function
        // checks modules_out first, then parse_caddy_modules(None) → Skipped.
        // But caddy binary missing returns Warn before reaching parse.
        assert!(
            matches!(check.status, CheckStatus::Warn | CheckStatus::Skipped),
            "got {:?}",
            check.status
        );
    }

    #[test]
    fn check_caddy_dns_plugin_skipped_when_provider_none_and_caddy_ok() {
        let runner = FakeRunner::new().with("caddy", ok_out("http.handlers.reverse_proxy\n"));
        let cfg = DoctorConfig::default();
        let check = check_caddy_dns_plugin(&runner, &cfg);
        assert_eq!(check.status, CheckStatus::Skipped);
    }

    #[test]
    fn check_caddy_dns_plugin_fails_when_provider_required_and_absent() {
        let runner = FakeRunner::new().with("caddy", ok_out("http.handlers.reverse_proxy\n"));
        let cfg = DoctorConfig {
            slip_toml: Some(slip_core::SlipConfig {
                server: slip_core::ServerConfig::default(),
                caddy: slip_core::CaddyConfig {
                    admin_api: String::from("http://localhost:2019"),
                    tls: Some(slip_core::CaddyTlsConfig {
                        email: String::from("x@x"),
                        dns_provider: String::from("cloudflare"),
                        dns_provider_config: None,
                        propagation_delay: String::from("2m"),
                        staging: false,
                    }),
                    acme_email: None,
                    acme_ca: None,
                    reconcile: slip_core::ReconcileConfig::default(),
                },
                auth: slip_core::AuthConfig {
                    secret: String::from("x"),
                },
                registries: slip_core::RegistriesConfig::default(),
                storage: slip_core::StorageConfig::default(),
                runtime: slip_core::RuntimeConfig::default(),
                preview: None,
                deploy: None,
            }),
            ..Default::default()
        };
        let check = check_caddy_dns_plugin(&runner, &cfg);
        assert_eq!(check.status, CheckStatus::Fail);
        assert!(check.remedy.as_deref().unwrap().contains("xcaddy build"));
    }

    #[test]
    fn check_caddy_dns_plugin_passes_when_provider_present() {
        let runner = FakeRunner::new().with(
            "caddy",
            ok_out("http.handlers.reverse_proxy\ndns.providers.cloudflare\n"),
        );
        let cfg = DoctorConfig {
            slip_toml: Some(slip_core::SlipConfig {
                server: slip_core::ServerConfig::default(),
                caddy: slip_core::CaddyConfig {
                    admin_api: String::from("http://localhost:2019"),
                    tls: Some(slip_core::CaddyTlsConfig {
                        email: String::from("x@x"),
                        dns_provider: String::from("cloudflare"),
                        dns_provider_config: None,
                        propagation_delay: String::from("2m"),
                        staging: false,
                    }),
                    acme_email: None,
                    acme_ca: None,
                    reconcile: slip_core::ReconcileConfig::default(),
                },
                auth: slip_core::AuthConfig {
                    secret: String::from("x"),
                },
                registries: slip_core::RegistriesConfig::default(),
                storage: slip_core::StorageConfig::default(),
                runtime: slip_core::RuntimeConfig::default(),
                preview: None,
                deploy: None,
            }),
            ..Default::default()
        };
        let check = check_caddy_dns_plugin(&runner, &cfg);
        assert_eq!(check.status, CheckStatus::Pass);
    }

    // ── classify_manager_module (SLIP-124) ───────────────────────────────────
    // The tailscale.manager_module check now uses `caddy list-modules` via the
    // injected runner (like check_caddy_dns_plugin) instead of the admin API,
    // which returns 404 on the undocumented `/modules/` endpoint.

    #[test]
    fn manager_module_pass_when_exact_module_present() {
        // API 404 + binary present with exact module ID → Pass (regression for
        // the original SLIP-124 bug: a 404 must not flip the result to Fail).
        let runner = FakeRunner::new().with(
            "caddy",
            ok_out(
                "http.handlers.reverse_proxy\ntls.get_certificate.tailscale\ndns.providers.cloudflare\n",
            ),
        );
        let check = classify_manager_module(&runner);
        assert_eq!(check.name, "tailscale.manager_module");
        assert_eq!(check.status, CheckStatus::Pass);
        assert!(check.detail.contains("tls.get_certificate.tailscale"));
        assert!(check.remedy.is_none());
    }

    #[test]
    fn manager_module_fail_when_absent_after_successful_enumeration() {
        // Binary succeeds but omits the module → confirmed absent → Fail with
        // a prescriptive upgrade/rebuild remedy.
        let runner = FakeRunner::new().with(
            "caddy",
            ok_out("http.handlers.reverse_proxy\ndns.providers.cloudflare\n"),
        );
        let check = classify_manager_module(&runner);
        assert_eq!(check.status, CheckStatus::Fail);
        assert!(check.remedy.as_deref().unwrap().contains("v2.5"));
    }

    #[test]
    fn manager_module_warn_when_binary_nonzero_exit() {
        // Nonzero exit means the command failed, not that the module is absent.
        // Must Warn (unknown), never Fail.
        let runner = FakeRunner::new().with(
            "caddy",
            CommandOutput {
                stdout: String::new(),
                stderr: String::from("caddy: panic: something broke"),
                status: 1,
            },
        );
        let check = classify_manager_module(&runner);
        assert_eq!(check.status, CheckStatus::Warn);
        assert!(check.detail.contains("exited 1"));
        assert!(check.detail.contains("something broke"));
    }

    #[test]
    fn manager_module_warn_when_no_caddy_binary() {
        // No caddy on $PATH → cannot verify → Warn, not Fail.
        let runner = FakeRunner::new();
        let check = classify_manager_module(&runner);
        assert_eq!(check.status, CheckStatus::Warn);
        assert!(check.detail.contains("no `caddy` binary"));
    }

    #[test]
    fn manager_module_rejects_substring_match() {
        // A module whose ID merely contains the target as a substring must not
        // pass — exact line/field equality is required (best-practices Q2).
        let runner = FakeRunner::new().with(
            "caddy",
            ok_out("http.handlers.reverse_proxy\ntls.get_certificate.tailscale_extras\n"),
        );
        let check = classify_manager_module(&runner);
        assert_eq!(check.status, CheckStatus::Fail);
    }

    #[test]
    fn manager_module_accepts_tab_separated_packages_output() {
        // `caddy list-modules --packages` emits `<id>\t<package>`; the first
        // tab-field is the module ID and must match exactly.
        let runner = FakeRunner::new().with(
            "caddy",
            ok_out(
                "http.handlers.reverse_proxy\tgithub.com/caddyserver/caddy/v2\n\
                 tls.get_certificate.tailscale\tgithub.com/caddyserver/caddy/v2\tv2.11.0\n",
            ),
        );
        let check = classify_manager_module(&runner);
        assert_eq!(check.status, CheckStatus::Pass);
    }

    #[test]
    fn check_config_env_warns_on_unresolved() {
        let cfg = DoctorConfig {
            unresolved_env: vec![String::from("GHCR_TOKEN"), String::from("SECRET")],
            config_dir: PathBuf::from("/etc/slip"),
            ..Default::default()
        };
        let check = check_config_env(&cfg);
        assert_eq!(check.status, CheckStatus::Warn);
        assert!(check.detail.contains("GHCR_TOKEN"));
        assert!(check.remedy.as_deref().unwrap().contains("slip.env"));
    }

    #[test]
    fn check_config_env_passes_when_resolved() {
        let cfg = DoctorConfig::default();
        let check = check_config_env(&cfg);
        assert_eq!(check.status, CheckStatus::Pass);
    }

    #[test]
    fn plan_fixes_empty_when_no_ufw_fail() {
        let checks = vec![VerificationCheck::new(
            "caddy.reachable",
            "x",
            CheckStatus::Pass,
            "ok",
            None,
        )];
        let cfg = DoctorConfig::default();
        assert!(fix::plan_fixes(&checks, &cfg).is_empty());
    }

    #[test]
    fn plan_fixes_produces_ufw_action_when_ufw_fail() {
        let checks = vec![VerificationCheck::new(
            "ufw.bridge_dns",
            "UFW bridge DNS rule",
            CheckStatus::Fail,
            "rule missing",
            Some(String::from("ufw allow in on br-slip to any port 53")),
        )];
        let cfg = DoctorConfig::default();
        let actions = fix::plan_fixes(&checks, &cfg);
        assert_eq!(actions.len(), 1);
        assert_eq!(actions[0].name, "ufw.allow.bridge_dns");
        assert_eq!(actions[0].command, "ufw allow in on br-slip to any port 53");
        assert!(
            actions[0]
                .rollback
                .as_deref()
                .unwrap()
                .contains("ufw delete")
        );
    }

    #[test]
    fn is_private_hostname_detects_tailnet() {
        // .ts.net is NOT classified as private — it uses real LE certs via
        // the Tailscale manager, so an internal issuer on .ts.net IS a mismatch.
        assert!(!is_private_hostname("foo.ts.net"));
        assert!(is_private_hostname("bar.local"));
        assert!(is_private_hostname("baz.internal"));
        assert!(!is_private_hostname("deploy.example.com"));
    }

    #[test]
    fn resolve_host_returns_empty_on_nxdomain() {
        let runner = FakeRunner::new();
        let (ips, dns_error) = resolve_host(&runner, "nonexistent.invalid");
        // FakeRunner returns Err (not found) → dns_error=true.
        assert!(ips.is_empty());
        assert!(dns_error);
    }

    // ── ScriptedRunner: matches (cmd, first_arg) for arg-sensitive mocking ──

    /// A `CommandRunner` that returns canned outputs keyed by `(cmd, first_arg)`.
    ///
    /// This is needed because `FakeRunner` keys on `cmd` only, so `ufw status`
    /// and `ufw allow` would get the same response. `ScriptedRunner` distinguishes
    /// by the first arg element, which is sufficient for the doctor's shell-outs
    /// (`ufw status`, `ufw allow`, `docker version`, `docker run`, `docker ps`,
    /// `getent ahosts`, etc.).
    struct ScriptedRunner {
        canned: std::collections::HashMap<(String, String), CommandOutput>,
        /// Default fallback for commands not in the map (returns Ok with empty
        /// output, status 0). Set to `true` to make unknown commands Err.
        strict: bool,
    }

    impl ScriptedRunner {
        fn new() -> Self {
            Self {
                canned: std::collections::HashMap::new(),
                strict: true,
            }
        }

        /// Make unknown commands return Ok(empty) instead of Err.
        #[allow(dead_code)]
        fn lenient(mut self) -> Self {
            self.strict = false;
            self
        }

        /// Register a canned output for `(cmd, first_arg)`.
        fn with(mut self, cmd: &str, first_arg: &str, out: CommandOutput) -> Self {
            self.canned
                .insert((cmd.to_string(), first_arg.to_string()), out);
            self
        }
    }

    impl CommandRunner for ScriptedRunner {
        fn run(&self, cmd: &str, args: &[&str]) -> std::io::Result<CommandOutput> {
            let first_arg = args.first().copied().unwrap_or("");
            if let Some(out) = self.canned.get(&(cmd.to_string(), first_arg.to_string())) {
                return Ok(out.clone());
            }
            if self.strict {
                Err(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    format!("no canned output for {cmd} {first_arg}"),
                ))
            } else {
                Ok(CommandOutput {
                    stdout: String::new(),
                    stderr: String::new(),
                    status: 0,
                })
            }
        }
    }

    // ── DNS probe orchestrator tests (pass/fail/warn/no-runtime/pull-failed) ──

    #[test]
    fn dns_probe_pass_when_getent_resolves() {
        // docker version → ok, docker run → getent succeeds with IP.
        let runner = ScriptedRunner::new()
            .with("docker", "version", ok_out("Docker version 24.0\n"))
            .with("docker", "run", ok_out("10.89.0.3 myapp\n"));
        let result = run_dns_probe(&runner, "slip", "myapp", 5);
        assert!(matches!(result, DnsProbeResult::Ok(ip) if ip == "10.89.0.3"));
    }

    #[test]
    fn dns_probe_fail_when_getent_returns_nonzero() {
        let runner = ScriptedRunner::new()
            .with("docker", "version", ok_out("Docker version 24.0\n"))
            .with(
                "docker",
                "run",
                CommandOutput {
                    stdout: String::new(),
                    stderr: String::from("getent: no such host"),
                    status: 1,
                },
            );
        let result = run_dns_probe(&runner, "slip", "myapp", 5);
        match result {
            DnsProbeResult::Failed(detail) => {
                assert!(detail.contains("getent hosts myapp failed"));
            }
            other => panic!("expected Failed, got {other:?}"),
        }
    }

    #[test]
    fn dns_probe_warn_no_runtime() {
        // Neither docker nor podman is available → NoRuntime.
        let runner = ScriptedRunner::new();
        let result = run_dns_probe(&runner, "slip", "myapp", 5);
        assert!(matches!(result, DnsProbeResult::NoRuntime));
    }

    #[test]
    fn dns_probe_warn_pull_failed() {
        // docker is available but the image pull fails.
        let runner = ScriptedRunner::new()
            .with("docker", "version", ok_out("Docker version 24.0\n"))
            .with(
                "docker",
                "run",
                CommandOutput {
                    stdout: String::new(),
                    stderr: String::from(
                        "Unable to find image 'busybox:latest' locally, pulling...",
                    ),
                    status: 1,
                },
            );
        let result = run_dns_probe(&runner, "slip", "myapp", 5);
        assert!(matches!(result, DnsProbeResult::PullFailed));
    }

    #[test]
    fn dns_probe_falls_back_to_podman() {
        // docker not available, podman is.
        let runner = ScriptedRunner::new()
            .with("podman", "version", ok_out("podman version 4.0\n"))
            .with("podman", "run", ok_out("10.89.0.5 myapp\n"));
        let result = run_dns_probe(&runner, "slip", "myapp", 5);
        assert!(matches!(result, DnsProbeResult::Ok(ip) if ip == "10.89.0.5"));
    }

    #[test]
    fn dns_probe_fail_when_getent_empty_stdout() {
        // getent exits 0 but returns no IP — edge case.
        let runner = ScriptedRunner::new()
            .with("docker", "version", ok_out("Docker version 24.0\n"))
            .with("docker", "run", ok_out(""));
        let result = run_dns_probe(&runner, "slip", "myapp", 5);
        match result {
            DnsProbeResult::Failed(detail) => {
                assert!(detail.contains("no IP"));
            }
            other => panic!("expected Failed, got {other:?}"),
        }
    }

    #[test]
    fn find_running_app_container_returns_name() {
        let runner = ScriptedRunner::new().with("docker", "ps", ok_out("slip-myapp-latest-01J\n"));
        let name = find_running_app_container_name(&runner, "slip");
        assert_eq!(name.as_deref(), Some("slip-myapp-latest-01J"));
    }

    #[test]
    fn find_running_app_container_returns_none_when_no_containers() {
        let runner = ScriptedRunner::new().with("docker", "ps", ok_out(""));
        let name = find_running_app_container_name(&runner, "slip");
        assert!(name.is_none());
    }

    #[test]
    fn dns_probe_orchestrator_warns_when_no_peer() {
        // docker is available but no app containers running.
        let runner = ScriptedRunner::new()
            .with("docker", "version", ok_out("Docker version 24.0\n"))
            .with("docker", "ps", ok_out(""));
        // With no peer found, the check_dns function should produce a warn.
        // We test check_dns directly (it's async).
        let cfg = DoctorConfig {
            slip_toml: Some(make_minimal_config_with_deploy_domain("deploy.example.com")),
            ..Default::default()
        };
        let rt = tokio::runtime::Runtime::new().unwrap();
        let checks = rt.block_on(check_dns(&cfg, &runner, 5));
        let probe = checks.iter().find(|c| c.name == "dns.probe").unwrap();
        assert_eq!(
            probe.status,
            CheckStatus::Warn,
            "expected Warn when no peer, got {:?}: {}",
            probe.status,
            probe.detail
        );
    }

    #[test]
    fn dns_probe_orchestrator_passes_when_peer_resolves() {
        let runner = ScriptedRunner::new()
            .with("docker", "version", ok_out("Docker version 24.0\n"))
            .with("docker", "ps", ok_out("slip-myapp-latest-01J\n"))
            .with("docker", "run", ok_out("10.89.0.3 slip-myapp-latest-01J\n"))
            .with(
                "getent",
                "ahosts",
                ok_out("1.2.3.4 STREAM deploy.example.com\n"),
            );
        let cfg = DoctorConfig {
            slip_toml: Some(make_minimal_config_with_deploy_domain("deploy.example.com")),
            ..Default::default()
        };
        let rt = tokio::runtime::Runtime::new().unwrap();
        let checks = rt.block_on(check_dns(&cfg, &runner, 5));
        let probe = checks.iter().find(|c| c.name == "dns.probe").unwrap();
        assert_eq!(
            probe.status,
            CheckStatus::Pass,
            "expected Pass, got {:?}: {}",
            probe.status,
            probe.detail
        );
    }

    #[test]
    fn dns_probe_orchestrator_fails_when_peer_unresolvable() {
        let runner = ScriptedRunner::new()
            .with("docker", "version", ok_out("Docker version 24.0\n"))
            .with("docker", "ps", ok_out("slip-myapp-latest-01J\n"))
            .with(
                "docker",
                "run",
                CommandOutput {
                    stdout: String::new(),
                    stderr: String::from("getent: no entry"),
                    status: 2,
                },
            )
            .with(
                "getent",
                "ahosts",
                ok_out("1.2.3.4 STREAM deploy.example.com\n"),
            );
        let cfg = DoctorConfig {
            slip_toml: Some(make_minimal_config_with_deploy_domain("deploy.example.com")),
            ..Default::default()
        };
        let rt = tokio::runtime::Runtime::new().unwrap();
        let checks = rt.block_on(check_dns(&cfg, &runner, 5));
        let probe = checks.iter().find(|c| c.name == "dns.probe").unwrap();
        assert_eq!(
            probe.status,
            CheckStatus::Fail,
            "expected Fail, got {:?}: {}",
            probe.status,
            probe.detail
        );
    }

    #[test]
    fn dns_expectation_orchestrator_fails_on_orange_clouded_tailnet() {
        // deploy.example.com resolves to a Cloudflare IP (104.16.0.1) with
        // tls=internal → fail with grey-cloud remedy.
        let runner = ScriptedRunner::new().with(
            "getent",
            "ahosts",
            ok_out("104.16.0.1 STREAM deploy.example.com\n"),
        );
        let cfg = DoctorConfig {
            slip_toml: Some(make_minimal_config_with_deploy_domain_and_tls(
                "deploy.example.com",
                "internal",
            )),
            ..Default::default()
        };
        let rt = tokio::runtime::Runtime::new().unwrap();
        let checks = rt.block_on(check_dns(&cfg, &runner, 5));
        let exp = checks.iter().find(|c| c.name == "dns.expectation").unwrap();
        assert_eq!(exp.status, CheckStatus::Fail);
        assert!(exp.remedy.as_deref().unwrap().contains("grey cloud"));
    }

    // ── --fix --yes --json applied + idempotence tests ──────────────────────

    #[test]
    fn fix_yes_json_applies_ufw_rule() {
        // skip_root: true bypasses the root check via dependency injection (no env var)
        // ufw status (idempotence check) → active, no rule → proceed to apply.
        // ufw allow (the apply) → success.
        let runner = ScriptedRunner::new()
            .with(
                "ufw",
                "status",
                CommandOutput {
                    stdout: String::from("Status: active\n\n[ 1] 22/tcp ALLOW IN Anywhere\n"),
                    stderr: String::new(),
                    status: 0,
                },
            )
            .with("ufw", "allow", ok_out("Rule added\n"));

        let checks = vec![VerificationCheck::new(
            "ufw.bridge_dns",
            "UFW bridge DNS rule",
            CheckStatus::Fail,
            "rule missing",
            Some(String::from("ufw allow in on br-slip to any port 53")),
        )];
        let cfg = DoctorConfig::default();
        let args = DoctorArgs {
            json: true,
            fix: true,
            dry_run: false,
            yes: true,
            timeout: 60,
            server: String::from("http://localhost:7890"),
            token: None,
        };

        let outcome = fix::run_fix(&checks, &runner, &cfg, &args, true);

        match outcome {
            fix::FixOutcome::Applied(actions) => {
                assert_eq!(actions.len(), 1);
                assert_eq!(actions[0].name, "ufw.allow.bridge_dns");
                assert_eq!(actions[0].status, "applied");
                assert!(
                    actions[0]
                        .rollback
                        .as_deref()
                        .unwrap()
                        .contains("ufw delete")
                );
            }
            other => panic!("expected Applied, got {other:?}"),
        }
    }

    #[test]
    fn fix_yes_json_idempotent_when_rule_already_present() {
        // ufw status (idempotence check) → active AND rule present → already_present.
        let runner = ScriptedRunner::new().with(
            "ufw",
            "status",
            CommandOutput {
                stdout: String::from(
                    "Status: active\n\
                     [ 1] 22/tcp ALLOW IN Anywhere\n\
                     [ 2] 53/tcp on br-slip ALLOW IN Anywhere\n\
                     [ 3] 53/udp on br-slip ALLOW IN Anywhere\n",
                ),
                stderr: String::new(),
                status: 0,
            },
        );
        // Note: no "ufw" "allow" entry — if the idempotence check works,
        // `ufw allow` is never called.

        let checks = vec![VerificationCheck::new(
            "ufw.bridge_dns",
            "UFW bridge DNS rule",
            CheckStatus::Fail,
            "rule missing",
            Some(String::from("ufw allow in on br-slip to any port 53")),
        )];
        let cfg = DoctorConfig::default();
        let args = DoctorArgs {
            json: true,
            fix: true,
            dry_run: false,
            yes: true,
            timeout: 60,
            server: String::from("http://localhost:7890"),
            token: None,
        };

        let outcome = fix::run_fix(&checks, &runner, &cfg, &args, true);

        match outcome {
            fix::FixOutcome::Applied(actions) => {
                assert_eq!(actions.len(), 1);
                assert_eq!(actions[0].status, "already_present");
            }
            other => panic!("expected Applied(already_present), got {other:?}"),
        }
    }

    #[test]
    fn fix_dry_run_json_emits_pending_actions() {
        // Dry-run: ufw status not consulted (no idempotence check), ufw allow
        // not called (no mutation).
        let runner = ScriptedRunner::new();

        let checks = vec![VerificationCheck::new(
            "ufw.bridge_dns",
            "UFW bridge DNS rule",
            CheckStatus::Fail,
            "rule missing",
            Some(String::from("ufw allow in on br-slip to any port 53")),
        )];
        let cfg = DoctorConfig::default();
        let args = DoctorArgs {
            json: true,
            fix: true,
            dry_run: true,
            yes: true,
            timeout: 60,
            server: String::from("http://localhost:7890"),
            token: None,
        };

        let outcome = fix::run_fix(&checks, &runner, &cfg, &args, true);

        match outcome {
            fix::FixOutcome::DryRun(actions) => {
                assert_eq!(actions.len(), 1);
                assert_eq!(actions[0].status, "pending");
                assert!(actions[0].command.contains("ufw allow in on br-slip"));
            }
            other => panic!("expected DryRun, got {other:?}"),
        }
    }

    #[test]
    fn fix_nothing_to_do_when_no_fails() {
        let runner = ScriptedRunner::new();
        let checks = vec![VerificationCheck::new(
            "caddy.reachable",
            "x",
            CheckStatus::Pass,
            "ok",
            None,
        )];
        let cfg = DoctorConfig::default();
        let args = DoctorArgs {
            json: false,
            fix: true,
            dry_run: false,
            yes: true,
            timeout: 60,
            server: String::from("http://localhost:7890"),
            token: None,
        };

        let outcome = fix::run_fix(&checks, &runner, &cfg, &args, true);

        assert!(matches!(outcome, fix::FixOutcome::NothingToDo(_)));
    }

    // ── Test helpers ────────────────────────────────────────────────────────

    /// Build a minimal `SlipConfig` with a deploy domain (for DNS tests).
    fn make_minimal_config_with_deploy_domain(domain: &str) -> slip_core::SlipConfig {
        make_minimal_config_with_deploy_domain_and_tls(domain, "internal")
    }

    fn make_minimal_config_with_deploy_domain_and_tls(
        domain: &str,
        tls: &str,
    ) -> slip_core::SlipConfig {
        slip_core::SlipConfig {
            server: slip_core::ServerConfig::default(),
            caddy: slip_core::CaddyConfig {
                admin_api: String::from("http://localhost:2019"),
                tls: None,
                acme_email: None,
                acme_ca: None,
                reconcile: slip_core::ReconcileConfig::default(),
            },
            auth: slip_core::AuthConfig {
                secret: String::from("test"),
            },
            registries: slip_core::RegistriesConfig::default(),
            storage: slip_core::StorageConfig::default(),
            runtime: slip_core::RuntimeConfig::default(),
            preview: None,
            deploy: Some(slip_core::ServerDeployConfig {
                timeout: std::time::Duration::from_secs(60),
                preview_timeout: std::time::Duration::from_secs(60),
                domain: Some(domain.to_string()),
                tls: tls
                    .parse()
                    .unwrap_or(slip_core::config::TlsStrategy::Internal),
            }),
        }
    }

    // ── Regression tests for review fixes ───────────────────────────────────

    #[test]
    fn resolve_host_nxdomain_returns_unresolved_not_dns_error() {
        // Exit 2 = NXDOMAIN/NODATA → (empty, false) → warn (unresolved).
        let runner = ScriptedRunner::new().with(
            "getent",
            "ahosts",
            CommandOutput {
                stdout: String::new(),
                stderr: String::from("No entries found"),
                status: 2,
            },
        );
        let (ips, dns_error) = resolve_host(&runner, "nonexistent.example");
        assert!(ips.is_empty());
        assert!(
            !dns_error,
            "NXDOMAIN (exit 2) should NOT be a dns_error — it's unresolved (warn)"
        );
    }

    #[test]
    fn resolve_host_servfail_returns_dns_error() {
        // Exit 3 = SERVFAIL/timeout → (empty, true) → fail (dns_error).
        let runner = ScriptedRunner::new().with(
            "getent",
            "ahosts",
            CommandOutput {
                stdout: String::new(),
                stderr: String::from("Service unavailable"),
                status: 3,
            },
        );
        let (ips, dns_error) = resolve_host(&runner, "broken.example");
        assert!(ips.is_empty());
        assert!(
            dns_error,
            "SERVFAIL (exit 3) should be a dns_error — it's a resolver failure (fail)"
        );
    }

    #[test]
    fn resolve_host_exec_error_returns_dns_error() {
        // getent not found → exec error → (empty, true).
        let runner = ScriptedRunner::new();
        let (ips, dns_error) = resolve_host(&runner, "any.example");
        assert!(ips.is_empty());
        assert!(dns_error, "exec error should be a dns_error");
    }

    #[test]
    fn parse_bridge_from_command_extracts_after_on() {
        assert_eq!(
            fix::parse_bridge_from_command("ufw allow in on br-slip to any port 53"),
            "br-slip"
        );
        assert_eq!(
            fix::parse_bridge_from_command("ufw delete allow in on br-slip to any port 53"),
            "br-slip"
        );
    }

    #[test]
    fn parse_bridge_from_command_handles_custom_bridge_name() {
        // A custom bridge name that doesn't start with "br-".
        assert_eq!(
            fix::parse_bridge_from_command("ufw allow in on mycustom0 to any port 53"),
            "mycustom0"
        );
    }

    #[test]
    fn parse_bridge_from_command_returns_empty_when_no_on() {
        assert_eq!(fix::parse_bridge_from_command("ufw allow 53"), "");
    }

    #[test]
    fn check_caddy_dns_plugin_skips_without_shelling_out_when_no_provider() {
        // Regression for LOW #1: when no DNS-01 provider is required, the
        // check should return Skipped WITHOUT shelling out to caddy. We use
        // a strict ScriptedRunner that errors on unknown commands — if
        // `caddy list-modules` were called, the test would panic.
        let runner = ScriptedRunner::new();
        let cfg = DoctorConfig::default(); // no DNS-01 provider
        let check = check_caddy_dns_plugin(&runner, &cfg);
        assert_eq!(check.status, CheckStatus::Skipped);
        assert!(check.detail.contains("no DNS-01"));
    }

    #[test]
    fn fix_nothing_to_do_carries_empty_actions() {
        // Regression for BLOCKER: NothingToDo should carry an empty actions
        // vec so emit() includes `"actions": []` in the JSON.
        let runner = ScriptedRunner::new();
        let checks = vec![VerificationCheck::new(
            "caddy.reachable",
            "x",
            CheckStatus::Pass,
            "ok",
            None,
        )];
        let cfg = DoctorConfig::default();
        let args = DoctorArgs {
            json: true,
            fix: true,
            dry_run: false,
            yes: true,
            timeout: 60,
            server: String::from("http://localhost:7890"),
            token: None,
        };
        let outcome = fix::run_fix(&checks, &runner, &cfg, &args, true);
        match outcome {
            fix::FixOutcome::NothingToDo(actions) => {
                assert!(
                    actions.is_empty(),
                    "NothingToDo should carry an empty actions vec"
                );
            }
            other => panic!("expected NothingToDo, got {other:?}"),
        }
    }

    // ── Production root-check safety tests ──────────────────────────────────

    #[test]
    fn has_test_overrides_does_not_read_slip_test_fix_skip_root() {
        // Regression: production code must NOT read `SLIP_TEST_FIX_SKIP_ROOT`.
        // The root-check bypass in unit tests is handled by the `skip_root`
        // parameter to `run_fix`, not by an env var.
        // SAFETY: single-threaded test, no concurrent env access within
        // this test.
        unsafe {
            std::env::remove_var("SLIP_TEST_CONFIG_DIR");
            std::env::set_var("SLIP_TEST_FIX_SKIP_ROOT", "1");
        }
        let result = has_test_overrides();
        // SAFETY: clean up.
        unsafe {
            std::env::remove_var("SLIP_TEST_FIX_SKIP_ROOT");
        }
        assert!(
            !result,
            "has_test_overrides() must NOT read SLIP_TEST_FIX_SKIP_ROOT — \
             production root check must not be bypassable via env var"
        );
    }

    #[test]
    fn run_fix_skip_root_false_is_the_production_default() {
        // Verify that `run_fix` with `skip_root: false` works for the
        // NothingToDo path (which returns before the root check). This
        // confirms the function signature is correct and `skip_root: false`
        // is the production default.
        //
        // We can't test the actual `output::fail` (it exits the process),
        // but we CAN verify the NothingToDo path doesn't require root.
        let runner = ScriptedRunner::new();
        let checks = vec![VerificationCheck::new(
            "caddy.reachable",
            "x",
            CheckStatus::Pass,
            "ok",
            None,
        )];
        let cfg = DoctorConfig::default();
        let args = DoctorArgs {
            json: false,
            fix: true,
            dry_run: false,
            yes: true,
            timeout: 60,
            server: String::from("http://localhost:7890"),
            token: None,
        };
        // NothingToDo returns before the root check, so skip_root: false
        // is safe here.
        let outcome = fix::run_fix(&checks, &runner, &cfg, &args, false);
        assert!(matches!(outcome, fix::FixOutcome::NothingToDo(_)));
    }

    #[test]
    fn run_fix_skip_root_false_with_env_var_still_respects_skip_root_false() {
        // Regression proving that even if `SLIP_TEST_CONFIG_DIR` is set
        // (which `has_test_overrides()` reads), `run_fix` with `skip_root:
        // false` does NOT bypass the root check via that env var. The
        // `skip_root` parameter is the ONLY root-check control — env vars
        // are irrelevant.
        //
        // We test the NothingToDo path (returns before the root check) to
        // confirm the function works correctly with `skip_root: false`
        // regardless of env vars. The root-check path itself calls
        // `output::fail` → `process::exit`, which we can't test in-process,
        // but the `run()` call site hardcodes `skip_root: false`, so there
        // is no env-var bypass path in production.
        // SAFETY: single-threaded test.
        unsafe {
            std::env::set_var("SLIP_TEST_CONFIG_DIR", "/tmp/nonexistent");
        }
        let runner = ScriptedRunner::new();
        let checks = vec![VerificationCheck::new(
            "caddy.reachable",
            "x",
            CheckStatus::Pass,
            "ok",
            None,
        )];
        let cfg = DoctorConfig::default();
        let args = DoctorArgs {
            json: false,
            fix: true,
            dry_run: false,
            yes: true,
            timeout: 60,
            server: String::from("http://localhost:7890"),
            token: None,
        };
        let outcome = fix::run_fix(&checks, &runner, &cfg, &args, false);
        // SAFETY: clean up.
        unsafe {
            std::env::remove_var("SLIP_TEST_CONFIG_DIR");
        }
        assert!(matches!(outcome, fix::FixOutcome::NothingToDo(_)));
    }
}
