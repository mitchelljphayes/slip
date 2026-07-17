//! `slip server init` — bootstrap a fresh slipd server.
//!
//! Generates an admin secret, writes `/etc/slip/slip.toml`, installs a hardened
//! systemd unit, starts slipd, verifies the full stack, emits a secret-free
//! server manifest, and prints next steps.
//!
//! ## Testability
//!
//! All system paths are overridable via `SLIP_TEST_*` env vars:
//! - `SLIP_TEST_CONFIG_DIR` — overrides `/etc/slip`
//! - `SLIP_TEST_SYSTEMD_DIR` — overrides `/etc/systemd/system`
//! - `SLIP_TEST_ENV_FILE` — overrides the env file path
//! - `SLIP_TEST_MANIFEST_DIR` — overrides the manifest output directory
//!
//! When any `SLIP_TEST_*` override is set, the root check is skipped AND
//! systemctl calls are skipped (the unit is still written to the test dir).
//! `--no-systemd` skips unit install and service start entirely.

use std::io::IsTerminal;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use clap::ValueEnum;

use slip_core::doctor::{CheckStatus, VerificationCheck};

use crate::output;

// ─── Public types ──────────────────────────────────────────────────────────────

/// Flags for `slip server init`.
#[derive(Debug, Clone)]
pub struct ServerInitOpts {
    /// Deploy webhook domain (e.g. deploy.example.com).
    pub domain: Option<String>,
    /// TLS strategy (default: "internal").
    pub tls: String,
    /// Container runtime backend (default: "auto").
    pub runtime: String,
    /// Non-interactive: use defaults, never prompt.
    pub yes: bool,
    /// Force overwrite specific components (empty = none, unless force_all).
    pub force: Vec<ForceTarget>,
    /// --force was passed with no value (force all).
    pub force_all: bool,
    /// Skip systemd unit install and service start.
    pub no_systemd: bool,
    /// Skip the verification step.
    pub skip_verify: bool,
    /// Initialize from a server manifest (disaster recovery).
    pub from_file: Option<PathBuf>,
    /// Emit JSON output.
    pub json: bool,
}

/// Components that can be force-overwritten.
#[derive(Debug, Clone, PartialEq, Eq, ValueEnum)]
pub enum ForceTarget {
    Config,
    Secret,
    Unit,
    /// Stop, disable, re-enable, and start the systemd service.
    Service,
    /// Force all components.
    All,
}

// `CheckStatus` and `VerificationCheck` are imported from `slip_core::doctor`
// (see the `use` block at the top of this file). They used to be defined here;
// promoting them to `slip-core` keeps `slip server init --verify` and
// `slip doctor` on one shared schema (SLIP-102).

// ─── Constants ─────────────────────────────────────────────────────────────────

const CONFIG_DIR_DEFAULT: &str = "/etc/slip";
const SYSTEMD_DIR_DEFAULT: &str = "/etc/systemd/system";
const ENV_FILE_NAME: &str = "slip.env";
const CONFIG_FILE_NAME: &str = "slip.toml";
const UNIT_FILE_NAME: &str = "slipd.service";

/// The systemd unit template.
/// `{prefix}` and `{config_dir}` are substituted at write time.
const UNIT_TEMPLATE: &str = r#"[Unit]
Description=slip deploy daemon
After=network-online.target podman.service docker.service caddy.service
Wants=network-online.target

[Service]
Type=simple
User=root
EnvironmentFile={config_dir}/slip.env
ExecStart={prefix}/bin/slipd --config {config_dir}
Restart=on-failure
RestartSec=3
RestartPreventExitStatus=78
Environment="RUST_LOG=info"
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=/var/lib/slip {config_dir}
ProtectHome=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
"#;

// ─── Helpers ────────────────────────────────────────────────────────────────────

/// Resolve the config directory: `SLIP_TEST_CONFIG_DIR` env > default.
fn config_dir() -> PathBuf {
    std::env::var("SLIP_TEST_CONFIG_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(CONFIG_DIR_DEFAULT))
}

/// Resolve the systemd directory: `SLIP_TEST_SYSTEMD_DIR` env > default.
fn systemd_dir() -> PathBuf {
    std::env::var("SLIP_TEST_SYSTEMD_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(SYSTEMD_DIR_DEFAULT))
}

/// Resolve the env file path: `SLIP_TEST_ENV_FILE` env > default.
fn env_file_path() -> PathBuf {
    std::env::var("SLIP_TEST_ENV_FILE")
        .map(PathBuf::from)
        .unwrap_or_else(|_| config_dir().join(ENV_FILE_NAME))
}

/// Resolve the manifest output directory: `SLIP_TEST_MANIFEST_DIR` env > cwd.
fn manifest_dir() -> PathBuf {
    std::env::var("SLIP_TEST_MANIFEST_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")))
}

/// Are any test overrides active?
fn has_test_overrides() -> bool {
    std::env::var("SLIP_TEST_CONFIG_DIR").is_ok()
        || std::env::var("SLIP_TEST_SYSTEMD_DIR").is_ok()
        || std::env::var("SLIP_TEST_ENV_FILE").is_ok()
        || std::env::var("SLIP_TEST_MANIFEST_DIR").is_ok()
}

/// Check that we are running as root (unless test overrides are set).
fn check_root() {
    if has_test_overrides() {
        return;
    }
    let euid = nix::unistd::geteuid();
    if !euid.is_root() {
        output::fail(
            output::GENERIC,
            "`slip server init` must be run as root",
            "re-run with sudo",
        );
    }
}

/// Generate a 64-hex-char admin secret (32 random bytes).
fn generate_secret() -> String {
    let mut buf = [0u8; 32];
    getrandom::getrandom(&mut buf).expect("getrandom should not fail on Linux");
    hex::encode(buf)
}

/// Create a directory with 0o700 permissions (recursive).
fn create_dir_mode_700(dir: &Path) -> Result<(), anyhow::Error> {
    std::fs::create_dir_all(dir)?;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    Ok(())
}

/// Write the env file with the admin secret.
///
/// Mode 0o600 set atomically via `OpenOptionsExt::mode`, tempfile in same dir,
/// fsync, rename.  Parent dir is created with 0o700.
fn write_env_file(path: &Path, secret: &str) -> Result<(), anyhow::Error> {
    let dir = path.parent().unwrap_or(Path::new("/"));
    create_dir_mode_700(dir)?;

    let temp_name = format!(
        ".{}",
        path.file_name().unwrap_or_default().to_string_lossy()
    );
    let temp_path = dir.join(&temp_name);

    let content = format!("SLIP_ADMIN_SECRET={secret}\n");

    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temp_path)?;
    std::io::Write::write_all(&mut file, content.as_bytes())?;
    file.sync_all()?;
    std::fs::rename(&temp_path, path)?;

    Ok(())
}

/// Write the server config TOML.
///
/// Mode 0o644, atomic write.
fn write_config(
    dir: &Path,
    domain: Option<&str>,
    tls: &str,
    runtime: &str,
    listen: Option<&str>,
    admin_api: Option<&str>,
    acme_email: Option<&str>,
) -> Result<PathBuf, anyhow::Error> {
    let path = dir.join(CONFIG_FILE_NAME);
    let temp_path = dir.join(format!(".{}.tmp", CONFIG_FILE_NAME));

    let effective_listen = listen.unwrap_or("127.0.0.1:7890");
    let effective_admin = admin_api.unwrap_or("http://localhost:2019");

    let mut toml = String::new();
    toml.push_str("[server]\n");
    toml.push_str(&format!("listen = \"{effective_listen}\"\n\n"));
    toml.push_str("[runtime]\n");
    toml.push_str(&format!("backend = \"{runtime}\"\n\n"));
    toml.push_str("[caddy]\n");
    toml.push_str(&format!("admin_api = \"{effective_admin}\"\n"));
    if let Some(email) = acme_email {
        // Escape backslashes and quotes for safe TOML string serialization.
        let escaped = email.replace('\\', "\\\\").replace('"', "\\\"");
        toml.push_str(&format!("acme_email = \"{escaped}\"\n"));
    }
    toml.push('\n');
    toml.push_str("[auth]\n");
    toml.push_str("secret = \"${SLIP_ADMIN_SECRET}\"\n\n");
    toml.push_str("[storage]\n");
    toml.push_str("path = \"/var/lib/slip\"\n");

    if let Some(d) = domain {
        toml.push_str("\n[deploy]\n");
        toml.push_str(&format!("domain = \"{d}\"\n"));
        toml.push_str(&format!("tls = \"{tls}\"\n"));
    }

    std::fs::create_dir_all(dir)?;
    std::fs::write(&temp_path, &toml)?;
    std::fs::set_permissions(&temp_path, std::fs::Permissions::from_mode(0o644))?;
    let file = std::fs::File::open(&temp_path)?;
    file.sync_all()?;
    std::fs::rename(&temp_path, &path)?;

    Ok(path)
}

/// Write the systemd unit file.
///
/// Mode 0o644, atomic write.
fn write_unit(dir: &Path, prefix: &str, config_dir: &str) -> Result<PathBuf, anyhow::Error> {
    let path = dir.join(UNIT_FILE_NAME);
    let temp_path = dir.join(format!(".{}.tmp", UNIT_FILE_NAME));

    let content = UNIT_TEMPLATE
        .replace("{prefix}", prefix)
        .replace("{config_dir}", config_dir);

    std::fs::create_dir_all(dir)?;
    std::fs::write(&temp_path, &content)?;
    std::fs::set_permissions(&temp_path, std::fs::Permissions::from_mode(0o644))?;
    let file = std::fs::File::open(&temp_path)?;
    file.sync_all()?;
    std::fs::rename(&temp_path, &path)?;

    Ok(path)
}

/// Check if a file exists and has the same content as what we would write.
fn file_matches(path: &Path, expected: &str) -> bool {
    std::fs::read_to_string(path)
        .ok()
        .is_some_and(|actual| actual == expected)
}

/// Read the unit template with substitutions for comparison.
fn unit_content(prefix: &str, config_dir: &str) -> String {
    UNIT_TEMPLATE
        .replace("{prefix}", prefix)
        .replace("{config_dir}", config_dir)
}

/// Enable and start the systemd service, polling until active or failed.
fn install_and_start_service() -> Result<(), anyhow::Error> {
    // daemon-reload
    let status = std::process::Command::new("systemctl")
        .arg("daemon-reload")
        .status()
        .map_err(|e| anyhow::anyhow!("failed to run systemctl daemon-reload: {e}"))?;
    if !status.success() {
        anyhow::bail!(
            "systemctl daemon-reload failed (exit {})",
            status.code().unwrap_or(-1)
        );
    }

    // enable --now
    let status = std::process::Command::new("systemctl")
        .args(["enable", "--now", "slipd.service"])
        .status()
        .map_err(|e| anyhow::anyhow!("failed to run systemctl enable --now: {e}"))?;
    if !status.success() {
        anyhow::bail!(
            "systemctl enable --now slipd.service failed (exit {})",
            status.code().unwrap_or(-1)
        );
    }

    // Poll for active state
    poll_service_active()
}

/// Poll `systemctl is-active slipd.service` until active, failed, or timeout.
fn poll_service_active() -> Result<(), anyhow::Error> {
    let max_polls = 20; // 10 seconds at 500ms intervals
    for _ in 0..max_polls {
        let output = std::process::Command::new("systemctl")
            .args(["is-active", "slipd.service"])
            .output()
            .map_err(|e| anyhow::anyhow!("failed to check service status: {e}"))?;

        let state = String::from_utf8_lossy(&output.stdout).trim().to_string();
        match state.as_str() {
            "active" => return Ok(()),
            "failed" => {
                let journal = std::process::Command::new("journalctl")
                    .args(["-u", "slipd.service", "-n", "20", "--no-pager"])
                    .output()
                    .ok()
                    .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
                    .unwrap_or_default();
                anyhow::bail!(
                    "slipd.service entered 'failed' state. Journal output:\n{journal}\n  → check the logs above for the cause"
                );
            }
            _ => {
                std::thread::sleep(std::time::Duration::from_millis(500));
            }
        }
    }
    anyhow::bail!(
        "timed out waiting for slipd.service to become active (10s)\n  → check `journalctl -u slipd -f` for details"
    );
}

/// Restart the systemd service (for --force=service).
fn restart_service() -> Result<(), anyhow::Error> {
    let status = std::process::Command::new("systemctl")
        .args(["restart", "slipd.service"])
        .status()
        .map_err(|e| anyhow::anyhow!("failed to run systemctl restart: {e}"))?;
    if !status.success() {
        anyhow::bail!(
            "systemctl restart slipd.service failed (exit {})",
            status.code().unwrap_or(-1)
        );
    }
    poll_service_active()
}

/// Get the hostname for the manifest filename.
fn get_hostname() -> String {
    std::process::Command::new("hostname")
        .output()
        .ok()
        .and_then(|o| {
            if o.status.success() {
                Some(String::from_utf8_lossy(&o.stdout).trim().to_string())
            } else {
                None
            }
        })
        .unwrap_or_else(|| "server".to_string())
}

/// Emit the server manifest (secret-free) to the manifest directory.
/// Also writes a DR copy to the config dir.
fn emit_manifest(
    opts: &ServerInitOpts,
    hostname: &str,
    listen: Option<&str>,
    admin_api: Option<&str>,
    acme_email: Option<&str>,
) -> Result<PathBuf, anyhow::Error> {
    let dir = manifest_dir();
    let path = dir.join(format!("{hostname}.slip.toml"));

    let force_manifest = opts.force_all || opts.force.contains(&ForceTarget::Config);

    if path.exists() && !force_manifest {
        eprintln!(
            "✓ {} already present (use --force=config to overwrite)",
            path.display()
        );
        return Ok(path);
    }

    let effective_listen = listen.unwrap_or("127.0.0.1:7890");
    let effective_admin = admin_api.unwrap_or("http://localhost:2019");

    let mut toml = format!(
        "# {hostname}.slip.toml — slip server manifest\n\
         # Generated by `slip server init` on {timestamp}.\n\
         # Commit this to your infrastructure repo.\n\
         # NOTE: This is a subset of the full manifest schema.\n\
         # See docs/draft-iac-with-slip.md for the complete schema.\n\n",
        timestamp = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ")
    );

    toml.push_str("[server]\n");
    toml.push_str(&format!("listen = \"{effective_listen}\"\n\n"));

    toml.push_str("[runtime]\n");
    toml.push_str(&format!("backend = \"{}\"\n\n", opts.runtime));

    toml.push_str("[caddy]\n");
    toml.push_str(&format!("admin_api = \"{effective_admin}\"\n"));
    if let Some(email) = acme_email {
        let escaped = email.replace('\\', "\\\\").replace('"', "\\\"");
        toml.push_str(&format!("acme_email = \"{escaped}\"\n"));
    }

    if let Some(ref domain) = opts.domain {
        toml.push_str("\n[deploy]\n");
        toml.push_str(&format!("domain = \"{domain}\"\n"));
        toml.push_str(&format!("tls = \"{}\"\n", opts.tls));
    }

    std::fs::write(&path, &toml)?;

    // Write DR copy to config dir
    let cfg_dir = config_dir();
    let dr_path = cfg_dir.join("server.toml");
    std::fs::write(&dr_path, &toml)?;

    Ok(path)
}

/// Parse a manifest file and extract values for init.
fn parse_manifest(path: &Path) -> Result<ManifestValues, anyhow::Error> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("failed to read manifest '{}': {e}", path.display()))?;
    let value: toml::Value = content
        .parse()
        .map_err(|e| anyhow::anyhow!("failed to parse manifest '{}': {e}", path.display()))?;

    let mut result = ManifestValues::default();

    if let Some(deploy) = value.get("deploy") {
        result.domain = deploy
            .get("domain")
            .and_then(|v| v.as_str().map(String::from));
        result.tls = deploy.get("tls").and_then(|v| v.as_str().map(String::from));
    }
    if let Some(caddy) = value.get("caddy") {
        result.admin_api = caddy
            .get("admin_api")
            .and_then(|v| v.as_str().map(String::from));
        result.acme_email = caddy
            .get("acme_email")
            .and_then(|v| v.as_str().map(String::from));
    }
    if let Some(server) = value.get("server") {
        result.listen = server
            .get("listen")
            .and_then(|v| v.as_str().map(String::from));
    }
    if let Some(runtime) = value.get("runtime") {
        result.runtime = runtime
            .get("backend")
            .and_then(|v| v.as_str().map(String::from));
    }

    Ok(result)
}

#[derive(Debug, Default)]
struct ManifestValues {
    domain: Option<String>,
    tls: Option<String>,
    admin_api: Option<String>,
    listen: Option<String>,
    runtime: Option<String>,
    acme_email: Option<String>,
}

/// Print next steps for the user.
/// Returns a JSON value for the single-envelope output when `json` is true.
fn print_next_steps(
    manifest_path: &Path,
    env_path: &Path,
    secret_written: bool,
    json: bool,
) -> Option<serde_json::Value> {
    let save_token_step = if secret_written && !json {
        "Save the admin token (shown above) in your password manager"
    } else {
        "Save the admin token from the env file in your password manager"
    };
    if json {
        let out = serde_json::json!({
            "manifest": manifest_path.to_string_lossy(),
            "secret_file": env_path.to_string_lossy(),
            "next_steps": [
                "Commit the manifest to your infrastructure repo",
                save_token_step,
                "Run `slip init` in your app repo to create a slip.toml",
                "Run `slip link --server <URL> --app <name>` to bind the repo",
                "Run `slip key --app <name>` to generate a deploy key"
            ]
        });
        Some(out)
    } else {
        println!();
        println!("Next steps:");
        println!(
            "  1. Commit the manifest ({}) to your infrastructure repo",
            manifest_path.display()
        );
        println!("  2. {save_token_step}");
        println!("  3. Run `slip init` in your app repo to create a slip.toml");
        println!("  4. Run `slip link --server <URL> --app <name>` to bind the repo");
        println!("  5. Run `slip key --app <name>` to generate a deploy key");
        None
    }
}

// ─── Verification ──────────────────────────────────────────────────────────────

/// Run all verification checks.
fn run_verification(opts: &ServerInitOpts) -> Vec<VerificationCheck> {
    let mut checks = Vec::new();

    checks.push(check_caddy_reachable());

    checks.push(check_slip_server_block());

    if opts.domain.is_some() {
        checks.push(check_deploy_webhook_route());
    }

    if opts.domain.is_some() {
        checks.push(check_tls_policy(opts.domain.as_deref().unwrap_or("")));
    }

    checks.push(check_runtime_socket(&opts.runtime));

    if !opts.no_systemd {
        checks.push(check_slipd_active());
    }

    if let Some(ref domain) = opts.domain {
        checks.push(check_webhook_https(domain));
    }

    checks
}

fn check_caddy_reachable() -> VerificationCheck {
    let admin_api = "http://localhost:2019";
    // Run blocking reqwest in a separate thread to avoid tokio runtime panic on drop
    let result = std::thread::spawn(move || {
        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .unwrap();
        client.get(format!("{admin_api}/config/")).send()
    })
    .join()
    .unwrap();
    match result {
        Ok(resp) if resp.status().is_success() => VerificationCheck {
            name: "caddy_reachable".into(),
            label: "Caddy admin API reachable".into(),
            status: CheckStatus::Pass,
            detail: format!("GET {admin_api}/config/ → {}", resp.status()),
            remedy: None,
        },
        Ok(resp) => VerificationCheck {
            name: "caddy_reachable".into(),
            label: "Caddy admin API reachable".into(),
            status: CheckStatus::Fail,
            detail: format!("GET {admin_api}/config/ → {}", resp.status()),
            remedy: Some("is Caddy running? systemctl status caddy".into()),
        },
        Err(e) => VerificationCheck {
            name: "caddy_reachable".into(),
            label: "Caddy admin API reachable".into(),
            status: CheckStatus::Fail,
            detail: format!("connection error: {e}"),
            remedy: Some("is Caddy running? systemctl status caddy".into()),
        },
    }
}

fn check_slip_server_block() -> VerificationCheck {
    let admin_api = "http://localhost:2019";
    let result = std::thread::spawn(move || {
        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .unwrap();
        client
            .get(format!("{admin_api}/config/apps/http/servers/slip"))
            .send()
    })
    .join()
    .unwrap();
    match result {
        Ok(resp) if resp.status().is_success() => VerificationCheck {
            name: "slip_server_block".into(),
            label: "slip HTTP server block exists".into(),
            status: CheckStatus::Pass,
            detail: "slip server block found in Caddy config".into(),
            remedy: None,
        },
        Ok(resp) => VerificationCheck {
            name: "slip_server_block".into(),
            label: "slip HTTP server block exists".into(),
            status: CheckStatus::Fail,
            detail: format!("GET /config/apps/http/servers/slip → {}", resp.status()),
            remedy: Some("check journalctl -u slipd for bootstrap errors".into()),
        },
        Err(e) => VerificationCheck {
            name: "slip_server_block".into(),
            label: "slip HTTP server block exists".into(),
            status: CheckStatus::Fail,
            detail: format!("connection error: {e}"),
            remedy: Some("check journalctl -u slipd for bootstrap errors".into()),
        },
    }
}

fn check_deploy_webhook_route() -> VerificationCheck {
    let admin_api = "http://localhost:2019";
    let result = std::thread::spawn(move || {
        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .unwrap();
        client
            .get(format!("{admin_api}/id/slip-deploy-webhook"))
            .send()
    })
    .join()
    .unwrap();
    match result {
        Ok(resp) if resp.status().is_success() => VerificationCheck {
            name: "deploy_webhook_route".into(),
            label: "Deploy webhook route registered".into(),
            status: CheckStatus::Pass,
            detail: "slip-deploy-webhook route found".into(),
            remedy: None,
        },
        Ok(resp) => VerificationCheck {
            name: "deploy_webhook_route".into(),
            label: "Deploy webhook route registered".into(),
            status: CheckStatus::Fail,
            detail: format!("GET /id/slip-deploy-webhook → {}", resp.status()),
            remedy: Some("check journalctl -u slipd for deploy bootstrap errors".into()),
        },
        Err(e) => VerificationCheck {
            name: "deploy_webhook_route".into(),
            label: "Deploy webhook route registered".into(),
            status: CheckStatus::Fail,
            detail: format!("connection error: {e}"),
            remedy: Some("check journalctl -u slipd for deploy bootstrap errors".into()),
        },
    }
}

fn check_tls_policy(domain: &str) -> VerificationCheck {
    let admin_api = "http://localhost:2019";
    let domain = domain.to_string();
    let result = std::thread::spawn(move || {
        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .unwrap();
        client
            .get(format!("{admin_api}/config/apps/tls/automation/policies"))
            .send()
    })
    .join()
    .unwrap();
    match result {
        Ok(resp) => {
            let body = resp.text().unwrap_or_default();
            if body.contains(&domain) {
                VerificationCheck {
                    name: "tls_policy".into(),
                    label: "TLS automation policy for domain".into(),
                    status: CheckStatus::Pass,
                    detail: format!("TLS policy found for {domain}"),
                    remedy: None,
                }
            } else {
                VerificationCheck {
                    name: "tls_policy".into(),
                    label: "TLS automation policy for domain".into(),
                    status: CheckStatus::Warn,
                    detail: format!("TLS policy for {domain} not found in automation policies"),
                    remedy: Some(
                        "may still be propagating; run `slip server init` again in a few seconds"
                            .into(),
                    ),
                }
            }
        }
        Err(e) => VerificationCheck {
            name: "tls_policy".into(),
            label: "TLS automation policy for domain".into(),
            status: CheckStatus::Warn,
            detail: format!("could not check TLS policies: {e}"),
            remedy: Some(
                "may still be propagating; run `slip server init` again in a few seconds".into(),
            ),
        },
    }
}

fn check_runtime_socket(runtime: &str) -> VerificationCheck {
    let effective_runtime = if runtime == "auto" {
        if Path::new("/run/podman/podman.sock").exists()
            || Path::new("/var/run/podman/podman.sock").exists()
        {
            "podman"
        } else if Path::new("/var/run/docker.sock").exists() {
            "docker"
        } else {
            "auto"
        }
    } else {
        runtime
    };

    let socket_path = match effective_runtime {
        "podman" => {
            let paths = ["/run/podman/podman.sock", "/var/run/podman/podman.sock"];
            paths.iter().find(|p| Path::new(p).exists()).copied()
        }
        "docker" => {
            if Path::new("/var/run/docker.sock").exists() {
                Some("/var/run/docker.sock")
            } else {
                None
            }
        }
        _ => None,
    };

    match socket_path {
        Some(path) => VerificationCheck {
            name: "runtime_socket".into(),
            label: format!("{effective_runtime} socket reachable"),
            status: CheckStatus::Pass,
            detail: format!("socket found at {path}"),
            remedy: None,
        },
        None => VerificationCheck {
            name: "runtime_socket".into(),
            label: format!("{effective_runtime} socket reachable"),
            status: CheckStatus::Warn,
            detail: format!("{effective_runtime} socket not found"),
            remedy: Some(format!(
                "ensure {effective_runtime} is installed and the socket exists, or use --runtime to specify"
            )),
        },
    }
}

fn check_slipd_active() -> VerificationCheck {
    let output = std::process::Command::new("systemctl")
        .args(["is-active", "slipd.service"])
        .output();

    match output {
        Ok(o) => {
            let state = String::from_utf8_lossy(&o.stdout).trim().to_string();
            if state == "active" {
                VerificationCheck {
                    name: "slipd_active".into(),
                    label: "slipd service active".into(),
                    status: CheckStatus::Pass,
                    detail: "slipd.service is active".into(),
                    remedy: None,
                }
            } else {
                VerificationCheck {
                    name: "slipd_active".into(),
                    label: "slipd service active".into(),
                    status: CheckStatus::Fail,
                    detail: format!("slipd.service is {state}"),
                    remedy: Some("check `journalctl -u slipd -f` for errors".into()),
                }
            }
        }
        Err(e) => VerificationCheck {
            name: "slipd_active".into(),
            label: "slipd service active".into(),
            status: CheckStatus::Fail,
            detail: format!("could not check service status: {e}"),
            remedy: Some("is systemd available?".into()),
        },
    }
}

fn check_webhook_https(domain: &str) -> VerificationCheck {
    let url = format!("https://{domain}/v1/status");
    let url_for_closure = url.clone();
    let result = std::thread::spawn(move || {
        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .danger_accept_invalid_certs(true)
            .build()
            .unwrap();
        client.get(&url_for_closure).send()
    })
    .join()
    .unwrap();
    match result {
        Ok(resp) => VerificationCheck {
            name: "webhook_https".into(),
            label: "Webhook reachable over HTTPS".into(),
            status: CheckStatus::Pass,
            detail: format!("GET {url} → {}", resp.status()),
            remedy: None,
        },
        Err(e) => VerificationCheck {
            name: "webhook_https".into(),
            label: "Webhook reachable over HTTPS".into(),
            status: CheckStatus::Fail,
            detail: format!("connection error: {e}"),
            remedy: Some(
                "check that the domain DNS resolves to this server and Caddy is running".into(),
            ),
        },
    }
}

/// Print verification results in human or JSON format.
/// Returns (passed, failed, Option<serde_json::Value>) — the JSON value
/// is returned so the caller can merge it into a single envelope.
fn print_verification(
    checks: &[VerificationCheck],
    json: bool,
) -> (usize, usize, Option<serde_json::Value>) {
    let passed = checks
        .iter()
        .filter(|c| c.status == CheckStatus::Pass)
        .count();
    let failed = checks
        .iter()
        .filter(|c| c.status == CheckStatus::Fail)
        .count();

    if json {
        let overall = if failed > 0 { "fail" } else { "pass" };
        let out = serde_json::json!({
            "checks": checks,
            "passed": passed,
            "failed": failed,
            "overall": overall,
        });
        (passed, failed, Some(out))
    } else {
        println!();
        println!("Verification:");
        for check in checks {
            let icon = match check.status {
                CheckStatus::Pass => "✓",
                CheckStatus::Fail => "✗",
                CheckStatus::Warn => "⚠",
                CheckStatus::Skipped => "–",
            };
            println!("  {icon} {} — {}", check.label, check.detail);
            if let Some(ref remedy) = check.remedy {
                println!("     → {remedy}");
            }
        }
        println!();
        println!("{passed} passed, {failed} failed");
        (passed, failed, None)
    }
}

// ─── Main entry point ──────────────────────────────────────────────────────────

/// Resolve the effective domain: CLI flag > manifest value > prompt > None.
fn resolve_domain(opts: &ServerInitOpts, manifest: Option<&ManifestValues>) -> Option<String> {
    if let Some(ref domain) = opts.domain {
        return Some(domain.clone());
    }
    if let Some(m) = manifest
        && let Some(ref domain) = m.domain
    {
        return Some(domain.clone());
    }
    // Interactive prompt (TTY, not --yes, not --from-file)
    if !opts.yes && std::io::stdin().is_terminal() && opts.from_file.is_none() {
        use dialoguer::Input;
        let domain: String = Input::new()
            .with_prompt("Deploy webhook domain (e.g. deploy.example.com, empty to skip)")
            .allow_empty(true)
            .interact_text()
            .unwrap_or_default();
        if domain.is_empty() {
            None
        } else {
            Some(domain)
        }
    } else {
        None
    }
}

/// Resolve the effective TLS strategy: CLI flag > manifest value > default.
fn resolve_tls(opts: &ServerInitOpts, manifest: Option<&ManifestValues>) -> String {
    if opts.tls != "internal" {
        return opts.tls.clone();
    }
    if let Some(m) = manifest
        && let Some(ref tls) = m.tls
    {
        return tls.clone();
    }
    "internal".to_string()
}

/// Resolve the effective runtime backend: CLI flag > manifest value > default.
fn resolve_runtime(opts: &ServerInitOpts, manifest: Option<&ManifestValues>) -> String {
    if opts.runtime != "auto" {
        return opts.runtime.clone();
    }
    if let Some(m) = manifest
        && let Some(ref runtime) = m.runtime
    {
        return runtime.clone();
    }
    "auto".to_string()
}

/// Resolve the effective listen address: manifest value > default.
fn resolve_listen(manifest: Option<&ManifestValues>) -> Option<String> {
    manifest.and_then(|m| m.listen.clone())
}

/// Resolve the effective admin API: manifest value > default.
fn resolve_admin_api(manifest: Option<&ManifestValues>) -> Option<String> {
    manifest.and_then(|m| m.admin_api.clone())
}

/// Resolve the effective ACME email: manifest value > None.
fn resolve_acme_email(manifest: Option<&ManifestValues>) -> Option<String> {
    manifest.and_then(|m| m.acme_email.clone())
}

/// Run the init flow with resolved values.
///
/// `from_file` flag controls whether this is a disaster-recovery flow
/// (secret always regenerated with loud warning).
#[allow(clippy::too_many_arguments)]
fn run_init(
    domain: Option<String>,
    tls: String,
    runtime: String,
    listen: Option<String>,
    admin_api: Option<String>,
    acme_email: Option<String>,
    opts: &ServerInitOpts,
    from_file: bool,
) -> ! {
    let cfg_dir = config_dir();
    let sysd_dir = systemd_dir();
    let env_path = env_file_path();
    let prefix = "/usr/local";

    // ── Phase: Secret + Config ──────────────────────────────────────────────

    // Check idempotency for env file
    let force_secret = opts.force_all || opts.force.contains(&ForceTarget::Secret) || from_file;
    let (secret_written, secret_value) = if env_path.exists() && !force_secret {
        eprintln!(
            "✓ {} already present (use --force=secret to regenerate)",
            env_path.display()
        );
        (false, String::new())
    } else {
        if env_path.exists() && force_secret {
            eprintln!("⚠ regenerating secret — old token will be invalidated");
        }
        if from_file {
            eprintln!("⚠ disaster recovery: admin secret regenerated — old token is invalid");
        }
        let secret = generate_secret();
        write_env_file(&env_path, &secret).unwrap_or_else(|e| {
            output::fail(
                output::GENERIC,
                &format!("failed to write env file: {e}"),
                "check permissions on /etc/slip and re-run as root",
            );
        });
        (true, secret)
    };

    // Check idempotency for config
    let force_config = opts.force_all || opts.force.contains(&ForceTarget::Config);
    let config_path = cfg_dir.join(CONFIG_FILE_NAME);
    if config_path.exists() && !force_config {
        eprintln!(
            "✓ {} already present (use --force=config to overwrite)",
            config_path.display()
        );
    } else {
        write_config(
            &cfg_dir,
            domain.as_deref(),
            &tls,
            &runtime,
            listen.as_deref(),
            admin_api.as_deref(),
            acme_email.as_deref(),
        )
        .unwrap_or_else(|e| {
            output::fail(
                output::GENERIC,
                &format!("failed to write config: {e}"),
                "check permissions on /etc/slip and re-run as root",
            );
        });
    }

    // Print the secret once (human banner) — only if actually written
    if secret_written && !opts.json {
        println!("✓ Admin secret generated: {secret_value}");
        println!("  (stored in {} with mode 0600)", env_path.display());
    }

    // ── Phase: systemd unit + service start ────────────────────────────────

    if !opts.no_systemd {
        let force_unit = opts.force_all || opts.force.contains(&ForceTarget::Unit);
        let unit_path = sysd_dir.join(UNIT_FILE_NAME);
        let expected_unit = unit_content(prefix, &cfg_dir.to_string_lossy());

        if unit_path.exists() && !force_unit {
            if file_matches(&unit_path, &expected_unit) {
                eprintln!("✓ {} already up to date", unit_path.display());
            } else {
                eprintln!(
                    "⚠ {} differs from expected — overwriting",
                    unit_path.display()
                );
                write_unit(&sysd_dir, prefix, &cfg_dir.to_string_lossy()).unwrap_or_else(|e| {
                    output::fail(
                        output::GENERIC,
                        &format!("failed to write unit file: {e}"),
                        "check permissions on /etc/systemd/system and re-run as root",
                    );
                });
            }
        } else {
            write_unit(&sysd_dir, prefix, &cfg_dir.to_string_lossy()).unwrap_or_else(|e| {
                output::fail(
                    output::GENERIC,
                    &format!("failed to write unit file: {e}"),
                    "check permissions on /etc/systemd/system and re-run as root",
                );
            });
        }

        // Install and start (skip if test overrides)
        if !has_test_overrides() {
            if let Err(e) = install_and_start_service() {
                output::fail(
                    output::DEPLOY_FAILED,
                    &format!("service start failed: {e}"),
                    "check `journalctl -u slipd -f` for details",
                );
            }
            eprintln!("✓ slipd.service enabled and started");
        } else {
            eprintln!(
                "✓ systemd unit written to {} (service start skipped: test mode)",
                sysd_dir.display()
            );
        }
    } else {
        eprintln!("✓ systemd unit skipped (--no-systemd)");
    }

    // ── Phase: --force=service restart ─────────────────────────────────────

    if !opts.no_systemd
        && !has_test_overrides()
        && (opts.force_all || opts.force.contains(&ForceTarget::Service))
    {
        if let Err(e) = restart_service() {
            output::fail(
                output::DEPLOY_FAILED,
                &format!("service restart failed: {e}"),
                "check `journalctl -u slipd -f` for details",
            );
        }
        eprintln!("✓ slipd.service restarted");
    }

    // ── Phase: Verification ───────────────────────────────────────────────

    let mut json_parts: Vec<serde_json::Value> = Vec::new();

    if !opts.skip_verify {
        let verify_opts = ServerInitOpts {
            domain: domain.clone(),
            tls: tls.clone(),
            runtime: runtime.clone(),
            ..opts.clone()
        };
        let checks = run_verification(&verify_opts);
        let (_passed, failed, json_verification) = print_verification(&checks, opts.json);

        if let Some(jv) = json_verification {
            json_parts.push(jv);
        }

        if failed > 0 {
            // Emit manifest before exiting so the user has something to commit
            let hostname = get_hostname();
            let manifest_opts = ServerInitOpts {
                domain: domain.clone(),
                tls: tls.clone(),
                runtime: runtime.clone(),
                ..opts.clone()
            };
            let manifest_path = emit_manifest(
                &manifest_opts,
                &hostname,
                listen.as_deref(),
                admin_api.as_deref(),
                acme_email.as_deref(),
            )
            .unwrap_or_else(|e| {
                eprintln!("warning: failed to write manifest: {e}");
                PathBuf::from("")
            });

            // Emit JSON envelope before exiting
            if opts.json {
                let json_next =
                    print_next_steps(&manifest_path, &env_path, secret_written, opts.json);
                if let Some(jv) = json_next {
                    json_parts.push(jv);
                }
                let mut envelope = serde_json::json!({});
                for part in &json_parts {
                    if let Some(part_map) = part.as_object()
                        && let Some(envelope_map) = envelope.as_object_mut()
                    {
                        for (k, v) in part_map {
                            envelope_map.insert(k.clone(), v.clone());
                        }
                    }
                }
                println!("{envelope}");
            }
            std::process::exit(output::DEPLOY_FAILED);
        }
    }

    // ── Phase: Manifest emission ───────────────────────────────────────────

    let hostname = get_hostname();
    let manifest_opts = ServerInitOpts {
        domain: domain.clone(),
        tls: tls.clone(),
        runtime: runtime.clone(),
        ..opts.clone()
    };
    let manifest_path = emit_manifest(
        &manifest_opts,
        &hostname,
        listen.as_deref(),
        admin_api.as_deref(),
        acme_email.as_deref(),
    )
    .unwrap_or_else(|e| {
        eprintln!("warning: failed to write manifest: {e}");
        PathBuf::from("")
    });

    if !manifest_path.as_os_str().is_empty() && !opts.json {
        println!("✓ Manifest written to {}", manifest_path.display());
    }

    // ── Phase: Next steps ──────────────────────────────────────────────────

    let json_next = print_next_steps(&manifest_path, &env_path, secret_written, opts.json);
    if let Some(jv) = json_next {
        json_parts.push(jv);
    }

    // Emit single JSON envelope if --json
    if opts.json {
        let mut envelope = serde_json::json!({});
        for part in &json_parts {
            if let Some(part_map) = part.as_object()
                && let Some(envelope_map) = envelope.as_object_mut()
            {
                for (k, v) in part_map {
                    envelope_map.insert(k.clone(), v.clone());
                }
            }
        }
        println!("{envelope}");
    }

    std::process::exit(output::OK);
}

/// Run `slip server init`.
pub fn run(opts: ServerInitOpts) -> ! {
    check_root();

    // ── Resolve values ──────────────────────────────────────────────────────

    let manifest = if let Some(ref path) = opts.from_file {
        let m = parse_manifest(path).unwrap_or_else(|e| {
            output::fail(
                output::USAGE,
                &format!("failed to parse manifest '{}': {e}", path.display()),
                "ensure the file is a valid server manifest TOML",
            );
        });
        Some(m)
    } else {
        None
    };

    // Interactive confirmation (TTY, not --yes, not --from-file)
    if !opts.yes && std::io::stdin().is_terminal() && opts.from_file.is_none() {
        use dialoguer::Confirm;
        if !Confirm::new()
            .with_prompt("This will configure slipd on this server. Continue?")
            .default(true)
            .interact()
            .unwrap_or(false)
        {
            eprintln!("Aborted.");
            std::process::exit(output::GENERIC);
        }
    }

    let domain = resolve_domain(&opts, manifest.as_ref());
    let tls = resolve_tls(&opts, manifest.as_ref());
    let runtime = resolve_runtime(&opts, manifest.as_ref());
    let listen = resolve_listen(manifest.as_ref());
    let admin_api = resolve_admin_api(manifest.as_ref());
    let acme_email = resolve_acme_email(manifest.as_ref());

    run_init(
        domain,
        tls,
        runtime,
        listen,
        admin_api,
        acme_email,
        &opts,
        opts.from_file.is_some(),
    )
}
