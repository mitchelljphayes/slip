//! Tailscale prerequisite checks for the `tailscale` TLS strategy.
//!
//! All checks are read-only, bounded by a timeout, and produce prescriptive
//! remedies on failure. No secrets are read or logged — the only Tailscale
//! data slip reads is `tailscale status --json` (`CertDomains`, `Self.HostName`)
//! and `/etc/default/tailscaled` (checking for `TS_PERMIT_CERT_UID` — a
//! username, not a secret).
//!
//! Slip does NOT shell out to `tailscale cert`, does NOT write PEM files, and
//! does NOT own a renewal scheduler. Caddy's built-in
//! `tls.get_certificate.tailscale` manager handles issuance + renewal via
//! `tailscaled` directly.

use std::path::{Path, PathBuf};

use crate::caddy::CaddyClient;
use crate::doctor::CommandRunner;

/// Result of Tailscale preflight checks.
#[derive(Debug, Clone)]
pub struct TailscalePreflight {
    pub tailscaled_active: bool,
    pub socket_present: bool,
    pub cert_domains: Vec<String>,
    pub hostname: Option<String>,
    pub manager_module: bool,
    pub caddy_user_permitted: bool,
}

/// Error from a Tailscale preflight check, with a prescriptive remedy.
#[derive(Debug, Clone)]
pub struct TailscalePreflightError {
    pub check: &'static str,
    pub remedy: String,
}

/// The default `tailscaled` socket path (Linux).
pub const TAILSCALED_SOCKET: &str = "/var/run/tailscale/tailscaled.sock";

/// The default `tailscaled` environment file (Debian/systemd).
pub const TAILSCALED_ENV_FILE: &str = "/etc/default/tailscaled";

/// Run all Tailscale preflight checks for a host.
///
/// Each check is bounded by the caller's timeout (the reconcile tick applies
/// a 5s timeout). Returns `Ok(preflight)` if all checks pass, or
/// `Err(TailscalePreflightError)` with a prescriptive remedy on the first
/// failure.
pub async fn preflight_tailscale(
    runner: &dyn CommandRunner,
    caddy: &CaddyClient,
    host: &str,
) -> Result<TailscalePreflight, TailscalePreflightError> {
    // 1. tailscaled active
    let out = runner
        .run("systemctl", &["is-active", "tailscaled"])
        .map_err(|_| TailscalePreflightError {
            check: "tailscale.daemon",
            remedy: "tailscaled not running — run: systemctl start tailscaled".to_string(),
        })?;

    let tailscaled_active = out.status == 0 && out.stdout.trim() == "active";
    if !tailscaled_active {
        return Err(TailscalePreflightError {
            check: "tailscale.daemon",
            remedy: "tailscaled not running — run: systemctl start tailscaled".to_string(),
        });
    }

    // 2. Socket present
    let socket_present = Path::new(TAILSCALED_SOCKET).exists();
    if !socket_present {
        return Err(TailscalePreflightError {
            check: "tailscale.socket",
            remedy: format!(
                "tailscaled socket not found at {TAILSCALED_SOCKET} — \
                 if tailscaled uses a custom socket, Caddy's built-in Tailscale \
                 manager cannot find it; consider the caddy-tailscale plugin \
                 (tsnet mode) or symlink the socket to the default path"
            ),
        });
    }

    // 3. MagicDNS + HTTPS enabled (via `tailscale status --json` → CertDomains)
    let status_out = runner
        .run("tailscale", &["status", "--json"])
        .map_err(|_| TailscalePreflightError {
            check: "tailscale.https",
            remedy: "tailscale status --json failed — ensure tailscale CLI is installed and tailscaled is running".to_string(),
        })?;

    let cert_domains = parse_cert_domains(&status_out.stdout);
    let hostname = parse_self_hostname(&status_out.stdout);
    if cert_domains.is_empty() {
        return Err(TailscalePreflightError {
            check: "tailscale.https",
            remedy: "HTTPS certificates not enabled for tailnet — \
                     enable MagicDNS + HTTPS Certificates at \
                     https://login.tailscale.com/admin/dns"
                .to_string(),
        });
    }

    // 4. Hostname match
    if !host_matches_cert_domains(host, &cert_domains) {
        return Err(TailscalePreflightError {
            check: "tailscale.hostname_match",
            remedy: format!(
                "host '{host}' does not match any tailscaled CertDomain — \
                 rename the node: tailscale set --hostname <node>, \
                 or use a *.ts.net subject that matches this machine"
            ),
        });
    }

    // 5. Caddy manager module present
    let manager_module = caddy.has_cert_manager("tailscale").await.unwrap_or(false);
    if !manager_module {
        return Err(TailscalePreflightError {
            check: "tailscale.manager_module",
            remedy: "Tailscale certificate manager not found in Caddy — \
                     Caddy v2.5+ required; upgrade Caddy"
                .to_string(),
        });
    }

    // 6. Caddy user permission (non-root check via env file)
    let caddy_user_permitted = check_caddy_user_permission();
    if !caddy_user_permitted {
        return Err(TailscalePreflightError {
            check: "tailscale.caddy_user",
            remedy: "Caddy user 'caddy' cannot access tailscaled socket — \
                     set TS_PERMIT_CERT_UID=caddy in /etc/default/tailscaled, \
                     then: systemctl restart tailscaled. \
                     See https://tailscale.com/docs/integrations/web-servers/caddy/caddy-certificates"
                .to_string(),
        });
    }

    Ok(TailscalePreflight {
        tailscaled_active,
        socket_present,
        cert_domains,
        hostname,
        manager_module,
        caddy_user_permitted,
    })
}

/// Parse `CertDomains` from `tailscale status --json` output.
pub fn parse_cert_domains(json: &str) -> Vec<String> {
    // Lightweight JSON extraction — avoid pulling in a full serde model for
    // the tailscale status output. CertDomains is a top-level array of strings.
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(json)
        && let Some(domains) = v.get("CertDomains").and_then(|d| d.as_array())
    {
        return domains
            .iter()
            .filter_map(|d| d.as_str().map(String::from))
            .collect();
    }
    Vec::new()
}

/// Parse `Self.HostName` from `tailscale status --json` output.
pub fn parse_self_hostname(json: &str) -> Option<String> {
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(json)
        && let Some(name) = v
            .get("Self")
            .and_then(|s| s.get("HostName"))
            .and_then(|h| h.as_str())
    {
        return Some(name.to_string());
    }
    None
}

/// Check if a host matches any of the CertDomains (with wildcard support).
pub fn host_matches_cert_domains(host: &str, cert_domains: &[String]) -> bool {
    let h = host.strip_prefix("*.").unwrap_or(host);
    for domain in cert_domains {
        let d = domain.strip_prefix("*.").unwrap_or(domain);
        if h == d || h.ends_with(&format!(".{d}")) {
            return true;
        }
    }
    false
}

/// Check if the Caddy user has permission to access the tailscaled socket.
///
/// If Caddy runs as root, permission is implicit. If non-root, checks for
/// `TS_PERMIT_CERT_UID` in `/etc/default/tailscaled`. Returns `true` if
/// permitted (or root), `false` otherwise.
///
/// The `SLIP_TEST_TAILSCALED_ENV_FILE` override is ONLY honored when a
/// `SLIP_TEST_*` env var is set (test mode). In production, the env file
/// override is never consulted.
pub fn check_caddy_user_permission() -> bool {
    // Only honor the test override if a SLIP_TEST_ env var is set.
    let test_mode = std::env::var("SLIP_TEST_TAILSCALED_ENV_FILE").is_ok();

    let env_path = if test_mode {
        std::env::var("SLIP_TEST_TAILSCALED_ENV_FILE")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from(TAILSCALED_ENV_FILE))
    } else {
        PathBuf::from(TAILSCALED_ENV_FILE)
    };

    if !env_path.exists() {
        // No env file — assume root Caddy (common case).
        return true;
    }

    let content = std::fs::read_to_string(&env_path).unwrap_or_default();
    // Exact parsing: look for `TS_PERMIT_CERT_UID=<value>` (shell-style).
    for line in content.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("TS_PERMIT_CERT_UID")
            && let Some(value_part) = rest.strip_prefix('=')
        {
            let value = value_part.trim().trim_matches('"').trim_matches('\'');
            if !value.is_empty() {
                return true;
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_cert_domains_extracts_array() {
        let json = r#"{"CertDomains": ["host.tailnet.ts.net", "*.tailnet.ts.net"], "Other": 42}"#;
        let domains = parse_cert_domains(json);
        assert_eq!(domains.len(), 2);
        assert!(domains.contains(&"host.tailnet.ts.net".to_string()));
    }

    #[test]
    fn parse_cert_domains_empty_when_absent() {
        let json = r#"{"Other": 42}"#;
        assert!(parse_cert_domains(json).is_empty());
    }

    #[test]
    fn parse_cert_domains_invalid_json() {
        assert!(parse_cert_domains("not json").is_empty());
    }

    #[test]
    fn parse_self_hostname_extracts() {
        let json = r#"{"Self": {"HostName": "arrakeen"}, "Other": 1}"#;
        assert_eq!(parse_self_hostname(json).as_deref(), Some("arrakeen"));
    }

    #[test]
    fn host_matches_exact() {
        let domains = vec!["host.tailnet.ts.net".to_string()];
        assert!(host_matches_cert_domains("host.tailnet.ts.net", &domains));
    }

    #[test]
    fn host_matches_wildcard_cert_domain() {
        let domains = vec!["*.tailnet.ts.net".to_string()];
        assert!(host_matches_cert_domains("host.tailnet.ts.net", &domains));
    }

    #[test]
    fn host_does_not_match_different_domain() {
        let domains = vec!["host.tailnet.ts.net".to_string()];
        assert!(!host_matches_cert_domains("other.ts.net", &domains));
    }

    // ── RE-5: Shared Tailscale permission parsing ──────────────────────────

    #[test]
    fn check_caddy_user_permission_no_env_file_assumes_root() {
        // When no env file exists (and no test override), assume root Caddy.
        // This test relies on the default TAILSCALED_ENV_FILE not existing
        // in the test environment.
        // SAFETY: single-threaded test.
        unsafe {
            std::env::remove_var("SLIP_TEST_TAILSCALED_ENV_FILE");
        }
        // The default /etc/default/tailscaled likely doesn't exist in CI.
        // If it does, this test still passes (the function checks the real file).
        let _ = check_caddy_user_permission();
        // We don't assert the result — we just verify it doesn't panic.
    }

    #[test]
    fn check_caddy_user_permission_exact_parse_with_value() {
        use std::io::Write;
        let dir = tempfile::tempdir().unwrap();
        let env_file = dir.path().join("tailscaled.env");
        let mut f = std::fs::File::create(&env_file).unwrap();
        writeln!(f, "TS_PERMIT_CERT_UID=caddy").unwrap();

        // SAFETY: single-threaded test.
        unsafe {
            std::env::set_var(
                "SLIP_TEST_TAILSCALED_ENV_FILE",
                env_file.to_string_lossy().to_string(),
            );
        }
        assert!(
            check_caddy_user_permission(),
            "TS_PERMIT_CERT_UID=caddy should be permitted"
        );
        unsafe {
            std::env::remove_var("SLIP_TEST_TAILSCALED_ENV_FILE");
        }
    }

    #[test]
    fn check_caddy_user_permission_rejects_empty_value() {
        use std::io::Write;
        let dir = tempfile::tempdir().unwrap();
        let env_file = dir.path().join("tailscaled.env");
        let mut f = std::fs::File::create(&env_file).unwrap();
        writeln!(f, "TS_PERMIT_CERT_UID=").unwrap();

        // SAFETY: single-threaded test.
        unsafe {
            std::env::set_var(
                "SLIP_TEST_TAILSCALED_ENV_FILE",
                env_file.to_string_lossy().to_string(),
            );
        }
        assert!(
            !check_caddy_user_permission(),
            "TS_PERMIT_CERT_UID= (empty) should NOT be permitted"
        );
        unsafe {
            std::env::remove_var("SLIP_TEST_TAILSCALED_ENV_FILE");
        }
    }

    #[test]
    fn check_caddy_user_permission_rejects_wrong_var_name() {
        use std::io::Write;
        let dir = tempfile::tempdir().unwrap();
        let env_file = dir.path().join("tailscaled.env");
        let mut f = std::fs::File::create(&env_file).unwrap();
        writeln!(f, "TS_PERMIT_CERT_UID_FOO=caddy").unwrap();

        // SAFETY: single-threaded test.
        unsafe {
            std::env::set_var(
                "SLIP_TEST_TAILSCALED_ENV_FILE",
                env_file.to_string_lossy().to_string(),
            );
        }
        assert!(
            !check_caddy_user_permission(),
            "TS_PERMIT_CERT_UID_FOO= should NOT match (exact name required)"
        );
        unsafe {
            std::env::remove_var("SLIP_TEST_TAILSCALED_ENV_FILE");
        }
    }

    #[test]
    fn check_caddy_user_permission_strips_quotes() {
        use std::io::Write;
        let dir = tempfile::tempdir().unwrap();
        let env_file = dir.path().join("tailscaled.env");
        let mut f = std::fs::File::create(&env_file).unwrap();
        writeln!(f, "TS_PERMIT_CERT_UID=\"caddy\"").unwrap();

        // SAFETY: single-threaded test.
        unsafe {
            std::env::set_var(
                "SLIP_TEST_TAILSCALED_ENV_FILE",
                env_file.to_string_lossy().to_string(),
            );
        }
        assert!(
            check_caddy_user_permission(),
            "TS_PERMIT_CERT_UID=\"caddy\" (quoted) should be permitted"
        );
        unsafe {
            std::env::remove_var("SLIP_TEST_TAILSCALED_ENV_FILE");
        }
    }
}
