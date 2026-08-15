//! Shared check-result types for `slip doctor` and `slip server init --verify`.
//!
//! This module is the single home for the `VerificationCheck` / `CheckStatus`
//! schema so the two diagnostic surfaces don't drift. `server_init.rs` re-imports
//! these types; `slip doctor` builds its report on top of them.
//!
//! Design rules (see SLIP-102 best-practices.md):
//! - Read-only by default; mutation lives behind `--fix` in the CLI layer.
//! - Stable `name` identifiers (snake_case dotted) for grep/jq.
//! - Deterministic declaration order — the orchestrator emits checks in a
//!   fixed `const` slice, never HashMap/parallel order.
//! - `warn` is non-fatal; `fail` drives the nonzero exit code.
//! - Every non-`pass` check carries a prescriptive `remedy`.

use std::net::IpAddr;

use serde::Serialize;

// ─── Check result schema ──────────────────────────────────────────────────────

/// Status of a single verification check.
///
/// `Skipped` is new versus the original `server_init.rs` three-variant enum;
/// `server_init` never emits it, so promoting the type is backwards-compatible.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckStatus {
    Pass,
    Fail,
    Warn,
    Skipped,
}

impl CheckStatus {
    /// Lowercase wire name used in JSON ("pass", "fail", "warn", "skipped").
    pub fn as_str(&self) -> &'static str {
        match self {
            CheckStatus::Pass => "pass",
            CheckStatus::Fail => "fail",
            CheckStatus::Warn => "warn",
            CheckStatus::Skipped => "skipped",
        }
    }

    /// Single-character icon for human output.
    pub fn icon(&self) -> &'static str {
        match self {
            CheckStatus::Pass => "✓",
            CheckStatus::Fail => "✗",
            CheckStatus::Warn => "⚠",
            CheckStatus::Skipped => "–",
        }
    }
}

/// A single verification check result.
///
/// Reused by both `slip server init --verify` and `slip doctor`. The `name`
/// field is the stable jq-able identifier; `label` is human-only and may
/// change between releases.
#[derive(Debug, Clone, Serialize)]
pub struct VerificationCheck {
    /// Stable snake_case identifier (for --json).
    pub name: String,
    /// Human-readable label.
    pub label: String,
    pub status: CheckStatus,
    pub detail: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remedy: Option<String>,
}

impl VerificationCheck {
    /// Convenience constructor.
    pub fn new(
        name: impl Into<String>,
        label: impl Into<String>,
        status: CheckStatus,
        detail: impl Into<String>,
        remedy: Option<String>,
    ) -> Self {
        Self {
            name: name.into(),
            label: label.into(),
            status,
            detail: detail.into(),
            remedy,
        }
    }
}

/// Aggregate counts for a [`DoctorReport`] or verification run.
#[derive(Debug, Clone, Default, Serialize)]
pub struct Summary {
    pub pass: usize,
    pub warn: usize,
    pub fail: usize,
    pub skipped: usize,
}

impl Summary {
    /// Tally a slice of checks into a summary.
    pub fn from_checks(checks: &[VerificationCheck]) -> Self {
        let mut s = Summary::default();
        for c in checks {
            match c.status {
                CheckStatus::Pass => s.pass += 1,
                CheckStatus::Warn => s.warn += 1,
                CheckStatus::Fail => s.fail += 1,
                CheckStatus::Skipped => s.skipped += 1,
            }
        }
        s
    }
}

/// A `--fix` action: a single planned/applied mutation with a rollback path.
///
/// Only populated under `slip doctor --fix`. The detection-only report omits
/// the `actions` array entirely (see [`DoctorReport`]).
#[derive(Debug, Clone, Serialize)]
pub struct DoctorAction {
    /// Stable snake_case identifier, e.g. `"ufw.allow.bridge_dns"`.
    pub name: String,
    /// The exact command that was (or would be) run.
    pub command: String,
    /// `pending` (planned, not yet applied), `applied`, `already_present`, or
    /// `failed`.
    pub status: String,
    /// The exact command to roll back this action.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rollback: Option<String>,
}

/// The top-level `slip doctor` report.
///
/// JSON shape (`slip.doctor/v1`):
///
/// ```json
/// {
///   "schema": "slip.doctor/v1",
///   "generated_at": "2026-07-12T09:55:18Z",
///   "summary": { "pass": 7, "warn": 2, "fail": 1, "skipped": 0 },
///   "checks": [ { "name": "...", "label": "...", "status": "pass", "detail": "..." } ],
///   "actions": [ { "name": "...", "command": "...", "status": "applied", "rollback": "..." } ]
/// }
/// ```
///
/// `actions` is `None` (and therefore omitted via `skip_serializing_if`) for
/// the detection-only run; it is `Some(vec![])` when `--fix` was requested but
/// no actions were planned, and `Some([...])` when actions were planned/applied.
#[derive(Debug, Clone, Serialize)]
pub struct DoctorReport {
    pub schema: &'static str,
    pub generated_at: chrono::DateTime<chrono::Utc>,
    pub summary: Summary,
    pub checks: Vec<VerificationCheck>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actions: Option<Vec<DoctorAction>>,
}

impl DoctorReport {
    pub const SCHEMA: &'static str = "slip.doctor/v1";

    /// Build a detection-only report (no `actions` field).
    pub fn detection(checks: Vec<VerificationCheck>) -> Self {
        let summary = Summary::from_checks(&checks);
        Self {
            schema: Self::SCHEMA,
            generated_at: chrono::Utc::now(),
            summary,
            checks,
            actions: None,
        }
    }

    /// Build a `--fix` report (with the `actions` field).
    pub fn with_actions(checks: Vec<VerificationCheck>, actions: Vec<DoctorAction>) -> Self {
        let summary = Summary::from_checks(&checks);
        Self {
            schema: Self::SCHEMA,
            generated_at: chrono::Utc::now(),
            summary,
            checks,
            actions: Some(actions),
        }
    }

    /// Serialize to a `serde_json::Value` for the CLI to print.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::to_value(self).expect("DoctorReport is serializable")
    }
}

// ─── Exit-code aggregation ────────────────────────────────────────────────────

/// Map a summary + global-timeout flag to the contractual slip exit code.
///
/// - `0` (OK) when `fail == 0` and the run did not time out.
/// - `1` (GENERIC) when `fail > 0`.
/// - `6` (TIMEOUT) when the global deadline was hit (regardless of fails,
///   because a timeout means the report is incomplete).
pub fn aggregate_exit(summary: &Summary, timed_out: bool) -> i32 {
    if timed_out {
        // TIMEOUT — mirrors `output::TIMEOUT` (6) without a CLI dep.
        6
    } else if summary.fail > 0 {
        1
    } else {
        0
    }
}

// ─── Human rendering ──────────────────────────────────────────────────────────

/// Render a slice of checks as human-readable lines (no trailing newline on
/// the final line; the caller decides spacing). Mirrors the format used by
/// `server_init.rs::print_verification` so the two surfaces look identical.
pub fn render_human(checks: &[VerificationCheck]) -> String {
    let mut out = String::new();
    out.push_str("\nVerification:\n");
    for check in checks {
        let icon = check.status.icon();
        out.push_str(&format!("  {icon} {} — {}\n", check.label, check.detail));
        if let Some(ref remedy) = check.remedy {
            out.push_str(&format!("     → {remedy}\n"));
        }
    }
    let summary = Summary::from_checks(checks);
    out.push_str(&format!(
        "\n{} passed, {} warn, {} failed, {} skipped",
        summary.pass, summary.warn, summary.fail, summary.skipped
    ));
    out
}

// ─── Command-runner + probe traits (Tier-2 test seams) ───────────────────────

/// Output of a shell-out command, captured for deterministic classification.
#[derive(Debug, Clone)]
pub struct CommandOutput {
    pub stdout: String,
    pub stderr: String,
    pub status: i32,
}

/// Trait for running a system command. The real impl shells out via
/// `std::process::Command`; tests inject a fake returning canned output.
pub trait CommandRunner: Send + Sync {
    fn run(&self, cmd: &str, args: &[&str]) -> std::io::Result<CommandOutput>;
}

// ─── Pure classifiers (Tier-1 test surface) ───────────────────────────────────

/// Result of classifying a UFW status dump for the bridge DNS rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UfwClass {
    pub status: CheckStatus,
    pub detail: String,
    pub remedy: Option<String>,
}

/// Classify `ufw status numbered` output for a `allow in on <bridge> to any
/// port 53` rule.
///
/// - UFW inactive (`Status: inactive`) → `warn` (firewall is off; the rule
///   is not needed but neither is anything protected).
/// - UFW active + rule present → `pass`.
/// - UFW active + rule absent → `fail` with the exact
///   `ufw allow in on <bridge> to any port 53` remedy.
/// - Bridge name empty (network missing) → caller should not call this; we
///   return `fail` with a "run slipd once to create the slip network" remedy.
pub fn classify_ufw(bridge: &str, ufw_status_output: &str) -> UfwClass {
    let lower = ufw_status_output.to_ascii_lowercase();
    if lower.contains("status: inactive") {
        return UfwClass {
            status: CheckStatus::Warn,
            detail: "UFW is inactive; bridge DNS rule not needed but firewall is off".into(),
            remedy: Some("enable UFW (`ufw enable`) or leave it off intentionally".into()),
        };
    }
    if bridge.is_empty() {
        return UfwClass {
            status: CheckStatus::Fail,
            detail: "slip network bridge interface not found".into(),
            remedy: Some(
                "run slipd once to create the slip network, then re-run `slip doctor`".into(),
            ),
        };
    }
    // Look for a rule mentioning the bridge and port 53. UFW `status numbered`
    // output looks like:
    //     [ 1] 22/tcp                     ALLOW IN    Anywhere
    //     [ 2] 53/tcp on br-slip          ALLOW IN    Anywhere
    //     [ 3] 53/udp on br-slip          ALLOW IN    Anywhere
    // We accept either tcp or udp (aardvark queries both) and require the
    // bridge interface to appear on the rule line.
    let bridge_lc = bridge.to_ascii_lowercase();
    let has_rule = lower
        .lines()
        .any(|line| line.contains(&bridge_lc) && line.contains("53/") && line.contains("allow in"));
    if has_rule {
        UfwClass {
            status: CheckStatus::Pass,
            detail: format!("UFW allows DNS (port 53) on bridge {bridge}"),
            remedy: None,
        }
    } else {
        let remedy = format!("ufw allow in on {bridge} to any port 53");
        UfwClass {
            status: CheckStatus::Fail,
            detail: format!(
                "UFW is active but no rule allows DNS (port 53) on bridge {bridge} — \
                 container→service lookups will be silently dropped (FR §3.8)"
            ),
            remedy: Some(remedy),
        }
    }
}

/// Classify `caddy list-modules` output for a required DNS provider plugin.
///
/// `required_provider` is e.g. `"cloudflare"`; we look for
/// `dns.providers.cloudflare` in the module list. If no provider is required
/// (`None` or empty), the check is `skipped`.
pub fn parse_caddy_modules(modules_output: &str, required_provider: Option<&str>) -> CheckStatus {
    let Some(provider) = required_provider else {
        return CheckStatus::Skipped;
    };
    if provider.is_empty() {
        return CheckStatus::Skipped;
    }
    let needle = format!("dns.providers.{provider}");
    if modules_output.contains(&needle) {
        CheckStatus::Pass
    } else {
        CheckStatus::Fail
    }
}

/// Classify `caddy list-modules` output for a required module ID using exact
/// matching.
///
/// Unlike `parse_caddy_modules` (which is hardcoded to `dns.providers.*` and
/// uses substring matching for the DNS-plugin contract), this helper takes an
/// arbitrary full module ID (e.g. `tls.get_certificate.tailscale`) and matches
/// it with **exact equality** against the first tab-separated field of each
/// line. This avoids false positives from substring/prefix matches (e.g. a
/// hypothetical `tls.get_certificate.tailscale_extras` must not match).
///
/// `caddy list-modules` prints one module ID per line (no flags). With
/// `--packages`/`--versions`, each line is `<id>\t<package>\t<version>`; we
/// split on `\t` and compare only the first field.
///
/// An empty `module_id` yields `Skipped` (parity with `parse_caddy_modules`).
pub fn module_present_exact(modules_output: &str, module_id: &str) -> CheckStatus {
    if module_id.is_empty() {
        return CheckStatus::Skipped;
    }
    if modules_output.lines().any(|line| {
        // Trim trailing \r (Windows/CRLF) and compare the first tab-separated
        // field with exact equality.
        let field = line.trim_end_matches('\r').split('\t').next().unwrap_or("");
        field == module_id
    }) {
        CheckStatus::Pass
    } else {
        CheckStatus::Fail
    }
}

/// Build the remedy string for a missing DNS plugin.
pub fn dns_plugin_remedy(provider: &str) -> String {
    format!(
        "build a Caddy binary with the DNS plugin: \
         `xcaddy build --with github.com/caddy-dns/{provider}` \
         and replace the system caddy binary, then restart caddy"
    )
}

// ─── Cloudflare / IP classification (check 8) ────────────────────────────────

/// A set of CIDR ranges (v4 + v6) for Cloudflare proxy detection.
///
/// Membership is checked by [`CidrSet::contains`]. The set is populated at
/// runtime from `cloudflare.com/ips-v4` + `ips-v6` with a bundled snapshot
/// fallback (see `fetch_cloudflare_ranges`).
#[derive(Debug, Clone, Default)]
pub struct CidrSet {
    v4: Vec<(u32, u32)>, // (network, mask) — host-byte-order
    v6: Vec<(u128, u128)>,
}

impl CidrSet {
    /// Parse a list of CIDR strings (v4 and v6) into a set.
    ///
    /// Unparseable entries are silently skipped (the fetcher logs a warn).
    pub fn from_cidrs(cidrs: &[&str]) -> Self {
        let mut set = CidrSet::default();
        for c in cidrs {
            if set.add(c).is_err() {
                // skip unparseable
            }
        }
        set
    }

    fn add(&mut self, cidr: &str) -> Result<(), ()> {
        let (ip, prefix) = cidr.split_once('/').ok_or(())?;
        let prefix: u32 = prefix.parse().map_err(|_| ())?;
        if let Ok(v4) = ip.parse::<std::net::Ipv4Addr>() {
            let net = u32::from(v4);
            let mask = if prefix == 0 {
                0
            } else {
                (!0u32) << (32 - prefix)
            };
            self.v4.push((net & mask, mask));
            Ok(())
        } else if let Ok(v6) = ip.parse::<std::net::Ipv6Addr>() {
            let net = u128::from(v6);
            let mask = if prefix == 0 {
                0
            } else {
                (!0u128) << (128 - prefix)
            };
            self.v6.push((net & mask, mask));
            Ok(())
        } else {
            Err(())
        }
    }

    /// True if `ip` falls inside any of the CIDR ranges.
    pub fn contains(&self, ip: &IpAddr) -> bool {
        match ip {
            IpAddr::V4(v4) => {
                let n = u32::from(*v4);
                self.v4.iter().any(|(net, mask)| (n & *mask) == *net)
            }
            IpAddr::V6(v6) => {
                let n = u128::from(*v6);
                self.v6.iter().any(|(net, mask)| (n & *mask) == *net)
            }
        }
    }

    /// Number of ranges (v4 + v6).
    pub fn len(&self) -> usize {
        self.v4.len() + self.v6.len()
    }

    /// Is the set empty?
    pub fn is_empty(&self) -> bool {
        self.v4.is_empty() && self.v6.is_empty()
    }
}

/// Bundled snapshot of Cloudflare's published ranges (from
/// `https://www.cloudflare.com/ips-v4` + `ips-v6`, captured 2026-07).
///
/// Used as a fallback when the runtime fetch fails. The fetcher logs a `warn`
/// when it falls back so the operator knows the data may be stale.
pub const CLOUDFLARE_RANGE_SNAPSHOT: &[&str] = &[
    // IPv4 (15)
    "103.21.244.0/22",
    "103.22.200.0/22",
    "103.31.4.0/22",
    "104.16.0.0/13",
    "104.24.0.0/14",
    "108.162.192.0/18",
    "131.0.72.0/22",
    "141.101.64.0/18",
    "162.158.0.0/15",
    "172.64.0.0/13",
    "173.245.48.0/20",
    "188.114.96.0/20",
    "190.93.240.0/20",
    "197.234.240.0/22",
    "198.41.128.0/17",
    // IPv6 (7)
    "2400:cb00::/32",
    "2606:4700::/32",
    "2803:f800::/32",
    "2405:b500::/32",
    "2405:8100::/32",
    "2a06:98c0::/29",
    "2c0f:f248::/32",
];

/// Classification of a resolved host's origin, per the Q5 taxonomy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsClass {
    /// At least one A/AAAA in Cloudflare ranges (orange-cloud proxied).
    Proxied,
    /// Globally routable, not in CF ranges, not private/CGNAT.
    Direct,
    /// RFC 1918 / RFC 6598 (CGNAT 100.64.0.0/10) / RFC 4193 ULA / link-local /
    /// loopback.
    PrivateOrigin,
}

/// Classify a single IP into the Q5 taxonomy.
pub fn classify_ip(ip: &IpAddr, cf: &CidrSet) -> DnsClass {
    if cf.contains(ip) {
        return DnsClass::Proxied;
    }
    if is_private_or_cgnat(ip) {
        return DnsClass::PrivateOrigin;
    }
    DnsClass::Direct
}

/// True for RFC 1918, RFC 6598 (CGNAT), RFC 4193 ULA, link-local, loopback.
pub fn is_private_or_cgnat(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_loopback() || v4.is_link_local() || v4.is_private() || is_cgnat_v4(v4)
        }
        IpAddr::V6(v6) => {
            v6.is_loopback() || v6.is_unspecified() || is_ula_v6(v6) || is_link_local_v6(v6)
        }
    }
}

/// RFC 6598: `100.64.0.0/10` — Shared Address Space for Carrier-Grade NAT.
fn is_cgnat_v4(ip: &std::net::Ipv4Addr) -> bool {
    let n = u32::from(*ip);
    let net = u32::from(std::net::Ipv4Addr::new(100, 64, 0, 0));
    let mask = 0xffc0_0000; // /10
    (n & mask) == net
}

/// RFC 4193: `fc00::/7` — IPv6 Unique Local Addresses.
fn is_ula_v6(ip: &std::net::Ipv6Addr) -> bool {
    let n = u128::from(*ip);
    (n & 0xfe00_0000_0000_0000_0000_0000_0000_0000) == 0xfc00_0000_0000_0000_0000_0000_0000_0000
}

/// RFC 4862: `fe80::/10` — IPv6 link-local.
fn is_link_local_v6(ip: &std::net::Ipv6Addr) -> bool {
    let n = u128::from(*ip);
    (n & 0xffc0_0000_0000_0000_0000_0000_0000_0000) == 0xfe80_0000_0000_0000_0000_0000_0000_0000
}

/// Result of classifying a declared host's DNS expectation (check 8).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsExpectation {
    pub status: CheckStatus,
    pub detail: String,
    pub remedy: Option<String>,
}

/// Classify a declared host's DNS expectation per the Q5 taxonomy.
///
/// Arguments:
/// - `host` — the declared hostname (for remedy text only).
/// - `ips` — resolved A/AAAA records (empty = unresolved).
/// - `tls_strategy` — the effective TLS strategy for this host
///   (`"internal"`, `"tailscale"`, `"acme"`, `"cloudflare-dns01"`, etc.).
/// - `proxied_hint` — `Some(false)` when SLIP-117's `dns = { proxied = false }`
///   hint says the origin should NOT be proxied. `None` today (heuristic path).
/// - `cf` — the Cloudflare range set.
/// - `dns_error` — true when the resolver returned SERVFAIL/timeout (vs simply
///   no records).
///
/// Classification:
/// - `dns_error` → `fail`.
/// - no records (NXDOMAIN/NODATA) → `warn` with expected-record remedy.
/// - any IP in CF ranges (`Proxied`):
///   - `tls_strategy` is `internal`/`tailscale` OR origin is private/CGNAT →
///     `fail` with grey-cloud remedy (orange-clouded tailnet/private origin).
///   - else (public origin behind CF proxy) → `pass`.
///   - `proxied_hint == Some(false)` → `fail` regardless (the manifest said
///     grey cloud and it's orange).
/// - `PrivateOrigin` → `warn` (not reachable from the public internet; may be
///   intentional behind CF).
/// - `Direct` → `pass`.
pub fn classify_dns_expectation(
    host: &str,
    ips: &[IpAddr],
    tls_strategy: &str,
    proxied_hint: Option<bool>,
    cf: &CidrSet,
    dns_error: bool,
) -> DnsExpectation {
    if dns_error {
        return DnsExpectation {
            status: CheckStatus::Fail,
            detail: format!("DNS resolver returned an error for {host}"),
            remedy: Some(format!(
                "check upstream DNS / resolver config for {host} — \
                 the resolver itself is broken (SERVFAIL/timeout)"
            )),
        };
    }
    if ips.is_empty() {
        return DnsExpectation {
            status: CheckStatus::Warn,
            detail: format!("{host} does not resolve to any A/AAAA record"),
            remedy: Some(format!(
                "create a DNS record for {host} pointing at this host (A/AAAA), \
                 or grey-cloud an existing Cloudflare record so it resolves to the origin"
            )),
        };
    }

    let any_proxied = ips.iter().any(|ip| cf.contains(ip));
    let any_private = ips.iter().any(is_private_or_cgnat);
    // Strategies that genuinely imply a non-public origin. DNS-01 strategies
    // (`cloudflare-dns01`, `dns01`) are TLS *issuance* methods, not origin
    // indicators — a public origin behind Cloudflare proxy with DNS-01 TLS
    // is a valid, common setup. The `any_private` check below independently
    // catches the case where the origin is actually private/CGNAT regardless
    // of TLS strategy.
    let tailnet_or_internal = matches!(tls_strategy, "internal" | "tailscale");

    if any_proxied {
        // Orange cloud.
        if proxied_hint == Some(false) {
            return DnsExpectation {
                status: CheckStatus::Fail,
                detail: format!(
                    "{host} resolves to a Cloudflare proxy IP but the manifest declares \
                     `dns = {{ proxied = false }}` (grey cloud expected)"
                ),
                remedy: Some(format!(
                    "in the Cloudflare dashboard, set the DNS record for {host} to \
                     'DNS only' (grey cloud) so traffic reaches the origin directly"
                )),
            };
        }
        if tailnet_or_internal || any_private {
            return DnsExpectation {
                status: CheckStatus::Fail,
                detail: format!(
                    "{host} resolves to a Cloudflare proxy IP (orange cloud) but the \
                     origin is on a tailnet/private network (tls={tls_strategy}) — \
                     Cloudflare's proxy cannot reach a 100.x / RFC1918 origin"
                ),
                remedy: Some(format!(
                    "in the Cloudflare dashboard, set the DNS record for {host} to \
                     'DNS only' (grey cloud) so traffic reaches the tailnet origin directly, \
                     or move the origin to a publicly routable address"
                )),
            };
        }
        return DnsExpectation {
            status: CheckStatus::Pass,
            detail: format!(
                "{host} resolves to a Cloudflare proxy IP (orange cloud) — origin is public"
            ),
            remedy: None,
        };
    }

    if any_private {
        return DnsExpectation {
            status: CheckStatus::Warn,
            detail: format!(
                "{host} resolves to a private/CGNAT origin — not reachable from the \
                 public internet (fine behind Cloudflare proxy; problematic if served directly)"
            ),
            remedy: Some(format!(
                "if {host} should be public, point its DNS at a public IP or grey-cloud \
                 a Cloudflare record; if it is intentionally tailnet-only, this is expected"
            )),
        };
    }

    DnsExpectation {
        status: CheckStatus::Pass,
        detail: format!("{host} resolves to a direct public origin IP"),
        remedy: None,
    }
}

/// Fetch Cloudflare's published IP ranges from `cloudflare.com/ips-v4` +
/// `ips-v6`, falling back to [`CLOUDFLARE_RANGE_SNAPSHOT`] on any error.
///
/// Returns `(set, used_fallback)`. The caller logs a `warn` when
/// `used_fallback` is true.
pub async fn fetch_cloudflare_ranges(client: &reqwest::Client) -> (CidrSet, bool) {
    let v4_url = "https://www.cloudflare.com/ips-v4";
    let v6_url = "https://www.cloudflare.com/ips-v6";

    let v4 = client
        .get(v4_url)
        .timeout(std::time::Duration::from_secs(3))
        .send()
        .await;
    let v6 = client
        .get(v6_url)
        .timeout(std::time::Duration::from_secs(3))
        .send()
        .await;

    let mut set = CidrSet::default();
    let mut ok = true;
    if let Ok(resp) = v4
        && let Ok(text) = resp.text().await
    {
        for line in text.lines() {
            let line = line.trim();
            if !line.is_empty() {
                let _ = set.add(line);
            }
        }
    } else {
        ok = false;
    }
    if let Ok(resp) = v6
        && let Ok(text) = resp.text().await
    {
        for line in text.lines() {
            let line = line.trim();
            if !line.is_empty() {
                let _ = set.add(line);
            }
        }
    } else {
        ok = false;
    }

    if ok && !set.is_empty() {
        (set, false)
    } else {
        // Fallback to bundled snapshot.
        let mut snap = CidrSet::default();
        for c in CLOUDFLARE_RANGE_SNAPSHOT {
            let _ = snap.add(c);
        }
        (snap, true)
    }
}

// ─── Tests (Tier-1: pure classification) ──────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    fn cf_set() -> CidrSet {
        CidrSet::from_cidrs(CLOUDFLARE_RANGE_SNAPSHOT)
    }

    // ── aggregate_exit ──────────────────────────────────────────────────────

    #[test]
    fn aggregate_exit_no_fail_no_timeout_is_zero() {
        let s = Summary {
            pass: 5,
            warn: 1,
            fail: 0,
            skipped: 1,
        };
        assert_eq!(aggregate_exit(&s, false), 0);
    }

    #[test]
    fn aggregate_exit_fail_is_one() {
        let s = Summary {
            pass: 3,
            warn: 0,
            fail: 2,
            skipped: 0,
        };
        assert_eq!(aggregate_exit(&s, false), 1);
    }

    #[test]
    fn aggregate_exit_timeout_is_six() {
        let s = Summary {
            pass: 5,
            warn: 0,
            fail: 0,
            skipped: 0,
        };
        assert_eq!(aggregate_exit(&s, true), 6);
    }

    #[test]
    fn aggregate_exit_timeout_overshadows_fail() {
        let s = Summary {
            pass: 0,
            warn: 0,
            fail: 3,
            skipped: 0,
        };
        assert_eq!(aggregate_exit(&s, true), 6);
    }

    // ── DoctorReport JSON ───────────────────────────────────────────────────

    #[test]
    fn detection_report_omits_actions() {
        let report = DoctorReport::detection(vec![VerificationCheck::new(
            "runtime.socket",
            "Runtime socket",
            CheckStatus::Pass,
            "ok",
            None,
        )]);
        let v = report.to_json();
        assert_eq!(v["schema"], "slip.doctor/v1");
        assert_eq!(v["summary"]["pass"], 1);
        assert_eq!(v["summary"]["fail"], 0);
        assert!(
            v.get("actions").is_none() || v["actions"].is_null(),
            "actions should be omitted"
        );
        assert_eq!(v["checks"][0]["name"], "runtime.socket");
        assert_eq!(v["checks"][0]["status"], "pass");
        // remedy omitted when None
        assert!(v["checks"][0].get("remedy").is_none());
    }

    #[test]
    fn with_actions_report_includes_actions() {
        let report = DoctorReport::with_actions(
            vec![VerificationCheck::new(
                "ufw.bridge_dns",
                "UFW bridge DNS",
                CheckStatus::Fail,
                "rule missing",
                Some("ufw allow in on br-slip to any port 53".into()),
            )],
            vec![DoctorAction {
                name: "ufw.allow.bridge_dns".into(),
                command: "ufw allow in on br-slip to any port 53".into(),
                status: "applied".into(),
                rollback: Some("ufw delete allow in on br-slip to any port 53".into()),
            }],
        );
        let v = report.to_json();
        assert!(v.get("actions").is_some());
        assert_eq!(v["actions"][0]["status"], "applied");
        assert_eq!(
            v["actions"][0]["rollback"],
            "ufw delete allow in on br-slip to any port 53"
        );
    }

    // ── classify_ufw ────────────────────────────────────────────────────────

    #[test]
    fn classify_ufw_inactive_is_warn() {
        let out = "Status: inactive\n";
        let r = classify_ufw("br-slip", out);
        assert_eq!(r.status, CheckStatus::Warn);
    }

    #[test]
    fn classify_ufw_active_no_rule_is_fail_with_exact_remedy() {
        let out = "Status: active\n\n     To                         Action      From\n--    ------                    ------      -----\n[ 1] 22/tcp                     ALLOW IN    Anywhere\n";
        let r = classify_ufw("br-slip", out);
        assert_eq!(r.status, CheckStatus::Fail);
        assert_eq!(
            r.remedy.as_deref(),
            Some("ufw allow in on br-slip to any port 53")
        );
    }

    #[test]
    fn classify_ufw_active_with_rule_is_pass() {
        let out = "Status: active\n\n[ 1] 53/tcp on br-slip          ALLOW IN    Anywhere\n[ 2] 53/udp on br-slip          ALLOW IN    Anywhere\n";
        let r = classify_ufw("br-slip", out);
        assert_eq!(r.status, CheckStatus::Pass);
        assert!(r.remedy.is_none());
    }

    #[test]
    fn classify_ufw_empty_bridge_is_fail() {
        let r = classify_ufw("", "Status: active\n");
        assert_eq!(r.status, CheckStatus::Fail);
        assert!(r.remedy.as_deref().unwrap().contains("slip network"));
    }

    // ── parse_caddy_modules ─────────────────────────────────────────────────

    #[test]
    fn parse_caddy_modules_no_provider_is_skipped() {
        assert_eq!(parse_caddy_modules("xxx", None), CheckStatus::Skipped);
        assert_eq!(parse_caddy_modules("xxx", Some("")), CheckStatus::Skipped);
    }

    #[test]
    fn parse_caddy_modules_present_is_pass() {
        let out = "http.handlers.reverse_proxy\ndns.providers.cloudflare\n";
        assert_eq!(
            parse_caddy_modules(out, Some("cloudflare")),
            CheckStatus::Pass
        );
    }

    #[test]
    fn parse_caddy_modules_absent_is_fail() {
        let out = "http.handlers.reverse_proxy\n";
        assert_eq!(
            parse_caddy_modules(out, Some("cloudflare")),
            CheckStatus::Fail
        );
    }

    #[test]
    fn dns_plugin_remedy_names_xcaddy_command() {
        let r = dns_plugin_remedy("cloudflare");
        assert!(r.contains("xcaddy build"));
        assert!(r.contains("caddy-dns/cloudflare"));
    }

    // ── module_present_exact ─────────────────────────────────────────────────

    #[test]
    fn module_present_exact_present_is_pass() {
        let out = "http.handlers.reverse_proxy\ntls.get_certificate.tailscale\n";
        assert_eq!(
            module_present_exact(out, "tls.get_certificate.tailscale"),
            CheckStatus::Pass
        );
    }

    #[test]
    fn module_present_exact_absent_is_fail() {
        let out = "http.handlers.reverse_proxy\n";
        assert_eq!(
            module_present_exact(out, "tls.get_certificate.tailscale"),
            CheckStatus::Fail
        );
    }

    #[test]
    fn module_present_exact_rejects_substring() {
        // A module whose ID merely contains the target as a substring must NOT
        // match; exact line/field equality is required.
        let out = "tls.get_certificate.tailscale_extras\n";
        assert_eq!(
            module_present_exact(out, "tls.get_certificate.tailscale"),
            CheckStatus::Fail
        );
        // Prefix-only also rejected.
        let out2 = "tls.get_certificate.tailscale.v2\n";
        assert_eq!(
            module_present_exact(out2, "tls.get_certificate.tailscale"),
            CheckStatus::Fail
        );
    }

    #[test]
    fn module_present_exact_tab_packages_first_field() {
        // `caddy list-modules --packages` emits `<id>\t<package>`. The first
        // tab-separated field is the module ID; only it must match exactly.
        let out = "http.handlers.reverse_proxy\tgithub.com/caddyserver/caddy/v2\n\
                   tls.get_certificate.tailscale\tgithub.com/caddyserver/caddy/v2\tv2.11.0\n";
        assert_eq!(
            module_present_exact(out, "tls.get_certificate.tailscale"),
            CheckStatus::Pass
        );
        // A package path that happens to contain the needle must not match.
        let out2 = "http.handlers.reverse_proxy\tgithub.com/x/tls.get_certificate.tailscale\n";
        assert_eq!(
            module_present_exact(out2, "tls.get_certificate.tailscale"),
            CheckStatus::Fail
        );
    }

    #[test]
    fn module_present_exact_empty_module_id_is_skipped() {
        assert_eq!(module_present_exact("anything", ""), CheckStatus::Skipped);
        // Empty output + empty id still skipped (id check first).
        assert_eq!(module_present_exact("", ""), CheckStatus::Skipped);
    }

    // ── CidrSet / is_cloudflare_ip ──────────────────────────────────────────

    #[test]
    fn cidr_set_contains_known_cloudflare_v4() {
        let s = cf_set();
        // 104.16.0.1 is inside 104.16.0.0/13
        let ip: IpAddr = "104.16.0.1".parse().unwrap();
        assert!(s.contains(&ip));
    }

    #[test]
    fn cidr_set_rejects_non_cloudflare_v4() {
        let s = cf_set();
        let ip: IpAddr = "8.8.8.8".parse().unwrap();
        assert!(!s.contains(&ip));
    }

    #[test]
    fn cidr_set_contains_known_cloudflare_v6() {
        let s = cf_set();
        let ip: IpAddr = "2606:4700::1".parse().unwrap();
        assert!(s.contains(&ip));
    }

    #[test]
    fn is_private_or_cgnat_rfc1918() {
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        assert!(is_private_or_cgnat(&ip));
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        assert!(is_private_or_cgnat(&ip));
        let ip: IpAddr = "172.16.0.1".parse().unwrap();
        assert!(is_private_or_cgnat(&ip));
    }

    #[test]
    fn is_private_or_cgnat_cgnat_100_64() {
        let ip: IpAddr = "100.64.0.1".parse().unwrap();
        assert!(is_private_or_cgnat(&ip));
    }

    #[test]
    fn is_private_or_cgnat_loopback() {
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        assert!(is_private_or_cgnat(&ip));
    }

    #[test]
    fn is_private_or_cgnat_public_is_false() {
        let ip: IpAddr = "1.1.1.1".parse().unwrap();
        assert!(!is_private_or_cgnat(&ip));
    }

    #[test]
    fn is_private_or_cgnat_ula_v6() {
        let ip: IpAddr = "fd00::1".parse().unwrap();
        assert!(is_private_or_cgnat(&ip));
    }

    #[test]
    fn is_private_or_cgnat_link_local_v6() {
        let ip: IpAddr = "fe80::1".parse().unwrap();
        assert!(is_private_or_cgnat(&ip));
    }

    // ── classify_dns_expectation (Q5 taxonomy, all branches) ────────────────

    #[test]
    fn dns_expectation_dns_error_is_fail() {
        let r = classify_dns_expectation("host.example", &[], "internal", None, &cf_set(), true);
        assert_eq!(r.status, CheckStatus::Fail);
    }

    #[test]
    fn dns_expectation_unresolved_is_warn_with_record_remedy() {
        let r = classify_dns_expectation("host.example", &[], "acme", None, &cf_set(), false);
        assert_eq!(r.status, CheckStatus::Warn);
        assert!(r.remedy.as_deref().unwrap().contains("DNS record"));
    }

    #[test]
    fn dns_expectation_proxied_tailnet_origin_is_fail_grey_cloud() {
        // 104.16.0.1 is in CF ranges; tls=internal → orange-clouded tailnet.
        let ip: IpAddr = "104.16.0.1".parse().unwrap();
        let r =
            classify_dns_expectation("tailnet.example", &[ip], "internal", None, &cf_set(), false);
        assert_eq!(r.status, CheckStatus::Fail);
        assert!(r.remedy.as_deref().unwrap().contains("grey cloud"));
    }

    #[test]
    fn dns_expectation_proxied_private_origin_is_fail() {
        let ip: IpAddr = "104.16.0.1".parse().unwrap();
        // private origin IP alongside the proxied one → fail (any_proxied && any_private).
        let priv_ip: IpAddr = "10.0.0.5".parse().unwrap();
        let r = classify_dns_expectation(
            "host.example",
            &[ip, priv_ip],
            "acme",
            None,
            &cf_set(),
            false,
        );
        assert_eq!(r.status, CheckStatus::Fail);
    }

    #[test]
    fn dns_expectation_proxied_public_origin_is_pass() {
        let ip: IpAddr = "104.16.0.1".parse().unwrap();
        let r = classify_dns_expectation("host.example", &[ip], "acme", None, &cf_set(), false);
        assert_eq!(r.status, CheckStatus::Pass);
    }

    #[test]
    fn dns_expectation_proxied_public_origin_with_dns01_is_pass() {
        // Regression: a public origin behind Cloudflare proxy with DNS-01
        // TLS is a valid, common setup. It must NOT be classified as fail
        // (the `tailnet_or_internal` set excludes `cloudflare-dns01`/`dns01`).
        let ip: IpAddr = "104.16.0.1".parse().unwrap();
        let r = classify_dns_expectation(
            "host.example",
            &[ip],
            "cloudflare-dns01",
            None,
            &cf_set(),
            false,
        );
        assert_eq!(r.status, CheckStatus::Pass);
    }

    #[test]
    fn dns_expectation_proxied_public_origin_with_dns01_is_pass_generic() {
        let ip: IpAddr = "104.16.0.1".parse().unwrap();
        let r = classify_dns_expectation("host.example", &[ip], "dns01", None, &cf_set(), false);
        assert_eq!(r.status, CheckStatus::Pass);
    }

    #[test]
    fn dns_expectation_proxied_private_origin_with_dns01_is_fail() {
        // Regression: even with DNS-01, a private/CGNAT origin behind an
        // orange cloud must still fail (Cloudflare proxy can't reach a
        // 100.x origin). The `any_private` check catches this independently
        // of the TLS strategy.
        let proxied_ip: IpAddr = "104.16.0.1".parse().unwrap();
        let private_ip: IpAddr = "100.64.0.1".parse().unwrap();
        let r = classify_dns_expectation(
            "tailnet.example",
            &[proxied_ip, private_ip],
            "cloudflare-dns01",
            None,
            &cf_set(),
            false,
        );
        assert_eq!(r.status, CheckStatus::Fail);
        assert!(r.remedy.as_deref().unwrap().contains("grey cloud"));
    }

    #[test]
    fn dns_expectation_proxied_hint_false_is_fail() {
        let ip: IpAddr = "104.16.0.1".parse().unwrap();
        let r =
            classify_dns_expectation("host.example", &[ip], "acme", Some(false), &cf_set(), false);
        assert_eq!(r.status, CheckStatus::Fail);
        assert!(r.remedy.as_deref().unwrap().contains("grey cloud"));
    }

    #[test]
    fn dns_expectation_private_origin_is_warn() {
        let ip: IpAddr = "10.0.0.5".parse().unwrap();
        let r = classify_dns_expectation("host.example", &[ip], "internal", None, &cf_set(), false);
        assert_eq!(r.status, CheckStatus::Warn);
    }

    #[test]
    fn dns_expectation_direct_public_is_pass() {
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        let r = classify_dns_expectation("host.example", &[ip], "acme", None, &cf_set(), false);
        assert_eq!(r.status, CheckStatus::Pass);
    }

    // ── render_human ────────────────────────────────────────────────────────

    #[test]
    fn render_human_shows_icons_and_remedy() {
        let checks = vec![
            VerificationCheck::new("a", "A", CheckStatus::Pass, "ok", None),
            VerificationCheck::new("b", "B", CheckStatus::Fail, "bad", Some("fix me".into())),
        ];
        let s = render_human(&checks);
        assert!(s.contains("✓"));
        assert!(s.contains("✗"));
        assert!(s.contains("→ fix me"));
        assert!(s.contains("1 passed"));
        assert!(s.contains("1 failed"));
    }
}
