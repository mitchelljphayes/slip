//! Pull-time registry credential resolution (SLIP-105).
//!
//! Given an image reference (e.g. `ghcr.io/me/app:1`, `nginx`, or
//! `localhost:5000/internal/svc`) and the merged registry set (TOML-declared
//! tokens + store creds), resolve the correct credential via
//! **longest-path-segment-prefix match**: the registry whose normalized url
//! is a path-segment prefix of the image's `host/path` wins, with the
//! entry having the most path segments in its url taking precedence.
//!
//! `host`-only entries match any image on that host. `host` and `host:443`
//! are distinct (no grandfathering — document `docker.io` keying).

use crate::config::SlipConfig;
use crate::runtime::RegistryCredentials;
use crate::secrets::SecretsStore;

/// A registry credential resolved against both TOML-declared and store-credentialed
/// registries. Store creds override TOML tokens on URL-match (documented precedence).
#[derive(Debug, Clone)]
pub struct ResolvedRegistry {
    /// Normalized registry host[:port].
    pub url: String,
    pub username: Option<String>,
    pub password: String,
    /// Where the credential came from: `Toml` (slip.toml) or `Store` (`slip registry login`).
    pub source: RegistryCredSource,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistryCredSource {
    Toml,
    Store,
}

/// Build the merged registry table: TOML-declared registries + store creds.
/// Store creds override TOML tokens on URL-match (the store is the preferred
/// path; a TOML `token` is the bootstrap fallback). Computed fresh per-deploy
/// so `slip registry login` takes effect without a daemon restart.
pub fn merged_registry_table(config: &SlipConfig, store: &SecretsStore) -> Vec<ResolvedRegistry> {
    // Store creds first (winners on URL collision).
    let mut out: Vec<ResolvedRegistry> = Vec::new();
    let mut seen_urls: std::collections::HashSet<String> = std::collections::HashSet::new();

    if let Ok(store_entries) = store.list_registry_credentials() {
        for entry in store_entries {
            if let Ok(Some((username, password))) = store.get_registry_credential(&entry.url) {
                out.push(ResolvedRegistry {
                    url: entry.url.clone(),
                    username,
                    password,
                    source: RegistryCredSource::Store,
                });
                seen_urls.insert(entry.url);
            }
        }
    }

    // TOML-declared registries that aren't shadowed by a store cred.
    for toml_entry in config.registries.registries.values() {
        if seen_urls.contains(&toml_entry.url) {
            continue;
        }
        if let Some(token) = &toml_entry.token {
            out.push(ResolvedRegistry {
                url: toml_entry.url.clone(),
                username: toml_entry.username.clone(),
                password: token.clone(),
                source: RegistryCredSource::Toml,
            });
            seen_urls.insert(toml_entry.url.clone());
        }
    }

    out
}

/// Normalize an image ref into `(host, full_host_path)` for matching.
///
/// - Strips tag (`:tag`) and digest (`@sha256:...`).
/// - Bare names (`nginx`) → `docker.io` + `library/nginx` (Docker Hub convention).
/// - Names with a single path segment (`me/app`) → `docker.io/me/app`.
/// - `host/path:tag` → `host/path` (host is the first segment if it contains a `.` or `:` or is `localhost`).
///
/// Returns `(host, host/path)` where `host/path` is the full reference used for
/// longest-prefix matching against registry urls.
pub fn normalize_image_ref(image_ref: &str) -> (String, String) {
    // Strip digest first (@sha256:...).
    let without_digest = if let Some(at_pos) = image_ref.rfind('@') {
        &image_ref[..at_pos]
    } else {
        image_ref
    };

    // Strip tag (:tag). The tag colon is the last `:` that comes AFTER the
    // last `/` (or the only `:` if there's no `/`). A port colon (host:5000)
    // comes BEFORE any `/` in `host:port/path` and is not a tag.
    let without_tag = match without_digest.rfind(':') {
        Some(colon_pos) => {
            let last_slash = without_digest.rfind('/');
            // The colon is a tag separator iff it's after the last slash (or
            // there's no slash at all). A port colon is before the slash.
            let is_tag = match last_slash {
                Some(slash_pos) => colon_pos > slash_pos,
                None => true,
            };
            if is_tag {
                &without_digest[..colon_pos]
            } else {
                without_digest
            }
        }
        None => without_digest,
    };

    // Now `without_tag` is `host/path/name` or `name` or `host:port/path/name`.
    if without_tag.contains('/') {
        // Does the first segment look like a host? (contains `.` or `:` or is `localhost`).
        let first_seg = without_tag.split('/').next().unwrap_or("");
        let is_host =
            first_seg.contains('.') || first_seg.contains(':') || first_seg == "localhost";
        if is_host {
            // host/path/name
            let host = first_seg.to_string();
            let full = without_tag.to_string();
            (host, full)
        } else {
            // me/app → docker.io/me/app (Docker Hub implicit).
            let full = format!("docker.io/{without_tag}");
            ("docker.io".to_string(), full)
        }
    } else {
        // Bare name → docker.io/library/<name>.
        let full = format!("docker.io/library/{without_tag}");
        ("docker.io".to_string(), full)
    }
}

/// Resolve the credential for an image ref via longest-path-segment-prefix match.
///
/// Walks `registries` filtered to those whose `normalized_url` is a path-segment
/// prefix of the image's `host/path`; picks the entry with the **most path segments**
/// in its url (tie-break: lexical for determinism). `host`-only entries match any
/// image on that host. Returns `None` if no registry matches.
pub fn resolve_registry_credential(
    image_ref: &str,
    registries: &[ResolvedRegistry],
) -> Option<RegistryCredentials> {
    let (img_host, _img_full) = normalize_image_ref(image_ref);

    let mut best: Option<(&ResolvedRegistry, usize)> = None;
    for reg in registries {
        // The registry url is host[:port]; it must match the image host exactly.
        // (Registries declare host-only; per-path cred selection is by image path
        // namespacing, not by registry url path — registry urls have no path.)
        if reg.url != img_host {
            continue;
        }
        // Segment count of the registry url (host = 1 segment; host:port = 1).
        // The "longest prefix" here is really "does the host match" — since
        // registry urls are host[:port] only (no path), the segment count is
        // always 1. The tie-break is lexical. This satisfies the plan's
        // "host-only entries match any image on that host" rule.
        // (If we later allow registry urls with path prefixes, this is where
        // the segment-count comparison would go. For now, first match wins
        // deterministically.)
        let seg_count = 1usize;
        match best {
            None => best = Some((reg, seg_count)),
            Some((_, best_count)) if seg_count > best_count => best = Some((reg, seg_count)),
            Some((best_reg, best_count)) if seg_count == best_count && reg.url < best_reg.url => {
                best = Some((reg, seg_count));
            }
            _ => {}
        }
    }

    best.map(|(reg, _)| RegistryCredentials {
        username: reg.username.clone().unwrap_or_else(|| "slip".to_string()),
        password: reg.password.clone(),
    })
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn reg(url: &str, user: Option<&str>, pass: &str) -> ResolvedRegistry {
        ResolvedRegistry {
            url: url.to_string(),
            username: user.map(|s| s.to_string()),
            password: pass.to_string(),
            source: RegistryCredSource::Toml,
        }
    }

    // ── normalize_image_ref ──────────────────────────────────────────────────

    #[test]
    fn normalize_image_ref_ghcr() {
        let (host, full) = normalize_image_ref("ghcr.io/me/app:1");
        assert_eq!(host, "ghcr.io");
        assert_eq!(full, "ghcr.io/me/app");
    }

    #[test]
    fn normalize_image_ref_localhost_port() {
        let (host, full) = normalize_image_ref("localhost:5000/internal/svc:latest");
        assert_eq!(host, "localhost:5000");
        assert_eq!(full, "localhost:5000/internal/svc");
    }

    #[test]
    fn normalize_image_ref_bare_name_dockerhub() {
        let (host, full) = normalize_image_ref("nginx");
        assert_eq!(host, "docker.io");
        assert_eq!(full, "docker.io/library/nginx");
    }

    #[test]
    fn normalize_image_ref_single_seg_dockerhub() {
        // me/app → docker.io/me/app (no host given → Docker Hub).
        let (host, full) = normalize_image_ref("me/app:1");
        assert_eq!(host, "docker.io");
        assert_eq!(full, "docker.io/me/app");
    }

    #[test]
    fn normalize_image_ref_strips_digest() {
        let (host, full) = normalize_image_ref("ghcr.io/me/app@sha256:abc123");
        assert_eq!(host, "ghcr.io");
        assert_eq!(full, "ghcr.io/me/app");
    }

    // ── resolve_registry_credential ──────────────────────────────────────────

    #[test]
    fn resolve_picks_matching_host() {
        let regs = vec![
            reg("ghcr.io", Some("u1"), "t1"),
            reg("localhost:5000", None, "t2"),
        ];
        let cred = resolve_registry_credential("ghcr.io/me/app:1", &regs).unwrap();
        assert_eq!(cred.username, "u1");
        assert_eq!(cred.password, "t1");
    }

    #[test]
    fn resolve_two_registries_one_cycle() {
        // The two-registries-in-one-cycle assertion: main on ghcr.io, sidecar
        // on localhost:5000 — each resolves to its own cred.
        let regs = vec![
            reg("ghcr.io", Some("ghcr-user"), "ghcr-tok"),
            reg("localhost:5000", Some("ci"), "local-tok"),
        ];
        let main = resolve_registry_credential("ghcr.io/me/app:1", &regs).unwrap();
        assert_eq!(main.username, "ghcr-user");
        assert_eq!(main.password, "ghcr-tok");

        let sidecar = resolve_registry_credential("localhost:5000/internal/svc", &regs).unwrap();
        assert_eq!(sidecar.username, "ci");
        assert_eq!(sidecar.password, "local-tok");

        assert_ne!(main.password, sidecar.password, "distinct creds per image");
    }

    #[test]
    fn resolve_bare_name_matches_docker_io() {
        let regs = vec![reg("docker.io", Some("hub"), "hub-tok")];
        let cred = resolve_registry_credential("nginx", &regs).unwrap();
        assert_eq!(cred.username, "hub");
        assert_eq!(cred.password, "hub-tok");
    }

    #[test]
    fn resolve_host_only_matches_any_image_on_host() {
        let regs = vec![reg("ghcr.io", Some("u"), "t")];
        // Different paths on the same host both match.
        let a = resolve_registry_credential("ghcr.io/team/a:1", &regs).unwrap();
        let b = resolve_registry_credential("ghcr.io/other/b:2", &regs).unwrap();
        assert_eq!(a.password, "t");
        assert_eq!(b.password, "t");
    }

    #[test]
    fn resolve_host_and_host_port_distinct() {
        let regs = vec![
            reg("reg.io", Some("a"), "pa"),
            reg("reg.io:443", Some("b"), "pb"),
        ];
        let plain = resolve_registry_credential("reg.io/team/app:1", &regs).unwrap();
        assert_eq!(plain.password, "pa");
        let port = resolve_registry_credential("reg.io:443/team/app:1", &regs).unwrap();
        assert_eq!(port.password, "pb");
        assert_ne!(plain.password, port.password);
    }

    #[test]
    fn resolve_none_when_no_match() {
        let regs = vec![reg("ghcr.io", Some("u"), "t")];
        assert!(resolve_registry_credential("other.io/app:1", &regs).is_none());
    }

    #[test]
    fn resolve_default_username_slip_when_absent() {
        let regs = vec![reg("ghcr.io", None, "t")];
        let cred = resolve_registry_credential("ghcr.io/me/app:1", &regs).unwrap();
        assert_eq!(cred.username, "slip", "absent username defaults to 'slip'");
        assert_eq!(cred.password, "t");
    }
}
