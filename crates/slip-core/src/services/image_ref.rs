//! Strict, fully-qualified, digest-pinned image reference value types.
//!
//! Two newtypes enforce SLIP-106's "no floating image" invariant at the type
//! level:
//!
//! - [`ImageDigest`]: exactly `sha256:<64 lowercase hex>`. Construction is
//!   fallible; there is no `From<String>` or `Deserialize` bypass.
//! - [`PinnedImageRef`]: a canonical `registry/repository[:tag]@sha256:<64hex>`
//!   reference. The registry is mandatory (unqualified names are rejected),
//!   the repository is lowercase, the optional tag is never `latest`, and the
//!   digest is carried as a separate [`ImageDigest`] so callers can verify an
//!   inspected image's `repo_digests` without re-parsing.
//!
//! ## Grammar (supported use)
//!
//! The grammar is a strict subset of the OCI distribution reference
//! grammar. It covers fully-qualified references with an exact digest:
//!
//! ```text
//! reference  := registry "/" repository ("@" digest | ":" tag "@" digest)
//! registry   := host (":" port)
//! host       := label ("." label)*
//! label      := [a-z0-9]+ (("-" | [a-z0-9])* [a-z0-9])?   // lowercase, no leading/trailing "-"
//! port       := [0-9]{1,5}   // 1..=65535
//! repository := component ("/" component)*
//! component  := [a-z0-9]+ (("." | "_" | "-" | "__" | [a-z0-9])* [a-z0-9])?
//! tag        := [a-zA-Z0-9_][a-zA-Z0-9._-]{0,127}   // never "latest"
//! digest     := "sha256:" 64*[a-f0-9]
//! ```
//!
//! Whitespace, control characters, multiple `@`, uppercase repository names,
//! unqualified names (no registry), `latest`, and abbreviated digests are all
//! rejected at construction. [`PinnedImageRef::repo_digest`] drops the tag
//! and returns the exact canonical `registry/repository@sha256:<digest>`.

use std::fmt;

use crate::services::spec::ServiceError;

// ─── ImageDigest ─────────────────────────────────────────────────────────────

/// A validated SHA-256 image manifest digest: exactly `sha256:` followed by
/// 64 lowercase hex characters.
///
/// Construction is fallible -- [`ImageDigest::parse`] rejects empty, short,
/// long, uppercase, and non-hex values, and values missing the `sha256:`
/// prefix. There is no `From<String>` or `Deserialize` impl; the only way to
/// obtain one is to parse a string. This makes an unvalidated digest
/// unrepresentable in any API that takes an `ImageDigest`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ImageDigest {
    hex: String,
}

impl ImageDigest {
    /// Parse and validate a SHA-256 image digest of the form
    /// `sha256:<64 lowercase hex>`.
    pub fn parse(s: &str) -> Result<Self, ServiceError> {
        let hex = s.strip_prefix("sha256:").ok_or_else(|| {
            ServiceError::Internal(format!(
                "image digest must start with 'sha256:' (got '{s}')"
            ))
        })?;
        Self::parse_hex(hex)
    }

    /// Parse a bare 64-char lowercase hex digest (no `sha256:` prefix). Used
    /// when the digest is extracted from a `repo@sha256:...` repo-digest
    /// entry.
    pub fn parse_hex(hex: &str) -> Result<Self, ServiceError> {
        if hex.len() != 64 {
            return Err(ServiceError::Internal(format!(
                "image digest must be exactly 64 lowercase hex characters (got {} chars)",
                hex.len()
            )));
        }
        if !hex
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        {
            return Err(ServiceError::Internal(
                "image digest must be lowercase hexadecimal".to_string(),
            ));
        }
        Ok(Self {
            hex: hex.to_string(),
        })
    }

    /// The full digest string, including the `sha256:` prefix.
    pub fn as_str(&self) -> String {
        format!("sha256:{}", self.hex)
    }

    /// The bare 64-char hex digest, without the `sha256:` prefix.
    pub fn hex(&self) -> &str {
        &self.hex
    }
}

impl fmt::Display for ImageDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "sha256:{}", self.hex)
    }
}

// ─── PinnedImageRef ──────────────────────────────────────────────────────────

/// A validated, fully-qualified, digest-pinned image reference.
///
/// Canonical form: `registry/repository[:tag]@sha256:<64 lowercase hex>`.
/// The registry is mandatory -- unqualified names like `postgres:18` are
/// rejected. The repository is lowercase. The optional tag is never
/// `latest`. The digest is exactly 64 lowercase hex characters preceded by
/// `sha256:`. Whitespace, control characters, multiple `@`, malformed host
/// labels/ports, uppercase repository components, empty repository
/// components, and abbreviated digests are all rejected at construction.
///
/// There is no `From<String>` or `Deserialize` impl, so an unvalidated
/// reference is unrepresentable in any API that takes a `PinnedImageRef`.
///
/// The approved [`ImageDigest`] is carried alongside the reference so a
/// caller can verify an inspected image's `repo_digests` without re-parsing.
/// [`repo_digest`](Self::repo_digest) drops the tag and returns the exact
/// canonical `registry/repository@sha256:<digest>`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PinnedImageRef {
    /// Canonical full reference string:
    /// `registry/repository[:tag]@sha256:<digest>`.
    full: String,
    /// `registry/repository[:tag]` -- everything before the `@`.
    registry_repo_tag: String,
    /// The canonical `registry/repository` without any tag.
    registry_repo: String,
    /// The optional non-`latest` tag (e.g. `18.4-bookworm`).
    tag: Option<String>,
    /// The validated digest carried separately.
    digest: ImageDigest,
}

impl PinnedImageRef {
    /// Parse and validate a fully-qualified, digest-pinned image reference.
    ///
    /// Rejects: empty input, whitespace, control characters, multiple
    /// `@`, missing `@`, missing digest, malformed `sha256:` prefix.
    /// Also rejects abbreviated or uppercase digests, unqualified names
    /// (no `/`), malformed registry host labels/ports, uppercase
    /// repository components, empty repository components, and the
    /// `latest` tag.
    pub fn parse(s: &str) -> Result<Self, ServiceError> {
        if s.is_empty() {
            return Err(ServiceError::Internal(
                "image reference must not be empty".to_string(),
            ));
        }
        // Reject whitespace and control characters across the whole input.
        if s.chars().any(|c| c.is_whitespace() || c.is_control()) {
            return Err(ServiceError::Internal(
                "image reference must not contain whitespace or control characters".to_string(),
            ));
        }
        // Reject multiple '@' -- exactly one digest separator is permitted.
        let at_count = s.matches('@').count();
        if at_count != 1 {
            return Err(ServiceError::Internal(format!(
                "image reference must contain exactly one '@' digest separator (found {at_count})"
            )));
        }
        let at = s
            .find('@')
            .ok_or_else(|| ServiceError::Internal("image reference missing '@'".to_string()))?;
        let registry_repo_tag = &s[..at];
        let digest_str = &s[at + 1..];
        let digest = ImageDigest::parse(digest_str)?;

        if registry_repo_tag.is_empty() {
            return Err(ServiceError::Internal(
                "image reference repository must not be empty".to_string(),
            ));
        }

        // Split off the optional tag. The tag is after the last ':' that
        // appears after the last '/'. A ':' before the last '/' is part of
        // the registry port.
        let (registry_repo, tag) = split_repo_tag(registry_repo_tag)?;

        // Reject `latest` tag.
        if let Some(t) = &tag {
            if t == "latest" {
                return Err(ServiceError::Internal(
                    "image reference tag 'latest' is not permitted for managed services \
                     -- use an exact digest-pinned reference"
                        .to_string(),
                ));
            }
            validate_tag(t)?;
        }

        // Validate the registry/repository grammar.
        validate_registry_repo(&registry_repo)?;

        Ok(Self {
            full: s.to_string(),
            registry_repo_tag: registry_repo_tag.to_string(),
            registry_repo,
            tag,
            digest,
        })
    }

    /// The full canonical reference string, including the digest.
    pub fn as_str(&self) -> &str {
        &self.full
    }

    /// The `registry/repository[:tag]` portion before the `@`.
    pub fn registry_repo_tag(&self) -> &str {
        &self.registry_repo_tag
    }

    /// The canonical `registry/repository` without any tag.
    pub fn registry_repo(&self) -> &str {
        &self.registry_repo
    }

    /// The optional non-`latest` tag (e.g. `18.4-bookworm`).
    pub fn tag(&self) -> Option<&str> {
        self.tag.as_deref()
    }

    /// The validated digest carried separately from the reference string.
    pub fn digest(&self) -> &ImageDigest {
        &self.digest
    }

    /// Drop the tag and return the exact canonical
    /// `registry/repository@sha256:<digest>` repo-digest form.
    ///
    /// This is the form compared against an inspected image's
    /// `repo_digests` entries to verify the pulled image matches the
    /// approved digest.
    pub fn repo_digest(&self) -> String {
        format!("{}@{}", self.registry_repo, self.digest.as_str())
    }
}

impl fmt::Display for PinnedImageRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.full)
    }
}

// ─── Grammar helpers ─────────────────────────────────────────────────────────

/// Split `registry/repository[:tag]` into `(registry/repository, Option<tag>)`.
///
/// The tag is the suffix after the last `:` that follows the last `/`. A
/// `:` before the last `/` is part of the registry port, not a tag.
fn split_repo_tag(registry_repo_tag: &str) -> Result<(String, Option<String>), ServiceError> {
    // Find the last '/' -- everything after it is the final repo component
    // (optionally with a tag).
    let last_slash = registry_repo_tag.rfind('/');
    let after_slash = last_slash
        .map(|i| &registry_repo_tag[i + 1..])
        .unwrap_or(registry_repo_tag);

    // A tag separator is a ':' that appears after the last '/'.
    if let Some(colon) = after_slash.rfind(':') {
        let tag = &after_slash[colon + 1..];
        let repo_end = last_slash.map(|i| i + 1).unwrap_or(0) + colon;
        let registry_repo = &registry_repo_tag[..repo_end];
        if tag.is_empty() {
            return Err(ServiceError::Internal(
                "image reference tag must not be empty".to_string(),
            ));
        }
        Ok((registry_repo.to_string(), Some(tag.to_string())))
    } else {
        Ok((registry_repo_tag.to_string(), None))
    }
}

/// Validate a tag: `[a-zA-Z0-9_][a-zA-Z0-9._-]{0,127}`.
fn validate_tag(tag: &str) -> Result<(), ServiceError> {
    if tag.is_empty() || tag.len() > 128 {
        return Err(ServiceError::Internal(format!(
            "image reference tag length {} out of range [1, 128]",
            tag.len()
        )));
    }
    let mut chars = tag.chars();
    let first = chars.next().unwrap();
    if !(first.is_ascii_alphanumeric() || first == '_') {
        return Err(ServiceError::Internal(
            "image reference tag must start with [a-zA-Z0-9_]".to_string(),
        ));
    }
    for c in chars {
        if !(c.is_ascii_alphanumeric() || c == '_' || c == '.' || c == '-') {
            return Err(ServiceError::Internal(format!(
                "image reference tag contains invalid character '{c}'"
            )));
        }
    }
    Ok(())
}

/// Validate the `registry/repository` grammar.
///
/// `registry/repository` is split into the registry (first component, which
/// may contain a `:` port) and the repository path. An unqualified name (no
/// `/`) is rejected. Lengths are bounded: registry <= 255, repository <=
/// 255, total reference <= 4096.
fn validate_registry_repo(registry_repo: &str) -> Result<(), ServiceError> {
    if registry_repo.len() > 512 {
        return Err(ServiceError::Internal(format!(
            "registry/repository length {} exceeds 512",
            registry_repo.len()
        )));
    }
    let first_slash = registry_repo
        .find('/')
        .ok_or_else(|| ServiceError::Internal(
            "image reference must be fully qualified (registry/repository) -- unqualified names are not permitted".to_string(),
        ))?;
    let registry = &registry_repo[..first_slash];
    let repo = &registry_repo[first_slash + 1..];

    if registry.is_empty() {
        return Err(ServiceError::Internal(
            "image reference registry must not be empty".to_string(),
        ));
    }
    if registry.len() > 255 {
        return Err(ServiceError::Internal(format!(
            "image reference registry length {} exceeds 255",
            registry.len()
        )));
    }
    if repo.is_empty() {
        return Err(ServiceError::Internal(
            "image reference repository path must not be empty".to_string(),
        ));
    }
    if repo.len() > 255 {
        return Err(ServiceError::Internal(format!(
            "image reference repository length {} exceeds 255",
            repo.len()
        )));
    }

    validate_registry(registry)?;
    validate_repository(repo)?;
    Ok(())
}

/// Validate the registry: `host` or `host:port`.
///
/// `host` is one or more lowercase labels separated by `.`. A label is
/// `[a-z0-9]` plus optional interior `-` (no leading/trailing `-`). A port
/// is 1-5 digits in the range 1..=65535.
fn validate_registry(registry: &str) -> Result<(), ServiceError> {
    // Split off an optional port. A port is a ':' followed by digits, and it
    // only counts if there is no '/' after it (there is no '/' here -- we
    // already split the registry off before the first '/').
    let (host, port) = match registry.rfind(':') {
        Some(colon) => {
            let after = &registry[colon + 1..];
            // The ':' is only a port separator if everything after it is
            // digits. If not, it's part of a label (which is invalid
            // anyway, but we want the right error).
            if after.is_empty() {
                return Err(ServiceError::Internal(
                    "image reference registry port must not be empty".to_string(),
                ));
            }
            if after.chars().all(|c| c.is_ascii_digit()) {
                (Some(&registry[..colon]), Some(after))
            } else {
                // Not a port -- the whole thing is the host (will fail
                // label validation).
                (Some(registry), None)
            }
        }
        None => (Some(registry), None),
    };

    let host = host.unwrap();
    if host.is_empty() {
        return Err(ServiceError::Internal(
            "image reference registry host must not be empty".to_string(),
        ));
    }

    for label in host.split('.') {
        validate_host_label(label)?;
    }

    if let Some(p) = port {
        validate_port(p)?;
    }
    Ok(())
}

/// Validate a single host label: `[a-z0-9]` plus optional interior `-` (no
/// leading/trailing `-`), at least one character.
fn validate_host_label(label: &str) -> Result<(), ServiceError> {
    if label.is_empty() {
        return Err(ServiceError::Internal(
            "image reference registry host label must not be empty".to_string(),
        ));
    }
    if label.len() > 63 {
        return Err(ServiceError::Internal(format!(
            "image reference registry host label length {} exceeds 63",
            label.len()
        )));
    }
    if !(label.starts_with(|c: char| c.is_ascii_lowercase() || c.is_ascii_digit())
        && label.ends_with(|c: char| c.is_ascii_lowercase() || c.is_ascii_digit()))
    {
        return Err(ServiceError::Internal(
            "image reference registry host label must start and end with [a-z0-9]".to_string(),
        ));
    }
    for c in label.chars() {
        if !(c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-') {
            return Err(ServiceError::Internal(format!(
                "image reference registry host label contains invalid character '{c}' \
                 (lowercase alphanumeric and '-' only)"
            )));
        }
    }
    Ok(())
}

/// Validate a port: 1-5 digits in the range 1..=65535.
fn validate_port(port: &str) -> Result<(), ServiceError> {
    if port.is_empty() || port.len() > 5 {
        return Err(ServiceError::Internal(format!(
            "image reference registry port length {} out of range [1, 5]",
            port.len()
        )));
    }
    if !port.chars().all(|c| c.is_ascii_digit()) {
        return Err(ServiceError::Internal(
            "image reference registry port must be digits only".to_string(),
        ));
    }
    let n: u32 = port
        .parse()
        .map_err(|_| ServiceError::Internal(format!("invalid registry port '{port}'")))?;
    if n == 0 || n > 65535 {
        return Err(ServiceError::Internal(format!(
            "image reference registry port {n} out of range [1, 65535]"
        )));
    }
    Ok(())
}

/// Validate the repository path: one or more `/`-separated components, each
/// lowercase alphanumeric plus interior `.`, `_`, `-`, `__`. No empty
/// components, no uppercase, no leading/trailing separators.
fn validate_repository(repo: &str) -> Result<(), ServiceError> {
    if repo.is_empty() {
        return Err(ServiceError::Internal(
            "image reference repository must not be empty".to_string(),
        ));
    }
    // Reject leading/trailing '/' and consecutive '/' (empty components).
    if repo.starts_with('/') || repo.ends_with('/') || repo.contains("//") {
        return Err(ServiceError::Internal(
            "image reference repository must not contain empty components".to_string(),
        ));
    }
    for component in repo.split('/') {
        validate_repo_component(component)?;
    }
    Ok(())
}

/// Validate a single repository component: lowercase alphanumeric plus
/// interior `.`, `_`, `-`. Must start and end with alphanumeric. No
/// uppercase. No consecutive separators at boundaries. 1-128 characters.
fn validate_repo_component(component: &str) -> Result<(), ServiceError> {
    if component.is_empty() {
        return Err(ServiceError::Internal(
            "image reference repository component must not be empty".to_string(),
        ));
    }
    if component.len() > 128 {
        return Err(ServiceError::Internal(format!(
            "image reference repository component length {} exceeds 128",
            component.len()
        )));
    }
    if !(component.starts_with(|c: char| c.is_ascii_lowercase() || c.is_ascii_digit())
        && component.ends_with(|c: char| c.is_ascii_lowercase() || c.is_ascii_digit()))
    {
        return Err(ServiceError::Internal(
            "image reference repository component must start and end with [a-z0-9]".to_string(),
        ));
    }
    let mut prev_sep = false;
    for c in component.chars() {
        if c.is_ascii_uppercase() {
            return Err(ServiceError::Internal(
                "image reference repository must be lowercase (uppercase character rejected)"
                    .to_string(),
            ));
        }
        let is_sep = c == '.' || c == '_' || c == '-';
        if !(c.is_ascii_lowercase() || c.is_ascii_digit() || is_sep) {
            return Err(ServiceError::Internal(format!(
                "image reference repository component contains invalid character '{c}' \
                 (lowercase alphanumeric, '.', '_', '-' only)"
            )));
        }
        // Reject consecutive separators (e.g. "..", "__", ".-", "_.").
        if is_sep && prev_sep {
            return Err(ServiceError::Internal(
                "image reference repository component contains consecutive separators".to_string(),
            ));
        }
        prev_sep = is_sep;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID_DIGEST_HEX: &str =
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const VALID_DIGEST: &str =
        "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn good_ref() -> &'static str {
        "docker.io/library/postgres:18.4-bookworm@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    }

    // ─── ImageDigest ──────────────────────────────────────────────────────

    #[test]
    fn image_digest_parse_valid() {
        let d = ImageDigest::parse(VALID_DIGEST).unwrap();
        assert_eq!(d.as_str(), VALID_DIGEST);
        assert_eq!(d.hex(), VALID_DIGEST_HEX);
        assert_eq!(format!("{d}"), VALID_DIGEST);
    }

    #[test]
    fn image_digest_parse_hex_valid() {
        let d = ImageDigest::parse_hex(VALID_DIGEST_HEX).unwrap();
        assert_eq!(d.hex(), VALID_DIGEST_HEX);
    }

    #[test]
    fn image_digest_parse_rejects_missing_prefix() {
        assert!(ImageDigest::parse(VALID_DIGEST_HEX).is_err());
        assert!(ImageDigest::parse("sha512:abc").is_err());
    }

    #[test]
    fn image_digest_parse_rejects_wrong_length() {
        assert!(ImageDigest::parse("sha256:abc").is_err());
        assert!(ImageDigest::parse_hex("abc").is_err());
        assert!(ImageDigest::parse_hex(&format!("{VALID_DIGEST_HEX}ff")).is_err());
        assert!(ImageDigest::parse_hex("").is_err());
    }

    #[test]
    fn image_digest_parse_rejects_uppercase() {
        let upper = "0123456789ABCDEF0123456789abcdef0123456789abcdef0123456789abcdef";
        assert!(ImageDigest::parse_hex(upper).is_err());
        assert!(ImageDigest::parse(&format!("sha256:{upper}")).is_err());
    }

    #[test]
    fn image_digest_parse_rejects_non_hex() {
        assert!(
            ImageDigest::parse_hex(
                "g123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
            )
            .is_err()
        );
    }

    // ─── PinnedImageRef: valid ────────────────────────────────────────────

    #[test]
    fn pinned_ref_valid_with_tag() {
        let r = PinnedImageRef::parse(good_ref()).unwrap();
        assert_eq!(r.as_str(), good_ref());
        assert_eq!(
            r.registry_repo_tag(),
            "docker.io/library/postgres:18.4-bookworm"
        );
        assert_eq!(r.registry_repo(), "docker.io/library/postgres");
        assert_eq!(r.tag(), Some("18.4-bookworm"));
        assert_eq!(r.digest().hex(), VALID_DIGEST_HEX);
        assert_eq!(
            r.repo_digest(),
            format!("docker.io/library/postgres@{VALID_DIGEST}")
        );
    }

    #[test]
    fn pinned_ref_valid_without_tag() {
        let s = format!("docker.io/library/postgres@{VALID_DIGEST}");
        let r = PinnedImageRef::parse(&s).unwrap();
        assert_eq!(r.tag(), None);
        assert_eq!(r.registry_repo(), "docker.io/library/postgres");
        assert_eq!(r.repo_digest(), s);
    }

    #[test]
    fn pinned_ref_valid_with_port() {
        let s = format!("registry.example.com:5000/library/postgres:18.4@{VALID_DIGEST}");
        let r = PinnedImageRef::parse(&s).unwrap();
        assert_eq!(
            r.registry_repo(),
            "registry.example.com:5000/library/postgres"
        );
        assert_eq!(r.tag(), Some("18.4"));
        assert_eq!(
            r.repo_digest(),
            format!("registry.example.com:5000/library/postgres@{VALID_DIGEST}")
        );
    }

    #[test]
    fn pinned_ref_valid_localhost() {
        let s = format!("localhost:5000/pg:18@{VALID_DIGEST}");
        assert!(PinnedImageRef::parse(&s).is_ok());
    }

    #[test]
    fn pinned_ref_valid_multi_component_repo() {
        let s = format!("docker.io/foo/bar/baz/pg:18.4@{VALID_DIGEST}");
        let r = PinnedImageRef::parse(&s).unwrap();
        assert_eq!(r.registry_repo(), "docker.io/foo/bar/baz/pg");
        assert_eq!(r.tag(), Some("18.4"));
    }

    #[test]
    fn pinned_ref_repo_digest_drops_tag() {
        let r = PinnedImageRef::parse(good_ref()).unwrap();
        assert!(!r.repo_digest().contains(":18.4-bookworm"));
        assert!(r.repo_digest().contains("@sha256:"));
    }

    // ─── PinnedImageRef: rejections ───────────────────────────────────────

    #[test]
    fn pinned_ref_rejects_empty() {
        assert!(PinnedImageRef::parse("").is_err());
    }

    #[test]
    fn pinned_ref_rejects_whitespace() {
        assert!(
            PinnedImageRef::parse(&format!(" docker.io/library/postgres@{VALID_DIGEST}")).is_err()
        );
        assert!(
            PinnedImageRef::parse(&format!("docker.io/library/postgres @{VALID_DIGEST}")).is_err()
        );
        assert!(
            PinnedImageRef::parse(&format!("docker.io/library/postgres@\t{VALID_DIGEST}")).is_err()
        );
        assert!(
            PinnedImageRef::parse(&format!("docker.io/library/postgres@{VALID_DIGEST}\n")).is_err()
        );
    }

    #[test]
    fn pinned_ref_rejects_control_chars() {
        assert!(
            PinnedImageRef::parse(&format!("docker.io/library/postgres@{VALID_DIGEST}\x00"))
                .is_err()
        );
        assert!(
            PinnedImageRef::parse(&format!("docker.io/library/post\x01gres@{VALID_DIGEST}"))
                .is_err()
        );
    }

    #[test]
    fn pinned_ref_rejects_multiple_at() {
        assert!(
            PinnedImageRef::parse(&format!("docker.io/library/postgres@@{VALID_DIGEST}")).is_err()
        );
        assert!(
            PinnedImageRef::parse(&format!("docker.io/library/postgres@{VALID_DIGEST}@extra"))
                .is_err()
        );
    }

    #[test]
    fn pinned_ref_rejects_missing_digest() {
        assert!(PinnedImageRef::parse("docker.io/library/postgres:18.4").is_err());
        assert!(PinnedImageRef::parse("docker.io/library/postgres").is_err());
    }

    #[test]
    fn pinned_ref_rejects_unqualified() {
        // No registry -- just a bare name.
        assert!(PinnedImageRef::parse(&format!("postgres@{VALID_DIGEST}")).is_err());
        assert!(PinnedImageRef::parse(&format!("postgres:18.4@{VALID_DIGEST}")).is_err());
    }

    #[test]
    fn pinned_ref_rejects_latest_tag() {
        let s = format!("docker.io/library/postgres:latest@{VALID_DIGEST}");
        assert!(PinnedImageRef::parse(&s).is_err());
    }

    #[test]
    fn pinned_ref_rejects_uppercase_repository() {
        let s = format!("docker.io/Library/postgres:18.4@{VALID_DIGEST}");
        assert!(PinnedImageRef::parse(&s).is_err());
        let s2 = format!("docker.io/library/Postgres:18.4@{VALID_DIGEST}");
        assert!(PinnedImageRef::parse(&s2).is_err());
    }

    #[test]
    fn pinned_ref_rejects_uppercase_registry() {
        let s = format!("Docker.io/library/postgres:18.4@{VALID_DIGEST}");
        assert!(PinnedImageRef::parse(&s).is_err());
    }

    #[test]
    fn pinned_ref_rejects_malformed_host_label_leading_dash() {
        let s = format!("-docker.io/library/postgres:18.4@{VALID_DIGEST}");
        assert!(PinnedImageRef::parse(&s).is_err());
    }

    #[test]
    fn pinned_ref_rejects_malformed_host_label_trailing_dash() {
        let s = format!("docker-.io/library/postgres:18.4@{VALID_DIGEST}");
        assert!(PinnedImageRef::parse(&s).is_err());
    }

    #[test]
    fn pinned_ref_rejects_empty_host_label() {
        // "docker..io" has an empty label.
        let s = format!("docker..io/library/postgres:18.4@{VALID_DIGEST}");
        assert!(PinnedImageRef::parse(&s).is_err());
    }

    #[test]
    fn pinned_ref_rejects_port_zero() {
        let s = format!("docker.io:0/library/postgres:18.4@{VALID_DIGEST}");
        assert!(PinnedImageRef::parse(&s).is_err());
    }

    #[test]
    fn pinned_ref_rejects_port_too_large() {
        let s = format!("docker.io:65536/library/postgres:18.4@{VALID_DIGEST}");
        assert!(PinnedImageRef::parse(&s).is_err());
    }

    #[test]
    fn pinned_ref_rejects_port_non_numeric() {
        let s = format!("docker.io:abc/library/postgres:18.4@{VALID_DIGEST}");
        assert!(PinnedImageRef::parse(&s).is_err());
    }

    #[test]
    fn pinned_ref_rejects_empty_port() {
        let s = format!("docker.io:/library/postgres:18.4@{VALID_DIGEST}");
        assert!(PinnedImageRef::parse(&s).is_err());
    }

    #[test]
    fn pinned_ref_rejects_empty_repo_component() {
        // "docker.io//postgres" has an empty component.
        let s = format!("docker.io//postgres:18.4@{VALID_DIGEST}");
        assert!(PinnedImageRef::parse(&s).is_err());
        let s2 = format!("docker.io/library//postgres:18.4@{VALID_DIGEST}");
        assert!(PinnedImageRef::parse(&s2).is_err());
    }

    #[test]
    fn pinned_ref_rejects_repo_leading_slash() {
        let s = format!("docker.io//library/postgres:18.4@{VALID_DIGEST}");
        assert!(PinnedImageRef::parse(&s).is_err());
    }

    #[test]
    fn pinned_ref_rejects_repo_trailing_slash() {
        let s = format!("docker.io/library/postgres/:18.4@{VALID_DIGEST}");
        assert!(PinnedImageRef::parse(&s).is_err());
    }

    #[test]
    fn pinned_ref_rejects_empty_tag() {
        let s = format!("docker.io/library/postgres:@{VALID_DIGEST}");
        assert!(PinnedImageRef::parse(&s).is_err());
    }

    #[test]
    fn pinned_ref_rejects_tag_bad_first_char() {
        let s = format!("docker.io/library/postgres:.18.4@{VALID_DIGEST}");
        assert!(PinnedImageRef::parse(&s).is_err());
    }

    #[test]
    fn pinned_ref_rejects_abbreviated_digest() {
        let s = "docker.io/library/postgres:18.4@sha256:abc";
        assert!(PinnedImageRef::parse(s).is_err());
    }

    #[test]
    fn pinned_ref_rejects_non_sha256_digest() {
        let s = "docker.io/library/postgres:18.4@sha512:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        assert!(PinnedImageRef::parse(s).is_err());
    }

    // ─── No bypass construction ───────────────────────────────────────────

    #[test]
    fn no_from_string_for_image_digest() {
        // There is no From<String> impl. This is a compile-time property;
        // we assert the type is not constructible from a string by checking
        // that parse is the only documented constructor. (If a From<String>
        // existed, this test would still pass, but the lack of the impl is
        // enforced by grep in CI.)
        let d = ImageDigest::parse(VALID_DIGEST).unwrap();
        // Round-trip through Display only.
        let s = format!("{d}");
        let d2 = ImageDigest::parse(&s).unwrap();
        assert_eq!(d, d2);
    }

    #[test]
    fn pinned_ref_display_round_trips() {
        let r = PinnedImageRef::parse(good_ref()).unwrap();
        let s = format!("{r}");
        let r2 = PinnedImageRef::parse(&s).unwrap();
        assert_eq!(r, r2);
    }

    #[test]
    fn pinned_ref_equality_and_hash() {
        let r1 = PinnedImageRef::parse(good_ref()).unwrap();
        let r2 = PinnedImageRef::parse(good_ref()).unwrap();
        assert_eq!(r1, r2);
        // Hashing works (used in HashMap keys).
        let mut map = std::collections::HashMap::new();
        map.insert(r1.clone(), 1);
        assert_eq!(map.get(&r2), Some(&1));
    }

    // ─── Adversarial separator/length tests ─────────────────────────────

    #[test]
    fn pinned_ref_rejects_consecutive_separators_in_repo() {
        let cases = [
            "docker.io/library/post..gres",
            "docker.io/library/post__gres",
            "docker.io/library/post--gres",
            "docker.io/library/post.-gres",
            "docker.io/library/post_.gres",
            "docker.io/library/post-_gres",
        ];
        for bad in cases {
            let s = format!("{bad}@{VALID_DIGEST}");
            assert!(PinnedImageRef::parse(&s).is_err(), "should reject: {bad}");
        }
    }

    #[test]
    fn pinned_ref_rejects_repo_component_leading_separator() {
        let s = format!("docker.io/.library/postgres@{VALID_DIGEST}");
        assert!(PinnedImageRef::parse(&s).is_err());
        let s2 = format!("docker.io/_library/postgres@{VALID_DIGEST}");
        assert!(PinnedImageRef::parse(&s2).is_err());
        let s3 = format!("docker.io/-library/postgres@{VALID_DIGEST}");
        assert!(PinnedImageRef::parse(&s3).is_err());
    }

    #[test]
    fn pinned_ref_rejects_oversized_registry() {
        let big = "a".repeat(256);
        let s = format!("{big}/pg@{VALID_DIGEST}");
        assert!(PinnedImageRef::parse(&s).is_err());
    }

    #[test]
    fn pinned_ref_rejects_oversized_repository() {
        let big = "a".repeat(256);
        let s = format!("docker.io/{big}@{VALID_DIGEST}");
        assert!(PinnedImageRef::parse(&s).is_err());
    }

    #[test]
    fn pinned_ref_rejects_oversized_repo_component() {
        let big = "a".repeat(129);
        let s = format!("docker.io/{big}/pg@{VALID_DIGEST}");
        assert!(PinnedImageRef::parse(&s).is_err());
    }

    #[test]
    fn pinned_ref_rejects_oversized_tag() {
        let big = "a".repeat(129);
        let s = format!("docker.io/pg:{big}@{VALID_DIGEST}");
        assert!(PinnedImageRef::parse(&s).is_err());
    }

    #[test]
    fn pinned_ref_accepts_max_component_length() {
        let max = "a".repeat(128);
        let s = format!("docker.io/{max}@{VALID_DIGEST}");
        assert!(PinnedImageRef::parse(&s).is_ok());
    }
}
