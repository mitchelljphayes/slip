//! Service resource credentials primitive (SLIP-107).
//!
//! A *resource* is a named, owned, isolated data namespace inside a managed
//! service instance (for PostgreSQL, a LOGIN role plus an owned database). Apps
//! bind to a resource via an alias; the controller allocates a
//! [`ResourceCredentials`] per (installation, service instance, app, alias)
//! tuple and persists it before calling
//! [`ServiceProvider::create_resource`].
//!
//! ## Identity
//!
//! The resource identifier is `slip_` + 48 lowercase hex characters derived
//! from a SHA-256 hash of `installation_id + service_instance_id + app +
//! alias` (see [`compute_resource_id`]). It is simultaneously:
//!
//! - the canonical resource identifier (persisted, exported in env),
//! - the PostgreSQL LOGIN role name, and
//! - the PostgreSQL database name.
//!
//! The format `slip_[0-9a-f]{48}` is a valid unquoted PostgreSQL identifier
//! (≤ 63 bytes, starts with a letter, contains only letters/digits/underscore)
//! and contains no metacharacters, so it can be interpolated into SQL
//! without quoting once validated.
//!
//! ## Secret handling
//!
//! The password is a 64-char lowercase hex string (32 CSPRNG bytes). It is
//! carried inside [`ResourceCredentials`] and never appears in:
//!
//! - command-line argv (SQL is piped via stdin to `psql`),
//! - the service container's env (only `PGPASSFILE` is mounted),
//! - logs, errors, or `Debug` output (the password field is redacted).
//!
//! The password DOES appear in the app-facing env produced by
//! [`ServiceProvider::resource_env`] (e.g. `DATABASE_URL`); that is the
//! whole point of a resource credential. The app container is the intended
//! recipient; the service runtime never sees it in argv/env.

use sha2::{Digest, Sha256};

use crate::services::spec::ServiceError;

// ─── Validation constants ─────────────────────────────────────────────────────

/// The mandatory prefix for every resource identifier.
const ID_PREFIX: &str = "slip_";

/// The number of lowercase hex characters after the prefix (24 bytes hashed).
const ID_HEX_LEN: usize = 48;

/// The total length of a resource identifier (`slip_` + 48 hex).
const ID_TOTAL_LEN: usize = ID_PREFIX.len() + ID_HEX_LEN; // 53

/// The number of lowercase hex characters in a resource password (32 bytes).
const PASSWORD_HEX_LEN: usize = 64;

/// The fixed marker stored as a COMMENT on the PostgreSQL role, used to
/// prove ownership of an existing role. The marker is the resource
/// identifier itself, prefixed with a namespace. Because the role name IS
/// the resource identifier, a role whose comment does not match this
/// marker cannot be adopted.
pub fn role_comment(resource_id: &str) -> String {
    format!("slip:resource:{resource_id}")
}

// ─── ResourceCredentials ──────────────────────────────────────────────────────

/// A validated resource credential: an opaque identifier + generated
/// password for an isolated data namespace inside a managed service.
///
/// The identifier is `slip_` + 48 lowercase hex; it is also the PostgreSQL
/// role and database name. The password is 64-char lowercase hex.
///
/// Construction is via [`new`](Self::new), which validates both fields
/// strongly to prevent SQL injection. There is no struct-literal bypass:
/// fields are private.
///
/// `Debug` redacts the password.
#[derive(Clone, PartialEq, Eq)]
pub struct ResourceCredentials {
    id: String,
    password: String,
}

impl ResourceCredentials {
    /// Construct a `ResourceCredentials` from a validated opaque resource
    /// identifier and a generated 64-char hex password.
    ///
    /// The caller (the main controller) is responsible for computing the
    /// identifier deterministically (see [`compute_resource_id`]) and
    /// generating the password from a CSPRNG. This constructor validates
    /// the format of both and rejects anything that could carry SQL
    /// metacharacters or non-canonical forms.
    pub fn new(id: String, password: String) -> Result<Self, ServiceError> {
        validate_resource_id(&id)?;
        validate_resource_password(&password)?;
        Ok(Self { id, password })
    }

    /// The validated resource identifier (`slip_` + 48 lowercase hex).
    /// This is also the PostgreSQL role and database name.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// The validated 64-char lowercase hex password.
    ///
    /// This is secret material. Callers must not log it, place it in
    /// service-container argv/env, or include it in error text. The only
    /// legitimate destination is the app-facing env map produced by
    /// [`ServiceProvider::resource_env`].
    pub fn password(&self) -> &str {
        &self.password
    }
}

impl std::fmt::Debug for ResourceCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResourceCredentials")
            .field("id", &self.id)
            .field("password", &"[REDACTED]")
            .finish()
    }
}

// ─── Validation ───────────────────────────────────────────────────────────────

/// Validate a resource identifier: exactly `slip_` + 48 lowercase hex.
///
/// This is the single boundary check that prevents SQL injection via the
/// identifier (which is interpolated unquoted into SQL) and ensures the
/// identifier is a valid PostgreSQL unquoted identifier.
///
/// Uses `strip_prefix` + byte-length check on the remainder to avoid
/// indexing at a byte offset that could split a multibyte UTF-8 character
/// (which would panic on `&id[..ID_PREFIX.len()]`).
fn validate_resource_id(id: &str) -> Result<(), ServiceError> {
    // Check total byte length first (Rust str::len() is byte length).
    if id.len() != ID_TOTAL_LEN {
        return Err(ServiceError::Internal(format!(
            "resource id length {} (expected exactly {}): 'slip_' + 48 lowercase hex",
            id.len(),
            ID_TOTAL_LEN
        )));
    }
    // strip_prefix is char-boundary safe; avoids panicking on multibyte
    // input where a byte-index slice would split a UTF-8 sequence.
    let hex_part = id.strip_prefix(ID_PREFIX).ok_or_else(|| {
        ServiceError::Internal(format!("resource id must start with '{ID_PREFIX}'"))
    })?;
    // Validate the remainder is exactly 48 lowercase hex bytes.
    if hex_part.len() != ID_HEX_LEN {
        return Err(ServiceError::Internal(format!(
            "resource id suffix length {} (expected {ID_HEX_LEN} lowercase hex)",
            hex_part.len()
        )));
    }
    if !hex_part
        .bytes()
        .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return Err(ServiceError::Internal(
            "resource id suffix must be 48 lowercase hex characters".to_string(),
        ));
    }
    Ok(())
}

/// Validate a resource password: exactly 64 lowercase hex characters.
///
/// Hex is injection-safe in SQL string literals (no quotes, semicolons, or
/// backslashes) and is the canonical form for a CSPRNG-generated password.
fn validate_resource_password(password: &str) -> Result<(), ServiceError> {
    if password.len() != PASSWORD_HEX_LEN {
        return Err(ServiceError::Internal(format!(
            "resource password length {} (expected exactly {} lowercase hex)",
            password.len(),
            PASSWORD_HEX_LEN
        )));
    }
    if !password
        .bytes()
        .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return Err(ServiceError::Internal(
            "resource password must be 64 lowercase hex characters".to_string(),
        ));
    }
    Ok(())
}

// ─── Deterministic resource id derivation ─────────────────────────────────────

/// Compute the deterministic resource identifier for a
/// (installation, service instance, app, alias) tuple.
///
/// Returns `slip_` + the first 48 lowercase hex characters of
/// `SHA-256(installation_id \0 service_instance_id \0 app \0 alias)`.
///
/// Domain separation uses NUL bytes so that no two distinct tuples can
/// collide via ambiguous concatenation (e.g. `("ab", "c")` vs
/// `("a", "bc")`).
pub fn compute_resource_id(
    installation_id: &str,
    service_instance_id: &str,
    app: &str,
    alias: &str,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"slip-resource-id-v1\x00");
    hasher.update(installation_id.as_bytes());
    hasher.update(b"\x00");
    hasher.update(service_instance_id.as_bytes());
    hasher.update(b"\x00");
    hasher.update(app.as_bytes());
    hasher.update(b"\x00");
    hasher.update(alias.as_bytes());
    let digest = hasher.finalize();
    // Take the first 24 bytes (48 hex chars).
    let hex = hex::encode(&digest[..24]);
    format!("{ID_PREFIX}{hex}")
}

/// Validate an app name component for resource id derivation. Rejects empty
/// and overlong inputs (the hash tolerates any bytes, but a 256-byte app
/// name is a caller bug). Returns Ok for reasonable lengths.
pub fn validate_resource_component(s: &str, name: &str) -> Result<(), ServiceError> {
    if s.is_empty() {
        return Err(ServiceError::Internal(format!(
            "resource {name} component must not be empty"
        )));
    }
    if s.len() > 256 {
        return Err(ServiceError::Internal(format!(
            "resource {name} component length {} exceeds 256",
            s.len()
        )));
    }
    if s.as_bytes().contains(&0) {
        return Err(ServiceError::Internal(format!(
            "resource {name} component must not contain NUL bytes"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID_ID: &str = "slip_0123456789abcdef0123456789abcdef0123456789abcdef";
    const VALID_PASSWORD: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    #[test]
    fn new_accepts_valid_credentials() {
        let creds = ResourceCredentials::new(VALID_ID.to_string(), VALID_PASSWORD.to_string());
        assert!(creds.is_ok(), "valid creds must construct");
        let creds = creds.unwrap();
        assert_eq!(creds.id(), VALID_ID);
        assert_eq!(creds.password(), VALID_PASSWORD);
    }

    #[test]
    fn new_rejects_bad_id_length() {
        assert!(
            ResourceCredentials::new("slip_short".to_string(), VALID_PASSWORD.to_string()).is_err()
        );
        assert!(
            ResourceCredentials::new(
                format!("slip_{}", "a".repeat(47)),
                VALID_PASSWORD.to_string()
            )
            .is_err()
        );
        assert!(
            ResourceCredentials::new(
                format!("slip_{}", "a".repeat(49)),
                VALID_PASSWORD.to_string()
            )
            .is_err()
        );
    }

    #[test]
    fn new_rejects_bad_id_prefix() {
        assert!(
            ResourceCredentials::new(format!("pg_{}", "a".repeat(48)), VALID_PASSWORD.to_string())
                .is_err()
        );
    }

    #[test]
    fn new_rejects_uppercase_or_nonhex_id() {
        assert!(
            ResourceCredentials::new(
                format!("slip_{}", "A".repeat(48)),
                VALID_PASSWORD.to_string()
            )
            .is_err()
        );
        assert!(
            ResourceCredentials::new(
                format!("slip_{}", "g".repeat(48)),
                VALID_PASSWORD.to_string()
            )
            .is_err()
        );
    }

    #[test]
    fn new_rejects_bad_password_length() {
        assert!(ResourceCredentials::new(VALID_ID.to_string(), "short".to_string()).is_err());
        assert!(
            ResourceCredentials::new(VALID_ID.to_string(), "a".repeat(63).to_string()).is_err()
        );
        assert!(
            ResourceCredentials::new(VALID_ID.to_string(), "a".repeat(65).to_string()).is_err()
        );
    }

    #[test]
    fn new_rejects_uppercase_or_nonhex_password() {
        assert!(
            ResourceCredentials::new(VALID_ID.to_string(), "A".repeat(64).to_string()).is_err()
        );
        assert!(
            ResourceCredentials::new(VALID_ID.to_string(), "g".repeat(64).to_string()).is_err()
        );
    }

    #[test]
    fn new_rejects_injection_in_id() {
        // These should all fail validation before reaching SQL.
        assert!(
            ResourceCredentials::new(
                "slip_; DROP TABLE--".to_string(),
                VALID_PASSWORD.to_string()
            )
            .is_err()
        );
        assert!(
            ResourceCredentials::new("slip_' OR '1'='1".to_string(), VALID_PASSWORD.to_string())
                .is_err()
        );
    }

    #[test]
    fn debug_redacts_password() {
        let creds =
            ResourceCredentials::new(VALID_ID.to_string(), VALID_PASSWORD.to_string()).unwrap();
        let dbg = format!("{creds:?}");
        assert!(dbg.contains("[REDACTED]"));
        assert!(!dbg.contains(VALID_PASSWORD));
        assert!(dbg.contains(VALID_ID));
    }

    #[test]
    fn role_comment_format() {
        assert_eq!(role_comment(VALID_ID), format!("slip:resource:{VALID_ID}"));
    }

    #[test]
    fn compute_resource_id_is_deterministic() {
        let a = compute_resource_id("install-1", "instance-1", "app-1", "db");
        let b = compute_resource_id("install-1", "instance-1", "app-1", "db");
        assert_eq!(a, b);
    }

    #[test]
    fn compute_resource_id_differs_for_different_inputs() {
        let base = compute_resource_id("install-1", "instance-1", "app-1", "db");
        assert_ne!(
            base,
            compute_resource_id("install-2", "instance-1", "app-1", "db")
        );
        assert_ne!(
            base,
            compute_resource_id("install-1", "instance-2", "app-1", "db")
        );
        assert_ne!(
            base,
            compute_resource_id("install-1", "instance-1", "app-2", "db")
        );
        assert_ne!(
            base,
            compute_resource_id("install-1", "instance-1", "app-1", "cache")
        );
    }

    #[test]
    fn compute_resource_id_has_canonical_format() {
        let id = compute_resource_id("install-1", "instance-1", "app-1", "db");
        assert!(id.starts_with("slip_"));
        assert_eq!(id.len(), ID_TOTAL_LEN);
        assert!(
            id[ID_PREFIX.len()..]
                .chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        );
    }

    #[test]
    fn compute_resource_id_no_concatenation_collision() {
        // ("ab", "c") must not collide with ("a", "bc").
        let a = compute_resource_id("i", "ab", "c", "x");
        let b = compute_resource_id("i", "a", "bc", "x");
        assert_ne!(a, b);
    }

    #[test]
    fn compute_resource_id_passes_validation() {
        let id = compute_resource_id("install-1", "instance-1", "app-1", "db");
        assert!(validate_resource_id(&id).is_ok());
    }

    #[test]
    fn validate_resource_component_rejects_empty_and_nul() {
        assert!(validate_resource_component("", "app").is_err());
        assert!(validate_resource_component("ok\0", "app").is_err());
        assert!(validate_resource_component(&"a".repeat(257), "app").is_err());
        assert!(validate_resource_component("app-1", "app").is_ok());
    }
}
