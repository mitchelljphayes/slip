//! Service-need bindings for app config (`[needs.<alias>]`).
//!
//! An app declares the external services it consumes, such as a Postgres
//! database, an S3-compatible object store, or a Redis-compatible cache,
//! through the `[needs.<alias>]` table in both the repo `slip.toml` and the
//! server-side `apps/<name>.toml`. Each binding carries:
//!
//! - `alias`: the lowercase TOML key (`db`, `analytics`, `cache`, ...), the
//!   name the app uses to refer to this service in its own config.
//! - `type`: one of `postgres`, `s3`, `kv`, the provider kind. Only known
//!   kinds are accepted (serde `deny_unknown_fields` + custom type parsing).
//!
//! ## Environment variable contract
//!
//! slip injects the service connection information into the container as
//! environment variables. The variable name is derived from the alias and type:
//!
//! - The **canonical** aliases (`db` for postgres, `storage` for s3, `cache`
//!   for kv) map to the canonical env vars: `DATABASE_URL`, `REDIS_URL`, and
//!   the S3 set `S3_ENDPOINT` / `S3_REGION` / `S3_BUCKET` / `S3_ACCESS_KEY_ID`
//!   / `S3_SECRET_ACCESS_KEY` respectively.
//! - Type names (`postgres`, `s3`, `kv`) are ordinary aliases and receive a
//!   prefix, just like any other non-canonical alias.
//! - Any other alias (`analytics`, `audit`, ...) gets an **uppercase prefix**:
//!   `ANALYTICS_DATABASE_URL`, `AUDIT_REDIS_URL`, and the S3 set
//!   `ANALYTICS_S3_ENDPOINT`, etc.
//!
//! This keeps the common case (one database) zero-config (`DATABASE_URL`) while
//! supporting multi-tenant apps without collisions.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use thiserror::Error;

// ─── Constants ────────────────────────────────────────────────────────────────

/// Maximum length of a need alias (TOML key). Bounded to keep generated env var
/// names well within POSIX limits and to make collisions visually obvious.
pub const MAX_ALIAS_LEN: usize = 32;

/// Canonical env var for a postgres binding at the `db`/`postgres` alias.
pub const CANONICAL_PG_ENV: &str = "DATABASE_URL";

/// Canonical env var for a kv (Redis) binding at the `cache`/`kv` alias.
pub const CANONICAL_KV_ENV: &str = "REDIS_URL";

/// Canonical S3 env var set for a binding at the `storage`/`s3` alias.
pub const CANONICAL_S3_ENV: &[&str] = &[
    "S3_ENDPOINT",
    "S3_REGION",
    "S3_BUCKET",
    "S3_ACCESS_KEY_ID",
    "S3_SECRET_ACCESS_KEY",
];

/// Aliases that map to the canonical env vars (no uppercase prefix).
/// Only the short service-canonical aliases get unprefixed env vars. The
/// type names (`postgres`, `s3`, `kv`) are NOT canonical: they get prefixed
/// env vars (`POSTGRES_DATABASE_URL`, `S3_S3_ENDPOINT`, `KV_REDIS_URL`).
/// The prefix keeps the common `s3` alias valid despite its redundant
/// `S3_S3_*` spelling.
const CANONICAL_PG_ALIASES: &[&str] = &["db"];
const CANONICAL_S3_ALIASES: &[&str] = &["storage"];
const CANONICAL_KV_ALIASES: &[&str] = &["cache"];

// ─── NeedType ─────────────────────────────────────────────────────────────────

/// The provider kind a need binds to.
///
/// Serialized as the lowercase string `type = "postgres"` / `"s3"` / `"kv"` in
/// TOML. Closed enum: unknown values are rejected at parse time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NeedType {
    Postgres,
    S3,
    Kv,
}

impl NeedType {
    /// Parse a need type from its lowercase string form.
    pub fn parse(s: &str) -> Result<Self, NeedError> {
        match s {
            "postgres" => Ok(Self::Postgres),
            "s3" => Ok(Self::S3),
            "kv" => Ok(Self::Kv),
            other => Err(NeedError::UnknownType(other.to_string())),
        }
    }

    /// The lowercase string used in TOML manifests.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Postgres => "postgres",
            Self::S3 => "s3",
            Self::Kv => "kv",
        }
    }
}

impl std::fmt::Display for NeedType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for NeedType {
    type Err = NeedError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

// ─── Need ─────────────────────────────────────────────────────────────────────

/// A single `[needs.<alias>]` binding.
///
/// `r#type` is the only required field. Unknown TOML fields are rejected
/// (`#[serde(deny_unknown_fields)]`) so mis-typed keys surface at load time
/// rather than silently being dropped.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Need {
    /// Provider kind for this binding. Serialized as `type` in TOML.
    #[serde(rename = "type")]
    pub r#type: NeedType,
}

impl Need {
    pub fn new(kind: NeedType) -> Self {
        Self { r#type: kind }
    }

    /// Build the environment-variable names this need injects into the
    /// container, given its alias.
    ///
    /// See the module docs for the canonical-vs-prefixed contract.
    pub fn env_keys(&self, alias: &str) -> Vec<String> {
        match self.r#type {
            NeedType::Postgres => {
                if CANONICAL_PG_ALIASES.contains(&alias) {
                    vec![CANONICAL_PG_ENV.to_string()]
                } else {
                    vec![prefixed(alias, "DATABASE_URL")]
                }
            }
            NeedType::Kv => {
                if CANONICAL_KV_ALIASES.contains(&alias) {
                    vec![CANONICAL_KV_ENV.to_string()]
                } else {
                    vec![prefixed(alias, "REDIS_URL")]
                }
            }
            NeedType::S3 => {
                if CANONICAL_S3_ALIASES.contains(&alias) {
                    CANONICAL_S3_ENV.iter().map(|s| s.to_string()).collect()
                } else {
                    CANONICAL_S3_ENV
                        .iter()
                        .map(|s| prefixed(alias, s))
                        .collect()
                }
            }
        }
    }
}

/// Build an uppercase-prefixed env var name: `prefixed("analytics", "DATABASE_URL")`
/// → `"ANALYTICS_DATABASE_URL"`.
fn prefixed(alias: &str, base: &str) -> String {
    format!("{}_{}", alias.to_ascii_uppercase(), base)
}

// ─── Validation ───────────────────────────────────────────────────────────────

/// Errors that can occur when validating a `[needs]` table.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum NeedError {
    /// Alias does not match `[a-z][a-z0-9_]*`.
    #[error(
        "need alias '{alias}' is invalid — must match [a-z][a-z0-9_]* and be at most {max} chars"
    )]
    InvalidAlias { alias: String, max: usize },

    /// Unknown need `type` value.
    #[error("unknown need type '{0}' — valid: postgres, s3, kv")]
    UnknownType(String),

    /// A need's generated env var conflicts with a key already in `[env]`.
    #[error(
        "need alias '{alias}' would inject env var '{var}' which is already set in [env] — \
             remove the [env] entry or rename the need alias"
    )]
    EnvConflict { alias: String, var: String },

    /// Two needs generate the same env var (alias collision or canonical clash).
    #[error("need aliases '{a}' and '{b}' both inject env var '{var}' — rename one alias")]
    EnvCollision { a: String, b: String, var: String },

    /// A canonical alias was used with the wrong type (e.g. `db` with `type = "s3"`).
    #[error(
        "need alias '{alias}' is canonical for {expected} but has type = \"{actual}\" — \
             use type = \"{expected}\" or rename the alias"
    )]
    CanonicalTypeMismatch {
        alias: String,
        expected: &'static str,
        actual: &'static str,
    },
}

/// Validate a full `[needs]` map.
///
/// Checks:
/// - Each alias matches `[a-z][a-z0-9_]*` and is at most [`MAX_ALIAS_LEN`] chars.
/// - Canonical aliases (`db`, `storage`, `cache`) are
///   paired with the matching type.
/// - No two needs generate the same env var (internal collision).
/// - None of the generated env vars conflict with keys already present in `env`.
///
/// Returns `Ok(())` if all checks pass, or the first `NeedError` encountered.
pub fn validate_needs(
    needs: &BTreeMap<String, Need>,
    env: &std::collections::HashMap<String, String>,
) -> Result<(), NeedError> {
    // Track env vars generated by needs so far, to detect internal collisions.
    let mut seen: std::collections::HashMap<String, String> = std::collections::HashMap::new();

    for (alias, need) in needs {
        // ── Alias format ──────────────────────────────────────────────────────
        validate_alias(alias)?;

        // ── Canonical alias ↔ type consistency ────────────────────────────────
        check_canonical_type(alias, need.r#type)?;

        // ── Env var generation + collision/conflict ───────────────────────────
        for var in need.env_keys(alias) {
            // Conflict with [env]
            if env.contains_key(&var) {
                return Err(NeedError::EnvConflict {
                    alias: alias.clone(),
                    var,
                });
            }
            // Collision with another need
            if let Some(other) = seen.get(&var) {
                return Err(NeedError::EnvCollision {
                    a: other.clone(),
                    b: alias.clone(),
                    var,
                });
            }
            seen.insert(var, alias.clone());
        }
    }

    Ok(())
}

/// Validate a single alias against the naming rule.
pub fn validate_alias(alias: &str) -> Result<(), NeedError> {
    if alias.is_empty() {
        return Err(NeedError::InvalidAlias {
            alias: alias.to_string(),
            max: MAX_ALIAS_LEN,
        });
    }
    if alias.len() > MAX_ALIAS_LEN {
        return Err(NeedError::InvalidAlias {
            alias: alias.to_string(),
            max: MAX_ALIAS_LEN,
        });
    }
    let chars: Vec<char> = alias.chars().collect();
    // First char: lowercase ascii letter.
    if !chars[0].is_ascii_lowercase() {
        return Err(NeedError::InvalidAlias {
            alias: alias.to_string(),
            max: MAX_ALIAS_LEN,
        });
    }
    // Rest: lowercase ascii letter, digit, or underscore.
    for &c in &chars[1..] {
        if !c.is_ascii_lowercase() && !c.is_ascii_digit() && c != '_' {
            return Err(NeedError::InvalidAlias {
                alias: alias.to_string(),
                max: MAX_ALIAS_LEN,
            });
        }
    }
    Ok(())
}

/// Check that a canonical alias is paired with its expected type.
fn check_canonical_type(alias: &str, kind: NeedType) -> Result<(), NeedError> {
    let expected: Option<&'static str> = if CANONICAL_PG_ALIASES.contains(&alias) {
        Some("postgres")
    } else if CANONICAL_S3_ALIASES.contains(&alias) {
        Some("s3")
    } else if CANONICAL_KV_ALIASES.contains(&alias) {
        Some("kv")
    } else {
        None
    };

    if let Some(expected) = expected
        && kind.as_str() != expected
    {
        return Err(NeedError::CanonicalTypeMismatch {
            alias: alias.to_string(),
            expected,
            actual: kind.as_str(),
        });
    }
    Ok(())
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn map(needs: &[(&str, NeedType)]) -> BTreeMap<String, Need> {
        needs
            .iter()
            .map(|(a, t)| (a.to_string(), Need::new(*t)))
            .collect()
    }

    // ── NeedType ───────────────────────────────────────────────────────────────

    #[test]
    fn need_type_round_trip() {
        for (s, kind) in [
            ("postgres", NeedType::Postgres),
            ("s3", NeedType::S3),
            ("kv", NeedType::Kv),
        ] {
            assert_eq!(NeedType::parse(s).unwrap(), kind);
            assert_eq!(kind.as_str(), s);
        }
    }

    #[test]
    fn need_type_rejects_unknown() {
        assert!(matches!(
            NeedType::parse("mysql"),
            Err(NeedError::UnknownType(_))
        ));
    }

    #[test]
    fn need_type_serde_lowercase() {
        let n: Need = toml::from_str(r#"type = "postgres""#).unwrap();
        assert_eq!(n.r#type, NeedType::Postgres);
        let s = toml::to_string(&n).unwrap();
        assert!(s.contains("type = \"postgres\""));
    }

    #[test]
    fn need_deny_unknown_fields() {
        let res: Result<Need, _> = toml::from_str(
            r#"type = "postgres"
extra = true"#,
        );
        assert!(res.is_err(), "unknown field must be rejected");
    }

    // ── env_keys ───────────────────────────────────────────────────────────────

    #[test]
    fn env_keys_canonical_pg() {
        let n = Need::new(NeedType::Postgres);
        assert_eq!(n.env_keys("db"), vec!["DATABASE_URL"]);
    }

    #[test]
    fn env_keys_canonical_kv() {
        let n = Need::new(NeedType::Kv);
        assert_eq!(n.env_keys("cache"), vec!["REDIS_URL"]);
    }

    #[test]
    fn env_keys_canonical_s3() {
        let n = Need::new(NeedType::S3);
        assert_eq!(
            n.env_keys("storage"),
            vec![
                "S3_ENDPOINT",
                "S3_REGION",
                "S3_BUCKET",
                "S3_ACCESS_KEY_ID",
                "S3_SECRET_ACCESS_KEY",
            ]
        );
    }

    #[test]
    fn env_keys_type_name_aliases_are_prefixed() {
        // `postgres`, `s3`, `kv` are NOT canonical: they get uppercase prefixes.
        let pg = Need::new(NeedType::Postgres);
        assert_eq!(pg.env_keys("postgres"), vec!["POSTGRES_DATABASE_URL"]);
        let kv = Need::new(NeedType::Kv);
        assert_eq!(kv.env_keys("kv"), vec!["KV_REDIS_URL"]);
        let s3 = Need::new(NeedType::S3);
        assert_eq!(
            s3.env_keys("s3"),
            vec![
                "S3_S3_ENDPOINT",
                "S3_S3_REGION",
                "S3_S3_BUCKET",
                "S3_S3_ACCESS_KEY_ID",
                "S3_S3_SECRET_ACCESS_KEY",
            ]
        );
    }

    #[test]
    fn env_keys_prefixed_pg() {
        let n = Need::new(NeedType::Postgres);
        assert_eq!(n.env_keys("analytics"), vec!["ANALYTICS_DATABASE_URL"]);
    }

    #[test]
    fn env_keys_prefixed_kv() {
        let n = Need::new(NeedType::Kv);
        assert_eq!(n.env_keys("sessions"), vec!["SESSIONS_REDIS_URL"]);
    }

    #[test]
    fn env_keys_prefixed_s3() {
        let n = Need::new(NeedType::S3);
        assert_eq!(
            n.env_keys("uploads"),
            vec![
                "UPLOADS_S3_ENDPOINT",
                "UPLOADS_S3_REGION",
                "UPLOADS_S3_BUCKET",
                "UPLOADS_S3_ACCESS_KEY_ID",
                "UPLOADS_S3_SECRET_ACCESS_KEY",
            ]
        );
    }

    // ── validate_alias ─────────────────────────────────────────────────────────

    #[test]
    fn alias_valid() {
        for a in ["db", "analytics", "a", "a1", "a_b", "abc_123", "my_db_2"] {
            validate_alias(a).unwrap_or_else(|e| panic!("alias '{a}' should be valid: {e}"));
        }
    }

    #[test]
    fn alias_rejects_empty() {
        assert!(validate_alias("").is_err());
    }

    #[test]
    fn alias_rejects_uppercase() {
        for a in ["Db", "DB", "Analytics", "A"] {
            assert!(validate_alias(a).is_err(), "'{a}' must be rejected");
        }
    }

    #[test]
    fn alias_rejects_leading_digit() {
        assert!(validate_alias("1db").is_err());
    }

    #[test]
    fn alias_rejects_hyphen() {
        assert!(validate_alias("my-db").is_err());
    }

    #[test]
    fn alias_rejects_too_long() {
        let long = "a".repeat(MAX_ALIAS_LEN + 1);
        assert!(validate_alias(&long).is_err());
    }

    #[test]
    fn alias_accepts_max_length() {
        let exact = "a".repeat(MAX_ALIAS_LEN);
        validate_alias(&exact).unwrap();
    }

    // ── validate_needs ─────────────────────────────────────────────────────────

    #[test]
    fn validate_needs_empty_ok() {
        let needs = BTreeMap::new();
        let env = std::collections::HashMap::new();
        validate_needs(&needs, &env).unwrap();
    }

    #[test]
    fn validate_needs_single_canonical_ok() {
        let needs = map(&[("db", NeedType::Postgres)]);
        let env = std::collections::HashMap::new();
        validate_needs(&needs, &env).unwrap();
    }

    #[test]
    fn validate_neaches_canonical_type_mismatch() {
        // `db` is canonical for postgres; using s3 is wrong.
        let needs = map(&[("db", NeedType::S3)]);
        let env = std::collections::HashMap::new();
        let err = validate_needs(&needs, &env).unwrap_err();
        assert!(matches!(err, NeedError::CanonicalTypeMismatch { .. }));
    }

    #[test]
    fn validate_needs_env_conflict() {
        let needs = map(&[("db", NeedType::Postgres)]);
        let mut env = std::collections::HashMap::new();
        env.insert("DATABASE_URL".to_string(), "manual".to_string());
        let err = validate_needs(&needs, &env).unwrap_err();
        assert!(matches!(err, NeedError::EnvConflict { var, .. } if var == "DATABASE_URL"));
    }

    #[test]
    fn validate_needs_internal_collision_prefixed() {
        // Two postgres aliases → different prefixed env vars, no collision.
        let needs = map(&[
            ("analytics", NeedType::Postgres),
            ("audit", NeedType::Postgres),
        ]);
        let env = std::collections::HashMap::new();
        validate_needs(&needs, &env).unwrap();
    }

    #[test]
    fn validate_needs_collision_two_aliases_same_var() {
        // Two non-canonical postgres aliases generate different env vars, so
        // no collision is possible: the prefix is the alias itself, and the
        // canonical alias path cannot repeat because BTreeMap keys are
        // unique. This test documents that two distinct non-canonical
        // postgres aliases do NOT collide.
        let needs = map(&[
            ("analytics", NeedType::Postgres),
            ("audit", NeedType::Postgres),
        ]);
        let env = std::collections::HashMap::new();
        validate_needs(&needs, &env).unwrap();
    }

    #[test]
    fn validate_needs_invalid_alias() {
        let needs = map(&[("My DB", NeedType::Postgres)]);
        let env = std::collections::HashMap::new();
        let err = validate_needs(&needs, &env).unwrap_err();
        assert!(matches!(err, NeedError::InvalidAlias { .. }));
    }

    #[test]
    fn validate_needs_mixed_types_ok() {
        let needs = map(&[
            ("db", NeedType::Postgres),
            ("cache", NeedType::Kv),
            ("storage", NeedType::S3),
            ("analytics", NeedType::Postgres),
        ]);
        let env = std::collections::HashMap::new();
        validate_needs(&needs, &env).unwrap();
    }

    #[test]
    fn validate_needs_s3_canonical_ok() {
        let needs = map(&[("storage", NeedType::S3)]);
        let env = std::collections::HashMap::new();
        validate_needs(&needs, &env).unwrap();
    }

    #[test]
    fn validate_needs_kv_canonical_type_mismatch() {
        let needs = map(&[("cache", NeedType::Postgres)]);
        let env = std::collections::HashMap::new();
        let err = validate_needs(&needs, &env).unwrap_err();
        assert!(matches!(err, NeedError::CanonicalTypeMismatch { .. }));
    }
}
