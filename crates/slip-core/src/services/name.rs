//! Canonical `ServiceName` newtype -- the single validator used at every
//! boundary (API, CLI, DB, filesystem, DNS, labels, runtime).
//!
//! Rules (security-research Issue 7):
//! - ASCII lowercase DNS label, 1-63 bytes.
//! - `[a-z0-9](?:[a-z0-9-]*[a-z0-9])?` -- no leading/trailing hyphens.
//! - No Unicode, dots, slash/backslash, percent-encoding, control/NUL.
//! - No reserved `__` prefix (internal namespace guard).

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

/// A canonical service name -- a lowercase ASCII DNS label.
///
/// Construct via `ServiceName::from_str` / `ServiceName::parse` which validate
/// at the boundary. Once constructed, the inner value is trusted by every
/// downstream consumer (path joins, container names, labels, SQLite keys).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ServiceName(String);

impl ServiceName {
    /// Parse a service name, returning a structured error on invalid input.
    pub fn parse(input: &str) -> Result<Self, ServiceNameError> {
        validate_service_name(input)?;
        Ok(Self(input.to_string()))
    }

    /// Return the validated name as a `&str`.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Container name used by the runtime.
    pub fn container_name(&self) -> String {
        format!("slip-service-{}", self.0)
    }

    /// The network alias on the `slip` network: the bare `<name>`.
    pub fn network_alias(&self) -> &str {
        &self.0
    }

    /// The hostname set on the container (also registered by aardvark-dns).
    pub fn hostname(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ServiceName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for ServiceName {
    type Err = ServiceNameError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl TryFrom<String> for ServiceName {
    type Error = ServiceNameError;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(&value)
    }
}

impl From<ServiceName> for String {
    fn from(name: ServiceName) -> String {
        name.0
    }
}

impl AsRef<str> for ServiceName {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

/// Error returned when a service name fails validation.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ServiceNameError {
    #[error("service name must be 1-63 bytes (got {0})")]
    EmptyOrTooLong(usize),
    #[error("service name '{0}' must be lowercase ASCII alphanumeric or hyphen")]
    InvalidChars(String),
    #[error("service name '{0}' must not start or end with a hyphen")]
    LeadingOrTrailingHyphen(String),
    #[error("service name '{0}' must not contain consecutive hyphens")]
    ConsecutiveHyphens(String),
    #[error("service name '{0}' is reserved (starts with '__')")]
    ReservedPrefix(String),
    #[error("service name must not be all numeric")]
    AllNumeric,
}

/// Validate a service name string against the canonical rules.
///
/// Used by [`ServiceName::parse`] and downstream identifier checks.
pub fn validate_service_name(name: &str) -> Result<(), ServiceNameError> {
    if name.is_empty() || name.len() > 63 {
        return Err(ServiceNameError::EmptyOrTooLong(name.len()));
    }

    // Reject anything that is not pure ASCII lowercase DNS-label material.
    // Allow [a-z0-9-] only; reject Unicode, dots, slashes, control chars, etc.
    for c in name.chars() {
        if !(c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-') {
            return Err(ServiceNameError::InvalidChars(name.to_string()));
        }
    }

    if name.starts_with('-') || name.ends_with('-') {
        return Err(ServiceNameError::LeadingOrTrailingHyphen(name.to_string()));
    }

    if name.contains("--") {
        return Err(ServiceNameError::ConsecutiveHyphens(name.to_string()));
    }

    if name.starts_with("__") {
        return Err(ServiceNameError::ReservedPrefix(name.to_string()));
    }

    if name.chars().all(|c| c.is_ascii_digit()) {
        return Err(ServiceNameError::AllNumeric);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_names() {
        assert!(ServiceName::parse("postgres").is_ok());
        assert!(ServiceName::parse("pg-main").is_ok());
        assert!(ServiceName::parse("redis2").is_ok());
        assert!(ServiceName::parse("a").is_ok());
        assert!(ServiceName::parse("a1").is_ok());
        // 63 chars exactly.
        assert!(ServiceName::parse(&"a".repeat(63)).is_ok());
    }

    #[test]
    fn invalid_names() {
        assert!(ServiceName::parse("").is_err());
        assert!(ServiceName::parse(&"a".repeat(64)).is_err());
        // Uppercase rejected.
        assert!(ServiceName::parse("Postgres").is_err());
        // Dots, slashes, unicode rejected.
        assert!(ServiceName::parse("pg.main").is_err());
        assert!(ServiceName::parse("pg/main").is_err());
        assert!(ServiceName::parse("pg\\main").is_err());
        assert!(ServiceName::parse("pg main").is_err());
        assert!(ServiceName::parse("pgé").is_err());
        // Leading/trailing hyphens.
        assert!(ServiceName::parse("-pg").is_err());
        assert!(ServiceName::parse("pg-").is_err());
        // Consecutive hyphens.
        assert!(ServiceName::parse("pg--main").is_err());
        // Reserved prefix.
        assert!(ServiceName::parse("__internal").is_err());
        // All-numeric.
        assert!(ServiceName::parse("12345").is_err());
        // Percent-encoding / control chars.
        assert!(ServiceName::parse("pg%2dmain").is_err());
        assert!(ServiceName::parse("pg\nmain").is_err());
        assert!(ServiceName::parse("pg\0main").is_err());
    }

    #[test]
    fn serde_round_trip() {
        let name = ServiceName::parse("pg-main").unwrap();
        let json = serde_json::to_string(&name).unwrap();
        assert_eq!(json, "\"pg-main\"");
        let back: ServiceName = serde_json::from_str(&json).unwrap();
        assert_eq!(back, name);
    }

    #[test]
    fn serde_rejects_invalid() {
        assert!(serde_json::from_str::<ServiceName>("\"PG-main\"").is_err());
        assert!(serde_json::from_str::<ServiceName>("\"pg.main\"").is_err());
        assert!(serde_json::from_str::<ServiceName>("\"\"").is_err());
    }

    #[test]
    fn container_name_and_alias() {
        let name = ServiceName::parse("postgres").unwrap();
        assert_eq!(name.container_name(), "slip-service-postgres");
        assert_eq!(name.network_alias(), "postgres");
        assert_eq!(name.hostname(), "postgres");
    }

    #[test]
    fn display_and_as_ref() {
        let name = ServiceName::parse("redis").unwrap();
        assert_eq!(format!("{name}"), "redis");
        assert_eq!(name.as_ref(), "redis");
        let s: String = name.clone().into();
        assert_eq!(s, "redis");
    }
}
