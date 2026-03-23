//! Error types for slip.

use std::path::PathBuf;

/// Errors that can occur when loading or parsing configuration.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("failed to read {path}: {source}")]
    ReadFile {
        path: PathBuf,
        source: std::io::Error,
    },

    #[error("failed to parse {path}: {source}")]
    Parse {
        path: PathBuf,
        source: toml::de::Error,
    },

    #[error("missing environment variable ${var} in {context}")]
    MissingEnvVar { var: String, context: String },

    #[error("app name mismatch: filename '{filename}' but config says '{config_name}'")]
    NameMismatch {
        filename: String,
        config_name: String,
    },
}

/// Errors related to HMAC signature verification.
#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("missing X-Slip-Signature header")]
    MissingSignature,
    #[error("invalid signature")]
    InvalidSignature,
}
