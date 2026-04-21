//! Per-app secret storage with restrictive file permissions.
//!
//! Each secret is stored as a single file under `{base_path}/secrets/{app_name}/{key}`
//! with 0o600 permissions. The per-app directory has 0o700 permissions.
//! Secret values are never logged — only key names and counts.

use std::collections::HashMap;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

use crate::error::ConfigError;

// ─── Secret key validation ──────────────────────────────────────────────────────

/// Validate a secret key name.
///
/// Rules:
/// - Non-empty
/// - Alphanumeric and underscores only
/// - Must start with a letter or underscore
/// - Maximum 256 characters
pub fn validate_secret_key(key: &str) -> Result<(), String> {
    if key.is_empty() {
        return Err("secret key must not be empty".to_string());
    }
    if key.len() > 256 {
        return Err(format!(
            "secret key must be 256 characters or less (got {})",
            key.len()
        ));
    }
    if !key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return Err(
            "secret key must contain only alphanumeric characters and underscores".to_string(),
        );
    }
    if !key.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_') {
        return Err("secret key must start with a letter or underscore".to_string());
    }
    Ok(())
}

// ─── SecretsStore ───────────────────────────────────────────────────────────────

/// File-system backed per-app secret storage.
///
/// Each app gets a directory `{base_path}/{app_name}/` (0o700) containing
/// one file per secret key (0o600). The file content is the secret value.
#[derive(Debug, Clone)]
pub struct SecretsStore {
    base_path: PathBuf,
}

impl SecretsStore {
    /// Create a new `SecretsStore` rooted at the given base path.
    ///
    /// The base path (typically `{storage.path}/secrets`) is created with 0o700
    /// permissions if it does not already exist.
    pub fn new(base_path: PathBuf) -> Result<Self, ConfigError> {
        if !base_path.exists() {
            std::fs::create_dir_all(&base_path).map_err(|e| ConfigError::WriteFile {
                path: base_path.clone(),
                source: e,
            })?;
            std::fs::set_permissions(&base_path, std::fs::Permissions::from_mode(0o700)).map_err(
                |e| ConfigError::WriteFile {
                    path: base_path.clone(),
                    source: e,
                },
            )?;
        }
        Ok(Self { base_path })
    }

    /// Ensure the per-app directory exists with 0o700 permissions, returning its path.
    fn ensure_app_dir(&self, app_name: &str) -> Result<PathBuf, ConfigError> {
        let dir = self.base_path.join(app_name);
        if !dir.exists() {
            std::fs::create_dir_all(&dir).map_err(|e| ConfigError::WriteFile {
                path: dir.clone(),
                source: e,
            })?;
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).map_err(
                |e| ConfigError::WriteFile {
                    path: dir.clone(),
                    source: e,
                },
            )?;
        }
        Ok(dir)
    }

    /// Set (or overwrite) a secret for an app.
    ///
    /// Uses atomic write (temp file → rename) for consistency.
    pub fn set(&self, app_name: &str, key: &str, value: &str) -> Result<(), ConfigError> {
        let dir = self.ensure_app_dir(app_name)?;
        let target_path = dir.join(key);
        let temp_path = dir.join(format!(".{key}.tmp"));

        std::fs::write(&temp_path, value.as_bytes()).map_err(|e| ConfigError::WriteFile {
            path: temp_path.clone(),
            source: e,
        })?;

        // Set 0o600 permissions on the temp file before rename.
        std::fs::set_permissions(&temp_path, std::fs::Permissions::from_mode(0o600)).map_err(
            |e| ConfigError::WriteFile {
                path: temp_path.clone(),
                source: e,
            },
        )?;

        std::fs::rename(&temp_path, &target_path).map_err(|e| ConfigError::WriteFile {
            path: target_path.clone(),
            source: e,
        })?;

        Ok(())
    }

    /// Get a single secret value by app name and key.
    ///
    /// Returns `Ok(None)` if the secret file does not exist.
    pub fn get(&self, app_name: &str, key: &str) -> Result<Option<String>, ConfigError> {
        let path = self.base_path.join(app_name).join(key);
        match std::fs::read_to_string(&path) {
            Ok(value) => Ok(Some(value)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(ConfigError::ReadFile { path, source: e }),
        }
    }

    /// List all secret key names for an app (sorted).
    ///
    /// Returns an empty vec if the app has no secrets directory.
    /// **Never returns secret values.**
    pub fn list(&self, app_name: &str) -> Result<Vec<String>, ConfigError> {
        let dir = self.base_path.join(app_name);
        if !dir.is_dir() {
            return Ok(Vec::new());
        }

        let mut keys: Vec<String> = std::fs::read_dir(&dir)
            .map_err(|e| ConfigError::ReadFile {
                path: dir.clone(),
                source: e,
            })?
            .filter_map(|entry| {
                let entry = entry.ok()?;
                let name = entry.file_name().to_string_lossy().to_string();
                // Skip dotfiles (e.g. temp files during writes)
                if name.starts_with('.') {
                    None
                } else {
                    Some(name)
                }
            })
            .collect();

        keys.sort();
        Ok(keys)
    }

    /// Remove a single secret by key.
    ///
    /// Returns `true` if the secret existed and was removed, `false` if it
    /// was not found (idempotent).
    pub fn remove(&self, app_name: &str, key: &str) -> Result<bool, ConfigError> {
        let path = self.base_path.join(app_name).join(key);
        match std::fs::remove_file(&path) {
            Ok(()) => Ok(true),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(ConfigError::DeleteFile { path, source: e }),
        }
    }

    /// Get all secrets for an app as a HashMap (key → value).
    ///
    /// Used by the deploy injection code to merge secrets into env vars.
    pub fn get_all(&self, app_name: &str) -> Result<HashMap<String, String>, ConfigError> {
        let keys = self.list(app_name)?;
        let mut result = HashMap::with_capacity(keys.len());
        for key in keys {
            if let Some(value) = self.get(app_name, &key)? {
                result.insert(key, value);
            }
        }
        Ok(result)
    }

    /// Remove all secrets for an app (deletes the entire app secrets directory).
    ///
    /// Called when an app is deleted.
    pub fn remove_all(&self, app_name: &str) -> Result<(), ConfigError> {
        let dir = self.base_path.join(app_name);
        if !dir.exists() {
            return Ok(());
        }
        std::fs::remove_dir_all(&dir).map_err(|e| ConfigError::DeleteFile {
            path: dir,
            source: e,
        })
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn make_store() -> (TempDir, SecretsStore) {
        let tmp = TempDir::new().unwrap();
        let base = tmp.path().join("secrets");
        let store = SecretsStore::new(base).unwrap();
        (tmp, store)
    }

    #[test]
    fn test_round_trip_set_get() {
        let (_tmp, store) = make_store();
        store
            .set("myapp", "DB_URL", "postgres://localhost/db")
            .unwrap();
        let value = store.get("myapp", "DB_URL").unwrap();
        assert_eq!(value, Some("postgres://localhost/db".to_string()));
    }

    #[test]
    fn test_get_nonexistent_returns_none() {
        let (_tmp, store) = make_store();
        let value = store.get("myapp", "NOPE").unwrap();
        assert_eq!(value, None);
    }

    #[test]
    fn test_list_returns_key_names_only() {
        let (_tmp, store) = make_store();
        store.set("myapp", "KEY_A", "val_a").unwrap();
        store.set("myapp", "KEY_B", "val_b").unwrap();
        let keys = store.list("myapp").unwrap();
        assert_eq!(keys, vec!["KEY_A", "KEY_B"]);
    }

    #[test]
    fn test_list_nonexistent_app_returns_empty() {
        let (_tmp, store) = make_store();
        let keys = store.list("noapp").unwrap();
        assert!(keys.is_empty());
    }

    #[test]
    fn test_remove_existing() {
        let (_tmp, store) = make_store();
        store.set("myapp", "KEY_A", "val").unwrap();
        assert!(store.remove("myapp", "KEY_A").unwrap());
        assert_eq!(store.get("myapp", "KEY_A").unwrap(), None);
    }

    #[test]
    fn test_remove_nonexistent_is_idempotent() {
        let (_tmp, store) = make_store();
        assert!(!store.remove("myapp", "NOPE").unwrap());
    }

    #[test]
    fn test_get_all() {
        let (_tmp, store) = make_store();
        store.set("myapp", "KEY_A", "val_a").unwrap();
        store.set("myapp", "KEY_B", "val_b").unwrap();
        let all = store.get_all("myapp").unwrap();
        assert_eq!(all.len(), 2);
        assert_eq!(all["KEY_A"], "val_a");
        assert_eq!(all["KEY_B"], "val_b");
    }

    #[test]
    fn test_get_all_empty_app() {
        let (_tmp, store) = make_store();
        let all = store.get_all("myapp").unwrap();
        assert!(all.is_empty());
    }

    #[test]
    fn test_remove_all() {
        let (_tmp, store) = make_store();
        store.set("myapp", "KEY_A", "val_a").unwrap();
        store.set("myapp", "KEY_B", "val_b").unwrap();
        store.remove_all("myapp").unwrap();
        assert!(store.list("myapp").unwrap().is_empty());
    }

    #[test]
    fn test_remove_all_nonexistent_app_is_ok() {
        let (_tmp, store) = make_store();
        store.remove_all("noapp").unwrap();
    }

    #[test]
    fn test_file_permissions_600() {
        let (_tmp, store) = make_store();
        store.set("myapp", "SECRET_KEY", "s3cret").unwrap();
        let path = store.base_path.join("myapp").join("SECRET_KEY");
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "secret file should have 600 permissions");
    }

    #[test]
    fn test_dir_permissions_700() {
        let (_tmp, store) = make_store();
        store.set("myapp", "SECRET_KEY", "s3cret").unwrap();
        let dir_path = store.base_path.join("myapp");
        let mode = std::fs::metadata(&dir_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700, "app secrets dir should have 700 permissions");
    }

    #[test]
    fn test_base_dir_permissions_700() {
        let tmp = TempDir::new().unwrap();
        let base = tmp.path().join("secrets");
        let _store = SecretsStore::new(base.clone()).unwrap();
        let mode = std::fs::metadata(&base).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700, "base secrets dir should have 700 permissions");
    }

    #[test]
    fn test_set_overwrites_existing() {
        let (_tmp, store) = make_store();
        store.set("myapp", "KEY", "old").unwrap();
        store.set("myapp", "KEY", "new").unwrap();
        assert_eq!(store.get("myapp", "KEY").unwrap(), Some("new".to_string()));
    }

    // ── Key validation ────────────────────────────────────────────────────────

    #[test]
    fn test_validate_key_valid() {
        assert!(validate_secret_key("DB_URL").is_ok());
        assert!(validate_secret_key("_PRIVATE").is_ok());
        assert!(validate_secret_key("a").is_ok());
        assert!(validate_secret_key("KEY_123").is_ok());
    }

    #[test]
    fn test_validate_key_empty() {
        assert!(validate_secret_key("").is_err());
    }

    #[test]
    fn test_validate_key_too_long() {
        let long_key = "A".repeat(257);
        assert!(validate_secret_key(&long_key).is_err());
    }

    #[test]
    fn test_validate_key_max_length_ok() {
        let max_key = "A".repeat(256);
        assert!(validate_secret_key(&max_key).is_ok());
    }

    #[test]
    fn test_validate_key_starts_with_digit() {
        assert!(validate_secret_key("1KEY").is_err());
    }

    #[test]
    fn test_validate_key_special_chars() {
        assert!(validate_secret_key("KEY-NAME").is_err());
        assert!(validate_secret_key("KEY.NAME").is_err());
        assert!(validate_secret_key("KEY NAME").is_err());
    }

    #[test]
    fn test_validate_key_starts_with_underscore() {
        assert!(validate_secret_key("_KEY").is_ok());
    }
}
