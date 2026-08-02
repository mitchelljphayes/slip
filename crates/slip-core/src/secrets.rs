//! Per-app secret storage with restrictive file permissions.
//!
//! Each secret is stored as a single file under `{base_path}/secrets/{app_name}/{key}`
//! with 0o600 permissions. The per-app directory has 0o700 permissions.
//! Secret values are never logged — only key names and counts.

use std::collections::HashMap;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::ConfigError;

/// Reserved key name for the per-app deploy key.
///
/// Stored in the secrets store (not in app TOML) with the same 0o600 perms
/// as any other secret.  The `__` prefix ensures it is filtered from `list()`
/// responses so it never leaks via `GET /v1/apps/{name}/secrets`.
pub const DEPLOY_KEY_NAME: &str = "__deploy_key";

/// Reserved synthetic app-name under which registry credentials are stored.
///
/// The store is per-app namespaced (`{base}/{app}/{key}`); registry creds are
/// not naturally app-scoped, so they live under this synthetic namespace. The
/// `__` prefix ensures the namespace is hidden from the public app `list()`
/// surface. The key for each registry is `sha256(normalized_host)[:16]`
/// (16 hex chars — passes [`validate_secret_key`]). A sidecar index file
/// `__index.json` (also `__`-prefixed, hidden from `list()`) maps key →
/// `{url, username}`.
pub const REGISTRY_NAMESPACE: &str = "__registry";

/// Sidecar index file name (under the `__registry` app dir) mapping the hash
/// key to the public `{url, username}` for each stored registry credential.
/// `__`-prefixed so it is filtered from `list()`.
pub const REGISTRY_INDEX_NAME: &str = "__index.json";

/// An entry in the registry credential index (public metadata only — no token).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryIndexEntry {
    pub url: String,
    #[serde(default)]
    pub username: Option<String>,
}

/// The on-disk index: `{ hash_key -> RegistryIndexEntry }`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RegistryIndex {
    #[serde(flatten)]
    pub entries: std::collections::BTreeMap<String, RegistryIndexEntry>,
}

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
    ///
    /// Internal/reserved keys (prefixed with `__`) are filtered out so they
    /// never appear in API responses.
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
                // Skip internal/reserved keys (prefixed with `__`)
                if name.starts_with('.') || name.starts_with("__") {
                    None
                } else {
                    Some(name)
                }
            })
            .collect();

        keys.sort();
        Ok(keys)
    }

    /// Get the deploy key for an app, if one exists.
    pub fn get_deploy_key(&self, app_name: &str) -> Result<Option<String>, ConfigError> {
        self.get(app_name, DEPLOY_KEY_NAME)
    }

    /// Set (or rotate) the deploy key for an app.
    ///
    /// Returns the newly generated key.
    pub fn set_deploy_key(&self, app_name: &str) -> Result<String, ConfigError> {
        // Generate 32 random bytes → 64-char hex string.
        let mut buf = [0u8; 32];
        getrandom::getrandom(&mut buf)
            .map_err(|e| ConfigError::Internal(format!("failed to generate deploy key: {e}")))?;
        let key = hex::encode(buf);

        self.set(app_name, DEPLOY_KEY_NAME, &key)?;
        Ok(key)
    }

    /// Remove the deploy key for an app.
    pub fn remove_deploy_key(&self, app_name: &str) -> Result<bool, ConfigError> {
        self.remove(app_name, DEPLOY_KEY_NAME)
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

    // ─── Registry credential store ───────────────────────────────────────────

    /// Compute the storage key for a registry URL: `sha256(normalized)[:16]`
    /// (16 lowercase hex chars). The hash is opaque, validation-safe (alnum),
    /// and stable for a given normalized host.
    fn registry_key(normalized_url: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(normalized_url.as_bytes());
        let digest = hasher.finalize();
        hex::encode(&digest[..8])
    }

    /// Read the on-disk registry index (key → {url, username}), or an empty
    /// index if none exists.
    fn read_registry_index(&self) -> Result<RegistryIndex, ConfigError> {
        let path = self
            .base_path
            .join(REGISTRY_NAMESPACE)
            .join(REGISTRY_INDEX_NAME);
        match std::fs::read_to_string(&path) {
            Ok(raw) => serde_json::from_str(&raw)
                .map_err(|e| ConfigError::Internal(format!("registry index parse failed: {e}"))),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(RegistryIndex::default()),
            Err(e) => Err(ConfigError::ReadFile { path, source: e }),
        }
    }

    /// Write the registry index atomically with 0o600 perms.
    fn write_registry_index(&self, index: &RegistryIndex) -> Result<(), ConfigError> {
        let dir = self.ensure_app_dir(REGISTRY_NAMESPACE)?;
        let target = dir.join(REGISTRY_INDEX_NAME);
        let tmp = dir.join(format!(".{REGISTRY_INDEX_NAME}.tmp"));
        let raw = serde_json::to_string(index)
            .map_err(|e| ConfigError::Internal(format!("registry index serialize failed: {e}")))?;
        std::fs::write(&tmp, raw.as_bytes()).map_err(|e| ConfigError::WriteFile {
            path: tmp.clone(),
            source: e,
        })?;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600)).map_err(|e| {
            ConfigError::WriteFile {
                path: tmp.clone(),
                source: e,
            }
        })?;
        std::fs::rename(&tmp, &target).map_err(|e| ConfigError::WriteFile {
            path: target.clone(),
            source: e,
        })?;
        Ok(())
    }

    /// Store (or overwrite) a registry credential.
    ///
    /// `url` is normalized via [`crate::config::normalize_registry_url`] before
    /// hashing, so `https://ghcr.io/` and `ghcr.io` map to the same key. The
    /// password is written to `{base}/__registry/{hash}` (0o600 via [`Self::set`]);
    /// the `{url, username}` pair is upserted in `__registry/__index.json`.
    pub fn set_registry_credential(
        &self,
        url: &str,
        username: Option<&str>,
        password: &str,
    ) -> Result<String, ConfigError> {
        let normalized = crate::config::normalize_registry_url(url)?;
        let key = Self::registry_key(&normalized);
        self.set(REGISTRY_NAMESPACE, &key, password)?;
        let mut index = self.read_registry_index()?;
        index.entries.insert(
            key.clone(),
            RegistryIndexEntry {
                url: normalized.clone(),
                username: username.map(|s| s.to_string()),
            },
        );
        self.write_registry_index(&index)?;
        Ok(normalized)
    }

    /// Look up a registry credential by URL.
    ///
    /// Returns `(username, password)` if a credential is stored for the
    /// (normalized) URL, else `None`.
    pub fn get_registry_credential(
        &self,
        url: &str,
    ) -> Result<Option<(Option<String>, String)>, ConfigError> {
        let normalized = crate::config::normalize_registry_url(url)?;
        let key = Self::registry_key(&normalized);
        let password = self.get(REGISTRY_NAMESPACE, &key)?;
        Ok(password.map(|p| {
            let username = self
                .read_registry_index()
                .ok()
                .and_then(|i| i.entries.get(&key).map(|e| e.username.clone()))
                .flatten();
            (username, p)
        }))
    }

    /// Remove a registry credential by URL.
    ///
    /// Returns `true` if a credential existed and was removed, `false` if it
    /// was not found (idempotent). The index entry is also removed.
    pub fn remove_registry_credential(&self, url: &str) -> Result<bool, ConfigError> {
        let normalized = crate::config::normalize_registry_url(url)?;
        let key = Self::registry_key(&normalized);
        let removed = self.remove(REGISTRY_NAMESPACE, &key)?;
        if removed && let Ok(mut index) = self.read_registry_index() {
            index.entries.remove(&key);
            self.write_registry_index(&index)?;
        }
        Ok(removed)
    }

    /// List stored registry credentials (public metadata only — never the
    /// password). Returns `{key, url, username}` for each entry.
    pub fn list_registry_credentials(&self) -> Result<Vec<RegistryListEntry>, ConfigError> {
        let index = self.read_registry_index()?;
        let mut out: Vec<RegistryListEntry> = index
            .entries
            .iter()
            .map(|(key, e)| RegistryListEntry {
                key: key.clone(),
                url: e.url.clone(),
                username: e.username.clone(),
            })
            .collect();
        out.sort_by(|a, b| a.url.cmp(&b.url));
        Ok(out)
    }
}

/// A registry credential as returned by [`SecretsStore::list_registry_credentials`].
///
/// Public metadata only — never includes the password/token.
#[derive(Debug, Clone, Serialize)]
pub struct RegistryListEntry {
    pub key: String,
    pub url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
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

    // ── Registry credential store ────────────────────────────────────────────

    #[test]
    fn test_registry_set_get_round_trip() {
        let (_tmp, store) = make_store();
        let url = store
            .set_registry_credential("ghcr.io", Some("slip"), "tok123")
            .unwrap();
        assert_eq!(url, "ghcr.io");
        let cred = store.get_registry_credential("ghcr.io").unwrap();
        assert_eq!(cred, Some((Some("slip".to_string()), "tok123".to_string())));
    }

    #[test]
    fn test_registry_get_missing_returns_none() {
        let (_tmp, store) = make_store();
        assert!(store.get_registry_credential("ghcr.io").unwrap().is_none());
    }

    #[test]
    fn test_registry_set_normalizes_url() {
        let (_tmp, store) = make_store();
        store
            .set_registry_credential("https://ghcr.io/", Some("u"), "p")
            .unwrap();
        // Lookup via a different normalization form hits the same key.
        let cred = store.get_registry_credential("ghcr.io").unwrap();
        assert_eq!(cred, Some((Some("u".to_string()), "p".to_string())));
    }

    #[test]
    fn test_registry_host_and_host_port_distinct() {
        let (_tmp, store) = make_store();
        store
            .set_registry_credential("reg.io", Some("a"), "pa")
            .unwrap();
        store
            .set_registry_credential("reg.io:443", Some("b"), "pb")
            .unwrap();
        assert_eq!(
            store.get_registry_credential("reg.io").unwrap(),
            Some((Some("a".to_string()), "pa".to_string()))
        );
        assert_eq!(
            store.get_registry_credential("reg.io:443").unwrap(),
            Some((Some("b".to_string()), "pb".to_string()))
        );
    }

    #[test]
    fn test_registry_remove() {
        let (_tmp, store) = make_store();
        store
            .set_registry_credential("ghcr.io", Some("slip"), "tok")
            .unwrap();
        assert!(store.remove_registry_credential("ghcr.io").unwrap());
        assert!(store.get_registry_credential("ghcr.io").unwrap().is_none());
        // Idempotent.
        assert!(!store.remove_registry_credential("ghcr.io").unwrap());
    }

    #[test]
    fn test_registry_list_excludes_password() {
        let (_tmp, store) = make_store();
        store
            .set_registry_credential("ghcr.io", Some("slip"), "secret-token")
            .unwrap();
        store
            .set_registry_credential("localhost:5000", None, "other")
            .unwrap();
        let list = store.list_registry_credentials().unwrap();
        assert_eq!(list.len(), 2);
        let ghcr = list.iter().find(|e| e.url == "ghcr.io").unwrap();
        assert_eq!(ghcr.username.as_deref(), Some("slip"));
        // No password field exists on RegistryListEntry (compile-time check is
        // implicit via the struct). Confirm the url/username are the only
        // payload by serializing.
        let json = serde_json::to_string(ghcr).unwrap();
        assert!(!json.contains("secret-token"));
    }

    #[test]
    fn test_registry_key_is_16_hex_chars() {
        let key = SecretsStore::registry_key("ghcr.io");
        assert_eq!(key.len(), 16, "key must be 16 hex chars");
        assert!(key.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_registry_password_file_is_0600() {
        let (_tmp, store) = make_store();
        store
            .set_registry_credential("ghcr.io", Some("slip"), "tok")
            .unwrap();
        let key = SecretsStore::registry_key("ghcr.io");
        let path = store.base_path.join(REGISTRY_NAMESPACE).join(&key);
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "registry cred file must be 0600");
    }

    #[test]
    fn test_registry_index_file_is_0600() {
        let (_tmp, store) = make_store();
        store
            .set_registry_credential("ghcr.io", Some("slip"), "tok")
            .unwrap();
        let path = store
            .base_path
            .join(REGISTRY_NAMESPACE)
            .join(REGISTRY_INDEX_NAME);
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "registry index must be 0600");
    }

    #[test]
    fn test_registry_hidden_from_app_list() {
        // The real invariant: a public app's `list("myapp")` never returns
        // registry cred files (they live under the separate `__registry/` app
        // dir, not under `myapp/`). Confirmed by: set a registry cred, set a
        // real-app secret, then assert list("myapp") returns only the real-app
        // secret and list("__registry") returns the hex cred key (documenting
        // the namespace-internal visibility — the cred key is hex, not
        // __-prefixed, so it IS returned by a direct list("__registry") call,
        // but no public app sees it).
        let (_tmp, store) = make_store();
        store
            .set_registry_credential("ghcr.io", Some("slip"), "tok")
            .unwrap();
        store.set("myapp", "API_KEY", "real-secret").unwrap();

        // The public app sees only its own secret — never the registry cred.
        let myapp_keys = store.list("myapp").unwrap();
        assert_eq!(
            myapp_keys,
            vec!["API_KEY".to_string()],
            "list(myapp) must not return registry cred files: {myapp_keys:?}"
        );

        // The registry namespace dir does contain the hex cred key (it's hex,
        // not __-prefixed, so list() doesn't filter it). This documents the
        // namespace-internal visibility — only the daemon reads this dir.
        let reg_keys = store.list("__registry").unwrap();
        assert_eq!(
            reg_keys.len(),
            1,
            "list(__registry) should return the single hex cred key: {reg_keys:?}"
        );
        assert!(
            reg_keys[0].chars().all(|c| c.is_ascii_hexdigit()),
            "registry cred key should be hex (sha256[:16]): {}",
            reg_keys[0]
        );
    }

    #[test]
    fn test_registry_rejects_url_with_path() {
        let (_tmp, store) = make_store();
        let err = store
            .set_registry_credential("reg.io/team", None, "p")
            .unwrap_err();
        assert!(err.to_string().contains("host[:port] only"));
    }
}
