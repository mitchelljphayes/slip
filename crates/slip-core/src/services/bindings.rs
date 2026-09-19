//! Retained binding credentials. Active injection is a projection of AppConfig,
//! not another mutable index: removing a need detaches without deleting data.

use std::collections::{BTreeMap, HashMap};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::{ServiceName, resource::ResourceCredentials};
use crate::{config::AppConfig, needs::Need, secrets::SecretsStore};

#[derive(Debug, thiserror::Error)]
pub enum BindingError {
    #[error("no {0} service: run `slip services add {0}` on the server")]
    MissingService(String),
    #[error("{0}")]
    Invalid(String),
    #[error("{0}")]
    Conflict(String),
    #[error(
        "binding operation failed — run `slip services list` and `slip services status <name>` on the server, then retry `slip apply`"
    )]
    Provision,
    #[error(
        "binding credentials unavailable — restore the server secrets backup and retry `slip apply`"
    )]
    Store,
}

// Deliberately no Debug: these records contain passwords and connection URLs.
#[derive(Clone, Serialize, Deserialize)]
pub(super) struct BindingRecord {
    pub service: ServiceName,
    pub instance: String,
    pub resource_id: String,
    pub password: String,
    pub env: Option<BTreeMap<String, String>>,
}

impl BindingRecord {
    pub fn credentials(&self) -> Result<ResourceCredentials, BindingError> {
        ResourceCredentials::new(self.resource_id.clone(), self.password.clone())
            .map_err(|_| BindingError::Store)
    }
}

/// Separate from the app's own secrets so app deletion also retains credentials.
const NAMESPACE: &str = "__bindings";
pub(super) type Records = BTreeMap<String, BindingRecord>;

fn app_key(app: &str) -> String {
    hex::encode(Sha256::digest(app.as_bytes()))
}

pub(super) fn record_key(alias: &str, need: &Need) -> String {
    format!("{}:{alias}", need.r#type)
}

pub(super) fn load(store: &SecretsStore, app: &str) -> Result<Records, BindingError> {
    let value = store
        .get(NAMESPACE, &app_key(app))
        .map_err(|_| BindingError::Store)?;
    match value {
        Some(value) => serde_json::from_str(&value).map_err(|_| BindingError::Store),
        None => Ok(BTreeMap::new()),
    }
}

pub(super) fn save(store: &SecretsStore, app: &str, records: &Records) -> Result<(), BindingError> {
    let value = serde_json::to_string(records).map_err(|_| BindingError::Store)?;
    store
        .set(NAMESPACE, &app_key(app), &value)
        .map_err(|_| BindingError::Store)
}

/// Read only currently declared bindings; missing credentials fail closed.
pub fn env(store: &SecretsStore, app: &AppConfig) -> Result<HashMap<String, String>, BindingError> {
    if app.needs.is_empty() {
        return Ok(HashMap::new());
    }
    let records = load(store, &app.app.name)?;
    let mut result = HashMap::new();
    for (alias, need) in &app.needs {
        let record = records.get(&record_key(alias, need)).ok_or_else(|| {
            BindingError::Conflict(format!("need '{alias}' is not bound — run `slip apply`"))
        })?;
        record.credentials()?;
        let values = record.env.as_ref().ok_or_else(|| {
            BindingError::Conflict(format!("need '{alias}' is not ready — retry `slip apply`"))
        })?;
        if values.keys().cloned().collect::<Vec<_>>() != {
            let mut keys = need.env_keys(alias);
            keys.sort();
            keys
        } {
            return Err(BindingError::Store);
        }
        result.extend(values.clone());
    }
    Ok(result)
}

/// Public keys only, alongside ordinary manually managed app secrets.
pub fn secret_keys(store: &SecretsStore, app: &AppConfig) -> Result<Vec<String>, BindingError> {
    let mut keys = store.list(&app.app.name).map_err(|_| BindingError::Store)?;
    for (alias, need) in &app.needs {
        keys.extend(need.env_keys(alias));
    }
    keys.sort();
    keys.dedup();
    Ok(keys)
}

/// Pod rendering preserves explicit manifest env entries. Reject collisions
/// rather than silently replacing a managed credential with an image value.
pub fn validate_pod_env(bytes: &[u8], app: &AppConfig) -> Result<(), BindingError> {
    if app.needs.is_empty() {
        return Ok(());
    }
    let manifest: serde_yaml::Value = serde_yaml::from_slice(bytes).map_err(|_| {
        BindingError::Invalid("invalid pod YAML — fix the manifest and retry the deployment".into())
    })?;
    let reserved: std::collections::HashSet<_> = app
        .needs
        .iter()
        .flat_map(|(alias, need)| need.env_keys(alias))
        .collect();
    for kind in ["containers", "initContainers"] {
        if let Some(containers) = manifest["spec"][kind].as_sequence() {
            for container in containers {
                if let Some(env) = container["env"].as_sequence() {
                    for entry in env {
                        if let Some(key) =
                            entry["name"].as_str().filter(|key| reserved.contains(*key))
                        {
                            return Err(BindingError::Conflict(format!(
                                "pod env '{key}' is managed by a binding — remove this env entry from the pod manifest"
                            )));
                        }
                    }
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::needs::{Need, NeedType};

    #[test]
    fn detach_and_app_deletion_retain_credentials() {
        let tmp = tempfile::tempdir().unwrap();
        let store = SecretsStore::new(tmp.path().join("secrets")).unwrap();
        let mut app: AppConfig = toml::from_str(
            "[app]\nname='app'\nimage='app'\n[health]\n[deploy]\n[needs.db]\ntype='postgres'\n",
        )
        .unwrap();
        let need = Need::new(NeedType::Postgres);
        let record = BindingRecord {
            service: ServiceName::parse("postgres").unwrap(),
            instance: "instance".into(),
            resource_id: format!("slip_{}", "a".repeat(48)),
            password: "b".repeat(64),
            env: Some(BTreeMap::from([(
                "DATABASE_URL".into(),
                "retained-url".into(),
            )])),
        };
        save(
            &store,
            "app",
            &BTreeMap::from([(record_key("db", &need), record)]),
        )
        .unwrap();
        assert_eq!(env(&store, &app).unwrap()["DATABASE_URL"], "retained-url");
        assert_eq!(secret_keys(&store, &app).unwrap(), ["DATABASE_URL"]);
        app.needs.clear();
        assert!(env(&store, &app).unwrap().is_empty());
        store.remove_all("app").unwrap();
        app.needs.insert("db".into(), need);
        assert_eq!(env(&store, &app).unwrap()["DATABASE_URL"], "retained-url");
        assert!(store.list("app").unwrap().is_empty());
    }

    #[test]
    fn corrupt_credentials_never_appear_in_errors() {
        let tmp = tempfile::tempdir().unwrap();
        let store = SecretsStore::new(tmp.path().join("secrets")).unwrap();
        store
            .set(NAMESPACE, &app_key("app"), "SECRET malformed json")
            .unwrap();
        let error = load(&store, "app").err().unwrap();
        assert!(!format!("{error:?} {error}").contains("SECRET"));
    }

    #[test]
    fn pod_binding_collisions_fail_without_disclosing_values() {
        let app: AppConfig = toml::from_str(
            "[app]\nname='app'\nimage='app'\n[health]\n[deploy]\n[needs.db]\ntype='postgres'\n",
        )
        .unwrap();
        for kind in ["containers", "initContainers"] {
            for value in [
                serde_json::json!({"value": "canary-do-not-print"}),
                serde_json::json!({"valueFrom": {"secretKeyRef": {"name": "canary-do-not-print", "key": "url"}}}),
            ] {
                let mut entry = value;
                entry["name"] = serde_json::json!("DATABASE_URL");
                let manifest =
                    serde_json::json!({"spec": {kind: [{"name": "app", "env": [entry]}]}});
                let error =
                    validate_pod_env(&serde_json::to_vec(&manifest).unwrap(), &app).unwrap_err();
                assert!(error.to_string().contains("DATABASE_URL"));
                assert!(!error.to_string().contains("canary-do-not-print"));
            }
        }
        assert!(validate_pod_env(b"spec:\n  containers:\n  - name: app\n    env:\n    - name: NORMAL_KEY\n      value: allowed\n", &app).is_ok());
    }

    #[test]
    fn unbound_need_never_silently_omits_required_env() {
        let tmp = tempfile::tempdir().unwrap();
        let store = SecretsStore::new(tmp.path().join("secrets")).unwrap();
        let app: AppConfig = toml::from_str("[app]\nname='other-app'\nimage='app'\n[health]\n[deploy]\n[needs.db]\ntype='postgres'\n").unwrap();
        assert!(matches!(env(&store, &app), Err(BindingError::Conflict(_))));
    }
}
