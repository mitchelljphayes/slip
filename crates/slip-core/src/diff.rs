//! Diff engine for `slip apply` — compares repo config against server state.
//!
//! Computes an RFC 6902 JSON Patch between the pushable subset of a repo
//! `slip.toml` and the server's `AppResponse`, renders human-readable diffs,
//! and builds API payloads for create/update.

use std::collections::BTreeMap;

use serde::Serialize;
use serde_json::Value;

use crate::api::AppResponse;
use crate::repo_config::RepoConfig;

// ─── Pushable subset ──────────────────────────────────────────────────────────

/// The canonical shape of fields that can be pushed from repo to server.
///
/// Both sides (repo config and server response) are normalized into this shape
/// before diffing. Fields that exist only on one side (e.g. `app.kind`,
/// `app.manifest`, `routing.container`) are excluded — they are not pushable.
#[derive(Debug, Serialize)]
struct Pushable {
    image: Option<String>,
    domain: Option<String>,
    port: Option<u16>,
    health: PushableHealth,
    resources: PushableResources,
    deploy: PushableDeploy,
    env: BTreeMap<String, String>,
    volumes: Vec<PushableVolume>,
    routes: Vec<PushableRoute>,
}

#[derive(Debug, Serialize)]
struct PushableHealth {
    path: Option<String>,
    interval_secs: Option<f64>,
    timeout_secs: Option<f64>,
    retries: Option<u32>,
    start_period_secs: Option<f64>,
}

#[derive(Debug, Serialize)]
struct PushableResources {
    memory: Option<String>,
    cpus: Option<String>,
}

#[derive(Debug, Serialize)]
struct PushableDeploy {
    strategy: Option<String>,
    drain_timeout_secs: Option<f64>,
    timeout_secs: Option<f64>,
}

#[derive(Debug, Serialize)]
struct PushableVolume {
    mount_path: String,
    read_only: bool,
}

#[derive(Debug, Serialize)]
struct PushableRoute {
    hostname: String,
    port: Option<u16>,
}

// ─── Normalization ────────────────────────────────────────────────────────────

fn repo_pushable(cfg: &RepoConfig) -> Pushable {
    Pushable {
        image: cfg.app.image.clone(),
        domain: cfg.routing.domain.clone(),
        port: cfg.routing.port,
        health: PushableHealth {
            path: cfg.health.path.clone(),
            interval_secs: cfg.health.interval.map(|d| d.as_secs_f64()),
            timeout_secs: cfg.health.timeout.map(|d| d.as_secs_f64()),
            retries: cfg.health.retries,
            start_period_secs: cfg.health.start_period.map(|d| d.as_secs_f64()),
        },
        resources: PushableResources {
            memory: cfg
                .defaults
                .resources
                .as_ref()
                .and_then(|r| r.memory.clone()),
            cpus: cfg.defaults.resources.as_ref().and_then(|r| r.cpus.clone()),
        },
        deploy: PushableDeploy {
            strategy: cfg.deploy.as_ref().and_then(|d| d.strategy.clone()),
            drain_timeout_secs: cfg
                .deploy
                .as_ref()
                .and_then(|d| d.drain_timeout.map(|t| t.as_secs_f64())),
            timeout_secs: cfg
                .deploy
                .as_ref()
                .and_then(|d| d.timeout.map(|t| t.as_secs_f64())),
        },
        env: cfg
            .env
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect(),
        volumes: cfg
            .volumes
            .iter()
            .map(|v| PushableVolume {
                mount_path: v.mount_path.clone(),
                read_only: v.read_only,
            })
            .collect(),
        routes: Vec::new(), // repo doesn't carry hostname — routes are server-side
    }
}

fn server_pushable(resp: &AppResponse) -> Pushable {
    // Normalize domain/port defaults: "" and 0 mean "unset"
    let port = if resp.port == 0 {
        None
    } else {
        Some(resp.port)
    };
    let domain = if resp.domain.is_empty() {
        None
    } else {
        Some(resp.domain.clone())
    };

    Pushable {
        image: Some(resp.image.clone()),
        domain,
        port,
        health: PushableHealth {
            path: resp.health.path.clone(),
            interval_secs: Some(resp.health.interval.as_secs_f64()),
            timeout_secs: Some(resp.health.timeout.as_secs_f64()),
            retries: Some(resp.health.retries),
            start_period_secs: Some(resp.health.start_period.as_secs_f64()),
        },
        resources: PushableResources {
            memory: resp.resources.memory.clone(),
            cpus: resp.resources.cpus.clone(),
        },
        deploy: PushableDeploy {
            strategy: Some(resp.deploy.strategy.clone()),
            drain_timeout_secs: Some(resp.deploy.drain_timeout.as_secs_f64()),
            timeout_secs: resp.deploy.timeout.map(|t| t.as_secs_f64()),
        },
        env: resp
            .env
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect(),
        volumes: resp
            .volumes
            .iter()
            .map(|v| PushableVolume {
                mount_path: v.mount_path.clone(),
                read_only: v.read_only,
            })
            .collect(),
        routes: resp
            .routes
            .iter()
            .map(|r| PushableRoute {
                hostname: r.hostname.clone(),
                port: r.port,
            })
            .collect(),
    }
}

/// Normalize the server pushable to match repo semantics: when the repo has
/// `None` for a field, set the server side to `None` too (so it doesn't show
/// as a diff — the repo is saying "use server defaults").
///
/// Fields the repo doesn't specify are left as-is on the server (not managed by apply).
fn normalize_server_to_repo(repo: &Pushable, server: &mut Pushable) {
    // Image: if repo has None, server should also be None (unmanaged)
    if repo.image.is_none() {
        server.image = None;
    }
    // Domain: if repo has None, server should also be None (unmanaged)
    if repo.domain.is_none() {
        server.domain = None;
    }
    // Port: if repo has None, server should also be None (no diff)
    if repo.port.is_none() {
        server.port = None;
    }
    // Health: if repo has None, server should also be None (no diff)
    if repo.health.path.is_none() {
        server.health.path = None;
    }
    if repo.health.interval_secs.is_none() {
        server.health.interval_secs = None;
    }
    if repo.health.timeout_secs.is_none() {
        server.health.timeout_secs = None;
    }
    if repo.health.retries.is_none() {
        server.health.retries = None;
    }
    if repo.health.start_period_secs.is_none() {
        server.health.start_period_secs = None;
    }
    // Resources: if repo has None, server should also be None
    if repo.resources.memory.is_none() {
        server.resources.memory = None;
    }
    if repo.resources.cpus.is_none() {
        server.resources.cpus = None;
    }
    // Deploy: if repo has None, server should also be None
    if repo.deploy.strategy.is_none() {
        server.deploy.strategy = None;
    }
    if repo.deploy.drain_timeout_secs.is_none() {
        server.deploy.drain_timeout_secs = None;
    }
    if repo.deploy.timeout_secs.is_none() {
        server.deploy.timeout_secs = None;
    }
}

// ─── Stable JSON value with sorted keys ───────────────────────────────────────

/// Recursively sort the keys of a `serde_json::Value` for deterministic ordering.
fn sort_value(v: &Value) -> Value {
    match v {
        Value::Object(m) => {
            let sorted: BTreeMap<String, Value> =
                m.iter().map(|(k, v)| (k.clone(), sort_value(v))).collect();
            Value::Object(sorted.into_iter().collect())
        }
        Value::Array(arr) => Value::Array(arr.iter().map(sort_value).collect()),
        other => other.clone(),
    }
}

// ─── ApplyDiff output ────────────────────────────────────────────────────────

/// Stable `--json` diff output envelope.
///
/// Schema: `slip.apply.diff/v1`
///
/// Fields:
/// - `schema`: always `"slip.apply.diff/v1"`
/// - `app`: the app name
/// - `changed`: whether there are changes
/// - `ops`: RFC 6902 patch operations (empty when `changed` is false)
/// - `create`: present and `true` when the app would be created (dry-run only)
/// - `message`: human-readable message (present for create/terminal states)
///
/// Terminal states (after apply):
/// - `status`: `"created"` or `"applied"`
#[derive(Debug, Clone, Serialize)]
pub struct ApplyDiff {
    pub schema: String,
    pub app: String,
    pub changed: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub ops: Vec<json_patch::PatchOperation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub create: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
}

impl ApplyDiff {
    /// Return a copy with environment variable values redacted to `"(redacted)"`.
    ///
    /// Replaces the value of any `Add` or `Replace` operation whose path starts
    /// with `/env/` or equals `/env`. The wire PATCH payload is never redacted —
    /// this is for display (human and `--json`) only.
    pub fn redacted(&self) -> Self {
        let redacted_ops: Vec<json_patch::PatchOperation> = self
            .ops
            .iter()
            .map(|op| match op {
                json_patch::PatchOperation::Add(a) => {
                    if a.path.to_string().starts_with("/env/") || a.path == "/env" {
                        json_patch::PatchOperation::Add(json_patch::AddOperation {
                            path: a.path.clone(),
                            value: serde_json::Value::String("(redacted)".to_string()),
                        })
                    } else {
                        op.clone()
                    }
                }
                json_patch::PatchOperation::Replace(r) => {
                    if r.path.to_string().starts_with("/env/") || r.path == "/env" {
                        json_patch::PatchOperation::Replace(json_patch::ReplaceOperation {
                            path: r.path.clone(),
                            value: serde_json::Value::String("(redacted)".to_string()),
                        })
                    } else {
                        op.clone()
                    }
                }
                _ => op.clone(),
            })
            .collect();

        ApplyDiff {
            ops: redacted_ops,
            ..self.clone()
        }
    }
}

// ─── Public API ───────────────────────────────────────────────────────────────

/// Compute the diff between a repo config and the server's current state.
///
/// Returns an `ApplyDiff` with the RFC 6902 operations needed to make the
/// server match the repo. If the two are already identical, `changed` is
/// `false` and `ops` is empty.
pub fn compute_diff(
    repo: &RepoConfig,
    server: &AppResponse,
) -> Result<ApplyDiff, serde_json::Error> {
    let repo_p = repo_pushable(repo);
    let mut server_p = server_pushable(server);

    // Normalize server defaults to None where repo doesn't specify them
    normalize_server_to_repo(&repo_p, &mut server_p);

    let repo_val = sort_value(&serde_json::to_value(&repo_p)?);
    let server_val = sort_value(&serde_json::to_value(&server_p)?);

    let patch = json_patch::diff(&server_val, &repo_val);
    let changed = !patch.0.is_empty();

    Ok(ApplyDiff {
        schema: "slip.apply.diff/v1".to_string(),
        app: repo.app.name.clone(),
        changed,
        ops: patch.0,
        create: None,
        message: None,
        status: None,
    })
}

/// Render a human-readable diff summary.
///
/// Uses `~` for replace, `+` for add, `-` for remove markers with dotted paths.
/// Environment variable values are shown as `(redacted)` unless `redact_env` is
/// `false`. Removed env keys are grouped under a "will remove env vars" header.
///
/// When `redact_env` is true, the diff is redacted first (same as `redacted()`)
/// so both human and `--json` paths use the same redaction logic.
pub fn render_human_diff(diff: &ApplyDiff, redact_env: bool) -> String {
    let effective = if redact_env {
        diff.redacted()
    } else {
        diff.clone()
    };

    if !effective.changed {
        return "no changes — up to date".to_string();
    }

    let mut lines: Vec<String> = Vec::new();
    let mut removed_env: Vec<String> = Vec::new();

    for op in &effective.ops {
        let path = op.path().to_string();
        let is_env = path.starts_with("/env/") || path == "/env";

        match op {
            json_patch::PatchOperation::Add(a) => {
                lines.push(format!("+ {path} = {}", a.value));
            }
            json_patch::PatchOperation::Remove(_) => {
                if is_env {
                    // Extract the env key name from the path
                    if let Some(key) = path.strip_prefix("/env/") {
                        removed_env.push(key.to_string());
                        continue; // Don't add to main lines yet
                    }
                }
                lines.push(format!("- {path}"));
            }
            json_patch::PatchOperation::Replace(r) => {
                lines.push(format!("~ {path} = {}", r.value));
            }
            _ => {
                lines.push(format!("? {path} (unknown operation)"));
            }
        }
    }

    // Group removed env vars
    if !removed_env.is_empty() {
        lines.push(String::new());
        lines.push("will remove env vars (not in slip.toml):".to_string());
        for key in &removed_env {
            lines.push(format!("  - {key}"));
        }
    }

    lines.join("\n")
}

/// Build a full `UpdateAppRequest` JSON payload from repo config fields.
///
/// Uses full-replace semantics for env, volumes, and routes.
pub fn build_update_payload(repo: &RepoConfig) -> Value {
    let mut payload = serde_json::json!({});

    // Image
    if let Some(ref image) = repo.app.image {
        payload["image"] = Value::String(image.clone());
    }

    // Domain
    if let Some(ref domain) = repo.routing.domain {
        payload["domain"] = Value::String(domain.clone());
    }

    // Port
    if let Some(port) = repo.routing.port {
        payload["port"] = Value::Number(port.into());
    }

    // Health
    let mut health: Option<Value> = None;
    if repo.health.path.is_some()
        || repo.health.interval.is_some()
        || repo.health.timeout.is_some()
        || repo.health.retries.is_some()
        || repo.health.start_period.is_some()
    {
        let mut h = serde_json::json!({});
        if let Some(ref path) = repo.health.path {
            h["path"] = Value::String(path.clone());
        }
        if let Some(interval) = repo.health.interval {
            h["interval"] = Value::Number(
                serde_json::Number::from_f64(interval.as_secs_f64())
                    .unwrap_or(serde_json::Number::from_f64(0.0).unwrap()),
            );
        }
        if let Some(timeout) = repo.health.timeout {
            h["timeout"] = Value::Number(
                serde_json::Number::from_f64(timeout.as_secs_f64())
                    .unwrap_or(serde_json::Number::from_f64(0.0).unwrap()),
            );
        }
        if let Some(retries) = repo.health.retries {
            h["retries"] = Value::Number(retries.into());
        }
        if let Some(start) = repo.health.start_period {
            h["start_period"] = Value::Number(
                serde_json::Number::from_f64(start.as_secs_f64())
                    .unwrap_or(serde_json::Number::from_f64(0.0).unwrap()),
            );
        }
        health = Some(h);
    }
    if let Some(h) = health {
        payload["health"] = h;
    }

    // Resources
    if let Some(ref res) = repo.defaults.resources {
        let mut r = serde_json::json!({});
        if let Some(ref mem) = res.memory {
            r["memory"] = Value::String(mem.clone());
        }
        if let Some(ref cpus) = res.cpus {
            r["cpus"] = Value::String(cpus.clone());
        }
        payload["resources"] = r;
    }

    // Deploy
    if let Some(ref d) = repo.deploy {
        let mut dep = serde_json::json!({});
        if let Some(ref strategy) = d.strategy {
            dep["strategy"] = Value::String(strategy.clone());
        }
        if let Some(dt) = d.drain_timeout {
            dep["drain_timeout"] = Value::Number(
                serde_json::Number::from_f64(dt.as_secs_f64())
                    .unwrap_or(serde_json::Number::from_f64(0.0).unwrap()),
            );
        }
        if let Some(t) = d.timeout {
            dep["timeout"] = Value::Number(
                serde_json::Number::from_f64(t.as_secs_f64())
                    .unwrap_or(serde_json::Number::from_f64(0.0).unwrap()),
            );
        }
        payload["deploy"] = dep;
    }

    // Env (full replace)
    if !repo.env.is_empty() {
        let env_map: Value = repo
            .env
            .iter()
            .map(|(k, v)| (k.clone(), Value::String(v.clone())))
            .collect();
        payload["env"] = env_map;
    } else {
        // Send empty map to clear server env
        payload["env"] = Value::Object(Default::default());
    }

    // Volumes (full replace)
    if !repo.volumes.is_empty() {
        let vols: Vec<Value> = repo
            .volumes
            .iter()
            .map(|v| {
                serde_json::json!({
                    "mount_path": v.mount_path,
                    "read_only": v.read_only,
                })
            })
            .collect();
        payload["volumes"] = Value::Array(vols);
    } else {
        payload["volumes"] = Value::Array(Vec::new());
    }

    payload
}

/// Build a `CreateAppRequest` JSON payload from repo config fields.
///
/// Returns an error if required fields (`image`, `domain`) are missing.
/// The repo config's `[app] image` and `[routing] domain` fields are used.
pub fn build_create_payload(repo: &RepoConfig) -> Result<Value, String> {
    let image = repo.app.image.as_deref().unwrap_or("");
    let domain = repo.routing.domain.as_deref().unwrap_or("");

    if image.is_empty() {
        return Err(format!(
            "cannot create app '{}': slip.toml is missing [app] image — \
             add `image = \"ghcr.io/you/{}\"` (and [routing] domain) \
             or register the app first with the API",
            repo.app.name, repo.app.name
        ));
    }
    if domain.is_empty() {
        return Err(format!(
            "cannot create app '{}': slip.toml is missing [routing] domain — \
             add `domain = \"{}.example.com\"` under [routing] \
             or register the app first with the API",
            repo.app.name, repo.app.name
        ));
    }

    let mut payload = serde_json::json!({
        "name": repo.app.name,
        "image": image,
        "domain": domain,
    });

    if let Some(port) = repo.routing.port {
        payload["port"] = Value::Number(port.into());
    }

    // Health
    let mut health: Option<Value> = None;
    if repo.health.path.is_some()
        || repo.health.interval.is_some()
        || repo.health.timeout.is_some()
        || repo.health.retries.is_some()
        || repo.health.start_period.is_some()
    {
        let mut h = serde_json::json!({});
        if let Some(ref path) = repo.health.path {
            h["path"] = Value::String(path.clone());
        }
        if let Some(interval) = repo.health.interval {
            h["interval"] = Value::Number(
                serde_json::Number::from_f64(interval.as_secs_f64())
                    .unwrap_or(serde_json::Number::from_f64(0.0).unwrap()),
            );
        }
        if let Some(timeout) = repo.health.timeout {
            h["timeout"] = Value::Number(
                serde_json::Number::from_f64(timeout.as_secs_f64())
                    .unwrap_or(serde_json::Number::from_f64(0.0).unwrap()),
            );
        }
        if let Some(retries) = repo.health.retries {
            h["retries"] = Value::Number(retries.into());
        }
        if let Some(start) = repo.health.start_period {
            h["start_period"] = Value::Number(
                serde_json::Number::from_f64(start.as_secs_f64())
                    .unwrap_or(serde_json::Number::from_f64(0.0).unwrap()),
            );
        }
        health = Some(h);
    }
    if let Some(h) = health {
        payload["health"] = h;
    }

    // Resources
    if let Some(ref res) = repo.defaults.resources {
        let mut r = serde_json::json!({});
        if let Some(ref mem) = res.memory {
            r["memory"] = Value::String(mem.clone());
        }
        if let Some(ref cpus) = res.cpus {
            r["cpus"] = Value::String(cpus.clone());
        }
        payload["resources"] = r;
    }

    // Deploy
    if let Some(ref d) = repo.deploy {
        let mut dep = serde_json::json!({});
        if let Some(ref strategy) = d.strategy {
            dep["strategy"] = Value::String(strategy.clone());
        }
        if let Some(dt) = d.drain_timeout {
            dep["drain_timeout"] = Value::Number(
                serde_json::Number::from_f64(dt.as_secs_f64())
                    .unwrap_or(serde_json::Number::from_f64(0.0).unwrap()),
            );
        }
        if let Some(t) = d.timeout {
            dep["timeout"] = Value::Number(
                serde_json::Number::from_f64(t.as_secs_f64())
                    .unwrap_or(serde_json::Number::from_f64(0.0).unwrap()),
            );
        }
        payload["deploy"] = dep;
    }

    // Env
    if !repo.env.is_empty() {
        let env_map: Value = repo
            .env
            .iter()
            .map(|(k, v)| (k.clone(), Value::String(v.clone())))
            .collect();
        payload["env"] = env_map;
    }

    // Volumes
    if !repo.volumes.is_empty() {
        let vols: Vec<Value> = repo
            .volumes
            .iter()
            .map(|v| {
                serde_json::json!({
                    "mount_path": v.mount_path,
                    "read_only": v.read_only,
                })
            })
            .collect();
        payload["volumes"] = Value::Array(vols);
    }

    Ok(payload)
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;
    use crate::api::AppResponse;
    use crate::config::{DeployConfig, HealthConfig, ResourceConfig};
    use crate::repo_config::{RepoDefaults, RepoHealthConfig, RepoRoutingConfig, RepoVolume};

    fn make_repo(overrides: impl FnOnce(&mut RepoConfig)) -> RepoConfig {
        let mut cfg = RepoConfig {
            app: crate::repo_config::RepoAppInfo {
                name: "testapp".to_string(),
                kind: "container".to_string(),
                manifest: None,
                image: None,
            },
            health: RepoHealthConfig::default(),
            routing: RepoRoutingConfig::default(),
            defaults: RepoDefaults::default(),
            preview: None,
            volumes: Vec::new(),
            env: HashMap::new(),
            deploy: None,
            remote: crate::repo_config::RemoteConfig::default(),
        };
        overrides(&mut cfg);
        cfg
    }

    fn make_server(overrides: impl FnOnce(&mut AppResponse)) -> AppResponse {
        let mut resp = AppResponse {
            name: "testapp".to_string(),
            image: "nginx:latest".to_string(),
            domain: "testapp.example.com".to_string(),
            port: 8080,
            secret: None,
            env: HashMap::new(),
            resources: ResourceConfig::default(),
            network: crate::config::NetworkConfig::default(),
            health: HealthConfig::default(),
            deploy: DeployConfig::default(),
            preview: None,
            volumes: Vec::new(),
            routes: Vec::new(),
            tls: None,
        };
        overrides(&mut resp);
        resp
    }

    #[test]
    fn identical_configs_no_changes() {
        let repo = make_repo(|_| {});
        let server = make_server(|_| {});
        let diff = compute_diff(&repo, &server).unwrap();
        if diff.changed {
            for op in &diff.ops {
                eprintln!("  unexpected op: path={:?}", op.path());
            }
        }
        assert!(!diff.changed);
        assert!(diff.ops.is_empty());
        assert_eq!(diff.schema, "slip.apply.diff/v1");
        assert_eq!(diff.app, "testapp");
    }

    #[test]
    fn health_path_change_shows_replace() {
        let repo = make_repo(|r| {
            r.health.path = Some("/api/healthz".to_string());
        });
        let server = make_server(|s| {
            s.health.path = Some("/".to_string());
        });
        let diff = compute_diff(&repo, &server).unwrap();
        assert!(diff.changed);
        assert!(diff.ops.iter().any(|op| {
            matches!(op, json_patch::PatchOperation::Replace(r) if r.path == "/health/path")
        }));
    }

    #[test]
    fn env_add_remove_ops() {
        let repo = make_repo(|r| {
            r.env.insert("NEW_KEY".to_string(), "new_val".to_string());
            r.env.insert("KEPT_KEY".to_string(), "kept_val".to_string());
        });
        let mut server_env = HashMap::new();
        server_env.insert("OLD_KEY".to_string(), "old_val".to_string());
        server_env.insert("KEPT_KEY".to_string(), "kept_val".to_string());
        let server = make_server(|s| {
            s.env = server_env;
        });
        let diff = compute_diff(&repo, &server).unwrap();
        assert!(diff.changed);

        // Should have add for NEW_KEY and remove for OLD_KEY
        let has_add = diff
            .ops
            .iter()
            .any(|op| matches!(op, json_patch::PatchOperation::Add(a) if a.path == "/env/NEW_KEY"));
        let has_remove = diff.ops.iter().any(
            |op| matches!(op, json_patch::PatchOperation::Remove(r) if r.path == "/env/OLD_KEY"),
        );
        assert!(has_add, "should have add for NEW_KEY");
        assert!(has_remove, "should have remove for OLD_KEY");
    }

    #[test]
    fn port_change_detected() {
        let repo = make_repo(|r| {
            r.routing.port = Some(3000);
        });
        let server = make_server(|s| {
            s.port = 8080;
        });
        let diff = compute_diff(&repo, &server).unwrap();
        assert!(diff.changed);
        assert!(diff.ops.iter().any(|op| {
            matches!(op, json_patch::PatchOperation::Replace(r) if r.path == "/port")
        }));
    }

    #[test]
    fn redaction_on_off() {
        let repo = make_repo(|r| {
            r.env.insert("SECRET".to_string(), "s3cret!".to_string());
        });
        let server = make_server(|_| {});
        let diff = compute_diff(&repo, &server).unwrap();
        assert!(diff.changed);

        let redacted = render_human_diff(&diff, true);
        assert!(redacted.contains("(redacted)"));
        assert!(!redacted.contains("s3cret!"));

        let unredacted = render_human_diff(&diff, false);
        assert!(unredacted.contains("s3cret!"));
    }

    #[test]
    fn stable_ordering() {
        let repo = make_repo(|r| {
            r.env.insert("b".to_string(), "2".to_string());
            r.env.insert("a".to_string(), "1".to_string());
            r.health.path = Some("/healthz".to_string());
        });
        let server = make_server(|_| {});

        let diff1 = compute_diff(&repo, &server).unwrap();
        let diff2 = compute_diff(&repo, &server).unwrap();

        // Same input should produce identical patch
        let json1 = serde_json::to_string(&diff1.ops).unwrap();
        let json2 = serde_json::to_string(&diff2.ops).unwrap();
        assert_eq!(json1, json2, "diff should be deterministic");
    }

    #[test]
    fn build_update_payload_contains_env() {
        let repo = make_repo(|r| {
            r.env.insert("KEY".to_string(), "val".to_string());
        });
        let payload = build_update_payload(&repo);
        assert_eq!(payload["env"]["KEY"], "val");
    }

    #[test]
    fn build_update_payload_contains_health() {
        let repo = make_repo(|r| {
            r.health.path = Some("/healthz".to_string());
        });
        let payload = build_update_payload(&repo);
        assert_eq!(payload["health"]["path"], "/healthz");
    }

    #[test]
    fn build_update_payload_contains_deploy() {
        let repo = make_repo(|r| {
            r.deploy = Some(crate::repo_config::RepoDeployConfig {
                strategy: Some("blue-green".to_string()),
                drain_timeout: Some(std::time::Duration::from_secs(30)),
                timeout: None,
            });
        });
        let payload = build_update_payload(&repo);
        assert_eq!(payload["deploy"]["strategy"], "blue-green");
    }

    #[test]
    fn build_update_payload_contains_volumes() {
        let repo = make_repo(|r| {
            r.volumes = vec![RepoVolume {
                mount_path: "/app/data".to_string(),
                read_only: true,
            }];
        });
        let payload = build_update_payload(&repo);
        assert_eq!(payload["volumes"][0]["mount_path"], "/app/data");
        assert_eq!(payload["volumes"][0]["read_only"], true);
    }

    #[test]
    fn build_create_payload_has_name() {
        let repo = make_repo(|r| {
            r.app.image = Some("ghcr.io/org/app:latest".to_string());
            r.routing.domain = Some("app.example.com".to_string());
        });
        let payload = build_create_payload(&repo).unwrap();
        assert_eq!(payload["name"], "testapp");
    }

    #[test]
    fn render_human_diff_empty() {
        let diff = ApplyDiff {
            schema: "slip.apply.diff/v1".to_string(),
            app: "testapp".to_string(),
            changed: false,
            ops: vec![],
            create: None,
            message: None,
            status: None,
        };
        let output = render_human_diff(&diff, true);
        assert_eq!(output, "no changes — up to date");
    }

    #[test]
    fn render_human_diff_shows_changes() {
        let diff = ApplyDiff {
            schema: "slip.apply.diff/v1".to_string(),
            app: "testapp".to_string(),
            changed: true,
            ops: vec![json_patch::PatchOperation::Replace(
                json_patch::ReplaceOperation {
                    path: "/port".to_string().try_into().unwrap(),
                    value: Value::Number(3000.into()),
                },
            )],
            create: None,
            message: None,
            status: None,
        };
        let output = render_human_diff(&diff, true);
        assert!(output.contains("~ /port"));
    }

    #[test]
    fn zero_port_normalized_to_none() {
        // Server port=0 should be treated as "unset" — no spurious diff
        let repo = make_repo(|r| {
            r.routing.port = None;
        });
        let server = make_server(|s| {
            s.port = 0;
        });
        let diff = compute_diff(&repo, &server).unwrap();
        assert!(!diff.changed, "port=0 should normalize to None");
    }

    #[test]
    fn empty_domain_normalized_to_none() {
        // Server domain="" should not cause spurious diffs
        let repo = make_repo(|_| {});
        let server = make_server(|s| {
            s.domain = String::new();
        });
        // domain is not in Pushable, so this should be no diff
        let diff = compute_diff(&repo, &server).unwrap();
        assert!(!diff.changed);
    }

    #[test]
    fn redacted_method_obscures_env_values() {
        let diff = ApplyDiff {
            schema: "slip.apply.diff/v1".to_string(),
            app: "testapp".to_string(),
            changed: true,
            ops: vec![
                json_patch::PatchOperation::Add(json_patch::AddOperation {
                    path: "/env/SECRET".to_string().try_into().unwrap(),
                    value: Value::String("s3cret!".to_string()),
                }),
                json_patch::PatchOperation::Replace(json_patch::ReplaceOperation {
                    path: "/env/OTHER".to_string().try_into().unwrap(),
                    value: Value::String("other_val".to_string()),
                }),
                json_patch::PatchOperation::Replace(json_patch::ReplaceOperation {
                    path: "/port".to_string().try_into().unwrap(),
                    value: Value::Number(3000.into()),
                }),
            ],
            create: None,
            message: None,
            status: None,
        };

        let redacted = diff.redacted();
        let json = serde_json::to_string(&redacted).unwrap();
        assert!(
            json.contains(r#""(redacted)""#),
            "redacted JSON should contain (redacted)"
        );
        assert!(
            !json.contains("s3cret!"),
            "redacted JSON should not contain raw env value"
        );
        assert!(
            !json.contains("other_val"),
            "redacted JSON should not contain other env value"
        );
        // Non-env ops should be unchanged
        assert!(json.contains("3000"), "non-env ops should be unchanged");
    }

    #[test]
    fn build_create_payload_missing_image_errors() {
        let repo = make_repo(|_| {});
        let result = build_create_payload(&repo);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.contains("[app] image"),
            "error should mention [app] image"
        );
    }

    #[test]
    fn build_create_payload_missing_domain_errors() {
        let repo = make_repo(|r| {
            r.app.image = Some("ghcr.io/org/app:latest".to_string());
        });
        let result = build_create_payload(&repo);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.contains("[routing] domain"),
            "error should mention [routing] domain"
        );
    }

    #[test]
    fn build_create_payload_with_image_and_domain_succeeds() {
        let repo = make_repo(|r| {
            r.app.image = Some("ghcr.io/org/app:latest".to_string());
            r.routing.domain = Some("app.example.com".to_string());
        });
        let payload = build_create_payload(&repo).unwrap();
        assert_eq!(payload["name"], "testapp");
        assert_eq!(payload["image"], "ghcr.io/org/app:latest");
        assert_eq!(payload["domain"], "app.example.com");
    }

    #[test]
    fn image_and_domain_in_diff() {
        let repo = make_repo(|r| {
            r.app.image = Some("ghcr.io/org/app:v2".to_string());
            r.routing.domain = Some("new.example.com".to_string());
        });
        let server = make_server(|s| {
            s.image = "ghcr.io/org/app:v1".to_string();
            s.domain = "old.example.com".to_string();
        });
        let diff = compute_diff(&repo, &server).unwrap();
        assert!(diff.changed);
        assert!(diff.ops.iter().any(|op| {
            matches!(op, json_patch::PatchOperation::Replace(r) if r.path == "/image")
        }));
        assert!(diff.ops.iter().any(|op| {
            matches!(op, json_patch::PatchOperation::Replace(r) if r.path == "/domain")
        }));
    }
}
