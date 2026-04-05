//! Pod manifest rendering for `podman kube play`.
//!
//! Transforms a raw Kubernetes Pod YAML at deploy-time by applying five
//! mutations in order:
//!
//! 1. Set a versioned pod name (append `{pod_suffix}`).
//! 2. Update the primary container's image tag.
//! 3. Apply per-sidecar image overrides.
//! 4. Set `hostPort: 0` on every container port (ephemeral port assignment).
//! 5. Inject env vars (no-clobber; creates `env` array if absent).

use std::collections::HashMap;

use serde_yaml::Value;

/// Context for rendering a pod manifest.
pub struct RenderContext {
    /// The app name (e.g., `"stat-stream"`).
    pub app_name: String,
    /// The image tag being deployed (e.g., `"abc123"`).
    pub tag: String,
    /// The primary container image base (e.g., `"ghcr.io/org/stat-stream"`).
    pub primary_image: String,
    /// Unique pod name suffix (lowercased ULID fragment, e.g., `"01abc"`).
    pub pod_suffix: String,
    /// Server secrets to inject as env vars (`KEY=VALUE` pairs).
    pub env_vars: Vec<String>,
    /// Optional image overrides for sidecars: `container_name → full image:tag`.
    pub image_overrides: HashMap<String, String>,
}

/// Errors that can occur during manifest rendering.
#[derive(Debug, thiserror::Error)]
pub enum ManifestError {
    /// The input bytes could not be parsed as YAML.
    #[error("invalid YAML: {0}")]
    InvalidYaml(String),

    /// A field that must be present for rendering is absent.
    #[error("manifest missing required field: {0}")]
    MissingField(String),

    /// The resulting pod name exceeds the 63-character DNS label limit.
    #[error("pod name too long after suffix: {name} ({len} chars, max 63)")]
    NameTooLong { name: String, len: usize },
}

// ────────────────────────────────────────────────────────────────────────────
// Public API
// ────────────────────────────────────────────────────────────────────────────

/// Render a pod manifest with deploy-time transformations.
///
/// Applies the five standard transformations (versioned name, primary image
/// tag, sidecar overrides, ephemeral host ports, env-var injection) and
/// returns the mutated YAML as a `String`.
pub fn render_manifest(raw_yaml: &[u8], ctx: &RenderContext) -> Result<String, ManifestError> {
    let mut doc: Value =
        serde_yaml::from_slice(raw_yaml).map_err(|e| ManifestError::InvalidYaml(e.to_string()))?;

    set_versioned_name(&mut doc, &ctx.pod_suffix)?;
    update_primary_image(&mut doc, &ctx.primary_image, &ctx.tag);
    apply_sidecar_overrides(&mut doc, &ctx.image_overrides);
    set_host_ports_zero(&mut doc);
    inject_env_vars(&mut doc, &ctx.env_vars);

    serde_yaml::to_string(&doc).map_err(|e| ManifestError::InvalidYaml(e.to_string()))
}

// ────────────────────────────────────────────────────────────────────────────
// Transformation 1 — versioned pod name
// ────────────────────────────────────────────────────────────────────────────

fn set_versioned_name(doc: &mut Value, pod_suffix: &str) -> Result<(), ManifestError> {
    let name = doc
        .get_mut("metadata")
        .and_then(|m| m.get_mut("name"))
        .ok_or_else(|| ManifestError::MissingField("metadata.name".to_string()))?;

    let base = name
        .as_str()
        .ok_or_else(|| ManifestError::MissingField("metadata.name (must be a string)".to_string()))?
        .to_owned();

    let versioned = format!("{base}-{pod_suffix}");
    let len = versioned.len();
    if len > 63 {
        return Err(ManifestError::NameTooLong {
            name: versioned,
            len,
        });
    }

    *name = Value::String(versioned);
    Ok(())
}

// ────────────────────────────────────────────────────────────────────────────
// Transformation 2 — primary container image tag
// ────────────────────────────────────────────────────────────────────────────

fn update_primary_image(doc: &mut Value, primary_image: &str, tag: &str) {
    if let Some(containers) = get_containers_mut(doc) {
        for container in containers {
            if let Some(image_val) = container.get_mut("image")
                && let Some(image_str) = image_val.as_str()
                && image_base(image_str) == primary_image
            {
                *image_val = Value::String(format!("{primary_image}:{tag}"));
                break;
            }
        }
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Transformation 3 — sidecar image overrides
// ────────────────────────────────────────────────────────────────────────────

fn apply_sidecar_overrides(doc: &mut Value, overrides: &HashMap<String, String>) {
    if overrides.is_empty() {
        return;
    }

    for containers in all_container_lists_mut(doc) {
        for container in containers {
            let name = container
                .get("name")
                .and_then(|n| n.as_str())
                .map(|s| s.to_owned());

            if let Some(name) = name
                && let Some(new_image) = overrides.get(&name)
                && let Some(image_val) = container.get_mut("image")
            {
                *image_val = Value::String(new_image.clone());
            }
        }
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Transformation 4 — set hostPort: 0 on all container ports
// ────────────────────────────────────────────────────────────────────────────

fn set_host_ports_zero(doc: &mut Value) {
    for containers in all_container_lists_mut(doc) {
        for container in containers {
            if let Some(ports) = container.get_mut("ports").and_then(|p| p.as_sequence_mut()) {
                for port in ports {
                    if let Some(map) = port.as_mapping_mut() {
                        map.insert(
                            Value::String("hostPort".to_string()),
                            Value::Number(serde_yaml::Number::from(0u64)),
                        );
                    }
                }
            }
        }
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Transformation 5 — inject env vars (no-clobber)
// ────────────────────────────────────────────────────────────────────────────

fn inject_env_vars(doc: &mut Value, env_vars: &[String]) {
    if env_vars.is_empty() {
        return;
    }

    // Parse the KEY=VALUE pairs once.
    let parsed: Vec<(&str, &str)> = env_vars
        .iter()
        .filter_map(|kv| {
            let mut parts = kv.splitn(2, '=');
            let key = parts.next()?;
            let val = parts.next().unwrap_or("");
            Some((key, val))
        })
        .collect();

    for containers in all_container_lists_mut(doc) {
        for container in containers {
            // Gather existing keys so we can skip duplicates.
            let existing_keys: Vec<String> = container
                .get("env")
                .and_then(|e| e.as_sequence())
                .map(|seq| {
                    seq.iter()
                        .filter_map(|entry| entry.get("name")?.as_str().map(|s| s.to_owned()))
                        .collect()
                })
                .unwrap_or_default();

            // Ensure the `env` array exists.
            if container.get("env").is_none()
                && let Some(map) = container.as_mapping_mut()
            {
                map.insert(Value::String("env".to_string()), Value::Sequence(vec![]));
            }

            if let Some(env_seq) = container.get_mut("env").and_then(|e| e.as_sequence_mut()) {
                for (key, val) in &parsed {
                    if existing_keys.iter().any(|k| k == key) {
                        continue;
                    }
                    let mut entry = serde_yaml::Mapping::new();
                    entry.insert(
                        Value::String("name".to_string()),
                        Value::String(key.to_string()),
                    );
                    entry.insert(
                        Value::String("value".to_string()),
                        Value::String(val.to_string()),
                    );
                    env_seq.push(Value::Mapping(entry));
                }
            }
        }
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Helpers
// ────────────────────────────────────────────────────────────────────────────

/// Strip the image tag (`:tag`) returning only the base image reference.
///
/// ```text
/// "ghcr.io/org/app:latest" → "ghcr.io/org/app"
/// "ghcr.io/org/app"        → "ghcr.io/org/app"
/// ```
fn image_base(image: &str) -> &str {
    // Only strip after the last `/` segment to avoid stripping ports like
    // `registry:5000/img`.
    let slash_pos = image.rfind('/').map(|p| p + 1).unwrap_or(0);
    if let Some(colon_pos) = image[slash_pos..].find(':') {
        &image[..slash_pos + colon_pos]
    } else {
        image
    }
}

/// Return a mutable reference to `spec.containers` if present.
fn get_containers_mut(doc: &mut Value) -> Option<&mut Vec<Value>> {
    doc.get_mut("spec")?
        .get_mut("containers")?
        .as_sequence_mut()
}

/// Return mutable references to every container list in the document
/// (`spec.containers` and `spec.initContainers` when present).
///
/// We cannot return two `&mut` slices of the same parent simultaneously, so
/// we process each list key separately by index.
fn all_container_lists_mut(doc: &mut Value) -> Vec<&mut Vec<Value>> {
    let mut lists: Vec<&mut Vec<Value>> = Vec::new();

    // We need to navigate into `spec` once and then access both keys.
    // Using raw pointer gymnastics is unsafe; instead we split the work by
    // collecting the (safe) indices first, then mutating in two separate passes.
    //
    // Because Rust won't let us hold two `&mut` to the same mapping value, we
    // extract pointers and process each list independently.
    let spec = match doc.get_mut("spec").and_then(|s| s.as_mapping_mut()) {
        Some(m) => m as *mut serde_yaml::Mapping,
        None => return lists,
    };

    // SAFETY: We obtain two non-overlapping `&mut` to distinct keys inside the
    // same mapping.  The keys ("containers" vs "initContainers") are guaranteed
    // distinct, so no aliasing occurs.
    unsafe {
        if let Some(seq) = (*spec)
            .get_mut(Value::String("containers".to_string()))
            .and_then(|v| v.as_sequence_mut())
        {
            lists.push(seq);
        }
        if let Some(seq) = (*spec)
            .get_mut(Value::String("initContainers".to_string()))
            .and_then(|v| v.as_sequence_mut())
        {
            lists.push(seq);
        }
    }

    lists
}

// ────────────────────────────────────────────────────────────────────────────
// Tests
// ────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE: &str = r#"
apiVersion: v1
kind: Pod
metadata:
  name: stat-stream
  labels:
    app: stat-stream
spec:
  containers:
    - name: web
      image: ghcr.io/org/stat-stream:latest
      ports:
        - containerPort: 3000
          hostPort: 3000
      env:
        - name: EXISTING_VAR
          value: "keep-me"
    - name: redis
      image: redis:7-alpine
      ports:
        - containerPort: 6379
          hostPort: 6379
"#;

    fn base_ctx() -> RenderContext {
        RenderContext {
            app_name: "stat-stream".to_string(),
            tag: "abc123".to_string(),
            primary_image: "ghcr.io/org/stat-stream".to_string(),
            pod_suffix: "01abc".to_string(),
            env_vars: vec![],
            image_overrides: HashMap::new(),
        }
    }

    fn parse_output(yaml: &str) -> Value {
        serde_yaml::from_str(yaml).expect("output must be valid YAML")
    }

    fn get_containers(doc: &Value) -> &Vec<Value> {
        doc["spec"]["containers"]
            .as_sequence()
            .expect("spec.containers must be a sequence")
    }

    fn get_init_containers(doc: &Value) -> &Vec<Value> {
        doc["spec"]["initContainers"]
            .as_sequence()
            .expect("spec.initContainers must be a sequence")
    }

    // 1. Pod name gets the suffix appended.
    #[test]
    fn render_sets_versioned_pod_name() {
        let ctx = base_ctx();
        let yaml = render_manifest(FIXTURE.as_bytes(), &ctx).unwrap();
        let doc = parse_output(&yaml);
        assert_eq!(
            doc["metadata"]["name"].as_str().unwrap(),
            "stat-stream-01abc"
        );
    }

    // 2. Primary image tag is updated.
    #[test]
    fn render_updates_primary_image_tag() {
        let ctx = base_ctx();
        let yaml = render_manifest(FIXTURE.as_bytes(), &ctx).unwrap();
        let doc = parse_output(&yaml);
        let containers = get_containers(&doc);
        let web = containers
            .iter()
            .find(|c| c["name"].as_str() == Some("web"))
            .unwrap();
        assert_eq!(
            web["image"].as_str().unwrap(),
            "ghcr.io/org/stat-stream:abc123"
        );
    }

    // 3. Sidecar image is preserved when there is no override.
    #[test]
    fn render_preserves_sidecar_image() {
        let ctx = base_ctx();
        let yaml = render_manifest(FIXTURE.as_bytes(), &ctx).unwrap();
        let doc = parse_output(&yaml);
        let containers = get_containers(&doc);
        let redis = containers
            .iter()
            .find(|c| c["name"].as_str() == Some("redis"))
            .unwrap();
        assert_eq!(redis["image"].as_str().unwrap(), "redis:7-alpine");
    }

    // 4. Sidecar image is replaced when an override is provided.
    #[test]
    fn render_applies_sidecar_override() {
        let mut ctx = base_ctx();
        ctx.image_overrides
            .insert("redis".to_string(), "redis:8-alpine".to_string());
        let yaml = render_manifest(FIXTURE.as_bytes(), &ctx).unwrap();
        let doc = parse_output(&yaml);
        let containers = get_containers(&doc);
        let redis = containers
            .iter()
            .find(|c| c["name"].as_str() == Some("redis"))
            .unwrap();
        assert_eq!(redis["image"].as_str().unwrap(), "redis:8-alpine");
    }

    // 5. All hostPorts become 0.
    #[test]
    fn render_sets_host_port_zero() {
        let ctx = base_ctx();
        let yaml = render_manifest(FIXTURE.as_bytes(), &ctx).unwrap();
        let doc = parse_output(&yaml);
        let containers = get_containers(&doc);
        for container in containers {
            if let Some(ports) = container["ports"].as_sequence() {
                for port in ports {
                    assert_eq!(
                        port["hostPort"].as_u64().unwrap(),
                        0,
                        "hostPort must be 0 in container {:?}",
                        container["name"]
                    );
                }
            }
        }
    }

    // 6. New env vars are injected into all containers.
    #[test]
    fn render_injects_env_vars() {
        let mut ctx = base_ctx();
        ctx.env_vars = vec!["SECRET_KEY=hunter2".to_string(), "PORT=3000".to_string()];
        let yaml = render_manifest(FIXTURE.as_bytes(), &ctx).unwrap();
        let doc = parse_output(&yaml);
        let containers = get_containers(&doc);

        for container in containers {
            let env = container["env"].as_sequence().expect("env must exist");
            let has_secret = env.iter().any(|e| {
                e["name"].as_str() == Some("SECRET_KEY") && e["value"].as_str() == Some("hunter2")
            });
            let has_port = env
                .iter()
                .any(|e| e["name"].as_str() == Some("PORT") && e["value"].as_str() == Some("3000"));
            assert!(
                has_secret,
                "container {:?} missing SECRET_KEY",
                container["name"]
            );
            assert!(has_port, "container {:?} missing PORT", container["name"]);
        }
    }

    // 7. Pre-existing env vars are not overwritten.
    #[test]
    fn render_no_clobber_existing_env() {
        let mut ctx = base_ctx();
        ctx.env_vars = vec!["EXISTING_VAR=new-value".to_string()];
        let yaml = render_manifest(FIXTURE.as_bytes(), &ctx).unwrap();
        let doc = parse_output(&yaml);
        let containers = get_containers(&doc);
        let web = containers
            .iter()
            .find(|c| c["name"].as_str() == Some("web"))
            .unwrap();
        let env = web["env"].as_sequence().unwrap();
        let existing: Vec<_> = env
            .iter()
            .filter(|e| e["name"].as_str() == Some("EXISTING_VAR"))
            .collect();
        assert_eq!(existing.len(), 1, "EXISTING_VAR must appear exactly once");
        assert_eq!(existing[0]["value"].as_str().unwrap(), "keep-me");
    }

    // 8. Env array is created when the container has none.
    #[test]
    fn render_creates_env_array_if_missing() {
        let mut ctx = base_ctx();
        ctx.env_vars = vec!["NEW_VAR=hello".to_string()];
        let yaml = render_manifest(FIXTURE.as_bytes(), &ctx).unwrap();
        let doc = parse_output(&yaml);
        let containers = get_containers(&doc);
        // `redis` container has no `env` in the fixture.
        let redis = containers
            .iter()
            .find(|c| c["name"].as_str() == Some("redis"))
            .unwrap();
        let env = redis["env"]
            .as_sequence()
            .expect("env array must be created");
        let has_new = env.iter().any(|e| e["name"].as_str() == Some("NEW_VAR"));
        assert!(has_new, "NEW_VAR must be injected into redis container");
    }

    // 9. Name > 63 chars returns NameTooLong.
    #[test]
    fn render_name_too_long_errors() {
        // Build a manifest whose base name is already 60 chars.
        let long_name = "a".repeat(60);
        let yaml = format!(
            "apiVersion: v1\nkind: Pod\nmetadata:\n  name: {long_name}\nspec:\n  containers: []\n"
        );
        let mut ctx = base_ctx();
        ctx.pod_suffix = "toolong".to_string(); // 60 + 1 + 7 = 68 chars
        let result = render_manifest(yaml.as_bytes(), &ctx);
        assert!(
            matches!(result, Err(ManifestError::NameTooLong { .. })),
            "expected NameTooLong, got {:?}",
            result
        );
    }

    // 10. Missing metadata.name returns MissingField.
    #[test]
    fn render_missing_metadata_errors() {
        let yaml = "apiVersion: v1\nkind: Pod\nmetadata:\n  labels:\n    app: foo\nspec:\n  containers: []\n";
        let ctx = base_ctx();
        let result = render_manifest(yaml.as_bytes(), &ctx);
        assert!(
            matches!(result, Err(ManifestError::MissingField(_))),
            "expected MissingField, got {:?}",
            result
        );
    }

    // 11. Empty overrides and env vars work fine.
    #[test]
    fn render_empty_overrides_and_env() {
        let ctx = base_ctx(); // already has empty overrides and env
        let result = render_manifest(FIXTURE.as_bytes(), &ctx);
        assert!(
            result.is_ok(),
            "empty overrides/env should succeed: {:?}",
            result
        );
    }

    // 12. Labels, volumes, and other fields survive rendering.
    #[test]
    fn render_preserves_other_fields() {
        let ctx = base_ctx();
        let yaml = render_manifest(FIXTURE.as_bytes(), &ctx).unwrap();
        let doc = parse_output(&yaml);
        assert_eq!(
            doc["metadata"]["labels"]["app"].as_str().unwrap(),
            "stat-stream"
        );
        assert_eq!(doc["apiVersion"].as_str().unwrap(), "v1");
        assert_eq!(doc["kind"].as_str().unwrap(), "Pod");
    }

    // 13. Transformations apply to initContainers as well.
    #[test]
    fn render_handles_init_containers() {
        let init_fixture = r#"
apiVersion: v1
kind: Pod
metadata:
  name: stat-stream
spec:
  initContainers:
    - name: init-migrate
      image: ghcr.io/org/stat-stream:latest
      ports:
        - containerPort: 8080
          hostPort: 8080
  containers:
    - name: web
      image: ghcr.io/org/stat-stream:latest
      ports:
        - containerPort: 3000
          hostPort: 3000
"#;
        let mut ctx = base_ctx();
        ctx.env_vars = vec!["INIT_VAR=yes".to_string()];
        let yaml = render_manifest(init_fixture.as_bytes(), &ctx).unwrap();
        let doc = parse_output(&yaml);

        // hostPort 0 in initContainers
        let init_containers = get_init_containers(&doc);
        for container in init_containers {
            if let Some(ports) = container["ports"].as_sequence() {
                for port in ports {
                    assert_eq!(port["hostPort"].as_u64().unwrap(), 0);
                }
            }
        }

        // env var injected into initContainers
        let init_migrate = init_containers
            .iter()
            .find(|c| c["name"].as_str() == Some("init-migrate"))
            .unwrap();
        let env = init_migrate["env"]
            .as_sequence()
            .expect("env must exist in initContainer");
        assert!(env.iter().any(|e| e["name"].as_str() == Some("INIT_VAR")));
    }
}
