//! Pod manifest rendering for `podman kube play`.
//!
//! Transforms a raw Kubernetes Pod YAML at deploy-time by applying seven
//! mutations in order:
//!
//! 1. Set a versioned pod name (append `{pod_suffix}`).
//! 2. Resolve `${tag}` placeholders in all container image fields.
//! 3. Update the primary container's image tag.
//! 4. Apply per-sidecar image overrides.
//! 5. Set `hostPort: 0` on every container port (ephemeral port assignment).
//! 6. Inject env vars (no-clobber; creates `env` array if absent).
//! 7. Inject host-path volumes (no-clobber; skips on name/mount-path collision).

use std::collections::HashMap;

use serde_yaml::Value;

use crate::merge::MergedVolume;

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
    /// Host-path volumes to inject into the pod manifest.
    pub volumes: Vec<MergedVolume>,
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
/// Applies the seven standard transformations (versioned name, `${tag}`
/// placeholder resolution, primary image tag, sidecar overrides, ephemeral
/// host ports, env-var injection, volume injection) and returns the mutated
/// YAML as a `String`.
pub fn render_manifest(raw_yaml: &[u8], ctx: &RenderContext) -> Result<String, ManifestError> {
    let mut doc: Value =
        serde_yaml::from_slice(raw_yaml).map_err(|e| ManifestError::InvalidYaml(e.to_string()))?;

    set_versioned_name(&mut doc, &ctx.pod_suffix)?;
    resolve_tag_placeholders(&mut doc, &ctx.tag);
    update_primary_image(&mut doc, &ctx.primary_image, &ctx.tag);
    apply_sidecar_overrides(&mut doc, &ctx.image_overrides);
    set_host_ports_zero(&mut doc);
    inject_env_vars(&mut doc, &ctx.env_vars);
    inject_volumes(&mut doc, ctx);

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
// Transformation 2 — ${tag} placeholder resolution
// ────────────────────────────────────────────────────────────────────────────

/// Replace `${tag}` with the actual tag in all container image fields.
///
/// This runs BEFORE `update_primary_image()` and `apply_sidecar_overrides()`,
/// so overrides take precedence over placeholder resolution.
fn resolve_tag_placeholders(doc: &mut Value, tag: &str) {
    for containers in all_container_lists_mut(doc) {
        for container in containers {
            if let Some(image_val) = container.get_mut("image")
                && let Some(image_str) = image_val.as_str()
                && image_str.contains("${tag}")
            {
                let resolved = image_str.replace("${tag}", tag);
                *image_val = Value::String(resolved);
            }
        }
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Transformation 3 — primary container image tag
// ────────────────────────────────────────────────────────────────────────────

fn update_primary_image(doc: &mut Value, primary_image: &str, tag: &str) {
    for containers in all_container_lists_mut(doc) {
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
// Transformation 6 — inject host-path volumes (no-clobber)
// ────────────────────────────────────────────────────────────────────────────

/// Sanitize a mount path into a DNS-label-safe volume name.
///
/// Format: `slip-{app_name}-{sanitized-mount-path}`
///
/// The sanitized path strips leading `/`, replaces remaining `/` with `-`,
/// removes non-DNS-label characters, deduplicates consecutive hyphens, and
/// truncates to 63 chars (ensuring it ends with alphanumeric).
fn sanitize_volume_name(app_name: &str, mount_path: &str) -> String {
    let sanitized: String = mount_path
        .trim_start_matches('/')
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '.' {
                c.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect();

    // Deduplicate consecutive hyphens
    let deduped: String = sanitized.chars().fold(String::new(), |mut acc, c| {
        if c == '-' && acc.ends_with('-') {
            // skip
        } else {
            acc.push(c);
        }
        acc
    });

    let name = format!("slip-{app_name}-{deduped}");

    // Truncate to 63 chars, ensuring it ends with alphanumeric
    if name.len() <= 63 {
        name
    } else {
        let mut truncated: String = name.chars().take(63).collect();
        // Trim trailing hyphens/dots
        while truncated.len() > 1 && truncated.ends_with(|c: char| !c.is_ascii_alphanumeric()) {
            truncated.pop();
        }
        truncated
    }
}

/// Inject host-path volumes into the pod manifest.
///
/// For each volume in `ctx.volumes`:
/// - Generates a DNS-label-safe volume name.
/// - Checks for name collision with existing `spec.volumes` → skip with warning.
/// - Checks for mount path collision in any container's `volumeMounts` → skip.
/// - Appends to `spec.volumes` with `hostPath.type: DirectoryOrCreate`.
/// - Appends `volumeMounts` entry to every container (including initContainers).
fn inject_volumes(doc: &mut Value, ctx: &RenderContext) {
    if ctx.volumes.is_empty() {
        return;
    }

    // Collect existing volume names from spec.volumes.
    let existing_volume_names: Vec<String> = doc
        .get("spec")
        .and_then(|s| s.get("volumes"))
        .and_then(|v| v.as_sequence())
        .map(|seq| {
            seq.iter()
                .filter_map(|entry| entry.get("name")?.as_str().map(|s| s.to_owned()))
                .collect()
        })
        .unwrap_or_default();

    // Collect existing mount paths from all containers' volumeMounts.
    let existing_mount_paths: Vec<String> = {
        let mut paths = Vec::new();
        for containers in all_container_lists_mut(doc) {
            for container in containers.iter() {
                if let Some(mounts) = container.get("volumeMounts").and_then(|m| m.as_sequence()) {
                    for mount in mounts {
                        if let Some(path) = mount.get("mountPath").and_then(|p| p.as_str()) {
                            paths.push(path.to_owned());
                        }
                    }
                }
            }
        }
        paths
    };

    for vol in &ctx.volumes {
        let vol_name = sanitize_volume_name(&ctx.app_name, &vol.mount_path);

        // Check name collision with existing volumes.
        if existing_volume_names.contains(&vol_name) {
            tracing::warn!(
                volume_name = %vol_name,
                mount_path = %vol.mount_path,
                "skipping volume injection: name collision with existing volume"
            );
            continue;
        }

        // Check mount path collision in any container.
        if existing_mount_paths.contains(&vol.mount_path) {
            tracing::warn!(
                mount_path = %vol.mount_path,
                "skipping volume injection: mount path collision with existing volumeMount"
            );
            continue;
        }

        // Ensure spec.volumes array exists.
        if doc.get("spec").and_then(|s| s.get("volumes")).is_none()
            && let Some(spec) = doc.get_mut("spec").and_then(|s| s.as_mapping_mut())
        {
            spec.insert(
                Value::String("volumes".to_string()),
                Value::Sequence(vec![]),
            );
        }

        // Append to spec.volumes.
        if let Some(volumes_seq) = doc
            .get_mut("spec")
            .and_then(|s| s.get_mut("volumes"))
            .and_then(|v| v.as_sequence_mut())
        {
            let mut volume_entry = serde_yaml::Mapping::new();
            volume_entry.insert(
                Value::String("name".to_string()),
                Value::String(vol_name.clone()),
            );
            let mut host_path_entry = serde_yaml::Mapping::new();
            host_path_entry.insert(
                Value::String("path".to_string()),
                Value::String(vol.host_path.clone()),
            );
            host_path_entry.insert(
                Value::String("type".to_string()),
                Value::String("DirectoryOrCreate".to_string()),
            );
            volume_entry.insert(
                Value::String("hostPath".to_string()),
                Value::Mapping(host_path_entry),
            );
            volumes_seq.push(Value::Mapping(volume_entry));
        }

        // Append volumeMounts to every container (including initContainers).
        for containers in all_container_lists_mut(doc) {
            for container in containers.iter_mut() {
                // Ensure volumeMounts array exists.
                if container.get("volumeMounts").is_none()
                    && let Some(map) = container.as_mapping_mut()
                {
                    map.insert(
                        Value::String("volumeMounts".to_string()),
                        Value::Sequence(vec![]),
                    );
                }

                if let Some(mounts_seq) = container
                    .get_mut("volumeMounts")
                    .and_then(|m| m.as_sequence_mut())
                {
                    let mut mount_entry = serde_yaml::Mapping::new();
                    mount_entry.insert(
                        Value::String("name".to_string()),
                        Value::String(vol_name.clone()),
                    );
                    mount_entry.insert(
                        Value::String("mountPath".to_string()),
                        Value::String(vol.mount_path.clone()),
                    );
                    mount_entry.insert(
                        Value::String("readOnly".to_string()),
                        Value::Bool(vol.read_only),
                    );
                    mounts_seq.push(Value::Mapping(mount_entry));
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
            volumes: Vec::new(),
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

        // init container image should also be updated (Phase 1 fix)
        assert_eq!(
            init_migrate["image"].as_str().unwrap(),
            "ghcr.io/org/stat-stream:abc123",
            "init container image should be updated by update_primary_image"
        );
    }

    // ── Volume injection tests ────────────────────────────────────────────────

    #[test]
    fn inject_volumes_adds_to_empty_manifest() {
        let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: myapp
spec:
  containers:
    - name: web
      image: myapp:latest
"#;
        let mut doc: Value = serde_yaml::from_str(yaml).unwrap();
        let ctx = RenderContext {
            app_name: "myapp".to_string(),
            tag: "abc".to_string(),
            primary_image: "myapp".to_string(),
            pod_suffix: "xyz".to_string(),
            env_vars: vec![],
            image_overrides: HashMap::new(),
            volumes: vec![MergedVolume {
                host_path: "/data/myapp".to_string(),
                mount_path: "/app/data".to_string(),
                read_only: false,
            }],
        };
        inject_volumes(&mut doc, &ctx);

        // spec.volumes should exist with one entry
        let volumes = doc["spec"]["volumes"]
            .as_sequence()
            .expect("volumes should exist");
        assert_eq!(volumes.len(), 1);
        assert_eq!(volumes[0]["name"].as_str().unwrap(), "slip-myapp-app-data");
        assert_eq!(
            volumes[0]["hostPath"]["path"].as_str().unwrap(),
            "/data/myapp"
        );
        assert_eq!(
            volumes[0]["hostPath"]["type"].as_str().unwrap(),
            "DirectoryOrCreate"
        );

        // volumeMounts should exist on the container
        let container = &doc["spec"]["containers"][0];
        let mounts = container["volumeMounts"]
            .as_sequence()
            .expect("volumeMounts should exist");
        assert_eq!(mounts.len(), 1);
        assert_eq!(mounts[0]["name"].as_str().unwrap(), "slip-myapp-app-data");
        assert_eq!(mounts[0]["mountPath"].as_str().unwrap(), "/app/data");
        assert!(!mounts[0]["readOnly"].as_bool().unwrap());
    }

    #[test]
    fn inject_volumes_appends_to_existing() {
        let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: myapp
spec:
  volumes:
    - name: existing-vol
      hostPath:
        path: /data/existing
        type: Directory
  containers:
    - name: web
      image: myapp:latest
      volumeMounts:
        - name: existing-vol
          mountPath: /data/existing
"#;
        let mut doc: Value = serde_yaml::from_str(yaml).unwrap();
        let ctx = RenderContext {
            app_name: "myapp".to_string(),
            tag: "abc".to_string(),
            primary_image: "myapp".to_string(),
            pod_suffix: "xyz".to_string(),
            env_vars: vec![],
            image_overrides: HashMap::new(),
            volumes: vec![MergedVolume {
                host_path: "/data/new".to_string(),
                mount_path: "/data/new".to_string(),
                read_only: true,
            }],
        };
        inject_volumes(&mut doc, &ctx);

        // Should have 2 volumes (existing + new)
        let volumes = doc["spec"]["volumes"]
            .as_sequence()
            .expect("volumes should exist");
        assert_eq!(volumes.len(), 2);
        assert_eq!(volumes[0]["name"].as_str().unwrap(), "existing-vol");
        assert_eq!(volumes[1]["name"].as_str().unwrap(), "slip-myapp-data-new");

        // Container should have 2 volumeMounts
        let container = &doc["spec"]["containers"][0];
        let mounts = container["volumeMounts"]
            .as_sequence()
            .expect("volumeMounts should exist");
        assert_eq!(mounts.len(), 2);
    }

    #[test]
    fn inject_volumes_skips_name_collision() {
        let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: myapp
spec:
  volumes:
    - name: slip-myapp-app-data
      hostPath:
        path: /data/user
        type: Directory
  containers:
    - name: web
      image: myapp:latest
      volumeMounts:
        - name: slip-myapp-app-data
          mountPath: /app/data
"#;
        let mut doc: Value = serde_yaml::from_str(yaml).unwrap();
        let ctx = RenderContext {
            app_name: "myapp".to_string(),
            tag: "abc".to_string(),
            primary_image: "myapp".to_string(),
            pod_suffix: "xyz".to_string(),
            env_vars: vec![],
            image_overrides: HashMap::new(),
            volumes: vec![MergedVolume {
                host_path: "/data/slip".to_string(),
                mount_path: "/app/data".to_string(),
                read_only: false,
            }],
        };
        inject_volumes(&mut doc, &ctx);

        // Should still have only 1 volume (user's wins)
        let volumes = doc["spec"]["volumes"]
            .as_sequence()
            .expect("volumes should exist");
        assert_eq!(volumes.len(), 1);
        assert_eq!(
            volumes[0]["hostPath"]["path"].as_str().unwrap(),
            "/data/user"
        );
    }

    #[test]
    fn inject_volumes_skips_mount_path_collision() {
        let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: myapp
spec:
  volumes:
    - name: user-vol
      hostPath:
        path: /data/user
        type: Directory
  containers:
    - name: web
      image: myapp:latest
      volumeMounts:
        - name: user-vol
          mountPath: /app/data
"#;
        let mut doc: Value = serde_yaml::from_str(yaml).unwrap();
        let ctx = RenderContext {
            app_name: "myapp".to_string(),
            tag: "abc".to_string(),
            primary_image: "myapp".to_string(),
            pod_suffix: "xyz".to_string(),
            env_vars: vec![],
            image_overrides: HashMap::new(),
            volumes: vec![MergedVolume {
                host_path: "/data/slip".to_string(),
                mount_path: "/app/data".to_string(), // same mount path
                read_only: false,
            }],
        };
        inject_volumes(&mut doc, &ctx);

        // Should still have only 1 volume (user's wins)
        let volumes = doc["spec"]["volumes"]
            .as_sequence()
            .expect("volumes should exist");
        assert_eq!(volumes.len(), 1);
    }

    #[test]
    fn inject_volumes_read_only_true() {
        let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: myapp
spec:
  containers:
    - name: web
      image: myapp:latest
"#;
        let mut doc: Value = serde_yaml::from_str(yaml).unwrap();
        let ctx = RenderContext {
            app_name: "myapp".to_string(),
            tag: "abc".to_string(),
            primary_image: "myapp".to_string(),
            pod_suffix: "xyz".to_string(),
            env_vars: vec![],
            image_overrides: HashMap::new(),
            volumes: vec![MergedVolume {
                host_path: "/data/config".to_string(),
                mount_path: "/app/config".to_string(),
                read_only: true,
            }],
        };
        inject_volumes(&mut doc, &ctx);

        let container = &doc["spec"]["containers"][0];
        let mount = &container["volumeMounts"][0];
        assert!(mount["readOnly"].as_bool().unwrap());
    }

    #[test]
    fn inject_volumes_host_path_type() {
        let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: myapp
spec:
  containers:
    - name: web
      image: myapp:latest
"#;
        let mut doc: Value = serde_yaml::from_str(yaml).unwrap();
        let ctx = RenderContext {
            app_name: "myapp".to_string(),
            tag: "abc".to_string(),
            primary_image: "myapp".to_string(),
            pod_suffix: "xyz".to_string(),
            env_vars: vec![],
            image_overrides: HashMap::new(),
            volumes: vec![MergedVolume {
                host_path: "/data/myapp".to_string(),
                mount_path: "/app/data".to_string(),
                read_only: false,
            }],
        };
        inject_volumes(&mut doc, &ctx);

        let vol = &doc["spec"]["volumes"][0];
        assert_eq!(
            vol["hostPath"]["type"].as_str().unwrap(),
            "DirectoryOrCreate"
        );
    }

    #[test]
    fn inject_volumes_init_containers() {
        let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: myapp
spec:
  initContainers:
    - name: init-setup
      image: busybox:latest
  containers:
    - name: web
      image: myapp:latest
"#;
        let mut doc: Value = serde_yaml::from_str(yaml).unwrap();
        let ctx = RenderContext {
            app_name: "myapp".to_string(),
            tag: "abc".to_string(),
            primary_image: "myapp".to_string(),
            pod_suffix: "xyz".to_string(),
            env_vars: vec![],
            image_overrides: HashMap::new(),
            volumes: vec![MergedVolume {
                host_path: "/data/myapp".to_string(),
                mount_path: "/app/data".to_string(),
                read_only: false,
            }],
        };
        inject_volumes(&mut doc, &ctx);

        // initContainer should have volumeMounts
        let init_container = &doc["spec"]["initContainers"][0];
        let init_mounts = init_container["volumeMounts"]
            .as_sequence()
            .expect("initContainer should have volumeMounts");
        assert_eq!(init_mounts.len(), 1);
        assert_eq!(
            init_mounts[0]["name"].as_str().unwrap(),
            "slip-myapp-app-data"
        );

        // regular container should also have volumeMounts
        let container = &doc["spec"]["containers"][0];
        let mounts = container["volumeMounts"]
            .as_sequence()
            .expect("container should have volumeMounts");
        assert_eq!(mounts.len(), 1);
    }

    #[test]
    fn sanitize_volume_name_formats_correctly() {
        assert_eq!(
            sanitize_volume_name("myapp", "/app/data"),
            "slip-myapp-app-data"
        );
        assert_eq!(
            sanitize_volume_name("my-app", "/var/lib/data"),
            "slip-my-app-var-lib-data"
        );
        assert_eq!(sanitize_volume_name("a", "/"), "slip-a-");
        // Long path should be truncated
        let long_path = format!("/{}", "a".repeat(100));
        let name = sanitize_volume_name("myapp", &long_path);
        assert!(name.len() <= 63);
        assert!(name.ends_with(|c: char| c.is_ascii_alphanumeric()));
    }

    // ── ${tag} placeholder tests ──────────────────────────────────────────────

    #[test]
    fn tag_placeholder_resolved_in_primary_container() {
        let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: myapp
spec:
  containers:
    - name: web
      image: ghcr.io/org/myapp:${tag}
"#;
        let mut doc: Value = serde_yaml::from_str(yaml).unwrap();
        resolve_tag_placeholders(&mut doc, "v1.2.3");
        let container = &doc["spec"]["containers"][0];
        assert_eq!(
            container["image"].as_str().unwrap(),
            "ghcr.io/org/myapp:v1.2.3"
        );
    }

    #[test]
    fn tag_placeholder_resolved_in_init_container() {
        let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: myapp
spec:
  initContainers:
    - name: init-setup
      image: ghcr.io/org/myapp:${tag}
  containers:
    - name: web
      image: ghcr.io/org/myapp:latest
"#;
        let mut doc: Value = serde_yaml::from_str(yaml).unwrap();
        resolve_tag_placeholders(&mut doc, "abc123");
        let init_container = &doc["spec"]["initContainers"][0];
        assert_eq!(
            init_container["image"].as_str().unwrap(),
            "ghcr.io/org/myapp:abc123"
        );
        // Regular container should be unchanged (no ${tag})
        let container = &doc["spec"]["containers"][0];
        assert_eq!(
            container["image"].as_str().unwrap(),
            "ghcr.io/org/myapp:latest"
        );
    }

    #[test]
    fn tag_placeholder_resolved_in_sidecar() {
        let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: myapp
spec:
  containers:
    - name: web
      image: ghcr.io/org/myapp:latest
    - name: redis
      image: redis:${tag}
"#;
        let mut doc: Value = serde_yaml::from_str(yaml).unwrap();
        resolve_tag_placeholders(&mut doc, "7-alpine");
        let redis = &doc["spec"]["containers"][1];
        assert_eq!(redis["image"].as_str().unwrap(), "redis:7-alpine");
    }

    #[test]
    fn tag_placeholder_override_wins_over_placeholder() {
        // ${tag} is resolved first, then sidecar override replaces it.
        let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: myapp
spec:
  containers:
    - name: web
      image: ghcr.io/org/myapp:${tag}
    - name: redis
      image: redis:${tag}
"#;
        let mut doc: Value = serde_yaml::from_str(yaml).unwrap();
        // Simulate the full pipeline: resolve_tag_placeholders then apply_sidecar_overrides
        resolve_tag_placeholders(&mut doc, "7-alpine");
        let mut overrides = HashMap::new();
        overrides.insert("redis".to_string(), "redis:8-alpine".to_string());
        apply_sidecar_overrides(&mut doc, &overrides);
        // redis should have the override (8-alpine), not the placeholder-resolved value
        let redis = &doc["spec"]["containers"][1];
        assert_eq!(redis["image"].as_str().unwrap(), "redis:8-alpine");
        // web should have the placeholder-resolved value
        let web = &doc["spec"]["containers"][0];
        assert_eq!(web["image"].as_str().unwrap(), "ghcr.io/org/myapp:7-alpine");
    }

    #[test]
    fn tag_placeholder_noop_when_not_present() {
        let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: myapp
spec:
  containers:
    - name: web
      image: ghcr.io/org/myapp:latest
"#;
        let mut doc: Value = serde_yaml::from_str(yaml).unwrap();
        resolve_tag_placeholders(&mut doc, "v1.0.0");
        let container = &doc["spec"]["containers"][0];
        assert_eq!(
            container["image"].as_str().unwrap(),
            "ghcr.io/org/myapp:latest"
        );
    }

    #[test]
    fn tag_placeholder_integration_with_render_manifest() {
        // Full pipeline: ${tag} in primary, init, and sidecar
        let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: myapp
spec:
  initContainers:
    - name: init-migrate
      image: ghcr.io/org/myapp:${tag}
  containers:
    - name: web
      image: ghcr.io/org/myapp:${tag}
    - name: redis
      image: redis:${tag}
"#;
        let ctx = RenderContext {
            app_name: "myapp".to_string(),
            tag: "v2.0.0".to_string(),
            primary_image: "ghcr.io/org/myapp".to_string(),
            pod_suffix: "xyz".to_string(),
            env_vars: vec![],
            image_overrides: HashMap::new(),
            volumes: Vec::new(),
        };
        let result = render_manifest(yaml.as_bytes(), &ctx).unwrap();
        let doc = parse_output(&result);

        // Primary container: ${tag} resolved, then update_primary_image sets it
        let web = &doc["spec"]["containers"][0];
        assert_eq!(web["image"].as_str().unwrap(), "ghcr.io/org/myapp:v2.0.0");

        // Init container: ${tag} resolved, then update_primary_image sets it
        let init = &doc["spec"]["initContainers"][0];
        assert_eq!(init["image"].as_str().unwrap(), "ghcr.io/org/myapp:v2.0.0");

        // Sidecar: ${tag} resolved (no override, so stays as resolved)
        let redis = &doc["spec"]["containers"][1];
        assert_eq!(redis["image"].as_str().unwrap(), "redis:v2.0.0");
    }
}
