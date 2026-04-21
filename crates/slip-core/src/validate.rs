//! Validation module for slip.toml config files and pod manifests.
//!
//! Provides comprehensive validation for repo-side configuration including:
//! - TOML parsing with error location reporting
//! - Config field validation (app name, kind, manifest paths)
//! - Pod manifest YAML validation (K8s required fields)
//! - Container reference validation
//! - Preview configuration validation
//! - Image reference validation (strict mode)

use std::path::Path;

use serde_yaml::Value;

use crate::repo_config::{PreviewConfig, RepoConfig, parse_repo_config};

// ─── Error Types ──────────────────────────────────────────────────────────────

/// Errors that can occur during validation.
#[derive(Debug, Clone, thiserror::Error)]
pub enum ValidationError {
    /// TOML parse error with location information.
    #[error("TOML parse error at line {line}, column {column}: {message}")]
    TomlParse {
        message: String,
        line: usize,
        column: usize,
    },

    /// Pod manifest file not found.
    #[error("pod manifest not found: {path}")]
    ManifestNotFound { path: String },

    /// Pod manifest YAML parse error.
    #[error("pod manifest parse error: {message}")]
    ManifestParse { message: String },

    /// Required Kubernetes field missing from pod manifest.
    #[error("pod manifest missing required field: {field}")]
    ManifestMissingField { field: String },

    /// Pod manifest has wrong kind (not "Pod").
    #[error("pod manifest has invalid kind: expected '{expected}', got '{got}'")]
    ManifestInvalidKind { expected: String, got: String },

    /// Referenced container not found in pod manifest.
    #[error("container '{name}' not found in pod manifest{context}")]
    ContainerNotFound { name: String, context: String },

    /// Pod kind specified but no manifest path provided.
    #[error("kind is 'pod' but no manifest path specified")]
    MissingManifest,

    /// Invalid app name.
    #[error("invalid app name: {message}")]
    InvalidAppName { message: String },

    /// Preview configuration is inconsistent.
    #[error("preview configuration issue: {message}")]
    PreviewInconsistent { message: String },

    /// Invalid image reference (strict mode).
    #[error("invalid image reference '{image}': {reason}")]
    InvalidImageRef { image: String, reason: String },
}

// ─── Validation Result ────────────────────────────────────────────────────────

/// Accumulated validation results (errors and warnings).
#[derive(Debug, Clone, Default)]
pub struct ValidationResult {
    /// Validation errors (cause validation to fail).
    pub errors: Vec<ValidationError>,
    /// Validation warnings (do not cause failure).
    pub warnings: Vec<String>,
}

impl ValidationResult {
    /// Create a new empty validation result.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add an error to the result.
    pub fn add_error(&mut self, error: ValidationError) {
        self.errors.push(error);
    }

    /// Add a warning to the result.
    pub fn add_warning(&mut self, warning: String) {
        self.warnings.push(warning);
    }

    /// Check if validation passed (no errors).
    pub fn is_valid(&self) -> bool {
        self.errors.is_empty()
    }

    /// Merge another validation result into this one.
    pub fn merge(&mut self, other: ValidationResult) {
        self.errors.extend(other.errors);
        self.warnings.extend(other.warnings);
    }
}

// ─── Config Validation ────────────────────────────────────────────────────────

/// Validate a repo config.
///
/// Checks:
/// - If kind is "pod" and manifest is None → error
/// - If kind is "pod" and manifest is Some → check file exists
/// - If kind is "container" and manifest is Some → warning
/// - App name is not empty and is a valid DNS label
/// - Preview database strategy "branch" requires provider
/// - Preview enabled without routing.port → warning
pub fn validate_repo_config(config: &RepoConfig, base_dir: &Path) -> ValidationResult {
    let mut result = ValidationResult::new();

    // Validate app name
    validate_app_name(&config.app.name, &mut result);

    // Validate kind and manifest
    let kind = config.app.kind.to_lowercase();
    match kind.as_str() {
        "pod" => match &config.app.manifest {
            None => {
                result.add_error(ValidationError::MissingManifest);
            }
            Some(manifest_path) => {
                let full_path = base_dir.join(manifest_path);
                if !full_path.exists() {
                    result.add_error(ValidationError::ManifestNotFound {
                        path: manifest_path.clone(),
                    });
                }
            }
        },
        "container" if config.app.manifest.is_some() => {
            result.add_warning("manifest is ignored for container kind".to_string());
        }
        _ => {
            // Unknown kind - could warn, but for now just pass
        }
    }

    // Validate preview configuration
    if let Some(ref preview) = config.preview {
        validate_preview_config(preview, &config.routing, &mut result);
    }

    result
}

/// Validate app name is a valid DNS label.
fn validate_app_name(name: &str, result: &mut ValidationResult) {
    if name.is_empty() {
        result.add_error(ValidationError::InvalidAppName {
            message: "app name cannot be empty".to_string(),
        });
        return;
    }

    // DNS label: lowercase alphanumeric and hyphens, must start and end with alphanumeric
    let chars: Vec<char> = name.chars().collect();

    // Check first char
    if !chars[0].is_ascii_lowercase() && !chars[0].is_ascii_digit() {
        result.add_error(ValidationError::InvalidAppName {
            message: format!("'{name}' must start with a lowercase letter or digit"),
        });
        return;
    }

    // Check last char
    if let Some(&last) = chars.last()
        && !last.is_ascii_lowercase()
        && !last.is_ascii_digit()
    {
        result.add_error(ValidationError::InvalidAppName {
            message: format!("'{name}' must end with a lowercase letter or digit"),
        });
        return;
    }

    // Check all chars
    for &c in &chars {
        if !c.is_ascii_lowercase() && !c.is_ascii_digit() && c != '-' {
            result.add_error(ValidationError::InvalidAppName {
                message: format!(
                    "'{name}' contains invalid character '{c}'; \
                     only lowercase letters, digits, and hyphens are allowed"
                ),
            });
            return;
        }
    }

    // Check length (DNS labels max 63 chars)
    if name.len() > 63 {
        result.add_error(ValidationError::InvalidAppName {
            message: format!("'{name}' exceeds 63 character limit"),
        });
    }
}

/// Validate preview configuration.
fn validate_preview_config(
    preview: &PreviewConfig,
    routing: &crate::repo_config::RepoRoutingConfig,
    result: &mut ValidationResult,
) {
    // Check database strategy
    if let Some(ref db) = preview.database
        && db.strategy == "branch"
        && db.provider.is_none()
    {
        result.add_error(ValidationError::PreviewInconsistent {
            message: "preview database strategy 'branch' requires provider to be set".to_string(),
        });
    }

    // Warn if preview enabled but no routing port
    if preview.enabled && routing.port.is_none() {
        result.add_warning(
            "preview is enabled but no routing.port is specified; \
             previews may not be accessible"
                .to_string(),
        );
    }
}

// ─── Pod Manifest Validation ──────────────────────────────────────────────────

/// Validate a pod manifest YAML.
///
/// Checks:
/// - apiVersion exists
/// - kind == "Pod" (warn if different)
/// - metadata.name exists
/// - spec.containers exists and is non-empty
/// - routing.container references valid container (if set)
/// - health.container references valid container (if set)
pub fn validate_pod_manifest(yaml_bytes: &[u8], config: &RepoConfig) -> ValidationResult {
    let mut result = ValidationResult::new();

    let doc: Value = match serde_yaml::from_slice(yaml_bytes) {
        Ok(doc) => doc,
        Err(e) => {
            result.add_error(ValidationError::ManifestParse {
                message: e.to_string(),
            });
            return result;
        }
    };

    // Check apiVersion
    if doc.get("apiVersion").is_none() {
        result.add_error(ValidationError::ManifestMissingField {
            field: "apiVersion".to_string(),
        });
    }

    // Check kind
    if let Some(kind_val) = doc.get("kind") {
        if let Some(kind_str) = kind_val.as_str() {
            if kind_str != "Pod" {
                result.add_error(ValidationError::ManifestInvalidKind {
                    expected: "Pod".to_string(),
                    got: kind_str.to_string(),
                });
            }
        } else {
            result.add_error(ValidationError::ManifestMissingField {
                field: "kind (must be a string)".to_string(),
            });
        }
    } else {
        result.add_error(ValidationError::ManifestMissingField {
            field: "kind".to_string(),
        });
    }

    // Check metadata.name
    let has_metadata_name = doc.get("metadata").and_then(|m| m.get("name")).is_some();
    if !has_metadata_name {
        result.add_error(ValidationError::ManifestMissingField {
            field: "metadata.name".to_string(),
        });
    }

    // Check spec.containers
    let containers = doc
        .get("spec")
        .and_then(|s| s.get("containers"))
        .and_then(|c| c.as_sequence());

    match containers {
        None => {
            result.add_error(ValidationError::ManifestMissingField {
                field: "spec.containers".to_string(),
            });
        }
        Some(containers) if containers.is_empty() => {
            result.add_error(ValidationError::ManifestMissingField {
                field: "spec.containers (must be non-empty)".to_string(),
            });
        }
        Some(_) => {}
    }

    // Extract container names for reference validation
    let container_names: Vec<String> = containers
        .iter()
        .flat_map(|seq| seq.iter())
        .filter_map(|c| c.get("name")?.as_str().map(|s| s.to_string()))
        .collect();

    // Validate routing.container reference
    if let Some(ref container_name) = config.routing.container
        && !container_names.contains(container_name)
    {
        result.add_error(ValidationError::ContainerNotFound {
            name: container_name.clone(),
            context: " (referenced in routing.container)".to_string(),
        });
    }

    // Validate health.container reference
    if let Some(ref container_name) = config.health.container
        && !container_names.contains(container_name)
    {
        result.add_error(ValidationError::ContainerNotFound {
            name: container_name.clone(),
            context: " (referenced in health.container)".to_string(),
        });
    }

    result
}

// ─── Image Reference Validation ──────────────────────────────────────────────

/// Validate image references in pod manifest (strict mode).
///
/// Checks:
/// - Each container has a well-formed image reference
/// - Warns about `:latest` tag usage
pub fn validate_image_refs(yaml_bytes: &[u8]) -> ValidationResult {
    let mut result = ValidationResult::new();

    let doc: Value = match serde_yaml::from_slice(yaml_bytes) {
        Ok(doc) => doc,
        Err(e) => {
            result.add_error(ValidationError::ManifestParse {
                message: e.to_string(),
            });
            return result;
        }
    };

    // Get all container lists (containers and initContainers)
    let spec = match doc.get("spec") {
        Some(s) => s,
        None => return result,
    };

    for list_key in ["containers", "initContainers"] {
        if let Some(containers) = spec.get(list_key).and_then(|c| c.as_sequence()) {
            for container in containers {
                if let Some(image_val) = container.get("image") {
                    if let Some(image) = image_val.as_str() {
                        validate_single_image_ref(image, &mut result);
                    } else {
                        result.add_error(ValidationError::InvalidImageRef {
                            image: "non-string".to_string(),
                            reason: "image must be a string".to_string(),
                        });
                    }
                }
                // Missing image is not an error here - could be validated separately
            }
        }
    }

    result
}

/// Validate a single image reference.
fn validate_single_image_ref(image: &str, result: &mut ValidationResult) {
    // Check empty
    if image.is_empty() {
        result.add_error(ValidationError::InvalidImageRef {
            image: image.to_string(),
            reason: "image reference cannot be empty".to_string(),
        });
        return;
    }

    // Basic validation: must have at least a name
    // Image format: [registry/][namespace/]name[:tag][@digest]
    let image_without_digest = image.split('@').next().unwrap_or(image);
    let image_without_tag = image_without_digest.split(':').next().unwrap_or(image);

    // The name part should be non-empty
    let name_part = image_without_tag
        .rsplit('/')
        .next()
        .unwrap_or(image_without_tag);

    if name_part.is_empty() {
        result.add_error(ValidationError::InvalidImageRef {
            image: image.to_string(),
            reason: "image reference must include an image name".to_string(),
        });
        return;
    }

    // Warn about :latest tag (explicit or implicit via no tag)
    let has_digest = image.contains('@');
    let has_tag = image_without_digest.contains(':');
    if image.contains(":latest") || image.ends_with(':') {
        result.add_warning(format!(
            "image '{image}' uses ':latest' tag; consider pinning to a specific version"
        ));
    } else if !has_tag && !has_digest {
        result.add_warning(format!(
            "image '{image}' has no tag (implies :latest); consider pinning to a specific version"
        ));
    }
}

// ─── Convenience Function ─────────────────────────────────────────────────────

/// Parse and validate a slip.toml file.
///
/// This is the main entry point for the CLI. It:
/// 1. Parses the TOML content
/// 2. Validates the config
/// 3. Validates the pod manifest if applicable
/// 4. Runs strict validation if enabled
///
/// Returns the parsed config (if successful) and the validation result.
pub fn parse_and_validate(
    toml_content: &str,
    base_dir: &Path,
    strict: bool,
) -> (Option<RepoConfig>, ValidationResult) {
    let mut result = ValidationResult::new();

    // Parse TOML
    let config = match parse_repo_config(toml_content.as_bytes()) {
        Ok(config) => config,
        Err(e) => {
            // Extract line/column from toml error
            let (line, col) = extract_toml_error_location(&e);
            result.add_error(ValidationError::TomlParse {
                message: e.to_string(),
                line,
                column: col,
            });
            return (None, result);
        }
    };

    // Validate config
    let config_result = validate_repo_config(&config, base_dir);
    result.merge(config_result);

    // Validate pod manifest if applicable
    if config.app.kind.to_lowercase() == "pod"
        && let Some(ref manifest_path) = config.app.manifest
    {
        let full_path = base_dir.join(manifest_path);
        if let Ok(yaml_bytes) = std::fs::read(&full_path) {
            let manifest_result = validate_pod_manifest(&yaml_bytes, &config);
            result.merge(manifest_result);

            // Strict mode: validate image refs
            if strict && result.is_valid() {
                let image_result = validate_image_refs(&yaml_bytes);
                result.merge(image_result);
            }
        }
        // If file doesn't exist, error already added by validate_repo_config
    }

    (Some(config), result)
}

/// Extract line and column from a toml::de::Error.
fn extract_toml_error_location(e: &toml::de::Error) -> (usize, usize) {
    // toml errors have line/col info in their Display output
    // Format: "TOML parse error at line X, column Y"
    let msg = e.to_string();

    // Try to parse line number
    let line = if let Some(line_start) = msg.find("line ") {
        let rest = &msg[line_start + 5..];
        let num_str: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
        num_str.parse().unwrap_or(1)
    } else {
        1
    };

    // Try to parse column number
    let col = if let Some(col_start) = msg.find("column ") {
        let rest = &msg[col_start + 7..];
        let num_str: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
        num_str.parse().unwrap_or(1)
    } else {
        1
    };

    (line, col)
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    // 1. valid_minimal_config — minimal [app] section passes
    #[test]
    fn valid_minimal_config() {
        let temp = TempDir::new().unwrap();
        let toml = r#"
[app]
name = "myapp"
"#;
        let (config, result) = parse_and_validate(toml, temp.path(), false);
        assert!(result.is_valid(), "errors: {:?}", result.errors);
        assert!(config.is_some());
        let cfg = config.unwrap();
        assert_eq!(cfg.app.name, "myapp");
        assert_eq!(cfg.app.kind, "container");
    }

    // 2. valid_pod_config_with_manifest — use tempfile/tempdir for manifest file
    #[test]
    fn valid_pod_config_with_manifest() {
        let temp = TempDir::new().unwrap();
        let manifest_content = r#"
apiVersion: v1
kind: Pod
metadata:
  name: myapp
spec:
  containers:
    - name: web
      image: myapp:latest
"#;
        let manifest_path = temp.path().join("pod.yaml");
        fs::write(&manifest_path, manifest_content).unwrap();

        let toml = r#"
[app]
name = "myapp"
kind = "pod"
manifest = "pod.yaml"
"#;
        let (config, result) = parse_and_validate(toml, temp.path(), false);
        assert!(
            result.is_valid(),
            "errors: {:?}, warnings: {:?}",
            result.errors,
            result.warnings
        );
        assert!(config.is_some());
    }

    // 3. pod_kind_without_manifest_errors — kind=pod, no manifest → error
    #[test]
    fn pod_kind_without_manifest_errors() {
        let temp = TempDir::new().unwrap();
        let toml = r#"
[app]
name = "myapp"
kind = "pod"
"#;
        let (_, result) = parse_and_validate(toml, temp.path(), false);
        assert!(!result.is_valid());
        assert!(
            result
                .errors
                .iter()
                .any(|e| matches!(e, ValidationError::MissingManifest))
        );
    }

    // 4. container_kind_with_manifest_warns — kind=container with manifest → warning
    #[test]
    fn container_kind_with_manifest_warns() {
        let temp = TempDir::new().unwrap();
        let toml = r#"
[app]
name = "myapp"
kind = "container"
manifest = "pod.yaml"
"#;
        let (_, result) = parse_and_validate(toml, temp.path(), false);
        assert!(result.is_valid());
        assert!(
            result
                .warnings
                .iter()
                .any(|w| w.contains("manifest is ignored"))
        );
    }

    // 5. manifest_not_found_errors — pod kind, manifest path doesn't exist
    #[test]
    fn manifest_not_found_errors() {
        let temp = TempDir::new().unwrap();
        let toml = r#"
[app]
name = "myapp"
kind = "pod"
manifest = "nonexistent.yaml"
"#;
        let (_, result) = parse_and_validate(toml, temp.path(), false);
        assert!(!result.is_valid());
        assert!(
            result
                .errors
                .iter()
                .any(|e| matches!(e, ValidationError::ManifestNotFound { .. }))
        );
    }

    // 6. manifest_invalid_yaml_errors — garbage YAML
    #[test]
    fn manifest_invalid_yaml_errors() {
        let temp = TempDir::new().unwrap();
        let manifest_content = "this is not valid yaml: [[[";
        let manifest_path = temp.path().join("pod.yaml");
        fs::write(&manifest_path, manifest_content).unwrap();

        let toml = r#"
[app]
name = "myapp"
kind = "pod"
manifest = "pod.yaml"
"#;
        let (_, result) = parse_and_validate(toml, temp.path(), false);
        assert!(!result.is_valid());
        assert!(
            result
                .errors
                .iter()
                .any(|e| matches!(e, ValidationError::ManifestParse { .. }))
        );
    }

    // 7. manifest_wrong_kind_errors — kind=Deployment instead of Pod
    #[test]
    fn manifest_wrong_kind_errors() {
        let temp = TempDir::new().unwrap();
        let manifest_content = r#"
apiVersion: apps/v1
kind: Deployment
metadata:
  name: myapp
spec:
  containers:
    - name: web
      image: myapp:latest
"#;
        let manifest_path = temp.path().join("pod.yaml");
        fs::write(&manifest_path, manifest_content).unwrap();

        let toml = r#"
[app]
name = "myapp"
kind = "pod"
manifest = "pod.yaml"
"#;
        let (_, result) = parse_and_validate(toml, temp.path(), false);
        assert!(!result.is_valid());
        assert!(
            result
                .errors
                .iter()
                .any(|e| matches!(e, ValidationError::ManifestInvalidKind { .. }))
        );
    }

    // 8. manifest_missing_containers_errors — no spec.containers
    #[test]
    fn manifest_missing_containers_errors() {
        let temp = TempDir::new().unwrap();
        let manifest_content = r#"
apiVersion: v1
kind: Pod
metadata:
  name: myapp
spec: {}
"#;
        let manifest_path = temp.path().join("pod.yaml");
        fs::write(&manifest_path, manifest_content).unwrap();

        let toml = r#"
[app]
name = "myapp"
kind = "pod"
manifest = "pod.yaml"
"#;
        let (_, result) = parse_and_validate(toml, temp.path(), false);
        assert!(!result.is_valid());
        assert!(
            result
                .errors
                .iter()
                .any(|e| matches!(e, ValidationError::ManifestMissingField { .. }))
        );
    }

    // 9. container_name_not_found_errors — routing.container references non-existent container
    #[test]
    fn container_name_not_found_errors() {
        let temp = TempDir::new().unwrap();
        let manifest_content = r#"
apiVersion: v1
kind: Pod
metadata:
  name: myapp
spec:
  containers:
    - name: web
      image: myapp:latest
"#;
        let manifest_path = temp.path().join("pod.yaml");
        fs::write(&manifest_path, manifest_content).unwrap();

        let toml = r#"
[app]
name = "myapp"
kind = "pod"
manifest = "pod.yaml"

[routing]
container = "api"
"#;
        let (_, result) = parse_and_validate(toml, temp.path(), false);
        assert!(!result.is_valid());
        assert!(
            result
                .errors
                .iter()
                .any(|e| matches!(e, ValidationError::ContainerNotFound { .. }))
        );
    }

    // 10. preview_branch_without_provider_errors — database strategy=branch but no provider
    #[test]
    fn preview_branch_without_provider_errors() {
        let temp = TempDir::new().unwrap();
        let toml = r#"
[app]
name = "myapp"

[preview]
enabled = true

[preview.database]
strategy = "branch"
"#;
        let (_, result) = parse_and_validate(toml, temp.path(), false);
        assert!(!result.is_valid());
        assert!(
            result
                .errors
                .iter()
                .any(|e| matches!(e, ValidationError::PreviewInconsistent { .. }))
        );
    }

    // 11. strict_mode_catches_latest_tag — warns about :latest
    #[test]
    fn strict_mode_catches_latest_tag() {
        let temp = TempDir::new().unwrap();
        let manifest_content = r#"
apiVersion: v1
kind: Pod
metadata:
  name: myapp
spec:
  containers:
    - name: web
      image: myapp:latest
"#;
        let manifest_path = temp.path().join("pod.yaml");
        fs::write(&manifest_path, manifest_content).unwrap();

        let toml = r#"
[app]
name = "myapp"
kind = "pod"
manifest = "pod.yaml"
"#;
        let (_, result) = parse_and_validate(toml, temp.path(), true);
        assert!(result.is_valid()); // warnings don't fail validation
        assert!(result.warnings.iter().any(|w| w.contains(":latest")));
    }

    // 12. invalid_app_name_errors — app name with spaces/uppercase
    #[test]
    fn invalid_app_name_errors() {
        let temp = TempDir::new().unwrap();
        let toml = r#"
[app]
name = "My App"
"#;
        let (_, result) = parse_and_validate(toml, temp.path(), false);
        assert!(!result.is_valid());
        assert!(
            result
                .errors
                .iter()
                .any(|e| matches!(e, ValidationError::InvalidAppName { .. }))
        );
    }

    // 13. toml_parse_error_has_location — bad TOML reports line/column
    #[test]
    fn toml_parse_error_has_location() {
        let temp = TempDir::new().unwrap();
        let bad_toml = r#"
[app
name = "myapp"
"#;
        let (_, result) = parse_and_validate(bad_toml, temp.path(), false);
        assert!(!result.is_valid());
        match result.errors.first() {
            Some(ValidationError::TomlParse { line, column, .. }) => {
                assert!(*line > 0);
                assert!(*column > 0);
            }
            _ => panic!("expected TomlParse error"),
        }
    }
}
