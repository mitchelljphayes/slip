//! Preview deployment state types.
//!
//! A "preview" is an ephemeral container/pod deployment for a pull request or
//! branch. Each preview has a unique ID, a subdomain, and an optional TTL.

use std::path::PathBuf;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::deploy::AppStatus;

// ─── Core state types ─────────────────────────────────────────────────────────

/// Full in-memory state for a single preview deployment.
///
/// This is stored in `AppState::preview_states` keyed by `"{app}:{preview_id}"`.
#[derive(Debug, Clone)]
pub struct PreviewState {
    /// Unique preview identifier (e.g. "pr-42", "feature-foo").
    pub preview_id: String,
    /// App name (matches an entry in `AppState::apps`).
    pub app: String,
    /// Git commit SHA associated with this preview.
    pub sha: String,
    /// Current lifecycle status.
    pub status: AppStatus,
    /// Running container ID (for container-mode previews).
    pub container_id: Option<String>,
    /// Pod name (for pod-mode previews).
    pub pod_name: Option<String>,
    /// Host port the container is listening on.
    pub port: Option<u16>,
    /// Image tag deployed.
    pub tag: Option<String>,
    /// When this preview was first deployed.
    pub deployed_at: DateTime<Utc>,
    /// When this preview expires (None = no expiry).
    pub expires_at: Option<DateTime<Utc>>,
    /// Fully-qualified preview domain (e.g. "pr-42.preview.example.com").
    pub domain: String,
    /// Path to the rendered pod manifest (pod-mode only).
    pub manifest_path: Option<PathBuf>,
    /// Current deploy ID (transient — not persisted).
    pub deploy_id: Option<String>,
}

/// Serde-serializable subset of [`PreviewState`] for on-disk persistence.
///
/// Omits transient fields (`deploy_id`) that are not meaningful across restarts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistedPreviewState {
    pub preview_id: String,
    pub app: String,
    pub sha: String,
    pub container_id: Option<String>,
    pub pod_name: Option<String>,
    pub port: Option<u16>,
    pub tag: Option<String>,
    pub deployed_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub domain: String,
    #[serde(default)]
    pub manifest_path: Option<PathBuf>,
}

// ─── Conversions ──────────────────────────────────────────────────────────────

impl From<&PreviewState> for PersistedPreviewState {
    fn from(s: &PreviewState) -> Self {
        Self {
            preview_id: s.preview_id.clone(),
            app: s.app.clone(),
            sha: s.sha.clone(),
            container_id: s.container_id.clone(),
            pod_name: s.pod_name.clone(),
            port: s.port,
            tag: s.tag.clone(),
            deployed_at: s.deployed_at,
            expires_at: s.expires_at,
            domain: s.domain.clone(),
            manifest_path: s.manifest_path.clone(),
        }
    }
}

impl From<PersistedPreviewState> for PreviewState {
    fn from(p: PersistedPreviewState) -> Self {
        // Infer status from available identifiers.
        let status = if p.container_id.is_some() || p.pod_name.is_some() {
            AppStatus::Running
        } else {
            AppStatus::NotDeployed
        };
        Self {
            preview_id: p.preview_id,
            app: p.app,
            sha: p.sha,
            status,
            container_id: p.container_id,
            pod_name: p.pod_name,
            port: p.port,
            tag: p.tag,
            deployed_at: p.deployed_at,
            expires_at: p.expires_at,
            domain: p.domain,
            manifest_path: p.manifest_path,
            deploy_id: None,
        }
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn sample_preview_state() -> PreviewState {
        PreviewState {
            preview_id: "pr-42".to_string(),
            app: "myapp".to_string(),
            sha: "abc123def456".to_string(),
            status: AppStatus::Running,
            container_id: Some("ctr-abc123".to_string()),
            pod_name: None,
            port: Some(54321),
            tag: Some("sha-abc123".to_string()),
            deployed_at: Utc::now(),
            expires_at: None,
            domain: "pr-42.preview.example.com".to_string(),
            manifest_path: None,
            deploy_id: Some("dep_transient".to_string()),
        }
    }

    #[test]
    fn test_preview_state_to_persisted_omits_deploy_id() {
        let state = sample_preview_state();
        let persisted = PersistedPreviewState::from(&state);

        assert_eq!(persisted.preview_id, "pr-42");
        assert_eq!(persisted.app, "myapp");
        assert_eq!(persisted.sha, "abc123def456");
        assert_eq!(persisted.container_id.as_deref(), Some("ctr-abc123"));
        assert_eq!(persisted.port, Some(54321));
        assert_eq!(persisted.domain, "pr-42.preview.example.com");

        // deploy_id is NOT in PersistedPreviewState — compile-time guarantee.
    }

    #[test]
    fn test_persisted_to_preview_state_infers_status_running() {
        let persisted = PersistedPreviewState {
            preview_id: "pr-1".to_string(),
            app: "app".to_string(),
            sha: "sha1".to_string(),
            container_id: Some("ctr-xyz".to_string()),
            pod_name: None,
            port: Some(9000),
            tag: Some("v1".to_string()),
            deployed_at: Utc::now(),
            expires_at: None,
            domain: "pr-1.preview.example.com".to_string(),
            manifest_path: None,
        };

        let state = PreviewState::from(persisted);
        assert_eq!(state.status, AppStatus::Running);
        assert!(
            state.deploy_id.is_none(),
            "deploy_id must be None after load"
        );
    }

    #[test]
    fn test_persisted_to_preview_state_infers_status_not_deployed() {
        let persisted = PersistedPreviewState {
            preview_id: "pr-2".to_string(),
            app: "app".to_string(),
            sha: "sha2".to_string(),
            container_id: None,
            pod_name: None,
            port: None,
            tag: None,
            deployed_at: Utc::now(),
            expires_at: None,
            domain: "pr-2.preview.example.com".to_string(),
            manifest_path: None,
        };

        let state = PreviewState::from(persisted);
        assert_eq!(state.status, AppStatus::NotDeployed);
    }

    #[test]
    fn test_round_trip_preserves_key_fields() {
        let original = sample_preview_state();
        let persisted = PersistedPreviewState::from(&original);
        let restored = PreviewState::from(persisted);

        assert_eq!(restored.preview_id, original.preview_id);
        assert_eq!(restored.app, original.app);
        assert_eq!(restored.sha, original.sha);
        assert_eq!(restored.container_id, original.container_id);
        assert_eq!(restored.port, original.port);
        assert_eq!(restored.tag, original.tag);
        assert_eq!(restored.domain, original.domain);
        // deploy_id is transient and not persisted
        assert!(restored.deploy_id.is_none());
    }

    #[test]
    fn test_persisted_preview_state_serializes_to_json() {
        let state = sample_preview_state();
        let persisted = PersistedPreviewState::from(&state);

        let json = serde_json::to_string(&persisted).expect("should serialize");
        let deserialized: PersistedPreviewState =
            serde_json::from_str(&json).expect("should deserialize");

        assert_eq!(deserialized.preview_id, "pr-42");
        assert_eq!(deserialized.container_id.as_deref(), Some("ctr-abc123"));
    }
}
