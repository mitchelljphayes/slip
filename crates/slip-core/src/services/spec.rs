//! Service spec, state, provider trait, and version representation.
//!
//! The `ServiceSpec` is the exportable desired state -- it maps directly to a
//! future `[services.<name>]` manifest block. `ServiceState` is internal
//! control/observed state that is never exported. The `ServiceProvider` trait
//! is object-safe, following the same boxed-future convention as
//! `RuntimeBackend`.
//!
//! Part 1 defines only the domain contracts and persistence foundation. The
//! PostgreSQL image catalog, version normalization, and concrete provider
//! implementation belong to Part 3 and are intentionally absent here.

use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::runtime::RuntimeBackend;
use crate::services::name::ServiceName;

// ─── Provider kind ────────────────────────────────────────────────────────────

/// Closed enum of supported service providers.
///
/// Serialized as the lowercase string `"postgres"` -- this is the `type`
/// field in a future `[services.<name>]` manifest. Adding a provider is a code
/// change; arbitrary provider input is rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProviderKind {
    Postgres,
}

impl ProviderKind {
    /// Parse a provider kind from its lowercase string form.
    pub fn parse(s: &str) -> Result<Self, ServiceError> {
        match s {
            "postgres" => Ok(Self::Postgres),
            other => Err(ServiceError::UnknownProvider(other.to_string())),
        }
    }

    /// The lowercase string used in manifests and the `services.provider` column.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Postgres => "postgres",
        }
    }
}

// ─── Provider version (generic bounded representation) ────────────────────────

/// A bounded, validated provider version string.
///
/// Part 1 stores only a generic bounded version label (e.g. `"18.4"`). The
/// PostgreSQL-specific image catalog, digest resolution, and version
/// normalization belong to Part 3.
///
/// Valid forms: dotted numeric with at least one dot (e.g. `"18.4"`,
/// `"18.4.1"`), 3-32 bytes, ASCII digits and dots only, must start and end
/// with a digit, no consecutive dots. A bare major like `"18"` is rejected
/// to match the SQLite CHECK constraint which requires a dotted form.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ProviderVersion(String);

impl ProviderVersion {
    /// Parse and validate a provider version string.
    pub fn parse(input: &str) -> Result<Self, ServiceError> {
        let s = input.trim();
        if s.is_empty() {
            return Err(ServiceError::InvalidVersion("empty version".to_string()));
        }
        if s.len() < 3 || s.len() > 32 {
            return Err(ServiceError::InvalidVersion(format!(
                "version length {} out of range [3, 32]: '{s}'",
                s.len()
            )));
        }
        if !s.chars().all(|c| c.is_ascii_digit() || c == '.') {
            return Err(ServiceError::InvalidVersion(format!(
                "version '{s}' must be dotted numeric (e.g. \"18.4\")"
            )));
        }
        if !s.starts_with(|c: char| c.is_ascii_digit())
            || !s.ends_with(|c: char| c.is_ascii_digit())
        {
            return Err(ServiceError::InvalidVersion(format!(
                "version '{s}' must start and end with a digit"
            )));
        }
        if !s.contains('.') {
            return Err(ServiceError::InvalidVersion(format!(
                "version '{s}' must contain at least one dot (e.g. \"18.4\")"
            )));
        }
        if s.contains("..") {
            return Err(ServiceError::InvalidVersion(format!(
                "version '{s}' must not contain consecutive dots"
            )));
        }
        let major_str = s.split('.').next().unwrap_or(s);
        let major: i64 = major_str
            .parse()
            .map_err(|_| ServiceError::InvalidVersion(format!("bad major '{major_str}'")))?;
        if major <= 0 || major >= 100_000 {
            return Err(ServiceError::InvalidVersion(format!(
                "major {major} out of range (0, 100000)"
            )));
        }
        Ok(Self(s.to_string()))
    }

    /// Return the validated version as a `&str`.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Extract the major version number (first segment before any dot).
    pub fn major(&self) -> i64 {
        let major_str = self.0.split('.').next().unwrap_or(&self.0);
        major_str.parse().unwrap_or(0)
    }
}

impl TryFrom<String> for ProviderVersion {
    type Error = ServiceError;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(&value)
    }
}

impl From<ProviderVersion> for String {
    fn from(v: ProviderVersion) -> String {
        v.0
    }
}

// ─── Validated opaque newtypes for persisted state ────────────────────────────

/// A random 128-bit instance ID (exactly 32 lowercase hex chars), generated
/// via CSPRNG. Identifies a single data instance across reattach cycles.
/// Truncated, uppercase, or non-CSPRNG IDs are rejected.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct InstanceId(String);

impl InstanceId {
    /// Generate a new random instance ID using the fallible CSPRNG.
    /// No panic fallback -- a CSPRNG failure returns `Err`.
    pub fn generate() -> Result<Self, ServiceError> {
        let mut buf = [0u8; 16];
        getrandom::getrandom(&mut buf)
            .map_err(|e| ServiceError::Internal(format!("csprng failure: {e}")))?;
        Ok(Self(hex::encode(buf)))
    }

    /// Parse and validate an existing instance ID.
    /// Must be exactly 32 lowercase hex characters.
    pub fn parse(s: &str) -> Result<Self, ServiceError> {
        if s.len() != 32 {
            return Err(ServiceError::Internal(format!(
                "instance_id length {} (expected exactly 32)",
                s.len()
            )));
        }
        if !s
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        {
            return Err(ServiceError::Internal(
                "instance_id must be lowercase hexadecimal".to_string(),
            ));
        }
        Ok(Self(s.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// An opaque secret reference bound to a specific service instance. This is
/// NOT a secret value -- it is a structured path reference into the filesystem
/// secrets store. The canonical format is `service/<instance-id>/<purpose>`
/// where `instance-id` is the 32-char hex InstanceId and `purpose` is a
/// short alphanumeric label. This binds the reference to the instance identity
/// and rejects arbitrary secret values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretRef {
    instance_id: String,
    purpose: String,
}

/// Allowed purposes for service secrets. Closed set prevents arbitrary keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretPurpose {
    Superuser,
}

impl SecretPurpose {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Superuser => "superuser",
        }
    }

    pub fn parse(s: &str) -> Result<Self, ServiceError> {
        match s {
            "superuser" => Ok(Self::Superuser),
            other => Err(ServiceError::Internal(format!(
                "unknown secret purpose '{other}'"
            ))),
        }
    }
}

impl SecretRef {
    /// Construct a `SecretRef` bound to a specific instance and purpose.
    /// The reference is canonical: `service/<instance-id>/<purpose>`.
    pub fn new(instance_id: &InstanceId, purpose: SecretPurpose) -> Self {
        Self {
            instance_id: instance_id.as_str().to_string(),
            purpose: purpose.as_str().to_string(),
        }
    }

    /// Parse and validate a secret reference. Must match the canonical
    /// `service/<instance-id>/<purpose>` format. Rejects raw secret values,
    /// path traversal, and references not bound to an instance.
    pub fn parse(s: &str) -> Result<Self, ServiceError> {
        if s.len() < 10 || s.len() > 256 {
            return Err(ServiceError::Internal(format!(
                "secret_ref length {} out of range [10, 256]",
                s.len()
            )));
        }
        let rest = s.strip_prefix("service/").ok_or_else(|| {
            ServiceError::Internal("secret_ref must start with 'service/'".to_string())
        })?;
        let parts: Vec<&str> = rest.splitn(2, '/').collect();
        if parts.len() != 2 {
            return Err(ServiceError::Internal(
                "secret_ref must be 'service/<instance-id>/<purpose>'".to_string(),
            ));
        }
        let instance_id_str = parts[0];
        let purpose_str = parts[1];
        InstanceId::parse(instance_id_str)?;
        SecretPurpose::parse(purpose_str)?;
        if s.contains("..") {
            return Err(ServiceError::Internal(
                "secret_ref must not contain path traversal".to_string(),
            ));
        }
        Ok(Self {
            instance_id: instance_id_str.to_string(),
            purpose: purpose_str.to_string(),
        })
    }

    pub fn as_str(&self) -> String {
        format!("service/{}/{}", self.instance_id, self.purpose)
    }

    /// The instance ID this reference is bound to.
    pub fn instance_id(&self) -> &str {
        &self.instance_id
    }

    /// The purpose of this secret reference.
    pub fn purpose(&self) -> &str {
        &self.purpose
    }
}

/// A full runtime container ID (exactly 64 lowercase hex chars for OCI
/// runtimes). Optional -- absent before the first create. Truncated IDs
/// are rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainerId(String);

impl ContainerId {
    /// Parse and validate a container ID.
    /// Must be exactly 64 lowercase hex characters.
    pub fn parse(s: &str) -> Result<Self, ServiceError> {
        if s.len() != 64 {
            return Err(ServiceError::Internal(format!(
                "container_id length {} (expected exactly 64)",
                s.len()
            )));
        }
        if !s
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        {
            return Err(ServiceError::Internal(
                "container_id must be lowercase hexadecimal".to_string(),
            ));
        }
        Ok(Self(s.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A SHA-256 spec hash (exactly 64 lowercase hex chars). Used for drift
/// detection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpecHash(String);

impl SpecHash {
    /// Parse and validate a spec hash. Must be exactly 64 lowercase hex chars.
    pub fn parse(s: &str) -> Result<Self, ServiceError> {
        if s.len() != 64 {
            return Err(ServiceError::Internal(format!(
                "spec_hash length {} (expected 64)",
                s.len()
            )));
        }
        if !s
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        {
            return Err(ServiceError::Internal(
                "spec_hash must be lowercase hexadecimal".to_string(),
            ));
        }
        Ok(Self(s.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A resolved image reference. Bounded, non-empty, no control characters.
/// Part 3 will enforce exact digest-pinned references; Part 1 only enforces
/// format bounds so persisted state cannot be arbitrary garbage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedImage(String);

impl ResolvedImage {
    /// Parse and validate a resolved image reference.
    /// Must be 1-512 bytes, ASCII printable, no control characters.
    pub fn parse(s: &str) -> Result<Self, ServiceError> {
        if s.is_empty() || s.len() > 512 {
            return Err(ServiceError::Internal(format!(
                "resolved_image length {} out of range [1, 512]",
                s.len()
            )));
        }
        if s.chars().any(|c| c.is_control()) {
            return Err(ServiceError::Internal(
                "resolved_image must not contain control characters".to_string(),
            ));
        }
        Ok(Self(s.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

// ─── Closed failure-code representation (F4) ──────────────────────────────────

/// A closed, allowlisted failure code persisted in `service_state.last_error`.
///
/// This replaces free-form error strings. Only allowlisted codes can be
/// persisted. Raw secret-bearing strings, runtime stderr, and arbitrary
/// operator text are unrepresentable. The canary test proves that no
/// free-form string can reach the DB, WAL, SHM, Debug, serde, or rendered
/// output.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureCode {
    /// Container creation failed.
    ProvisionFailed,
    /// Health check timed out.
    HealthTimeout,
    /// Ownership mismatch detected.
    OwnershipMismatch,
    /// Filesystem check failed.
    FilesystemCheck,
    /// Image pull failed.
    ImagePullFailed,
    /// Readiness check failed.
    ReadinessFailed,
    /// Internal error.
    Internal,
}

impl FailureCode {
    /// All valid failure codes as strings (for SQLite CHECK constraint).
    pub const ALL: &'static [&'static str] = &[
        "provision_failed",
        "health_timeout",
        "ownership_mismatch",
        "filesystem_check",
        "image_pull_failed",
        "readiness_failed",
        "internal",
    ];

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ProvisionFailed => "provision_failed",
            Self::HealthTimeout => "health_timeout",
            Self::OwnershipMismatch => "ownership_mismatch",
            Self::FilesystemCheck => "filesystem_check",
            Self::ImagePullFailed => "image_pull_failed",
            Self::ReadinessFailed => "readiness_failed",
            Self::Internal => "internal",
        }
    }

    /// Parse a failure code from its string form. Returns an explicit error
    /// for unknown values -- never silently coerces.
    pub fn parse(s: &str) -> Result<Self, ServiceError> {
        match s {
            "provision_failed" => Ok(Self::ProvisionFailed),
            "health_timeout" => Ok(Self::HealthTimeout),
            "ownership_mismatch" => Ok(Self::OwnershipMismatch),
            "filesystem_check" => Ok(Self::FilesystemCheck),
            "image_pull_failed" => Ok(Self::ImagePullFailed),
            "readiness_failed" => Ok(Self::ReadinessFailed),
            "internal" => Ok(Self::Internal),
            other => Err(ServiceError::Internal(format!(
                "unknown failure code '{other}'"
            ))),
        }
    }
}

// ─── Service spec ─────────────────────────────────────────────────────────────

/// Exportable desired service state.
///
/// Every field maps directly to a future `[services.<name>]` manifest block:
/// `name`, `provider` (serialized as `type`), `version`, and provider config.
/// This is the entire export source -- `slip server export` (SLIP-117) will be a
/// straight read of the `services` table, not a reconstruction from
/// containers. Secret values, container IDs, paths, and runtime status are
/// never part of this struct.
///
/// Fields are private and validated through the [`ServiceSpec::new`]
/// constructor. Serde deserialization goes through a private wire DTO with
/// `deny_unknown_fields` and then calls `ServiceSpec::new` for validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceSpec {
    name: ServiceName,
    provider: ProviderKind,
    version: ProviderVersion,
    config: PostgresConfig,
}

/// Private wire DTO for deserialization. Uses `deny_unknown_fields` to reject
/// unknown top-level fields (e.g. `password`), then converts to
/// `ServiceSpec` via `new()` for validation.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct ServiceSpecDto {
    name: ServiceName,
    #[serde(rename = "type")]
    provider: ProviderKind,
    version: ProviderVersion,
    #[serde(default)]
    config: PostgresConfig,
}

impl Serialize for ServiceSpec {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut s = serializer.serialize_struct("ServiceSpec", 4)?;
        s.serialize_field("name", &self.name)?;
        s.serialize_field("type", &self.provider)?;
        s.serialize_field("version", &self.version)?;
        s.serialize_field("config", &self.config)?;
        s.end()
    }
}

impl<'de> Deserialize<'de> for ServiceSpec {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let dto = ServiceSpecDto::deserialize(deserializer)?;
        ServiceSpec::new(dto.name, dto.provider, dto.version, dto.config)
            .map_err(serde::de::Error::custom)
    }
}

impl ServiceSpec {
    /// Construct a validated `ServiceSpec`.
    pub fn new(
        name: ServiceName,
        provider: ProviderKind,
        version: ProviderVersion,
        config: PostgresConfig,
    ) -> Result<Self, ServiceError> {
        Ok(Self {
            name,
            provider,
            version,
            config,
        })
    }

    pub fn name(&self) -> &ServiceName {
        &self.name
    }
    pub fn provider(&self) -> ProviderKind {
        self.provider
    }
    pub fn version(&self) -> &ProviderVersion {
        &self.version
    }
    pub fn config(&self) -> &PostgresConfig {
        &self.config
    }

    /// Compute the canonical effective spec hash used for drift detection.
    ///
    /// Uses a deterministic canonical JSON projection with a domain-separation
    /// prefix (`slip-service-spec-v1\0`). Object keys are recursively sorted.
    /// Returns `Err` on serialization failure -- never falls back to hashing
    /// an empty string.
    pub fn effective_hash(&self) -> Result<SpecHash, ServiceError> {
        let canonical = canonical_spec_json(self)
            .map_err(|e| ServiceError::Internal(format!("canonical serialization failed: {e}")))?;
        let mut hasher = Sha256::new();
        hasher.update(b"slip-service-spec-v1\x00");
        hasher.update(&canonical);
        Ok(SpecHash(hex::encode(hasher.finalize())))
    }
}

/// PostgreSQL provider config.
///
/// Today this is empty (the provider uses fixed, secure defaults). The struct
/// exists so future fields (e.g. custom memory limits) can be added without a
/// schema migration -- `config_json` in SQLite is a JSON blob.
/// `deny_unknown_fields` ensures unsupported configuration is rejected at
/// deserialization rather than silently discarded.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PostgresConfig {}

// ─── Service state ────────────────────────────────────────────────────────────

/// Internal control/observed state for a service. Never exported.
///
/// This is persisted in the `service_state` table. It deliberately has no
/// cascade FK to `services`: a normal removal deletes desired state but
/// retains this row (phase `retained`) so the data instance can be safely
/// recognized and reattached.
///
/// Fields are private and validated through constructors. The repository
/// validates again at the persistence boundary. The `secret_ref` is always
/// derived from the `instance_id` -- it is impossible to construct a state
/// where the secret reference points to a different instance.
#[derive(Debug, Clone)]
pub struct ServiceState {
    service_name: ServiceName,
    provider: ProviderKind,
    data_major: i64,
    version: ProviderVersion,
    instance_id: InstanceId,
    generation: i64,
    phase: LifecyclePhase,
    container_id: Option<ContainerId>,
    resolved_image: ResolvedImage,
    applied_spec_hash: Option<SpecHash>,
    secret_ref: SecretRef,
    health: Option<HealthKind>,
    last_error: Option<FailureCode>,
    last_checked_at: Option<DateTime<Utc>>,
    updated_at: DateTime<Utc>,
}

impl ServiceState {
    /// Construct a validated `ServiceState` for a new provisioning instance.
    ///
    /// Generates a fresh CSPRNG instance ID internally and derives the
    /// `SecretRef` from that same instance ID. The caller cannot supply an
    /// unrelated `SecretRef` -- the binding is enforced by construction.
    /// The generation starts at 1 and the phase is `Provisioning`.
    pub fn for_provisioning(
        service_name: ServiceName,
        provider: ProviderKind,
        version: ProviderVersion,
        resolved_image: ResolvedImage,
        now: DateTime<Utc>,
    ) -> Result<Self, ServiceError> {
        let data_major = version.major();
        if data_major <= 0 || data_major >= 100_000 {
            return Err(ServiceError::InvalidVersion(format!(
                "data_major {data_major} out of range (0, 100000)"
            )));
        }
        let instance_id = InstanceId::generate()?;
        let secret_ref = SecretRef::new(&instance_id, SecretPurpose::Superuser);
        Ok(Self {
            service_name,
            provider,
            data_major,
            version,
            instance_id,
            generation: 1,
            phase: LifecyclePhase::Provisioning,
            container_id: None,
            resolved_image,
            applied_spec_hash: None,
            secret_ref,
            health: None,
            last_error: None,
            last_checked_at: None,
            updated_at: now,
        })
    }

    /// Construct a `ServiceState` from validated components. Used by the
    /// repository when reconstructing state from the database. Enforces
    /// that `secret_ref.instance_id() == instance_id` -- the secret reference
    /// must be bound to the same instance.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_validated(
        service_name: ServiceName,
        provider: ProviderKind,
        data_major: i64,
        version: ProviderVersion,
        instance_id: InstanceId,
        generation: i64,
        phase: LifecyclePhase,
        container_id: Option<ContainerId>,
        resolved_image: ResolvedImage,
        applied_spec_hash: Option<SpecHash>,
        secret_ref: SecretRef,
        health: Option<HealthKind>,
        last_error: Option<FailureCode>,
        last_checked_at: Option<DateTime<Utc>>,
        updated_at: DateTime<Utc>,
    ) -> Result<Self, ServiceError> {
        if data_major <= 0 || data_major >= 100_000 {
            return Err(ServiceError::InvalidVersion(format!(
                "data_major {data_major} out of range"
            )));
        }
        if generation <= 0 {
            return Err(ServiceError::Internal(
                "generation must be positive".to_string(),
            ));
        }
        if secret_ref.instance_id() != instance_id.as_str() {
            return Err(ServiceError::Internal(
                "secret_ref instance_id does not match state instance_id".to_string(),
            ));
        }
        Ok(Self {
            service_name,
            provider,
            data_major,
            version,
            instance_id,
            generation,
            phase,
            container_id,
            resolved_image,
            applied_spec_hash,
            secret_ref,
            health,
            last_error,
            last_checked_at,
            updated_at,
        })
    }

    // Accessors (read-only, no mutable access to fields).
    pub fn service_name(&self) -> &ServiceName {
        &self.service_name
    }
    pub fn provider(&self) -> ProviderKind {
        self.provider
    }
    pub fn data_major(&self) -> i64 {
        self.data_major
    }
    pub fn version(&self) -> &ProviderVersion {
        &self.version
    }
    pub fn instance_id(&self) -> &InstanceId {
        &self.instance_id
    }
    pub fn generation(&self) -> i64 {
        self.generation
    }
    pub fn phase(&self) -> LifecyclePhase {
        self.phase
    }
    pub fn container_id(&self) -> Option<&ContainerId> {
        self.container_id.as_ref()
    }
    pub fn resolved_image(&self) -> &ResolvedImage {
        &self.resolved_image
    }
    pub fn applied_spec_hash(&self) -> Option<&SpecHash> {
        self.applied_spec_hash.as_ref()
    }
    pub fn secret_ref(&self) -> &SecretRef {
        &self.secret_ref
    }
    pub fn health(&self) -> Option<HealthKind> {
        self.health
    }
    pub fn last_error(&self) -> Option<FailureCode> {
        self.last_error
    }
    pub fn last_checked_at(&self) -> Option<DateTime<Utc>> {
        self.last_checked_at
    }
    pub fn updated_at(&self) -> DateTime<Utc> {
        self.updated_at
    }
}

/// Lifecycle phases for a service data instance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LifecyclePhase {
    Provisioning,
    Ready,
    Deleting,
    Retained,
    Blocked,
    Error,
}

impl LifecyclePhase {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Provisioning => "provisioning",
            Self::Ready => "ready",
            Self::Deleting => "deleting",
            Self::Retained => "retained",
            Self::Blocked => "blocked",
            Self::Error => "error",
        }
    }

    /// Parse a lifecycle phase, returning an explicit error for unknown
    /// values. Never silently coerces.
    pub fn parse(s: &str) -> Result<Self, ServiceError> {
        match s {
            "provisioning" => Ok(Self::Provisioning),
            "ready" => Ok(Self::Ready),
            "deleting" => Ok(Self::Deleting),
            "retained" => Ok(Self::Retained),
            "blocked" => Ok(Self::Blocked),
            "error" => Ok(Self::Error),
            other => Err(ServiceError::InvalidPhase(other.to_string())),
        }
    }

    /// Phases eligible for delete-and-retain (the service must be in an
    /// active, non-terminal state to be removed).
    pub fn is_eligible_for_retain(&self) -> bool {
        matches!(
            self,
            Self::Provisioning | Self::Ready | Self::Error | Self::Blocked
        )
    }
}

/// Health status reported by a provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HealthKind {
    Healthy,
    Unhealthy,
    Starting,
    Unknown,
}

impl HealthKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Healthy => "healthy",
            Self::Unhealthy => "unhealthy",
            Self::Starting => "starting",
            Self::Unknown => "unknown",
        }
    }

    /// Parse a health kind, returning an explicit error for unknown values.
    /// Never silently coerces to `Unknown`.
    pub fn parse(s: &str) -> Result<Self, ServiceError> {
        match s {
            "healthy" => Ok(Self::Healthy),
            "unhealthy" => Ok(Self::Unhealthy),
            "starting" => Ok(Self::Starting),
            "unknown" => Ok(Self::Unknown),
            other => Err(ServiceError::InvalidHealth(other.to_string())),
        }
    }
}

// ─── Canonical JSON hashing ───────────────────────────────────────────────────

/// Produce a deterministic canonical JSON byte vector for a `ServiceSpec`.
///
/// Object keys are recursively sorted. The output is stable regardless of
/// struct field declaration order or serializer behavior. Returns `Err` on
/// serialization failure -- never falls back to an empty string.
fn canonical_spec_json(spec: &ServiceSpec) -> Result<Vec<u8>, serde_json::Error> {
    let mut obj = serde_json::Map::new();
    obj.insert(
        "name".to_string(),
        serde_json::Value::String(spec.name.as_str().to_string()),
    );
    obj.insert(
        "type".to_string(),
        serde_json::Value::String(spec.provider.as_str().to_string()),
    );
    obj.insert(
        "version".to_string(),
        serde_json::Value::String(spec.version.as_str().to_string()),
    );
    let config_val = serde_json::to_value(&spec.config)?;
    obj.insert("config".to_string(), canonicalize_value(config_val));
    let sorted = serde_json::Value::Object(obj);
    serde_json::to_vec(&sorted)
}

/// Recursively sort all object keys in a JSON value.
fn canonicalize_value(value: serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Object(map) => {
            let mut sorted: Vec<(String, serde_json::Value)> = map
                .into_iter()
                .map(|(k, v)| (k, canonicalize_value(v)))
                .collect();
            sorted.sort_by(|a, b| a.0.cmp(&b.0));
            serde_json::Value::Object(serde_json::Map::from_iter(sorted))
        }
        serde_json::Value::Array(arr) => {
            serde_json::Value::Array(arr.into_iter().map(canonicalize_value).collect())
        }
        other => other,
    }
}

// ─── Instance-scoped secret capability ─────────────────────────────────────────

/// Validated, provider-safe secret mount tokens for an active generation.
///
/// This is the provider-safe alternative to `read_superuser()`. The provider
/// receives validated bind-source file tokens (canonical host paths) for the
/// active `raw_password` and `pgpass` files, plus the non-secret generation
/// name for ownership-label comparison. The provider never sees plaintext
/// secret material — it mounts these files into the container.
///
/// On non-Linux (or when the bundle has no active generation), the capability
/// returns `Unsupported`.
#[derive(Debug, Clone)]
pub struct ActiveSecretMounts {
    /// The active generation name (non-secret, 32 hex).
    pub generation: crate::services::secret::GenerationName,
    /// Canonical host path of the raw_password file.
    pub raw_password_path: PathBuf,
    /// Canonical host path of the pgpass file.
    pub pgpass_path: PathBuf,
}

/// An instance-scoped secret capability bound to one validated `InstanceId`.
///
/// This object is constructed with a specific instance identity and only
/// exposes operations relative to that instance. Providers cannot pass an
/// arbitrary `SecretRef` -- the capability is bound at construction and
/// only offers operations for its instance. Cross-instance reads are
/// unrepresentable because there is no `read(secret_ref)` method.
///
/// Part 2 provides the concrete implementation with descriptor-confined
/// filesystem access. Part 1 defines the interface so the `ServiceProvider`
/// trait compiles without leaking the unrestricted `SecretsStore`.
pub trait InstanceSecretCapability: Send + Sync {
    /// The instance ID this capability is bound to.
    fn instance_id(&self) -> &InstanceId;

    /// Read the superuser secret for this instance.
    /// Returns `Ok(None)` if the secret does not exist.
    ///
    /// **Not for provider use**: this returns plaintext and invites leakage.
    /// Providers should use [`active_secret_mounts`](Self::active_secret_mounts)
    /// instead. Retained for test compatibility.
    fn read_superuser(&self) -> Result<Option<String>, ServiceError>;

    /// Return validated mount tokens for the active generation's `raw_password`
    /// and `pgpass` files, plus the non-secret generation name.
    ///
    /// This is the provider-safe path: the provider mounts these files
    /// read-only into the container and never sees plaintext. Default
    /// returns `Unsupported` (fakes override for test configuration).
    fn active_secret_mounts(&self) -> Result<ActiveSecretMounts, ServiceError> {
        Err(ServiceError::Internal(
            "active_secret_mounts not supported by this capability".to_string(),
        ))
    }
}

/// A fake implementation for testing. Returns the provided value or `None`.
/// Bound to a specific instance ID and rejects cross-instance access by
/// construction (there is no method that accepts a different instance).
///
/// For provider tests that need `active_secret_mounts`, use
/// [`FakeInstanceSecrets::with_mounts`](Self::with_mounts).
pub struct FakeInstanceSecrets {
    instance_id: InstanceId,
    value: Option<String>,
    mounts: Option<ActiveSecretMounts>,
}

impl FakeInstanceSecrets {
    pub fn new(instance_id: InstanceId, value: Option<String>) -> Self {
        Self {
            instance_id,
            value,
            mounts: None,
        }
    }

    /// Create a fake with configured mount tokens (for provider tests).
    pub fn with_mounts(instance_id: InstanceId, mounts: ActiveSecretMounts) -> Self {
        Self {
            instance_id,
            value: None,
            mounts: Some(mounts),
        }
    }
}

impl InstanceSecretCapability for FakeInstanceSecrets {
    fn instance_id(&self) -> &InstanceId {
        &self.instance_id
    }

    fn read_superuser(&self) -> Result<Option<String>, ServiceError> {
        Ok(self.value.clone())
    }

    fn active_secret_mounts(&self) -> Result<ActiveSecretMounts, ServiceError> {
        self.mounts
            .clone()
            .ok_or_else(|| ServiceError::Internal("no mounts configured on fake".to_string()))
    }
}

/// Narrow context passed to provider methods.
///
/// Providers receive only the capabilities they need -- they do not own
/// `AppState`, SQLite, or the runtime client. This keeps the controller
/// authoritative for transactions, locking, and status persistence while
/// permitting narrow provider I/O (image pull, container create, health probe).
///
/// The secret capability is instance-scoped: it is bound to one
/// `InstanceId` at construction and exposes no method that accepts an
/// arbitrary `SecretRef`. Cross-instance reads are unrepresentable.
/// The `ProviderContext::new` constructor validates that the secret
/// capability's bound instance matches the state's instance.
///
/// All fields are private. Construction is only through [`new`](Self::new),
/// which validates the instance binding. There is no struct-literal bypass
/// inside or outside the crate.
pub struct ProviderContext<'a> {
    runtime: &'a dyn RuntimeBackend,
    secrets: &'a dyn InstanceSecretCapability,
    services_root: &'a std::path::Path,
    network: &'a str,
    installation_id: &'a str,
    storage: Option<&'a crate::services::storage::ServiceStorage>,
}

impl<'a> ProviderContext<'a> {
    /// Construct a `ProviderContext`, validating that the secret capability
    /// is bound to the same instance as the state.
    pub fn new(
        runtime: &'a dyn RuntimeBackend,
        secrets: &'a dyn InstanceSecretCapability,
        services_root: &'a std::path::Path,
        network: &'a str,
        installation_id: &'a str,
        state: &ServiceState,
    ) -> Result<Self, ServiceError> {
        if secrets.instance_id() != state.instance_id() {
            return Err(ServiceError::Internal(
                "secret capability instance_id does not match state instance_id".to_string(),
            ));
        }
        Ok(Self {
            runtime,
            secrets,
            services_root,
            network,
            installation_id,
            storage: None,
        })
    }

    /// Set the storage accessor (Linux only). Non-Linux callers omit this.
    pub fn with_storage(
        mut self,
        storage: Option<&'a crate::services::storage::ServiceStorage>,
    ) -> Self {
        self.storage = storage;
        self
    }

    pub fn runtime(&self) -> &dyn RuntimeBackend {
        self.runtime
    }
    pub fn secrets(&self) -> &dyn InstanceSecretCapability {
        self.secrets
    }
    pub fn services_root(&self) -> &std::path::Path {
        self.services_root
    }
    pub fn network(&self) -> &str {
        self.network
    }
    pub fn installation_id(&self) -> &str {
        self.installation_id
    }
    /// Linux-only storage accessor; `None` on non-Linux.
    pub fn storage(&self) -> Option<&crate::services::storage::ServiceStorage> {
        self.storage
    }
}

/// Outcome of a `provision` call.
#[derive(Debug, Clone)]
pub struct ProvisionOutcome {
    /// The full container ID (64 hex chars) of the created/ensured container.
    pub container_id: ContainerId,
    /// True if a new container was created; false if an existing owned one was
    /// reused unchanged.
    pub created: bool,
}

/// Outcome of an `ensure` call (idempotent reconcile).
#[derive(Debug, Clone)]
pub struct EnsureOutcome {
    /// The full container ID after ensure.
    pub container_id: ContainerId,
    /// What happened: `created`, `started`, `recreated`, `noop`, or `blocked`.
    pub action: EnsureAction,
    /// Current health, if known.
    pub health: Option<HealthKind>,
}

/// The action an ensure pass took.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnsureAction {
    Created,
    Started,
    Recreated,
    Noop,
    Blocked,
}

impl EnsureAction {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Created => "created",
            Self::Started => "started",
            Self::Recreated => "recreated",
            Self::Noop => "noop",
            Self::Blocked => "blocked",
        }
    }
}

/// A boxed future returned by provider methods, matching `RuntimeBackend`'s
/// convention.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Object-safe service provider trait.
///
/// One boxed-future allocation per call around slow runtime I/O is
/// negligible. The controller always dispatches through
/// `Box<dyn ServiceProvider>`; there is no native-async companion trait and
/// no `async-trait` dependency.
///
/// Part 1 defines the contract only. The concrete PostgreSQL provider
/// implementation (Part 3) supplies `provision`, `ensure`, `health`, and
/// `remove` bodies. No placeholder binding methods are added here -- resource
/// and credential ownership APIs are deferred to SLIP-107.
pub trait ServiceProvider: Send + Sync {
    /// The provider kind (e.g. `"postgres"`).
    fn kind(&self) -> ProviderKind;

    /// Validate a spec for this provider (provider-specific rules).
    fn validate(&self, spec: &ServiceSpec) -> Result<(), ServiceError>;

    /// Provision a service for the first time. Idempotent: if an owned
    /// container already exists, returns its ID with `created: false`.
    fn provision<'a>(
        &'a self,
        ctx: &'a ProviderContext<'a>,
        spec: &'a ServiceSpec,
        state: &'a ServiceState,
    ) -> BoxFuture<'a, Result<ProvisionOutcome, ServiceError>>;

    /// Idempotent reconcile: create if absent, start if stopped, recreate on
    /// safe immutable drift, no-op if healthy and matching.
    fn ensure<'a>(
        &'a self,
        ctx: &'a ProviderContext<'a>,
        spec: &'a ServiceSpec,
        state: &'a ServiceState,
    ) -> BoxFuture<'a, Result<EnsureOutcome, ServiceError>>;

    /// Probe health. Cheap and side-effect-free.
    fn health<'a>(
        &'a self,
        ctx: &'a ProviderContext<'a>,
        state: &'a ServiceState,
    ) -> BoxFuture<'a, Result<ServiceHealth, ServiceError>>;

    /// Remove the owned container only. Never deletes PGDATA or the secret.
    /// Idempotent: a missing owned container is success.
    fn remove<'a>(
        &'a self,
        ctx: &'a ProviderContext<'a>,
        state: &'a ServiceState,
    ) -> BoxFuture<'a, Result<(), ServiceError>>;

    /// Authenticated readiness check: execute a provider-specific query
    /// (e.g. `SELECT 1` for PostgreSQL) using the mounted secret to prove
    /// the service is ready to accept authenticated connections. The password
    /// is never placed in command args. Returns `Ok(())` only if the query
    /// succeeds. Default returns `Ok(())` for providers that don't need it.
    fn readiness_check<'a>(
        &'a self,
        ctx: &'a ProviderContext<'a>,
        spec: &'a ServiceSpec,
        container_id: &'a ContainerId,
    ) -> BoxFuture<'a, Result<(), ServiceError>> {
        let _ = (ctx, spec, container_id);
        Box::pin(async { Ok(()) })
    }
}

/// Health probe result.
#[derive(Debug, Clone)]
pub struct ServiceHealth {
    pub kind: HealthKind,
}

// ─── Errors ───────────────────────────────────────────────────────────────────

/// Errors from the services framework.
///
/// Part 1 defines only the structurally non-secret errors needed by the domain
/// types and the provider trait contract. Part 2/3 will extend this enum as
/// those modules land.
#[derive(Debug, thiserror::Error)]
pub enum ServiceError {
    #[error("unknown provider '{0}' -- supported: postgres")]
    UnknownProvider(String),
    #[error("invalid version: {0}")]
    InvalidVersion(String),
    #[error("invalid lifecycle phase '{0}'")]
    InvalidPhase(String),
    #[error("invalid health kind '{0}'")]
    InvalidHealth(String),
    #[error("service name invalid: {0}")]
    InvalidName(#[from] crate::services::name::ServiceNameError),
    #[error("filesystem check failed for service '{service}': {reason}")]
    FilesystemCheck { service: String, reason: String },
    #[error("ownership mismatch for container: {reason}")]
    OwnershipMismatch { reason: String },
    #[error("foreign container exists with the same name -- refusing to adopt")]
    ForeignContainer,
    #[error("permanent blocked condition for service '{0}': {1}")]
    Blocked(String, String),
    #[error("provision failed: {0}")]
    ProvisionFailed(String),
    #[error("internal error: {0}")]
    Internal(String),
    #[error("container not found in runtime (persisted ID is stale or container was removed)")]
    ContainerNotFound,
    #[error("readiness check failed: {0}")]
    ReadinessFailed(String),
    /// A state conflict: a different spec already exists for this name, or
    /// the caller's observed generation is stale. The `reason` is a
    /// sanitized, non-secret description with a prescriptive remedy.
    #[error("conflict: {0}")]
    Conflict(String),
    /// Concurrent modification: the CAS (compare-and-swap) on persisted state
    /// failed because another caller modified the row between read and write.
    #[error("concurrent modification detected (generation mismatch)")]
    ConcurrentModification,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ResourceConfig;
    use crate::error::RuntimeError;
    use crate::merge::MergedVolume;
    use crate::runtime::{ContainerInfo, LogStreamItem, RegistryCredentials};

    /// Minimal fake runtime for testing ProviderContext construction.
    struct FakeRuntime;

    impl crate::runtime::RuntimeBackend for FakeRuntime {
        fn name(&self) -> &str {
            "fake"
        }
        fn ping(&self) -> Pin<Box<dyn Future<Output = Result<(), RuntimeError>> + Send + '_>> {
            Box::pin(async { Ok(()) })
        }
        fn ensure_network<'a>(
            &'a self,
            _name: &'a str,
        ) -> Pin<Box<dyn Future<Output = Result<(), RuntimeError>> + Send + 'a>> {
            Box::pin(async { Ok(()) })
        }
        fn pull_image<'a>(
            &'a self,
            _image: &'a str,
            _tag: &'a str,
            _creds: Option<RegistryCredentials>,
        ) -> Pin<Box<dyn Future<Output = Result<(), RuntimeError>> + Send + 'a>> {
            Box::pin(async { Ok(()) })
        }
        fn create_and_start<'a>(
            &'a self,
            _app: &'a str,
            _img: &'a str,
            _tag: &'a str,
            _port: u16,
            _env: Vec<String>,
            _net: &'a str,
            _res: &'a ResourceConfig,
            _vol: &'a [MergedVolume],
        ) -> Pin<Box<dyn Future<Output = Result<(String, u16), RuntimeError>> + Send + 'a>>
        {
            Box::pin(async { Err(RuntimeError::Unsupported("fake".into())) })
        }
        fn stop_container<'a>(
            &'a self,
            _id: &'a str,
        ) -> Pin<Box<dyn Future<Output = Result<(), RuntimeError>> + Send + 'a>> {
            Box::pin(async { Ok(()) })
        }
        fn start_container<'a>(
            &'a self,
            _id: &'a str,
        ) -> Pin<Box<dyn Future<Output = Result<(), RuntimeError>> + Send + 'a>> {
            Box::pin(async { Ok(()) })
        }
        fn inspect_container_port<'a>(
            &'a self,
            _id: &'a str,
            _port: u16,
        ) -> Pin<Box<dyn Future<Output = Result<u16, RuntimeError>> + Send + 'a>> {
            Box::pin(async { Err(RuntimeError::Unsupported("fake".into())) })
        }
        fn stop_and_remove<'a>(
            &'a self,
            _id: &'a str,
        ) -> Pin<Box<dyn Future<Output = Result<(), RuntimeError>> + Send + 'a>> {
            Box::pin(async { Ok(()) })
        }
        fn container_is_running<'a>(
            &'a self,
            _id: &'a str,
        ) -> Pin<Box<dyn Future<Output = Result<bool, RuntimeError>> + Send + 'a>> {
            Box::pin(async { Ok(false) })
        }
        fn container_exists<'a>(
            &'a self,
            _id: &'a str,
        ) -> Pin<Box<dyn Future<Output = Result<bool, RuntimeError>> + Send + 'a>> {
            Box::pin(async { Ok(false) })
        }
        fn list_by_label<'a>(
            &'a self,
            _key: &'a str,
            _val: &'a str,
        ) -> Pin<Box<dyn Future<Output = Result<Vec<ContainerInfo>, RuntimeError>> + Send + 'a>>
        {
            Box::pin(async { Ok(vec![]) })
        }
        fn container_logs<'a>(
            &'a self,
            _id: &'a str,
            _since: Option<i64>,
            _follow: bool,
        ) -> Pin<
            Box<dyn futures_util::Stream<Item = Result<LogStreamItem, RuntimeError>> + Send + 'a>,
        > {
            Box::pin(futures_util::stream::empty())
        }
    }

    #[test]
    fn provider_kind_round_trip() {
        assert_eq!(
            ProviderKind::parse("postgres").unwrap(),
            ProviderKind::Postgres
        );
        assert_eq!(ProviderKind::Postgres.as_str(), "postgres");
        assert!(ProviderKind::parse("s3").is_err());
        assert!(ProviderKind::parse("").is_err());
    }

    #[test]
    fn provider_version_valid() {
        assert!(ProviderVersion::parse("18.4").is_ok());
        assert!(ProviderVersion::parse("18.4.1").is_ok());
        assert!(ProviderVersion::parse("1.0").is_ok());
    }

    #[test]
    fn provider_version_rejects_bare_major() {
        assert!(ProviderVersion::parse("18").is_err());
    }

    #[test]
    fn provider_version_invalid() {
        assert!(ProviderVersion::parse("").is_err());
        assert!(ProviderVersion::parse("latest").is_err());
        assert!(ProviderVersion::parse("18abc").is_err());
        assert!(ProviderVersion::parse(".18").is_err());
        assert!(ProviderVersion::parse("18.").is_err());
        assert!(ProviderVersion::parse("18..4").is_err());
        assert!(ProviderVersion::parse(&"a".repeat(33)).is_err());
        assert!(ProviderVersion::parse("ab").is_err());
    }

    #[test]
    fn provider_version_major() {
        assert_eq!(ProviderVersion::parse("18.4").unwrap().major(), 18);
        assert_eq!(ProviderVersion::parse("1.0").unwrap().major(), 1);
    }

    #[test]
    fn provider_version_serde_round_trip() {
        let v = ProviderVersion::parse("18.4").unwrap();
        let json = serde_json::to_string(&v).unwrap();
        assert_eq!(json, "\"18.4\"");
        let back: ProviderVersion = serde_json::from_str(&json).unwrap();
        assert_eq!(back, v);
    }

    #[test]
    fn provider_version_serde_rejects_invalid() {
        assert!(serde_json::from_str::<ProviderVersion>("\"latest\"").is_err());
        assert!(serde_json::from_str::<ProviderVersion>("\"\"").is_err());
        assert!(serde_json::from_str::<ProviderVersion>("\"18\"").is_err());
    }

    #[test]
    fn instance_id_generate_is_32_lowercase_hex() {
        let id = InstanceId::generate().unwrap();
        assert_eq!(id.as_str().len(), 32);
        assert!(id.as_str().chars().all(|c| c.is_ascii_hexdigit()));
        assert!(id.as_str().chars().all(|c| !c.is_ascii_uppercase()));
    }

    #[test]
    fn instance_id_generate_is_unique() {
        let id1 = InstanceId::generate().unwrap();
        let id2 = InstanceId::generate().unwrap();
        assert_ne!(id1, id2);
    }

    #[test]
    fn instance_id_parse_requires_exact_32_lowercase_hex() {
        let valid = "0123456789abcdef0123456789abcdef";
        assert!(InstanceId::parse(valid).is_ok());
        assert!(InstanceId::parse("0123456789abcdef").is_err());
        assert!(InstanceId::parse(&format!("{valid}ff")).is_err());
        assert!(InstanceId::parse("0123456789ABCDEF0123456789ABCDEF").is_err());
        assert!(InstanceId::parse("g123456789abcdef0123456789abcdef").is_err());
    }

    #[test]
    fn container_id_parse_requires_exact_64_lowercase_hex() {
        let valid = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        assert!(ContainerId::parse(valid).is_ok());
        assert!(
            ContainerId::parse("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abc")
                .is_err()
        );
        assert!(ContainerId::parse(&format!("{valid}f")).is_err());
        assert!(
            ContainerId::parse("0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF")
                .is_err()
        );
        assert!(ContainerId::parse(&valid.to_string().replacen('0', "g", 1)).is_err());
    }

    #[test]
    fn spec_hash_parse_requires_exact_64_lowercase_hex() {
        let valid = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        assert!(SpecHash::parse(valid).is_ok());
        assert!(SpecHash::parse("short").is_err());
        assert!(SpecHash::parse(&format!("{valid}ff")).is_err());
        assert!(
            SpecHash::parse("0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF")
                .is_err()
        );
    }

    #[test]
    fn secret_ref_new_binds_to_instance() {
        let id = InstanceId::generate().unwrap();
        let r = SecretRef::new(&id, SecretPurpose::Superuser);
        assert_eq!(r.instance_id(), id.as_str());
        assert_eq!(r.purpose(), "superuser");
        assert_eq!(r.as_str(), format!("service/{}/superuser", id.as_str()));
    }

    #[test]
    fn secret_ref_parse_canonical_format() {
        let id = InstanceId::generate().unwrap();
        let s = format!("service/{}/superuser", id.as_str());
        let r = SecretRef::parse(&s).unwrap();
        assert_eq!(r.instance_id(), id.as_str());
        assert_eq!(r.purpose(), "superuser");
    }

    #[test]
    fn secret_ref_parse_rejects_raw_password() {
        assert!(SecretRef::parse("supersecretpassword123").is_err());
        assert!(SecretRef::parse("password123").is_err());
    }

    #[test]
    fn secret_ref_parse_rejects_wrong_format() {
        assert!(SecretRef::parse("short").is_err());
        assert!(SecretRef::parse("service/short/superuser").is_err());
        assert!(SecretRef::parse("service/0123456789abcdef0123456789abcdef/unknown").is_err());
        assert!(SecretRef::parse("service/0123456789abcdef0123456789abcdef").is_err());
        assert!(SecretRef::parse("service/../etc/passwd").is_err());
        assert!(SecretRef::parse(&"x".repeat(257)).is_err());
    }

    #[test]
    fn resolved_image_parse_validates() {
        assert!(
            ResolvedImage::parse("docker.io/library/postgres:18.4-bookworm@sha256:abc").is_ok()
        );
        assert!(ResolvedImage::parse("").is_err());
        assert!(ResolvedImage::parse(&"a".repeat(513)).is_err());
        assert!(ResolvedImage::parse("has\nnewline").is_err());
    }

    // ── FailureCode tests ───────────────────────────────────────────────────

    #[test]
    fn failure_code_round_trip() {
        for code in [
            FailureCode::ProvisionFailed,
            FailureCode::HealthTimeout,
            FailureCode::OwnershipMismatch,
            FailureCode::FilesystemCheck,
            FailureCode::ImagePullFailed,
            FailureCode::ReadinessFailed,
            FailureCode::Internal,
        ] {
            let s = code.as_str();
            assert_eq!(FailureCode::parse(s).unwrap(), code);
        }
        assert!(FailureCode::parse("nonsense").is_err());
        assert!(FailureCode::parse("").is_err());
    }

    #[test]
    fn failure_code_rejects_arbitrary_strings() {
        // A raw secret-bearing string must not parse as a FailureCode.
        assert!(FailureCode::parse("password=secret123").is_err());
        assert!(FailureCode::parse("postgres://user:pass@host").is_err());
        assert!(FailureCode::parse("Bearer abc123token").is_err());
    }

    // ── Canonical hashing tests ─────────────────────────────────────────────

    #[test]
    fn spec_effective_hash_is_deterministic() {
        let spec = sample_spec("pg");
        let h1 = spec.effective_hash().unwrap();
        let h2 = spec.effective_hash().unwrap();
        assert_eq!(h1, h2);
        assert_eq!(h1.as_str().len(), 64);
    }

    #[test]
    fn spec_effective_hash_returns_result_not_default() {
        let spec = sample_spec("pg");
        let h = spec.effective_hash().unwrap();
        let empty_hash = {
            let hasher = Sha256::new();
            hex::encode(hasher.finalize())
        };
        assert_ne!(h.as_str(), empty_hash);
    }

    #[test]
    fn spec_effective_hash_includes_domain_prefix() {
        let spec = sample_spec("pg");
        let canonical = canonical_spec_json(&spec).unwrap();
        let mut plain_hasher = Sha256::new();
        plain_hasher.update(&canonical);
        let plain_hash = hex::encode(plain_hasher.finalize());
        let prefixed_hash = spec.effective_hash().unwrap();
        assert_ne!(prefixed_hash.as_str(), plain_hash);
    }

    #[test]
    fn spec_effective_hash_differs_for_different_specs() {
        let spec1 = sample_spec("pg");
        let spec2 = sample_spec("redis");
        assert_ne!(
            spec1.effective_hash().unwrap(),
            spec2.effective_hash().unwrap()
        );
    }

    #[test]
    fn spec_effective_hash_differs_for_different_versions() {
        let spec1 = sample_spec("pg");
        let spec2 = ServiceSpec::new(
            ServiceName::parse("pg").unwrap(),
            ProviderKind::Postgres,
            ProviderVersion::parse("18.5").unwrap(),
            PostgresConfig {},
        )
        .unwrap();
        assert_ne!(
            spec1.effective_hash().unwrap(),
            spec2.effective_hash().unwrap()
        );
    }

    // ── Serde tests ──────────────────────────────────────────────────────────

    #[test]
    fn spec_serde_round_trip() {
        let spec = sample_spec("pg-main");
        let json = serde_json::to_string(&spec).unwrap();
        let back: ServiceSpec = serde_json::from_str(&json).unwrap();
        assert_eq!(spec, back);
        assert!(json.contains("\"pg-main\""));
        assert!(json.contains("\"postgres\""));
    }

    #[test]
    fn spec_serde_uses_type_rename() {
        let spec = sample_spec("pg");
        let json = serde_json::to_string(&spec).unwrap();
        assert!(
            json.contains("\"type\""),
            "provider must serialize as 'type': {json}"
        );
        assert!(
            !json.contains("\"provider\""),
            "field must not be 'provider': {json}"
        );
        let parsed: ServiceSpec = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, spec);
    }

    #[test]
    fn spec_serde_rejects_unknown_top_level_fields() {
        let json =
            r#"{"name":"pg","type":"postgres","version":"18.4","config":{},"password":"secret"}"#;
        assert!(
            serde_json::from_str::<ServiceSpec>(json).is_err(),
            "unknown top-level fields must be rejected"
        );
    }

    #[test]
    fn postgres_config_deny_unknown_fields() {
        let json = r#"{"extra": "field"}"#;
        assert!(serde_json::from_str::<PostgresConfig>(json).is_err());
        assert!(serde_json::from_str::<PostgresConfig>(r#"{}"#).is_ok());
    }

    // ── Lifecycle/health ─────────────────────────────────────────────────────

    #[test]
    fn lifecycle_phase_round_trip() {
        for phase in [
            LifecyclePhase::Provisioning,
            LifecyclePhase::Ready,
            LifecyclePhase::Deleting,
            LifecyclePhase::Retained,
            LifecyclePhase::Blocked,
            LifecyclePhase::Error,
        ] {
            let s = phase.as_str();
            assert_eq!(LifecyclePhase::parse(s).unwrap(), phase);
        }
        assert!(LifecyclePhase::parse("nonsense").is_err());
    }

    #[test]
    fn lifecycle_phase_eligible_for_retain() {
        assert!(LifecyclePhase::Provisioning.is_eligible_for_retain());
        assert!(LifecyclePhase::Ready.is_eligible_for_retain());
        assert!(LifecyclePhase::Error.is_eligible_for_retain());
        assert!(LifecyclePhase::Blocked.is_eligible_for_retain());
        assert!(!LifecyclePhase::Deleting.is_eligible_for_retain());
        assert!(!LifecyclePhase::Retained.is_eligible_for_retain());
    }

    #[test]
    fn health_kind_parse_rejects_unknown() {
        assert!(HealthKind::parse("healthy").is_ok());
        assert!(HealthKind::parse("unhealthy").is_ok());
        assert!(HealthKind::parse("starting").is_ok());
        assert!(HealthKind::parse("unknown").is_ok());
        assert!(HealthKind::parse("nonsense").is_err());
        assert!(HealthKind::parse("").is_err());
    }

    // ── ServiceState ─────────────────────────────────────────────────────────

    #[test]
    fn service_state_for_provisioning_generates_instance_id_and_derives_secret_ref() {
        let state = ServiceState::for_provisioning(
            ServiceName::parse("pg").unwrap(),
            ProviderKind::Postgres,
            ProviderVersion::parse("18.4").unwrap(),
            ResolvedImage::parse("docker.io/library/postgres:18.4-bookworm@sha256:abc").unwrap(),
            Utc::now(),
        )
        .unwrap();
        assert_eq!(state.generation(), 1);
        assert_eq!(state.phase(), LifecyclePhase::Provisioning);
        assert_eq!(state.instance_id().as_str().len(), 32);
        assert!(state.container_id().is_none());
        assert_eq!(
            state.secret_ref().instance_id(),
            state.instance_id().as_str()
        );
        assert_eq!(state.secret_ref().purpose(), "superuser");
    }

    #[test]
    fn service_state_for_provisioning_rejects_bad_data_major() {
        // ProviderVersion::parse already rejects major 0 and >= 100000,
        // so for_provisioning can never receive a bad data_major from a
        // valid version. We test from_validated directly for the boundary.
        let id = InstanceId::generate().unwrap();
        let secret_ref = SecretRef::new(&id, SecretPurpose::Superuser);
        assert!(
            ServiceState::from_validated(
                ServiceName::parse("pg").unwrap(),
                ProviderKind::Postgres,
                0,
                ProviderVersion::parse("18.4").unwrap(),
                id.clone(),
                1,
                LifecyclePhase::Provisioning,
                None,
                ResolvedImage::parse("img").unwrap(),
                None,
                secret_ref,
                None,
                None,
                None,
                Utc::now(),
            )
            .is_err()
        );
        assert!(
            ServiceState::from_validated(
                ServiceName::parse("pg").unwrap(),
                ProviderKind::Postgres,
                100_000,
                ProviderVersion::parse("18.4").unwrap(),
                id.clone(),
                1,
                LifecyclePhase::Provisioning,
                None,
                ResolvedImage::parse("img").unwrap(),
                None,
                SecretRef::new(&id, SecretPurpose::Superuser),
                None,
                None,
                None,
                Utc::now(),
            )
            .is_err()
        );
    }

    #[test]
    fn from_validated_rejects_secret_ref_mismatch() {
        let id1 = InstanceId::generate().unwrap();
        let id2 = InstanceId::generate().unwrap();
        let wrong_secret_ref = SecretRef::new(&id2, SecretPurpose::Superuser);
        let err = ServiceState::from_validated(
            ServiceName::parse("pg").unwrap(),
            ProviderKind::Postgres,
            18,
            ProviderVersion::parse("18.4").unwrap(),
            id1,
            1,
            LifecyclePhase::Provisioning,
            None,
            ResolvedImage::parse("img").unwrap(),
            None,
            wrong_secret_ref,
            None,
            None,
            None,
            Utc::now(),
        )
        .unwrap_err();
        assert!(err.to_string().contains("secret_ref instance_id"));
    }

    // ── Instance-scoped secret capability ────────────────────────────────────

    #[test]
    fn fake_instance_secrets_bound_to_instance() {
        let id = InstanceId::generate().unwrap();
        let caps = FakeInstanceSecrets::new(id.clone(), Some("secret-value".to_string()));
        assert_eq!(caps.instance_id(), &id);
        assert_eq!(
            caps.read_superuser().unwrap(),
            Some("secret-value".to_string())
        );
    }

    #[test]
    fn fake_instance_secrets_no_cross_instance_access() {
        let id1 = InstanceId::generate().unwrap();
        let id2 = InstanceId::generate().unwrap();
        let caps1 = FakeInstanceSecrets::new(id1, Some("secret-1".to_string()));
        let caps2 = FakeInstanceSecrets::new(id2, Some("secret-2".to_string()));
        assert_eq!(
            caps1.read_superuser().unwrap(),
            Some("secret-1".to_string())
        );
        assert_eq!(
            caps2.read_superuser().unwrap(),
            Some("secret-2".to_string())
        );
    }

    #[test]
    fn provider_context_new_succeeds_on_match() {
        let state = ServiceState::for_provisioning(
            ServiceName::parse("pg").unwrap(),
            ProviderKind::Postgres,
            ProviderVersion::parse("18.4").unwrap(),
            ResolvedImage::parse("img").unwrap(),
            Utc::now(),
        )
        .unwrap();
        let caps = FakeInstanceSecrets::new(state.instance_id().clone(), Some("v".to_string()));
        let runtime = FakeRuntime;
        let root = std::path::Path::new("/tmp");
        let ctx = ProviderContext::new(
            &runtime as &dyn RuntimeBackend,
            &caps as &dyn InstanceSecretCapability,
            root,
            "slip",
            "install-id",
            &state,
        );
        assert!(ctx.is_ok(), "matching instance must succeed");
        let ctx = ctx.unwrap();
        assert_eq!(ctx.network(), "slip");
        assert_eq!(ctx.installation_id(), "install-id");
    }

    #[test]
    fn provider_context_new_fails_on_mismatch() {
        let state = ServiceState::for_provisioning(
            ServiceName::parse("pg").unwrap(),
            ProviderKind::Postgres,
            ProviderVersion::parse("18.4").unwrap(),
            ResolvedImage::parse("img").unwrap(),
            Utc::now(),
        )
        .unwrap();
        let wrong_id = InstanceId::generate().unwrap();
        let wrong_caps = FakeInstanceSecrets::new(wrong_id, Some("v".to_string()));
        let runtime = FakeRuntime;
        let root = std::path::Path::new("/tmp");
        let result = ProviderContext::new(
            &runtime as &dyn RuntimeBackend,
            &wrong_caps as &dyn InstanceSecretCapability,
            root,
            "slip",
            "install-id",
            &state,
        );
        match result {
            Err(e) => assert!(e.to_string().contains("instance_id")),
            Ok(_) => panic!("mismatched instance must fail"),
        }
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    fn sample_spec(name: &str) -> ServiceSpec {
        ServiceSpec::new(
            ServiceName::parse(name).unwrap(),
            ProviderKind::Postgres,
            ProviderVersion::parse("18.4").unwrap(),
            PostgresConfig {},
        )
        .unwrap()
    }

    // ── Phase 1: ServiceContainerSpec validation ────────────────────────────

    fn sample_pinned_image() -> crate::services::image_ref::PinnedImageRef {
        crate::services::image_ref::PinnedImageRef::parse(
            "docker.io/library/postgres:18.4-bookworm@sha256:882236b897e39051d2368c5ccc6cda944904723506b2dfc97f2a8f5bc9afa382",
        )
        .unwrap()
    }

    fn sample_healthcheck() -> crate::runtime::ServiceHealthcheck {
        crate::runtime::ServiceHealthcheck {
            test_cmd: vec!["pg_isready".into(), "-U".into(), "postgres".into()],
            interval_secs: 10,
            timeout_secs: 5,
            retries: 5,
            start_period_secs: 30,
        }
    }

    #[test]
    fn service_container_spec_valid() {
        let spec = crate::runtime::ServiceContainerSpec::new(
            "slip-service-pg".to_string(),
            "slip-service-pg".to_string(),
            sample_pinned_image(),
            "slip".to_string(),
            vec!["pg".to_string()],
            vec![],
            std::collections::BTreeMap::new(),
            std::collections::BTreeMap::new(),
            sample_healthcheck(),
            crate::runtime::ServiceResourceLimits::default(),
            crate::runtime::ServiceSecurityOpts::default(),
        );
        assert!(spec.is_ok(), "valid spec must succeed");
        let spec = spec.unwrap();
        assert_eq!(spec.name(), "slip-service-pg");
        assert_eq!(spec.network(), "slip");
        assert!(spec.restart_unless_stopped());
    }

    #[test]
    fn service_container_spec_rejects_wrong_name_prefix() {
        let spec = crate::runtime::ServiceContainerSpec::new(
            "pg".to_string(), // missing slip-service- prefix
            "pg".to_string(),
            sample_pinned_image(),
            "slip".to_string(),
            vec!["pg".to_string()],
            vec![],
            std::collections::BTreeMap::new(),
            std::collections::BTreeMap::new(),
            sample_healthcheck(),
            crate::runtime::ServiceResourceLimits::default(),
            crate::runtime::ServiceSecurityOpts::default(),
        );
        assert!(spec.is_err());
    }

    #[test]
    fn service_container_spec_rejects_empty_network() {
        let spec = crate::runtime::ServiceContainerSpec::new(
            "slip-service-pg".to_string(),
            "slip-service-pg".to_string(),
            sample_pinned_image(),
            "".to_string(),
            vec!["pg".to_string()],
            vec![],
            std::collections::BTreeMap::new(),
            std::collections::BTreeMap::new(),
            sample_healthcheck(),
            crate::runtime::ServiceResourceLimits::default(),
            crate::runtime::ServiceSecurityOpts::default(),
        );
        assert!(spec.is_err());
    }

    #[test]
    fn service_container_spec_rejects_empty_aliases() {
        let spec = crate::runtime::ServiceContainerSpec::new(
            "slip-service-pg".to_string(),
            "slip-service-pg".to_string(),
            sample_pinned_image(),
            "slip".to_string(),
            vec![],
            vec![],
            std::collections::BTreeMap::new(),
            std::collections::BTreeMap::new(),
            sample_healthcheck(),
            crate::runtime::ServiceResourceLimits::default(),
            crate::runtime::ServiceSecurityOpts::default(),
        );
        assert!(spec.is_err());
    }

    #[test]
    fn service_container_spec_rejects_secret_env_key() {
        let mut env = std::collections::BTreeMap::new();
        env.insert("POSTGRES_PASSWORD".to_string(), "secret".to_string());
        let spec = crate::runtime::ServiceContainerSpec::new(
            "slip-service-pg".to_string(),
            "slip-service-pg".to_string(),
            sample_pinned_image(),
            "slip".to_string(),
            vec!["pg".to_string()],
            vec![],
            env,
            std::collections::BTreeMap::new(),
            sample_healthcheck(),
            crate::runtime::ServiceResourceLimits::default(),
            crate::runtime::ServiceSecurityOpts::default(),
        );
        assert!(spec.is_err());
    }

    #[test]
    fn service_container_spec_accepts_password_file_env_key() {
        let mut env = std::collections::BTreeMap::new();
        env.insert(
            "POSTGRES_PASSWORD_FILE".to_string(),
            "/run/secrets/slip-raw-password".to_string(),
        );
        let spec = crate::runtime::ServiceContainerSpec::new(
            "slip-service-pg".to_string(),
            "slip-service-pg".to_string(),
            sample_pinned_image(),
            "slip".to_string(),
            vec!["pg".to_string()],
            vec![],
            env,
            std::collections::BTreeMap::new(),
            sample_healthcheck(),
            crate::runtime::ServiceResourceLimits::default(),
            crate::runtime::ServiceSecurityOpts::default(),
        );
        assert!(spec.is_ok(), "POSTGRES_PASSWORD_FILE must be accepted");
    }

    // ── Phase 1: active_secret_mounts default ────────────────────────────────

    #[test]
    fn fake_instance_secrets_active_mounts_default_unsupported() {
        let id = InstanceId::generate().unwrap();
        let caps = FakeInstanceSecrets::new(id, Some("v".to_string()));
        assert!(caps.active_secret_mounts().is_err());
    }

    #[test]
    fn fake_instance_secrets_with_mounts() {
        let id = InstanceId::generate().unwrap();
        let generation = crate::services::secret::GenerationName::generate().unwrap();
        let mounts = ActiveSecretMounts {
            generation,
            raw_password_path: std::path::PathBuf::from("/tmp/raw"),
            pgpass_path: std::path::PathBuf::from("/tmp/pgpass"),
        };
        let caps = FakeInstanceSecrets::with_mounts(id.clone(), mounts);
        let result = caps.active_secret_mounts().unwrap();
        assert_eq!(
            result.raw_password_path,
            std::path::PathBuf::from("/tmp/raw")
        );
        assert_eq!(result.pgpass_path, std::path::PathBuf::from("/tmp/pgpass"));
    }

    // ── Phase 1: ServiceError variants ───────────────────────────────────────

    #[test]
    fn service_error_conflict_display() {
        let e = ServiceError::Conflict("spec differs".to_string());
        assert!(e.to_string().contains("conflict"));
    }

    #[test]
    fn service_error_concurrent_modification_display() {
        let e = ServiceError::ConcurrentModification;
        assert!(e.to_string().contains("concurrent"));
    }

    // ── Phase 1: is_rootful default ──────────────────────────────────────────

    #[tokio::test]
    async fn fake_runtime_is_rootful_defaults_false() {
        let rt = FakeRuntime;
        let rootful = rt.is_rootful().await;
        assert!(!rootful, "default is_rootful must be false (fail closed)");
    }
}
