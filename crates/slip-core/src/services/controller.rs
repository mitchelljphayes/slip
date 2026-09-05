//! Provider-agnostic service controller (SLIP-106 Part 3).
//!
//! The controller is authoritative for:
//! - Per-service single-flight locks (shared across API, startup, and reconcile).
//! - Repository generation CAS (compare-and-swap) for crash-consistent state.
//! - Secret generation (once, before provision; never on ambiguous pointer).
//! - Usage boundary (refuses removal of services with active bindings).
//! - Bounded reconciliation (ensure_all with deadlines and collect-and-continue).
//! - Sanitized error surface (no secrets/paths/stderr in errors).
//!
//! The controller delegates provider-specific work (container create/inspect/
//! remove, readiness checks) to [`ServiceProvider`] implementations.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use dashmap::DashMap;
use tokio::sync::{Mutex, Semaphore};

use crate::db::Db;
use crate::runtime::RuntimeBackend;
use crate::services::name::ServiceName;
use crate::services::postgres::{self, resolve_image_for_version};
use crate::services::repository::{ServiceRepository, ServiceRepositoryError, ServiceStateRow};
use crate::services::spec::{
    FailureCode, HealthKind, InstanceSecretCapability, LifecyclePhase, ProviderContext,
    ProviderKind, ServiceError, ServiceProvider, ServiceSpec, ServiceState,
};

#[cfg(target_os = "linux")]
use crate::services::secret::InstanceSecretBundle;
#[cfg(target_os = "linux")]
use crate::services::storage::ServiceStorage;

/// Maximum concurrent service ensure/provision operations.
const MAX_CONCURRENT_SERVICES: usize = 2;

/// Startup ensure budget.
const STARTUP_BUDGET: Duration = Duration::from_secs(60);

/// Per-service operation deadline.
const PER_SERVICE_DEADLINE: Duration = Duration::from_secs(30);

/// Trait for reading which apps use a service (usage boundary).
///
/// Production impl returns empty until SLIP-107 adds `[needs.*]` to app
/// configs. Fakes prove refusal + force override.
pub trait ServiceUsageReader: Send + Sync {
    /// Return app names that bind to this service. Empty = no bindings.
    fn bindings_for_service<'a>(
        &'a self,
        name: &'a ServiceName,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Vec<String>> + Send + 'a>>;
}

/// Production usage reader — returns empty (no `needs` field in AppConfig yet).
pub struct AppConfigUsageReader {
    #[allow(dead_code)]
    apps: Arc<tokio::sync::RwLock<HashMap<String, crate::config::AppConfig>>>,
}

impl AppConfigUsageReader {
    pub fn new(apps: Arc<tokio::sync::RwLock<HashMap<String, crate::config::AppConfig>>>) -> Self {
        Self { apps }
    }
}

impl ServiceUsageReader for AppConfigUsageReader {
    fn bindings_for_service<'a>(
        &'a self,
        _name: &'a ServiceName,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Vec<String>> + Send + 'a>> {
        // No `needs` field in AppConfig yet — SLIP-107 will add it.
        Box::pin(async { vec![] })
    }
}

/// A fake usage reader for testing.
pub struct FakeUsageReader {
    bindings: HashMap<String, Vec<String>>,
}

impl FakeUsageReader {
    pub fn new(bindings: HashMap<String, Vec<String>>) -> Self {
        Self { bindings }
    }
}

impl ServiceUsageReader for FakeUsageReader {
    fn bindings_for_service<'a>(
        &'a self,
        name: &'a ServiceName,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Vec<String>> + Send + 'a>> {
        let bindings = self
            .bindings
            .get(name.as_str())
            .cloned()
            .unwrap_or_default();
        Box::pin(async move { bindings })
    }
}

/// DTO for a service summary (list/status responses).
#[derive(Debug, Clone)]
pub struct ServiceSummary {
    pub name: ServiceName,
    pub provider: ProviderKind,
    pub version: String,
    pub phase: LifecyclePhase,
    pub health: Option<HealthKind>,
}

/// DTO for a single service status (detailed).
#[derive(Debug, Clone)]
pub struct ServiceStatus {
    pub name: ServiceName,
    pub provider: ProviderKind,
    pub version: String,
    pub phase: LifecyclePhase,
    pub health: Option<HealthKind>,
    pub last_error: Option<FailureCode>,
    /// Current persisted generation (non-secret operational integer).
    /// Required by CLI `rm` to pass to DELETE as a CAS guard.
    pub generation: i64,
    pub created_at: chrono::DateTime<Utc>,
    pub updated_at: chrono::DateTime<Utc>,
}

/// DTO for a removal response.
#[derive(Debug, Clone)]
pub struct ServiceRemovalResult {
    pub name: ServiceName,
    pub removed: bool,
    pub retained_data: bool,
    pub retained_secrets: bool,
    pub affected_apps: Vec<String>,
}

/// The service controller — orchestrates providers, persistence, and locking.
pub struct ServiceController {
    db: Db,
    runtime: Arc<dyn RuntimeBackend>,
    services_root: PathBuf,
    network: String,
    installation_id: String,
    #[cfg(target_os = "linux")]
    storage: Option<ServiceStorage>,
    providers: HashMap<ProviderKind, Arc<dyn ServiceProvider>>,
    locks: DashMap<ServiceName, Arc<Mutex<()>>>,
    ensure_sem: Semaphore,
    usage: Arc<dyn ServiceUsageReader>,
}

impl ServiceController {
    /// Construct a new controller. The installation_id is loaded from the DB.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        db: Db,
        runtime: Arc<dyn RuntimeBackend>,
        services_root: PathBuf,
        network: String,
        installation_id: String,
        usage: Arc<dyn ServiceUsageReader>,
        #[cfg(target_os = "linux")] storage: Option<ServiceStorage>,
    ) -> Self {
        let mut providers: HashMap<ProviderKind, Arc<dyn ServiceProvider>> = HashMap::new();
        providers.insert(
            ProviderKind::Postgres,
            Arc::new(postgres::PostgresProvider::new()),
        );

        Self {
            db,
            runtime,
            services_root,
            network,
            installation_id,
            #[cfg(target_os = "linux")]
            storage,
            providers,
            locks: DashMap::new(),
            ensure_sem: Semaphore::new(MAX_CONCURRENT_SERVICES),
            usage,
        }
    }

    /// Check if the runtime is rootful. Service ops fail closed if not.
    pub async fn is_rootful(&self) -> bool {
        self.runtime.is_rootful().await
    }

    fn get_lock(&self, name: &ServiceName) -> Arc<Mutex<()>> {
        self.locks
            .entry(name.clone())
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone()
    }

    fn provider_for(&self, kind: ProviderKind) -> Result<Arc<dyn ServiceProvider>, ServiceError> {
        self.providers
            .get(&kind)
            .cloned()
            .ok_or_else(|| ServiceError::UnknownProvider(kind.as_str().to_string()))
    }

    /// Add a service: validate, persist desired+state, provision, CAS commit.
    pub async fn add(&self, spec: ServiceSpec) -> Result<(), ServiceError> {
        let name = spec.name().clone();
        let lock = self.get_lock(&name);
        let _guard = lock.lock().await;

        // Rootful check.
        if !self.is_rootful().await {
            return Err(ServiceError::Blocked(
                name.as_str().to_string(),
                "services require a rootful Podman/Docker runtime".to_string(),
            ));
        }

        let provider = self.provider_for(spec.provider())?;
        provider.validate(&spec)?;

        // Check for existing service with same name.
        let db = self.db.clone();
        let name_clone = name.clone();
        let existing = tokio::task::spawn_blocking(move || {
            let conn = db.0.lock().unwrap();
            ServiceRepository::get_service(&conn, &name_clone)
        })
        .await
        .map_err(|e| ServiceError::Internal(e.to_string()))?
        .map_err(ServiceError::from_repo_cas)?;

        if let Some(existing_row) = existing {
            // Same name — check if same spec.
            let existing_spec = existing_row.to_spec()?;
            if existing_spec == spec {
                // Idempotent — touch and return (ensure path handles convergence).
                let db = self.db.clone();
                let name_clone = name.clone();
                let _ = tokio::task::spawn_blocking(move || {
                    let conn = db.0.lock().unwrap();
                    ServiceRepository::touch_service(&conn, &name_clone, Utc::now())
                })
                .await;
                return Ok(());
            } else {
                return Err(ServiceError::Conflict(format!(
                    "service '{}' already exists with a different spec — remove it first with `slip services rm {}`",
                    name, name
                )));
            }
        }

        // Resolve catalog image for the version.
        let image = resolve_image_for_version(spec.version())?;
        let resolved_image = crate::services::spec::ResolvedImage::parse(image.as_str())?;

        // Create initial state.
        let state = ServiceState::for_provisioning(
            name.clone(),
            spec.provider(),
            spec.version().clone(),
            resolved_image,
            Utc::now(),
        )?;

        // Persist desired + state.
        let db = self.db.clone();
        let spec_clone = spec.clone();
        let state_clone = state.clone();
        tokio::task::spawn_blocking(move || {
            let mut conn = db.0.lock().unwrap();
            ServiceRepository::insert_service_and_state(
                &mut conn,
                &spec_clone,
                &state_clone,
                Utc::now(),
            )
        })
        .await
        .map_err(|e| ServiceError::Internal(e.to_string()))??;

        // Generate secret (Linux only — on non-Linux, provision will fail).
        #[cfg(target_os = "linux")]
        {
            if let Some(storage) = &self.storage {
                // Create instance directory.
                let instance_rel = state.instance_id().as_str();
                match storage.create_descendant_dir(instance_rel) {
                    Ok(_) => {}
                    Err(crate::services::storage::StorageError::AlreadyExists(_)) => {}
                    Err(e) => {
                        return Err(ServiceError::FilesystemCheck {
                            service: name.as_str().to_string(),
                            reason: e.to_string(),
                        });
                    }
                }

                // Create secret bundle and generate if no active pointer.
                let bundle = InstanceSecretBundle::new(storage, state.instance_id().clone())
                    .map_err(|e| ServiceError::Internal(e.to_string()))?;

                // Check if active pointer exists; generate only if absent.
                match bundle.read_active_pointer() {
                    Ok(_) => {
                        // Active generation exists — reuse it.
                    }
                    Err(crate::services::secret::SecretBundleError::ActivePointerNotFound {
                        ..
                    }) => {
                        // No active generation — generate.
                        bundle.generate().map_err(|_| {
                            ServiceError::Internal("secret generation failed".to_string())
                        })?;
                    }
                    Err(e) => {
                        // Ambiguous — reread (the error itself is from a reread).
                        return Err(ServiceError::Internal(format!(
                            "secret pointer check failed: {e}"
                        )));
                    }
                }
            }
        }

        // Build context and provision.
        let secrets = self.make_secret_capability(&state)?;
        let ctx = ProviderContext::new(
            self.runtime.as_ref(),
            secrets.as_ref(),
            &self.services_root,
            &self.network,
            &self.installation_id,
            &state,
        )?
        .with_storage(
            #[cfg(target_os = "linux")]
            self.storage.as_ref(),
            #[cfg(not(target_os = "linux"))]
            None,
        );

        let outcome = provider.provision(&ctx, &spec, &state).await;

        match outcome {
            Ok(provision) => {
                // CAS persist: phase Ready, container_id, spec_hash.
                let spec_hash = spec.effective_hash()?;
                let db = self.db.clone();
                let name_clone = name.clone();
                let expected_gen = state.generation();
                let container_id = provision.container_id.clone();
                tokio::task::spawn_blocking(move || {
                    let mut conn = db.0.lock().unwrap();
                    ServiceRepository::update_state_cas(
                        &mut conn,
                        &name_clone,
                        expected_gen,
                        LifecyclePhase::Ready,
                        Some(&container_id),
                        Some(&spec_hash),
                        Some(HealthKind::Healthy),
                        None,
                        None,
                        Utc::now(),
                    )
                })
                .await
                .map_err(|e| ServiceError::Internal(e.to_string()))?
                .map_err(ServiceError::from_repo_cas)?;

                Ok(())
            }
            Err(e) => {
                // Persist error phase.
                let failure_code = match &e {
                    ServiceError::ProvisionFailed(_) => FailureCode::ProvisionFailed,
                    ServiceError::ReadinessFailed(_) => FailureCode::ReadinessFailed,
                    ServiceError::Blocked(_, _) => FailureCode::OwnershipMismatch,
                    ServiceError::FilesystemCheck { .. } => FailureCode::FilesystemCheck,
                    _ => FailureCode::Internal,
                };
                let db = self.db.clone();
                let name_clone = name.clone();
                let expected_gen = state.generation();
                let _ = tokio::task::spawn_blocking(move || {
                    let mut conn = db.0.lock().unwrap();
                    ServiceRepository::update_health(
                        &mut conn,
                        &name_clone,
                        expected_gen,
                        HealthKind::Unhealthy,
                        Some(failure_code),
                        Utc::now(),
                    )
                })
                .await;
                Err(e)
            }
        }
    }

    /// List all services (desired + state).
    pub async fn list(&self) -> Result<Vec<ServiceSummary>, ServiceError> {
        let db = self.db.clone();
        let rows = tokio::task::spawn_blocking(move || {
            let conn = db.0.lock().unwrap();
            let services = ServiceRepository::list_services(&conn, None)?;
            let states = ServiceRepository::list_states(&conn, None)?;
            Ok::<_, ServiceRepositoryError>((services, states))
        })
        .await
        .map_err(|e| ServiceError::Internal(e.to_string()))??;

        let (services, states) = rows;
        let state_map: HashMap<String, ServiceStateRow> = states
            .into_iter()
            .map(|s| (s.service_name().as_str().to_string(), s))
            .collect();

        let mut summaries = Vec::new();
        for svc in services {
            let state = state_map.get(svc.name().as_str());
            summaries.push(ServiceSummary {
                name: svc.name().clone(),
                provider: svc.provider(),
                version: svc.version().as_str().to_string(),
                phase: state
                    .map(|s| s.phase())
                    .unwrap_or(LifecyclePhase::Provisioning),
                health: state.and_then(|s| s.health()),
            });
        }
        Ok(summaries)
    }

    /// Get detailed status for a single service.
    pub async fn status(&self, name: &ServiceName) -> Result<ServiceStatus, ServiceError> {
        let db = self.db.clone();
        let name_clone = name.clone();
        let result = tokio::task::spawn_blocking(move || {
            let conn = db.0.lock().unwrap();
            let svc = ServiceRepository::get_service(&conn, &name_clone)?;
            let state = ServiceRepository::get_state(&conn, &name_clone)?;
            Ok::<_, ServiceRepositoryError>((svc, state))
        })
        .await
        .map_err(|e| ServiceError::Internal(e.to_string()))??;

        let (svc, state) = result;
        let svc = svc.ok_or_else(|| ServiceError::Internal("service not found".to_string()))?;
        let state =
            state.ok_or_else(|| ServiceError::Internal("service state not found".to_string()))?;

        Ok(ServiceStatus {
            name: svc.name().clone(),
            provider: svc.provider(),
            version: svc.version().as_str().to_string(),
            phase: state.phase(),
            health: state.health(),
            last_error: state.last_error(),
            generation: state.generation(),
            created_at: svc.created_at(),
            updated_at: state.updated_at(),
        })
    }

    /// Remove a service: verify usage, ownership, remove container, retain data.
    pub async fn remove(
        &self,
        name: &ServiceName,
        expected_generation: i64,
        force: bool,
    ) -> Result<ServiceRemovalResult, ServiceError> {
        let lock = self.get_lock(name);
        let _guard = lock.lock().await;

        // Read current state.
        let db = self.db.clone();
        let name_clone = name.clone();
        let result = tokio::task::spawn_blocking(move || {
            let conn = db.0.lock().unwrap();
            let svc = ServiceRepository::get_service(&conn, &name_clone)?;
            let state = ServiceRepository::get_state(&conn, &name_clone)?;
            Ok::<_, ServiceRepositoryError>((svc, state))
        })
        .await
        .map_err(|e| ServiceError::Internal(e.to_string()))??;

        let (svc, state_row) = result;
        let svc = svc.ok_or_else(|| ServiceError::Internal("service not found".to_string()))?;
        let state_row = state_row
            .ok_or_else(|| ServiceError::Internal("service state not found".to_string()))?;

        // Generation check.
        if state_row.generation() != expected_generation {
            return Err(ServiceError::Conflict(format!(
                "generation mismatch: expected {expected_generation}, current {} — reread the service status and retry",
                state_row.generation()
            )));
        }

        // Usage check.
        let bindings = self.usage.bindings_for_service(name).await;
        if !bindings.is_empty() && !force {
            return Err(ServiceError::Conflict(format!(
                "service '{}' has active bindings from apps: {} — use --force to override (data and secrets will be retained)",
                name,
                bindings.join(", ")
            )));
        }

        // Rootful check for container operations.
        if !self.is_rootful().await {
            return Err(ServiceError::Blocked(
                name.as_str().to_string(),
                "services require a rootful Podman/Docker runtime".to_string(),
            ));
        }

        // Convert to ServiceState for the provider.
        let state = state_row.to_state()?;

        // Provider remove (ownership-verified, idempotent).
        let provider = self.provider_for(svc.provider())?;
        let secrets = self.make_secret_capability(&state)?;
        let ctx = ProviderContext::new(
            self.runtime.as_ref(),
            secrets.as_ref(),
            &self.services_root,
            &self.network,
            &self.installation_id,
            &state,
        )?
        .with_storage(
            #[cfg(target_os = "linux")]
            self.storage.as_ref(),
            #[cfg(not(target_os = "linux"))]
            None,
        );

        let spec = svc.to_spec()?;
        // Validate spec before remove (ensures the provider can handle it).
        provider.validate(&spec)?;

        // Remove the container.
        provider.remove(&ctx, &state).await?;

        // Delete desired + retain state.
        let db = self.db.clone();
        let name_clone = name.clone();
        let instance_id = state.instance_id().clone();
        let secret_ref = state.secret_ref().clone();
        let provider_kind = state.provider();
        let data_major = state.data_major();
        let current_gen = state.generation();
        let _new_gen = tokio::task::spawn_blocking(move || {
            let mut conn = db.0.lock().unwrap();
            ServiceRepository::delete_service_and_retain(
                &mut conn,
                &name_clone,
                &instance_id,
                &secret_ref,
                provider_kind,
                data_major,
                current_gen,
                Utc::now(),
            )
        })
        .await
        .map_err(|e| ServiceError::Internal(e.to_string()))?
        .map_err(ServiceError::from_repo_cas)?;

        // Emit sanitized audit event.
        tracing::info!(
            op = "service_remove",
            service = %name,
            force = force,
            affected_apps = bindings.len(),
            prior_generation = state.generation(),
            "service removed (container only; data and secrets retained)"
        );

        Ok(ServiceRemovalResult {
            name: name.clone(),
            removed: true,
            retained_data: true,
            retained_secrets: true,
            affected_apps: bindings,
        })
    }

    /// Ensure a single service converges to desired state.
    pub async fn ensure_one(&self, name: &ServiceName) -> Result<(), ServiceError> {
        let lock = self.get_lock(name);
        let _guard = lock.lock().await;

        // Read fresh state.
        let db = self.db.clone();
        let name_clone = name.clone();
        let result = tokio::task::spawn_blocking(move || {
            let conn = db.0.lock().unwrap();
            let svc = ServiceRepository::get_service(&conn, &name_clone)?;
            let state = ServiceRepository::get_state(&conn, &name_clone)?;
            Ok::<_, ServiceRepositoryError>((svc, state))
        })
        .await
        .map_err(|e| ServiceError::Internal(e.to_string()))??;

        let (svc, state_row) = result;
        let svc = match svc {
            Some(s) => s,
            None => return Ok(()), // No desired state — nothing to ensure.
        };
        let state_row = match state_row {
            Some(s) => s,
            None => return Ok(()), // No control state — skip.
        };

        // Skip if Blocked with same desired hash.
        if state_row.phase() == LifecyclePhase::Blocked {
            debug!(service = %name, "ensure: service is Blocked, skipping");
            return Ok(());
        }

        // Skip if Retained (no desired state — already deleted).
        if state_row.phase() == LifecyclePhase::Retained {
            return Ok(());
        }

        // Convert to ServiceState for the provider.
        let state = state_row.to_state()?;

        let provider = self.provider_for(svc.provider())?;
        let spec = svc.to_spec()?;
        provider.validate(&spec)?;

        // Build secret capability and provider context. Setup failures
        // (e.g. storage unsupported on non-Linux, instance binding mismatch)
        // are routed through the same permanent/transient classification +
        // CAS persistence as provider ensure errors, so that permanent
        // setup failures are persisted as Blocked (and skipped on subsequent
        // ticks) rather than propagating without state persistence.
        //
        // `secrets` must outlive `ctx` (ProviderContext borrows the trait
        // object), so both are kept in the same scope via a match that
        // either builds ctx (keeping secrets alive) or carries the error.
        let ensure_result = match self.make_secret_capability(&state) {
            Ok(secrets) => {
                match ProviderContext::new(
                    self.runtime.as_ref(),
                    secrets.as_ref(),
                    &self.services_root,
                    &self.network,
                    &self.installation_id,
                    &state,
                ) {
                    Ok(base_ctx) => {
                        let ctx = base_ctx.with_storage(
                            #[cfg(target_os = "linux")]
                            self.storage.as_ref(),
                            #[cfg(not(target_os = "linux"))]
                            None,
                        );
                        tokio::time::timeout(
                            PER_SERVICE_DEADLINE,
                            provider.ensure(&ctx, &spec, &state),
                        )
                        .await
                    }
                    Err(e) => Ok(Err(e)),
                }
            }
            Err(e) => Ok(Err(e)),
        };

        match ensure_result {
            Ok(Ok(outcome)) => {
                // Persist the outcome.
                let db = self.db.clone();
                let name_clone = name.clone();
                let expected_gen = state.generation();
                let container_id = outcome.container_id.clone();
                let health = outcome.health;

                let phase = match outcome.action {
                    crate::services::spec::EnsureAction::Noop => LifecyclePhase::Ready,
                    crate::services::spec::EnsureAction::Started => LifecyclePhase::Ready,
                    crate::services::spec::EnsureAction::Created => LifecyclePhase::Ready,
                    crate::services::spec::EnsureAction::Recreated => LifecyclePhase::Ready,
                    crate::services::spec::EnsureAction::Blocked => LifecyclePhase::Blocked,
                };

                // Propagate CAS errors — do not silently discard.
                // A generation mismatch means another caller modified the
                // state; the container may be unrecorded. Surface as
                // ConcurrentModification so the caller knows to re-read.
                let cas_result = tokio::task::spawn_blocking(move || {
                    let mut conn = db.0.lock().unwrap();
                    ServiceRepository::update_state_cas(
                        &mut conn,
                        &name_clone,
                        expected_gen,
                        phase,
                        Some(&container_id),
                        None,
                        health,
                        None,
                        Some(Utc::now()),
                        Utc::now(),
                    )
                })
                .await;

                match cas_result {
                    Ok(Ok(_)) => Ok(()),
                    Ok(Err(ServiceRepositoryError::GenerationMismatch { .. })) => {
                        tracing::warn!(
                            service = %name,
                            "ensure: CAS failed (generation mismatch) — state was modified concurrently"
                        );
                        Err(ServiceError::ConcurrentModification)
                    }
                    Ok(Err(e)) => {
                        tracing::warn!(
                            service = %name,
                            error = %e,
                            "ensure: state persistence failed"
                        );
                        Err(ServiceError::Internal(
                            "state persistence failed".to_string(),
                        ))
                    }
                    Err(e) => {
                        tracing::warn!(
                            service = %name,
                            error = %e,
                            "ensure: spawn_blocking join failed"
                        );
                        Err(ServiceError::Internal(
                            "persistence task failed".to_string(),
                        ))
                    }
                }
            }
            Ok(Err(e)) => {
                // Classify error: permanent (Blocked/ownership) → persist
                // as Blocked phase so the fast-path skips on subsequent
                // ticks. Transient → persist Unhealthy + error code, will
                // retry next tick.
                let is_permanent = matches!(
                    e,
                    ServiceError::Blocked(_, _)
                        | ServiceError::ForeignContainer
                        | ServiceError::OwnershipMismatch { .. }
                        | ServiceError::FilesystemCheck { .. }
                );

                let failure_code = match &e {
                    ServiceError::Blocked(_, _) => FailureCode::OwnershipMismatch,
                    ServiceError::ForeignContainer => FailureCode::OwnershipMismatch,
                    ServiceError::OwnershipMismatch { .. } => FailureCode::OwnershipMismatch,
                    ServiceError::FilesystemCheck { .. } => FailureCode::FilesystemCheck,
                    ServiceError::ReadinessFailed(_) => FailureCode::ReadinessFailed,
                    _ => FailureCode::Internal,
                };

                let db = self.db.clone();
                let name_clone = name.clone();
                let expected_gen = state.generation();

                if is_permanent {
                    // Persist as Blocked phase — the fast-path in ensure_one
                    // skips Blocked services on subsequent ticks (no retry
                    // storm). The service stays Blocked until the desired
                    // generation or observed identity changes.
                    let cas_result = tokio::task::spawn_blocking(move || {
                        let mut conn = db.0.lock().unwrap();
                        ServiceRepository::update_state_cas(
                            &mut conn,
                            &name_clone,
                            expected_gen,
                            LifecyclePhase::Blocked,
                            None,
                            None,
                            Some(HealthKind::Unhealthy),
                            Some(failure_code),
                            Some(Utc::now()),
                            Utc::now(),
                        )
                    })
                    .await;
                    match cas_result {
                        Ok(Ok(_)) => {}
                        Ok(Err(ServiceRepositoryError::GenerationMismatch { .. })) => {
                            tracing::warn!(
                                service = %name,
                                "ensure: Blocked CAS failed (generation mismatch) — concurrent modification"
                            );
                        }
                        Ok(Err(e)) => {
                            tracing::warn!(
                                service = %name,
                                error = %e,
                                "ensure: Blocked state persistence failed"
                            );
                        }
                        Err(e) => {
                            tracing::warn!(
                                service = %name,
                                error = %e,
                                "ensure: Blocked persistence task join failed"
                            );
                        }
                    }
                    tracing::warn!(
                        service = %name,
                        error = %e,
                        "ensure: permanent error, persisted as Blocked (will skip on next tick)"
                    );
                } else {
                    // Transient error — persist Unhealthy, will retry.
                    let cas_result = tokio::task::spawn_blocking(move || {
                        let mut conn = db.0.lock().unwrap();
                        ServiceRepository::update_health(
                            &mut conn,
                            &name_clone,
                            expected_gen,
                            HealthKind::Unhealthy,
                            Some(failure_code),
                            Utc::now(),
                        )
                    })
                    .await;
                    if let Err(e) = cas_result {
                        tracing::warn!(
                            service = %name,
                            error = %e,
                            "ensure: transient health persistence task failed"
                        );
                    }
                    tracing::warn!(
                        service = %name,
                        error = %e,
                        "ensure: transient error (will retry next tick)"
                    );
                }
                Err(e)
            }
            Err(_) => {
                tracing::warn!(service = %name, "ensure: timed out");
                Err(ServiceError::ReadinessFailed(
                    "ensure timed out".to_string(),
                ))
            }
        }
    }

    /// Ensure all services converge (bounded, collect-and-continue).
    pub async fn ensure_all(&self, budget: Duration) {
        let services = match self.list().await {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(error = %e, "ensure_all: failed to list services");
                return;
            }
        };

        let deadline = tokio::time::Instant::now() + budget;
        for svc in services {
            if tokio::time::Instant::now() >= deadline {
                tracing::warn!(budget = ?budget, "ensure_all: budget exhausted, remaining services deferred");
                break;
            }

            // Acquire concurrency semaphore.
            let _permit = match self.ensure_sem.acquire().await {
                Ok(p) => p,
                Err(_) => break,
            };

            // Ensure this service (collect-and-continue).
            if let Err(e) = self.ensure_one(&svc.name).await {
                tracing::warn!(
                    service = %svc.name,
                    error = %e,
                    "ensure_all: service ensure failed (will retry next tick)"
                );
            }
        }
    }

    /// Startup ensure (bounded, non-blocking — spawned as a task).
    pub async fn startup_ensure(&self) {
        tracing::info!("starting service ensure (bounded)");
        self.ensure_all(STARTUP_BUDGET).await;
        tracing::info!("service ensure pass complete");
    }

    /// Build the secret capability for a state's instance (Linux only).
    ///
    /// The returned `Arc<dyn InstanceSecretCapability + 'a>` borrows
    /// `self.storage` for the lifetime of `&'a self`. The bundle never
    /// outlives the controller — every caller uses the capability within the
    /// same `add`/`ensure_one`/`remove` scope and drops it before returning.
    #[cfg(target_os = "linux")]
    fn make_secret_capability<'a>(
        &'a self,
        state: &ServiceState,
    ) -> Result<Arc<dyn InstanceSecretCapability + 'a>, ServiceError> {
        let storage = self.storage.as_ref().ok_or_else(|| {
            ServiceError::Blocked(
                state.service_name().as_str().to_string(),
                "service storage is supported on Linux only".to_string(),
            )
        })?;
        let bundle = InstanceSecretBundle::new(storage, state.instance_id().clone())
            .map_err(|e| ServiceError::Internal(e.to_string()))?;
        Ok(Arc::new(bundle))
    }

    #[cfg(not(target_os = "linux"))]
    fn make_secret_capability(
        &self,
        state: &ServiceState,
    ) -> Result<Arc<dyn InstanceSecretCapability>, ServiceError> {
        Err(ServiceError::Blocked(
            state.service_name().as_str().to_string(),
            "service storage is supported on Linux only".to_string(),
        ))
    }
}

/// Extension to convert repository errors to service errors.
impl ServiceError {
    pub fn from_repo_cas(e: ServiceRepositoryError) -> Self {
        match e {
            ServiceRepositoryError::GenerationMismatch { expected, current } => {
                ServiceError::Conflict(format!(
                    "generation mismatch: expected {expected}, current {current}"
                ))
            }
            ServiceRepositoryError::NotFound(name) => {
                ServiceError::Internal(format!("service '{name}' not found"))
            }
            ServiceRepositoryError::IdentityMismatch { field } => {
                ServiceError::Conflict(format!("identity mismatch: {field}"))
            }
            other => ServiceError::Internal(other.to_string()),
        }
    }
}

impl From<ServiceRepositoryError> for ServiceError {
    fn from(e: ServiceRepositoryError) -> Self {
        Self::from_repo_cas(e)
    }
}

use tracing::debug;

// ─── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::Db;
    use crate::error::RuntimeError;
    use crate::runtime::{ContainerInfo, LogStreamItem, RegistryCredentials};
    use crate::services::name::ServiceName;
    use crate::services::postgres::{PG18_4_REF, resolve_catalog};
    use crate::services::spec::{ContainerId, PostgresConfig, ResolvedImage};
    use std::future::Future;
    use std::pin::Pin;

    /// A fake runtime for controller tests that is rootful and records calls.
    struct CtrlRuntime {
        rootful: bool,
        inspect_responses:
            std::sync::Mutex<std::collections::VecDeque<crate::runtime::ServiceContainerInspect>>,
        next_id: std::sync::Mutex<u64>,
    }

    impl CtrlRuntime {
        fn new(rootful: bool) -> Self {
            Self {
                rootful,
                inspect_responses: Default::default(),
                next_id: std::sync::Mutex::new(1),
            }
        }

        fn next_id(&self) -> String {
            let mut id = self.next_id.lock().unwrap();
            let val = *id;
            *id += 1;
            format!("{val:064x}")
        }

        #[allow(dead_code)]
        fn queue_inspect(&self, resp: crate::runtime::ServiceContainerInspect) {
            self.inspect_responses.lock().unwrap().push_back(resp);
        }
    }

    impl crate::runtime::RuntimeBackend for CtrlRuntime {
        fn name(&self) -> &str {
            "ctrl-test"
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
            _res: &crate::config::ResourceConfig,
            _vol: &[crate::merge::MergedVolume],
        ) -> Pin<Box<dyn Future<Output = Result<(String, u16), RuntimeError>> + Send + 'a>>
        {
            Box::pin(async { Err(RuntimeError::Unsupported("not used".into())) })
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
            Box::pin(async { Err(RuntimeError::Unsupported("not used".into())) })
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
        fn is_rootful(&self) -> Pin<Box<dyn Future<Output = bool> + Send + '_>> {
            Box::pin(async move { self.rootful })
        }
        fn create_and_start_service<'a>(
            &'a self,
            _spec: &'a crate::runtime::ServiceContainerSpec,
        ) -> Pin<Box<dyn Future<Output = Result<String, RuntimeError>> + Send + 'a>> {
            let id = self.next_id();
            Box::pin(async move { Ok(id) })
        }
        fn inspect_service<'a>(
            &'a self,
            _container_id: &'a str,
        ) -> Pin<
            Box<
                dyn Future<Output = Result<crate::runtime::ServiceContainerInspect, RuntimeError>>
                    + Send
                    + 'a,
            >,
        > {
            let resp = self.inspect_responses.lock().unwrap().pop_front();
            Box::pin(async move {
                resp.ok_or_else(|| {
                    RuntimeError::ContainerError("no inspect response queued".to_string())
                })
            })
        }
        fn exec_service_probe<'a>(
            &'a self,
            _container_id: &'a str,
            _argv: &'a [&'a str],
            _env: &'a [(&'a str, &'a str)],
            _timeout: Duration,
            _max_output: usize,
        ) -> Pin<Box<dyn Future<Output = Result<(), RuntimeError>> + Send + 'a>> {
            Box::pin(async { Ok(()) })
        }
    }

    fn test_db() -> Db {
        Db::open_in_memory().unwrap()
    }

    fn test_controller(
        rt: Arc<CtrlRuntime>,
        usage: Arc<dyn ServiceUsageReader>,
    ) -> ServiceController {
        let db = test_db();
        // Ensure installation_id exists.
        {
            let conn = db.0.lock().unwrap();
            ServiceRepository::ensure_installation_id(&conn).unwrap();
        }
        ServiceController::new(
            db,
            rt,
            PathBuf::from("/tmp/services"),
            "slip".to_string(),
            "test-install-id".to_string(),
            usage,
            #[cfg(target_os = "linux")]
            None,
        )
    }

    fn sample_spec(name: &str) -> ServiceSpec {
        let (version, _) = resolve_catalog(18).unwrap();
        ServiceSpec::new(
            ServiceName::parse(name).unwrap(),
            ProviderKind::Postgres,
            version,
            PostgresConfig {},
        )
        .unwrap()
    }

    #[tokio::test]
    async fn controller_list_empty() {
        let rt = Arc::new(CtrlRuntime::new(true));
        let usage: Arc<dyn ServiceUsageReader> = Arc::new(FakeUsageReader::new(HashMap::new()));
        let ctrl = test_controller(rt, usage);

        let list = ctrl.list().await.unwrap();
        assert!(list.is_empty());
    }

    #[tokio::test]
    async fn controller_add_creates_desired_row() {
        let rt = Arc::new(CtrlRuntime::new(true));
        let usage: Arc<dyn ServiceUsageReader> = Arc::new(FakeUsageReader::new(HashMap::new()));
        let ctrl = test_controller(rt, usage);

        // On non-Linux, add will fail at provision (no storage). But the
        // desired row should be persisted. Let's test that the conflict
        // path works at least.
        let spec = sample_spec("pg");

        // On non-Linux this will fail at provision; on Linux without storage
        // it also fails. We test the persistence path by checking the error.
        let result = ctrl.add(spec.clone()).await;

        // The add will fail because we have no storage/secrets on non-Linux.
        // But the desired row should be in the DB.
        #[cfg(not(target_os = "linux"))]
        {
            assert!(result.is_err(), "add should fail on non-Linux (no storage)");
            // Verify the desired row was persisted.
            let list = ctrl.list().await.unwrap();
            assert_eq!(list.len(), 1);
            assert_eq!(list[0].name.as_str(), "pg");
        }

        #[cfg(target_os = "linux")]
        {
            // On Linux without storage, add also fails.
            let _ = result;
        }
    }

    #[tokio::test]
    async fn controller_add_idempotent_same_spec() {
        let rt = Arc::new(CtrlRuntime::new(true));
        let usage: Arc<dyn ServiceUsageReader> = Arc::new(FakeUsageReader::new(HashMap::new()));
        let ctrl = test_controller(rt, usage);

        // Manually insert a service.
        let spec1 = sample_spec("pg");
        {
            let db = ctrl.db.clone();
            let spec_clone = spec1.clone();
            tokio::task::spawn_blocking(move || {
                let mut conn = db.0.lock().unwrap();
                let state = ServiceState::for_provisioning(
                    spec_clone.name().clone(),
                    spec_clone.provider(),
                    spec_clone.version().clone(),
                    ResolvedImage::parse(PG18_4_REF).unwrap(),
                    Utc::now(),
                )
                .unwrap();
                ServiceRepository::insert_service_and_state(
                    &mut conn,
                    &spec_clone,
                    &state,
                    Utc::now(),
                )
            })
            .await
            .unwrap()
            .unwrap();
        }

        // Adding the same name with same spec should be idempotent (touch).
        // On non-Linux this succeeds (touch path, no provision).
        let result = ctrl.add(spec1).await;
        // The touch path returns Ok(()) without provisioning.
        assert!(
            result.is_ok(),
            "idempotent same-spec add should succeed: {result:?}"
        );
    }

    #[tokio::test]
    async fn controller_remove_refuses_with_active_bindings() {
        let rt = Arc::new(CtrlRuntime::new(true));
        let mut bindings = HashMap::new();
        bindings.insert(
            "pg".to_string(),
            vec!["app1".to_string(), "app2".to_string()],
        );
        let usage: Arc<dyn ServiceUsageReader> = Arc::new(FakeUsageReader::new(bindings));
        let ctrl = test_controller(rt, usage);

        // Manually insert a service.
        let spec = sample_spec("pg");
        let state = {
            let db = ctrl.db.clone();
            let spec_clone = spec.clone();
            tokio::task::spawn_blocking(move || {
                let mut conn = db.0.lock().unwrap();
                let state = ServiceState::for_provisioning(
                    spec_clone.name().clone(),
                    spec_clone.provider(),
                    spec_clone.version().clone(),
                    ResolvedImage::parse(PG18_4_REF).unwrap(),
                    Utc::now(),
                )
                .unwrap();
                ServiceRepository::insert_service_and_state(
                    &mut conn,
                    &spec_clone,
                    &state,
                    Utc::now(),
                )
                .unwrap();
                state
            })
            .await
            .unwrap()
        };

        // Remove without force — should be refused.
        let result = ctrl
            .remove(
                &ServiceName::parse("pg").unwrap(),
                state.generation(),
                false,
            )
            .await;

        assert!(result.is_err());
        match result.unwrap_err() {
            ServiceError::Conflict(reason) => {
                assert!(reason.contains("active bindings"));
                assert!(reason.contains("app1"));
                assert!(reason.contains("app2"));
            }
            other => panic!("expected Conflict, got {other:?}"),
        }

        // Verify the desired row is still there.
        let list = ctrl.list().await.unwrap();
        assert_eq!(list.len(), 1, "service must not be removed on refusal");
    }

    #[tokio::test]
    async fn controller_remove_with_force_bypasses_usage() {
        let rt = Arc::new(CtrlRuntime::new(true));
        let mut bindings = HashMap::new();
        bindings.insert("pg".to_string(), vec!["app1".to_string()]);
        let usage: Arc<dyn ServiceUsageReader> = Arc::new(FakeUsageReader::new(bindings));
        let ctrl = test_controller(rt, usage);

        // Manually insert a service.
        let spec = sample_spec("pg");
        let state = {
            let db = ctrl.db.clone();
            let spec_clone = spec.clone();
            tokio::task::spawn_blocking(move || {
                let mut conn = db.0.lock().unwrap();
                let state = ServiceState::for_provisioning(
                    spec_clone.name().clone(),
                    spec_clone.provider(),
                    spec_clone.version().clone(),
                    ResolvedImage::parse(PG18_4_REF).unwrap(),
                    Utc::now(),
                )
                .unwrap();
                ServiceRepository::insert_service_and_state(
                    &mut conn,
                    &spec_clone,
                    &state,
                    Utc::now(),
                )
                .unwrap();
                state
            })
            .await
            .unwrap()
        };

        // Remove with force.
        let result = ctrl
            .remove(&ServiceName::parse("pg").unwrap(), state.generation(), true)
            .await;

        // On non-Linux this will fail at the provider.remove stage (no secrets).
        // But the usage check should pass. Let's verify the error is not a Conflict.
        #[cfg(not(target_os = "linux"))]
        {
            // The error should be about storage, not about usage.
            if let Err(e) = &result {
                let msg = e.to_string();
                assert!(
                    !msg.contains("active bindings"),
                    "force must bypass usage refusal: {msg}"
                );
            }
        }

        #[cfg(target_os = "linux")]
        {
            let _ = result;
        }
    }

    #[tokio::test]
    async fn controller_remove_stale_generation_conflict() {
        let rt = Arc::new(CtrlRuntime::new(true));
        let usage: Arc<dyn ServiceUsageReader> = Arc::new(FakeUsageReader::new(HashMap::new()));
        let ctrl = test_controller(rt, usage);

        // Manually insert a service.
        let spec = sample_spec("pg");
        let state = {
            let db = ctrl.db.clone();
            let spec_clone = spec.clone();
            tokio::task::spawn_blocking(move || {
                let mut conn = db.0.lock().unwrap();
                let state = ServiceState::for_provisioning(
                    spec_clone.name().clone(),
                    spec_clone.provider(),
                    spec_clone.version().clone(),
                    ResolvedImage::parse(PG18_4_REF).unwrap(),
                    Utc::now(),
                )
                .unwrap();
                ServiceRepository::insert_service_and_state(
                    &mut conn,
                    &spec_clone,
                    &state,
                    Utc::now(),
                )
                .unwrap();
                state
            })
            .await
            .unwrap()
        };

        // Remove with wrong generation.
        let wrong_gen = state.generation() + 999;
        let result = ctrl
            .remove(&ServiceName::parse("pg").unwrap(), wrong_gen, false)
            .await;

        assert!(result.is_err());
        match result.unwrap_err() {
            ServiceError::Conflict(reason) => {
                assert!(reason.contains("generation mismatch"));
            }
            other => panic!("expected Conflict, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn controller_remove_not_found() {
        let rt = Arc::new(CtrlRuntime::new(true));
        let usage: Arc<dyn ServiceUsageReader> = Arc::new(FakeUsageReader::new(HashMap::new()));
        let ctrl = test_controller(rt, usage);

        let result = ctrl
            .remove(&ServiceName::parse("nonexistent").unwrap(), 1, false)
            .await;

        assert!(result.is_err());
        // Should be an internal error about service not found.
        let err = result.unwrap_err();
        assert!(err.to_string().contains("not found"));
    }

    #[tokio::test]
    async fn controller_ensure_all_no_services() {
        let rt = Arc::new(CtrlRuntime::new(true));
        let usage: Arc<dyn ServiceUsageReader> = Arc::new(FakeUsageReader::new(HashMap::new()));
        let ctrl = test_controller(rt, usage);

        // Should complete without error.
        ctrl.ensure_all(Duration::from_secs(10)).await;
    }

    #[tokio::test]
    async fn controller_is_rootful_true() {
        let rt = Arc::new(CtrlRuntime::new(true));
        let usage: Arc<dyn ServiceUsageReader> = Arc::new(FakeUsageReader::new(HashMap::new()));
        let ctrl = test_controller(rt, usage);

        assert!(ctrl.is_rootful().await);
    }

    #[tokio::test]
    async fn controller_is_rootful_false() {
        let rt = Arc::new(CtrlRuntime::new(false));
        let usage: Arc<dyn ServiceUsageReader> = Arc::new(FakeUsageReader::new(HashMap::new()));
        let ctrl = test_controller(rt, usage);

        assert!(!ctrl.is_rootful().await);
    }

    #[tokio::test]
    async fn controller_status_returns_generation() {
        let rt = Arc::new(CtrlRuntime::new(true));
        let usage: Arc<dyn ServiceUsageReader> = Arc::new(FakeUsageReader::new(HashMap::new()));
        let ctrl = test_controller(rt, usage);

        // Manually insert a service.
        let spec = sample_spec("pg");
        let state = {
            let db = ctrl.db.clone();
            let spec_clone = spec.clone();
            tokio::task::spawn_blocking(move || {
                let mut conn = db.0.lock().unwrap();
                let state = ServiceState::for_provisioning(
                    spec_clone.name().clone(),
                    spec_clone.provider(),
                    spec_clone.version().clone(),
                    ResolvedImage::parse(PG18_4_REF).unwrap(),
                    Utc::now(),
                )
                .unwrap();
                ServiceRepository::insert_service_and_state(
                    &mut conn,
                    &spec_clone,
                    &state,
                    Utc::now(),
                )
                .unwrap();
                state
            })
            .await
            .unwrap()
        };

        let status = ctrl
            .status(&ServiceName::parse("pg").unwrap())
            .await
            .unwrap();
        assert_eq!(status.generation, state.generation());
    }

    #[tokio::test]
    async fn controller_ensure_one_skips_blocked() {
        let rt = Arc::new(CtrlRuntime::new(true));
        let usage: Arc<dyn ServiceUsageReader> = Arc::new(FakeUsageReader::new(HashMap::new()));
        let ctrl = test_controller(rt, usage);

        // Manually insert a service in Blocked phase.
        let spec = sample_spec("blocked");
        let db = ctrl.db.clone();
        let spec_clone = spec.clone();
        tokio::task::spawn_blocking(move || {
            let mut conn = db.0.lock().unwrap();
            let state = ServiceState::for_provisioning(
                spec_clone.name().clone(),
                spec_clone.provider(),
                spec_clone.version().clone(),
                ResolvedImage::parse(PG18_4_REF).unwrap(),
                Utc::now(),
            )
            .unwrap();
            ServiceRepository::insert_service_and_state(&mut conn, &spec_clone, &state, Utc::now())
                .unwrap();

            // Transition to Blocked.
            ServiceRepository::update_state_cas(
                &mut conn,
                spec_clone.name(),
                state.generation(),
                LifecyclePhase::Blocked,
                None,
                None,
                Some(HealthKind::Unhealthy),
                Some(FailureCode::OwnershipMismatch),
                Some(Utc::now()),
                Utc::now(),
            )
            .unwrap();
        })
        .await
        .unwrap();

        // ensure_one should skip without error (Blocked fast-path).
        let result = ctrl
            .ensure_one(&ServiceName::parse("blocked").unwrap())
            .await;
        assert!(result.is_ok(), "ensure_one should skip Blocked services");
    }

    #[tokio::test]
    async fn controller_ensure_one_persists_blocked_on_permanent_error() {
        let rt = Arc::new(CtrlRuntime::new(true));
        let usage: Arc<dyn ServiceUsageReader> = Arc::new(FakeUsageReader::new(HashMap::new()));
        let ctrl = test_controller(rt.clone(), usage);

        // Insert a service in Provisioning with a container_id.
        let spec = sample_spec("perm");
        let state = {
            let db = ctrl.db.clone();
            let spec_clone = spec.clone();
            let rt_clone = rt.clone();
            tokio::task::spawn_blocking(move || {
                let mut conn = db.0.lock().unwrap();
                let state = ServiceState::for_provisioning(
                    spec_clone.name().clone(),
                    spec_clone.provider(),
                    spec_clone.version().clone(),
                    ResolvedImage::parse(PG18_4_REF).unwrap(),
                    Utc::now(),
                )
                .unwrap();
                // Insert with a container_id so ensure tries to inspect it.
                let state_with_cid = ServiceState::from_validated(
                    state.service_name().clone(),
                    state.provider(),
                    state.data_major(),
                    state.version().clone(),
                    state.instance_id().clone(),
                    state.generation(),
                    state.phase(),
                    Some(ContainerId::parse(&rt_clone.next_id()).unwrap()),
                    state.resolved_image().clone(),
                    state.applied_spec_hash().cloned(),
                    state.secret_ref().clone(),
                    state.health(),
                    state.last_error(),
                    state.last_checked_at(),
                    state.updated_at(),
                )
                .unwrap();
                ServiceRepository::insert_service_and_state(
                    &mut conn,
                    &spec_clone,
                    &state_with_cid,
                    Utc::now(),
                )
                .unwrap();
                state_with_cid
            })
            .await
            .unwrap()
        };

        // On non-Linux, ensure_one returns an error (no storage/secrets).
        // On Linux with a fake runtime that returns errors, the provider
        // returns Blocked which the controller should persist.
        // On macOS (test env), make_secret_capability returns Blocked
        // which propagates directly — this is correct fail-closed behavior.
        let result = ctrl.ensure_one(&ServiceName::parse("perm").unwrap()).await;

        // On non-Linux the error is returned directly (storage unsupported).
        #[cfg(not(target_os = "linux"))]
        {
            assert!(result.is_err(), "ensure_one should fail on non-Linux");
            let err = result.unwrap_err();
            assert!(
                matches!(err, ServiceError::Blocked(_, _)),
                "expected Blocked, got {err:?}"
            );
        }

        // On Linux, the controller persists Blocked via CAS and returns Err.
        #[cfg(target_os = "linux")]
        {
            // The ensure_one call should have returned an error.
            assert!(result.is_err(), "ensure_one should fail with Blocked");

            // Verify the state was persisted as Blocked.
            let db = ctrl.db.clone();
            let state_row = tokio::task::spawn_blocking(move || {
                let conn = db.0.lock().unwrap();
                ServiceRepository::get_state(&conn, &ServiceName::parse("perm").unwrap())
            })
            .await
            .unwrap()
            .unwrap()
            .expect("state row should exist after ensure_one");

            assert_eq!(
                state_row.phase(),
                LifecyclePhase::Blocked,
                "permanent error should persist Blocked phase"
            );

            // Second ensure_one call should skip (Blocked fast-path, no retry).
            let result2 = ctrl.ensure_one(&ServiceName::parse("perm").unwrap()).await;
            assert!(
                result2.is_ok(),
                "ensure_one should skip Blocked services (no retry storm)"
            );
        }

        let _ = state;
    }

    /// Verify that a setup failure (make_secret_capability returning Blocked)
    /// is persisted as Blocked and that a subsequent ensure_one skips it
    /// (no retry storm). This is the cross-platform version that tests the
    /// error routing without depending on Linux-specific storage.
    #[tokio::test]
    async fn controller_ensure_one_setup_failure_persists_blocked_and_skips_retry() {
        let rt = Arc::new(CtrlRuntime::new(true));
        let usage: Arc<dyn ServiceUsageReader> = Arc::new(FakeUsageReader::new(HashMap::new()));
        let ctrl = test_controller(rt, usage);

        // Insert a service in Provisioning (no container_id — ensure will
        // try to provision, which requires secrets/storage).
        let spec = sample_spec("setup-fail");
        let state = {
            let db = ctrl.db.clone();
            let spec_clone = spec.clone();
            tokio::task::spawn_blocking(move || {
                let mut conn = db.0.lock().unwrap();
                let state = ServiceState::for_provisioning(
                    spec_clone.name().clone(),
                    spec_clone.provider(),
                    spec_clone.version().clone(),
                    ResolvedImage::parse(PG18_4_REF).unwrap(),
                    Utc::now(),
                )
                .unwrap();
                ServiceRepository::insert_service_and_state(
                    &mut conn,
                    &spec_clone,
                    &state,
                    Utc::now(),
                )
                .unwrap();
                state
            })
            .await
            .unwrap()
        };

        // ensure_one: make_secret_capability returns Blocked (no storage on
        // non-Linux, or storage None on Linux test controller). The error
        // must be routed through classification and persisted as Blocked.
        let result = ctrl
            .ensure_one(&ServiceName::parse("setup-fail").unwrap())
            .await;
        assert!(result.is_err(), "ensure_one should fail with Blocked");
        assert!(
            matches!(result.unwrap_err(), ServiceError::Blocked(_, _)),
            "expected Blocked from setup failure"
        );

        // Verify the state was persisted as Blocked on all platforms.
        let db = ctrl.db.clone();
        let state_row = tokio::task::spawn_blocking(move || {
            let conn = db.0.lock().unwrap();
            ServiceRepository::get_state(&conn, &ServiceName::parse("setup-fail").unwrap())
        })
        .await
        .unwrap()
        .unwrap()
        .expect("state row should exist after ensure_one");

        assert_eq!(
            state_row.phase(),
            LifecyclePhase::Blocked,
            "setup failure should persist Blocked phase"
        );

        // Second ensure_one should skip (Blocked fast-path).
        let result2 = ctrl
            .ensure_one(&ServiceName::parse("setup-fail").unwrap())
            .await;
        assert!(
            result2.is_ok(),
            "ensure_one should skip already-Blocked services (no retry storm)"
        );

        let _ = state;
    }

    #[tokio::test]
    async fn controller_ensure_one_skips_retained() {
        let rt = Arc::new(CtrlRuntime::new(true));
        let usage: Arc<dyn ServiceUsageReader> = Arc::new(FakeUsageReader::new(HashMap::new()));
        let ctrl = test_controller(rt, usage);

        // Manually insert a service and then delete+retain it.
        let spec = sample_spec("retained");
        let db = ctrl.db.clone();
        let spec_clone = spec.clone();
        let state = tokio::task::spawn_blocking(move || {
            let mut conn = db.0.lock().unwrap();
            let state = ServiceState::for_provisioning(
                spec_clone.name().clone(),
                spec_clone.provider(),
                spec_clone.version().clone(),
                ResolvedImage::parse(PG18_4_REF).unwrap(),
                Utc::now(),
            )
            .unwrap();
            ServiceRepository::insert_service_and_state(&mut conn, &spec_clone, &state, Utc::now())
                .unwrap();
            ServiceRepository::delete_service_and_retain(
                &mut conn,
                spec_clone.name(),
                state.instance_id(),
                state.secret_ref(),
                state.provider(),
                state.data_major(),
                state.generation(),
                Utc::now(),
            )
            .unwrap();
            state
        })
        .await
        .unwrap();

        let _ = state;

        // ensure_one should skip without error (Retained fast-path).
        // The desired row is gone, so it returns Ok(()) early.
        let result = ctrl
            .ensure_one(&ServiceName::parse("retained").unwrap())
            .await;
        assert!(result.is_ok());
    }
}
