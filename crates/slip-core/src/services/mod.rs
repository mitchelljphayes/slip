//! Managed service-provider framework (SLIP-106, Part 1/3).
//!
//! A *service* is desired server state backed by a Slip-owned rootful Podman
//! container on the shared `slip` network, with stable DNS, persistent data,
//! no host ports, and startup plus periodic reconciliation.
//!
//! Part 1 defines the domain contracts and persistence foundation only:
//!
//! - [`name`]: canonical `ServiceName` newtype used at every boundary.
//! - [`spec`]: exportable `ServiceSpec`, internal `ServiceState`, provider
//!   kinds, version representation, opaque state newtypes, and the
//!   object-safe `ServiceProvider` trait.
//! - [`repository`]: typed SQLite persistence for desired and control state.
//!
//! Part 2 will add the hardened managed-container runtime and service-secret
//! facade. Part 3 will add the PostgreSQL 18 provider, controller, API, CLI,
//! and reconciliation.

pub mod name;
pub mod repository;
pub mod spec;

pub use name::{ServiceName, ServiceNameError, validate_service_name};
pub use repository::{ServiceRepository, ServiceRepositoryError, ServiceRow, ServiceStateRow};
pub use spec::{
    ContainerId, EnsureAction, EnsureOutcome, FailureCode, FakeInstanceSecrets, HealthKind,
    InstanceId, InstanceSecretCapability, LifecyclePhase, PostgresConfig, ProviderContext,
    ProviderKind, ProviderVersion, ProvisionOutcome, ResolvedImage, SecretPurpose, SecretRef,
    ServiceError, ServiceHealth, ServiceProvider, ServiceSpec, ServiceState, SpecHash,
};
