pub mod api;
pub mod auth;
pub mod caddy;
pub mod config;
pub mod db;
pub mod deploy;
pub mod diff;
pub mod docker;
pub mod doctor;
pub mod error;
pub mod health;
pub mod manifest;
pub mod merge;
pub mod podman;
pub mod preview;
pub mod reconcile;
pub mod registry;
pub mod repo_config;
pub mod runtime;
pub mod secrets;
pub mod services;
pub mod state;
pub mod status_expectation;
pub mod tailscale;
pub mod validate;

// Re-exports for convenience
pub use api::{
    AppResponse, AppState, DeployRequest, DeployResponse, DeploySummary, PreviewRequestInfo,
    StatusResponse, build_router,
};
pub use caddy::{
    CaddyClient, ReverseProxy, RouteInfo, RouteTlsDecision, TlsClassification, build_tls_policy,
    classify_host_tls, redact_external_error, resolve_route_tls, tls_policy_id,
};
pub use config::{
    AppConfig, AppInfo, AppPreviewConfig, AuthConfig, CaddyConfig, CaddyTlsConfig, DeployConfig,
    EnvFileConfig, HealthConfig, NetworkConfig, ReconcileConfig, RegistriesConfig, RegistryEntry,
    ResolveMode, ResourceConfig, RouteEntry, RoutingConfig, RuntimeConfig, ServerConfig,
    ServerDeployConfig, ServerPreviewConfig, SlipConfig, StorageConfig, TlsStrategy, VolumeConfig,
    format_duration, is_ts_net_host, load_config, load_config_check, load_config_with_mode,
    normalize_registry_url, parse_env_file, resolve_acme_email, resolve_env_vars,
    resolve_env_vars_warn, validate_tls_strategy,
};
pub use db::Db;
pub use deploy::{
    AppRuntimeState, AppStatus, DeployContext, DeployStatus, TriggerSource, execute_deploy,
};
pub use docker::{DockerClient, parse_cpu_limit, parse_memory_limit};
pub use doctor::{
    CheckStatus, CidrSet, DoctorAction, DoctorReport, Summary, VerificationCheck, aggregate_exit,
    classify_dns_expectation, classify_ip, classify_ufw, fetch_cloudflare_ranges,
    is_private_or_cgnat, module_present_exact, parse_caddy_modules, render_human,
};
pub use error::{CaddyError, ConfigError, HealthError, RuntimeError};
pub use health::{HealthCheck, HealthChecker};
pub use manifest::{ManifestError, RenderContext, render_manifest};
pub use merge::{MergedConfig, MergedVolume, merge_config};
pub use podman::PodmanBackend;
pub use preview::{PersistedPreviewState, PreviewState};
pub use reconcile::{
    ReconcileContext, ReconcileSummary, RouteFailure, default_backoff, reconcile_app_routes,
    reconcile_loop, reconcile_tick, run_reconcile,
};
pub use registry::{
    RegistryCredSource, ResolvedRegistry, merged_registry_table, normalize_image_ref,
    resolve_registry_credential,
};
pub use repo_config::{
    PreviewConfig, RemoteConfig, RepoConfig, RepoDeployConfig, RepoVolume, parse_repo_config,
};
pub use runtime::{
    ContainerInfo, LogStream, LogStreamItem, PodInfo, RegistryCredentials, RuntimeBackend,
};
pub use secrets::SecretsStore;
pub use state::{
    PersistedAppState, delete_preview_state, load_app_states, load_preview_states,
    reconcile_preview_routes, reconcile_routes, save_app_state, save_last_applied,
    save_preview_state, verify_containers,
};
pub use tailscale::{
    TAILSCALED_ENV_FILE, TAILSCALED_SOCKET, TailscalePreflight, TailscalePreflightError,
    check_caddy_user_permission, host_matches_cert_domains, parse_cert_domains,
    parse_self_hostname, preflight_tailscale,
};
pub use validate::{
    ValidationError, ValidationResult, parse_and_validate, validate_image_refs,
    validate_merged_volumes, validate_pod_manifest, validate_repo_config, validate_volumes,
};
