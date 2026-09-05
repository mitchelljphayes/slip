# Managed Service Framework

SLIP-106 introduces a managed-service framework for slip. A *service* is desired
server state backed by a Slip-owned rootful Podman container on the shared `slip`
network, with stable DNS, persistent data, no host ports, and startup plus
periodic reconciliation.

## Architecture

The framework has four layers:

1. **Domain contracts** (`services/spec.rs`): `ServiceSpec` (exportable), `ServiceState`
   (internal), `ServiceProvider` trait, `InstanceSecretCapability` trait,
   `ProviderContext`, `ServiceError`.
2. **Secure foundations** (`services/storage.rs`, `services/secret.rs`): Linux-only
   descriptor-confined storage and atomic instance-scoped secret bundles.
3. **PostgreSQL provider** (`services/postgres.rs`): implements `ServiceProvider` for
   PostgreSQL 18.4 with a pinned digest image, SCRAM auth, and mounted secrets.
4. **Controller** (`services/controller.rs`): provider-agnostic orchestration with
   per-service locks, generation CAS, usage boundary, and bounded reconciliation.

## Adding a provider

To add a new service provider:

1. **Add a `ProviderKind` variant** in `spec.rs` (e.g. `Redis`). This is a code change;
   arbitrary provider input is rejected.

2. **Implement `ServiceProvider`** in a new module (e.g. `services/redis.rs`):
   ```rust
   pub struct RedisProvider;
   impl ServiceProvider for RedisProvider {
       fn kind(&self) -> ProviderKind { ProviderKind::Redis }
       fn validate(&self, spec: &ServiceSpec) -> Result<(), ServiceError> { ... }
       fn provision<'a>(...) -> BoxFuture<'a, Result<ProvisionOutcome, ServiceError>> { ... }
       fn ensure<'a>(...) -> BoxFuture<'a, Result<EnsureOutcome, ServiceError>> { ... }
       fn health<'a>(...) -> BoxFuture<'a, Result<ServiceHealth, ServiceError>> { ... }
       fn remove<'a>(...) -> BoxFuture<'a, Result<(), ServiceError>> { ... }
   }
   ```

3. **Add an image catalog**: a `resolve_catalog(major) -> (ProviderVersion, PinnedImageRef)`
   function that maps a CLI major version to a normalized version and exact
   digest-pinned image reference. Resolve the digest via registry inspection
   and commit it as code with evidence in the build log.

4. **Register the provider** in `ServiceController::new()`:
   ```rust
   providers.insert(ProviderKind::Redis, Arc::new(RedisProvider::new()));
   ```

5. **Export the module** from `services/mod.rs`.

## Ownership labels

Every service container carries these labels, compared exactly during `ensure`
and `remove`:

| Label | Value |
|---|---|
| `slip.managed` | `true` |
| `slip.installation` | installation ID (per slip install) |
| `slip.service.name` | service name |
| `slip.service.instance` | instance ID (per data instance) |
| `slip.service.provider` | provider kind (e.g. `postgres`) |
| `slip.service.spec-hash` | canonical spec hash |
| `slip.service.secret-generation` | active secret generation name |
| `slip.label-schema` | `1` |

Any mismatch → `Blocked`, zero mutations.

## Ownership verification

Both `ensure` and `remove` verify the **full ownership tuple** before any
mutation:

- **Labels**: exact match (all 8 labels)
- **Image digest**: `repo_digests` contains the catalog digest (normalized
  for registry spelling: `docker.io` vs `index.docker.io`)
- **Network**: must be the sole network (`slip`)
- **Network aliases**: must include the service name
- **Ports**: must be empty (no host port bindings)
- **Restart policy**: must be `unless-stopped`
- **Mounts**: expected mount tuples (source/destination/read-only) must match
  exactly; no extra mounts allowed

Any mismatch → `Blocked`, zero start/stop/remove calls. The container is
reinspected by its persisted full ID immediately before `stop_and_remove`
in the `remove` path.

## PostgreSQL 18.4

### Image pin

The provider uses a single pinned image:

```
docker.io/library/postgres:18.4-bookworm@sha256:882236b897e39051d2368c5ccc6cda944904723506b2dfc97f2a8f5bc9afa382
```

**Update procedure:**

1. Run `docker buildx imagetools inspect docker.io/library/postgres:18.4-bookworm`
2. Copy the `Digest:` value (manifest index digest).
3. Replace `PG18_4_DIGEST` and `PG18_4_REF` in `services/postgres.rs`.
4. Record evidence in the build log and this doc.
5. The CI contract job will fail fast on digest drift.

### Data layout

- Host: `/var/lib/slip/services/<name>` (root-owned, 0700)
- Container mount: `/var/lib/postgresql` (rw)
- PG18 default PGDATA: `/var/lib/postgresql/18/docker`

### Security

- `POSTGRES_PASSWORD_FILE=/run/secrets/slip-raw-password` (never `POSTGRES_PASSWORD`)
- `POSTGRES_INITDB_ARGS=--auth-host=scram-sha-256 --auth-local=scram-sha-256` (no trust)
- `PGPASSFILE=/run/secrets/slip-pgpass` for authenticated readiness probes
- No host ports (enforced in spec construction and verified on ensure/remove)
- `unless-stopped` restart policy
- `no-new-privileges`, all caps dropped
- Read-only rootfs disabled (PG entrypoint requires write access on first init)
- Default seccomp is implicit (no explicit seccomp profile is set; the daemon
  default applies)
- Podman probe output is discarded via `Stdio::null()` (no unbounded buffering)

### DNS

- Container name: `slip-service-<name>`
- Network alias: `<name>` on the `slip` network
- App containers resolve `<name>:5432`

## Crash consistency

1. **Bootstrap marker**: `initializing` → `complete` (atomic, after verified
   readiness). If the parent-directory fsync after the `complete` rename fails,
   the provider restores an `initializing` marker via a compensating atomic
   temp+rename+fsync and returns a `FilesystemCheck` error — the controller
   never persists `Ready` for a marker whose durability barrier failed. If the
   compensating restore also fails, the error is honest about residual
   uncertainty (the marker may be stale). A subsequent provision attempt sees
   `initializing` and Blocks (operator must inspect).
2. **Secret generation**: once, before provision; never on ambiguous pointer
3. **Container ID**: persisted only after create + start + readiness succeeds
4. **Remove**: verify full ownership tuple → stop/remove container → atomic delete-and-retain
5. **Reconcile healing**: if a persisted container is missing (crash, manual
   removal), `ensure` detects the missing container and re-provisions from
   retained data + existing secret (no regeneration). The new container ID
   is persisted via CAS.
6. **Blocked fast-path**: permanent errors (ownership mismatch, foreign
   container, filesystem check) are persisted as `LifecyclePhase::Blocked`.
   Subsequent reconcile ticks skip Blocked services (no retry storm). The
   service stays Blocked until the desired state changes.

## Remove / force semantics

- Normal `rm`: refuses if active bindings exist (409 conflict + affected app names)
- `--force`: bypasses active-binding refusal ONLY; retains PGDATA + secrets + control state
- Both paths: remove only the verified container, transition to `Retained`
- No purge API in this version (future ticket)

## Reconciliation

- **Startup**: bounded ensure pass (60s budget), non-blocking — does not gate API start
- **Periodic**: service ensure runs before app routes in the reconcile tick
- **Blocked fast-path**: permanent mismatches are persisted once as `Blocked`, not retried
- **Collect-and-continue**: one bad service doesn't block others

## Reboot survival

Containers use `restart_policy: unless-stopped`, so they survive a host reboot
while slipd is down. The reconcile loop is the slipd-restart safety net.

**Reboot validation** is a manual gate (documented step, not automated):
1. Provision a service with a sentinel table + row.
2. Reboot the host (or stop slipd + restart the container).
3. Verify: container is running, sentinel row persists, `slip services status` shows Ready.
4. This is a release checklist item, not a CI test.

## Supported platforms

- **Runtime storage**: Linux only (rootful Podman with openat2 support)
- **macOS dev**: portable tests compile and pass; Linux-gated tests are CI-only
- **Service operations**: fail closed on non-rootful or non-Linux runtimes

## API

All service routes are management-authenticated (Bearer token only; deploy HMAC
is rejected). See `plan.md` for the full route/schema table.

## CLI

```
slip services add postgres [--version 18] [--name pg]
slip services list
slip services status [name]
slip services rm <name> [--force]
```

`rm` composes two API calls: first `GET /v1/services/{name}` to obtain the
current generation (a non-secret operational integer), then
`DELETE /v1/services/{name}?generation=<n>&force=<bool>`. The generation is
a CAS guard — if the service was modified between the GET and DELETE, the
server returns 409 and the CLI reports a stale-generation conflict.

Exit codes follow the SLIP-86 contract: 0 ok, 1 generic/conflict, 2 usage, 3 auth,
4 not-found, 5 provision-failed, 6 timeout.