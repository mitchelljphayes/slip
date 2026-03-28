# Design: slip v2 — From Static Sites to Pod Deploys

**Status:** Draft  
**Author:** MJP  
**Date:** March 2026

---

## Vision

slip should be the easiest way to deploy anything on a VPS — from a static Astro site to a multi-container application with databases. Same tool, same workflow, progressive complexity. Preview deployments for every PR.

```
Simple                                                     Complex
  |                                                           |
  v                                                           v

Static site     Single container     Container + sidecar     Full pod
(Astro, Hugo)   (API, web app)       (app + redis)           (app + pg + redis + workers)

  slip deploy     slip deploy          slip deploy             slip deploy
  (just works)    (just works)         (just works)            (just works)
      |               |                    |                       |
      +-- preview --- +--- preview -------+------ preview --------+
```

---

## Config Model: Repo Defines App, Server Defines Infra

### Principle

The **repo** describes **what the app is**. The **server** describes **where it runs**.

The repo's `slip.toml` and optional `pod.yaml` are baked into the container image. slip extracts them at deploy time and merges with server-side config. CI only needs to send `{app, tag}`.

### Repo-side config (`slip.toml` — checked into git)

```toml
# What this app IS — lives in the repo
[app]
name = "stat-stream"
kind = "pod"                    # "container" (default) or "pod"
manifest = "pod.yaml"           # path to K8s Pod YAML (relative to repo root)

[health]
path = "/v1/status"
container = "api"               # which container to health check (pod mode)
interval = "2s"
timeout = "5s"
retries = 5
start_period = "10s"

[routing]
port = 8000
container = "api"               # which container to route to (pod mode)

[defaults]
resources = { memory = "512m", cpus = "1" }

[preview]
enabled = true
ttl = "72h"
max = 5

[preview.database]
strategy = "shared"             # "shared", "branch", or "ephemeral"
# provider = "neon"             # for "branch" strategy
# project_id = "${NEON_PROJECT_ID}"
# branch_from = "main"

[preview.hooks]
# Commands run inside the container after startup, before traffic switch
migrate = "uv run alembic upgrade head"
seed = "uv run python scripts/seed.py"
```

### Server-side config (`slip.toml` on server — managed via CLI)

```toml
# Where apps RUN — lives on the server
[server]
listen = "0.0.0.0:7890"

[auth]
secret = "${SLIP_SECRET}"

[caddy]
admin_api = "http://localhost:2019"

[storage]
path = "/var/lib/slip"

[runtime]
backend = "auto"                # "auto", "docker", or "podman"

[[apps]]
name = "blog"
domain = "blog.example.com"
secret = "${BLOG_SECRET}"

[[apps]]
name = "stat-stream"
domain = "stat-stream.example.com"
secret = "${STAT_STREAM_SECRET}"
preview_domain = "*.preview.stat-stream.dev"    # wildcard for previews
resources = { memory = "1g", cpus = "2" }       # override repo defaults

[[apps.secrets]]
# Injected as env vars, never leave the server
POSTGRES_PASSWORD = "${POSTGRES_PASSWORD}"
API_FOOTBALL_KEY = "${API_FOOTBALL_KEY}"
NEON_PROJECT_ID = "${NEON_PROJECT_ID}"
```

### Config merge at deploy time

| Concern | Source | Who controls | Example |
|---------|--------|-------------|---------|
| App shape | Repo `slip.toml` + `pod.yaml` | Developer | containers, ports, health checks |
| Domain + TLS | Server `slip.toml` `[[apps]]` | Operator | `stat-stream.example.com` |
| Secrets | Server `slip.toml` `[[apps.secrets]]` | Operator | `POSTGRES_PASSWORD` |
| Resource limits | Server overrides repo defaults | Operator | memory, CPU caps |
| Preview config | Repo `slip.toml` `[preview]` | Developer | TTL, max, DB strategy |
| Preview domain | Server `slip.toml` `[[apps]]` | Operator | wildcard DNS |

### Config extraction from image

The repo config travels inside the container image — no need to sync git repos or send config in webhooks.

```dockerfile
# In your Dockerfile — convention: put slip config at /slip/
COPY slip.toml /slip/slip.toml
COPY pod.yaml /slip/pod.yaml
```

At deploy time, slip extracts config from the image:

```bash
podman create --name slip-tmp ghcr.io/me/statstream-api:v1.2.3
podman cp slip-tmp:/slip/slip.toml ./rendered/slip.toml
podman cp slip-tmp:/slip/pod.yaml ./rendered/pod.yaml
podman rm slip-tmp
```

If no `/slip/slip.toml` exists in the image, slip falls back to the server-side `[[apps]]` config (backwards compatible with Phase 1).

---

## Full Pipeline

```
Developer pushes code
    |
    v
CI Pipeline (GitHub Actions)
    |-- 1. Lint / test
    |-- 2. slip validate                   <-- validates slip.toml + pod.yaml
    |-- 3. Build image(s)
    |-- 4. Push to registry
    '-- 5. POST /v1/deploy { app, tag }    <-- minimal webhook
    |
    v
slipd (on server)
    |-- 1. Pull image
    |-- 2. Extract /slip/slip.toml + /slip/pod.yaml from image
    |-- 3. Merge with server config (domain, secrets, resources)
    |-- 4. Deploy (container or pod via podman kube play)
    |-- 5. Run hooks (migrate, seed) if configured
    |-- 6. Health check
    |-- 7. Switch Caddy route
    '-- 8. Tear down old container/pod
```

### CI is minimal

```yaml
# .github/workflows/deploy.yml — simple single-image deploy
- run: |
    curl -X POST https://slip.example.com/v1/deploy \
      -H "X-Slip-Signature: sha256=$(echo -n '{"app":"stat-stream","tag":"${{ github.sha }}"}' | openssl dgst -sha256 -hmac ${{ secrets.SLIP_SECRET }} | cut -d' ' -f2)" \
      -d '{"app":"stat-stream","tag":"${{ github.sha }}"}'
```

```yaml
# Multi-image deploy — tag applies to primary image, override specific sidecars
- run: |
    curl -X POST https://slip.example.com/v1/deploy \
      -d '{"app":"stat-stream","tag":"v1.2.3","images":{"dagster-daemon":"ghcr.io/me/statstream-dagster:v1.2.3"}}'
```

CI doesn't know about domains, secrets, or infrastructure. It just says "deploy this tag." The `images` map is optional — only needed when updating sidecar images alongside the primary.

---

## Key Insight: `podman kube play`

Podman natively understands Kubernetes Pod YAML via `podman kube play`. This means:

- **We don't build pod orchestration** — Podman does it
- **We don't invent a config format** — we use K8s YAML (a universal standard)
- **Users can graduate to real K8s** — same YAML, different runtime
- **Blue-green works at the pod level** — create new pod, health check, switch Caddy, tear down old

```bash
# What Podman already does:
podman kube play pod.yaml          # Create pod + all containers
podman kube play --replace pod.yaml  # Update pod in place
podman kube down pod.yaml          # Tear down everything
```

---

## App Tiers

### Tier 1: Single Container

A static site, simple API, or any single-process app.

```toml
# In repo: slip.toml
[app]
name = "blog"

[routing]
port = 80

[health]
path = "/"
```

```dockerfile
FROM caddy:2-alpine
COPY dist /srv
```

Deploy: Pull image → start container → health check → switch Caddy → stop old.

**This is what slip does today** (with the webhook providing the image reference).

### Tier 2: Pod Deploy

A multi-container app defined as a Kubernetes Pod YAML.

```toml
# In repo: slip.toml
[app]
name = "stat-stream"
kind = "pod"
manifest = "pod.yaml"

[routing]
port = 8000
container = "api"

[health]
path = "/v1/status"
container = "api"
```

```yaml
# In repo: pod.yaml — standard K8s Pod spec
apiVersion: v1
kind: Pod
metadata:
  name: stat-stream
  labels:
    app: stat-stream
spec:
  containers:
    - name: api
      image: ghcr.io/me/statstream-api:latest
      ports:
        - containerPort: 8000
          hostPort: 0           # slip assigns ephemeral port
      env:
        - name: DATABASE_URL
          value: "postgres://statstream:$(POSTGRES_PASSWORD)@localhost:5432/statstream"
        - name: REDIS_URL
          value: "redis://localhost:6379"

    - name: postgres
      image: postgres:15
      env:
        - name: POSTGRES_PASSWORD
          valueFrom:
            secretKeyRef:
              name: stat-stream-secrets
              key: postgres-password
      volumeMounts:
        - name: pgdata
          mountPath: /var/lib/postgresql/data

    - name: redis
      image: redis:7-alpine

  volumes:
    - name: pgdata
      hostPath:
        path: /var/lib/statstream/postgres
        type: DirectoryOrCreate
```

Deploy flow:
1. Pull images for all containers
2. Render manifest (inject secrets, set versioned pod name)
3. `podman kube play rendered-manifest.yaml`
4. Health check the `api` container
5. Switch Caddy route to new pod's API port
6. `podman kube down old-manifest.yaml`

**Why this works:**
- Containers in a pod share `localhost` — api talks to postgres at `localhost:5432`
- Podman manages the full lifecycle as a unit
- The YAML is valid K8s — copy it to a cluster later if needed
- Secrets injected by slip, never leave the server

### Tier 3: Future — Multi-pod with dependencies (not in scope)

Multiple pods with dependency ordering (e.g., database pod starts before app pod). This is where you'd graduate to k3s. We explicitly don't build this.

---

## Preview Deployments

### Overview

Every PR can get its own running instance at a unique URL. Preview deploys are just deploys with an ephemeral lifecycle and a dynamic subdomain.

```
PR #42 opened  → slip creates preview
                   - container/pod running PR code
                   - route: pr-42.stat-stream.preview.dev
                   - comment on PR with URL

PR #42 updated → slip redeploys the preview

PR #42 closed  → slip tears down preview + cleans up resources
```

### Repo config

```toml
# In repo: slip.toml
[preview]
enabled = true
ttl = "72h"                     # auto-teardown after 72 hours
max = 5                         # max concurrent previews for this app
resources = { memory = "256m", cpus = "0.5" }   # resource requests for previews

[preview.database]
strategy = "shared"             # no migration, use staging DB as-is
# strategy = "branch"           # Neon/Supabase: create DB branch per preview
# strategy = "ephemeral"        # Postgres in the pod, seeded from snapshot

# For "branch" strategy:
# provider = "neon"
# project_id = "${NEON_PROJECT_ID}"
# branch_from = "main"

[preview.hooks]
# Commands run inside the container after startup, before traffic switch
# migrate = "uv run alembic upgrade head"
# seed = "uv run python scripts/seed.py"
```

### Server config

```toml
[[apps]]
name = "stat-stream"
domain = "stat-stream.example.com"
preview_domain = "*.stat-stream.preview.dev"    # wildcard DNS + TLS
preview_max = 3                                 # override: fewer previews
preview_resources = { memory = "128m", cpus = "0.25" }  # override: smaller
```

Server caps override repo requests. Production resources are reserved separately — previews only use what's left.

### API

```
# Create/update a preview (CI calls this on PR open + push)
POST /v1/deploy
{
  "app": "stat-stream",
  "tag": "abc123def456",
  "preview": {
    "id": "pr-42",              # used for subdomain: pr-42.stat-stream.preview.dev
    "sha": "abc123def456"       # tracked in deploy metadata
  }
}

# Tear down a preview (CI calls this on PR close/merge)
DELETE /v1/previews/stat-stream/pr-42
```

### Example CI workflow

```yaml
# .github/workflows/preview.yml
on:
  pull_request:
    types: [opened, synchronize]

jobs:
  preview:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Build and push
        run: |
          docker build -t ghcr.io/me/statstream-api:${{ github.sha }} .
          docker push ghcr.io/me/statstream-api:${{ github.sha }}

      - name: Deploy preview
        run: |
          PAYLOAD='{"app":"stat-stream","tag":"${{ github.sha }}","preview":{"id":"pr-${{ github.event.number }}","sha":"${{ github.sha }}"}}'
          SIG=$(echo -n "$PAYLOAD" | openssl dgst -sha256 -hmac "${{ secrets.SLIP_SECRET }}" | cut -d' ' -f2)
          RESPONSE=$(curl -s -X POST https://slip.example.com/v1/deploy \
            -H "X-Slip-Signature: sha256=$SIG" \
            -d "$PAYLOAD")
          echo "Deploy ID: $(echo $RESPONSE | jq -r '.deploy_id')"

      - name: Comment preview URL
        uses: actions/github-script@v7
        with:
          script: |
            github.rest.issues.createComment({
              owner: context.repo.owner,
              repo: context.repo.repo,
              issue_number: context.issue.number,
              body: `Preview deployed: https://pr-${context.issue.number}.stat-stream.preview.dev`
            })

---
# .github/workflows/preview-cleanup.yml
on:
  pull_request:
    types: [closed]

jobs:
  teardown:
    runs-on: ubuntu-latest
    steps:
      - name: Teardown preview
        run: |
          curl -X DELETE https://slip.example.com/v1/previews/stat-stream/pr-${{ github.event.number }} \
            -H "X-Slip-Signature: sha256=..."
```

### Preview deploy flow

```
1. Receive deploy request with preview context
2. Pull image
3. Extract /slip/slip.toml from image
4. Check preview limits (max concurrent)
    - If at limit, evict oldest preview
5. Create DB branch (if strategy = "branch")
    - Call Neon/Supabase API
    - Get branch DATABASE_URL
6. Deploy container/pod
    - Name: stat-stream-preview-pr-42
    - Inject: DATABASE_URL (branched or shared), secrets
7. Run hooks (migrate, seed) in container
    - If hooks fail → preview fails, teardown, report
8. Health check
9. Create Caddy route: pr-42.stat-stream.preview.dev
10. Comment on PR with preview URL (GitHub API)
11. Set TTL timer for auto-cleanup
```

### Preview teardown flow

```
Triggered by: PR closed/merged, TTL expired, manual, eviction

1. Remove Caddy route
2. Stop and remove container/pod
3. Delete DB branch (if strategy = "branch")
4. Update PR comment: "Preview torn down"
5. Clean up state
```

### Database strategies for previews

**Strategy: `shared`** (default)
- Preview connects to the same staging database
- No migrations run (unless explicitly configured)
- Cheapest and simplest
- Works when PRs don't change the schema

**Strategy: `branch`** (Neon / Supabase / PlanetScale)
- slip calls the provider API to create a copy-on-write DB branch
- Each preview gets its own `DATABASE_URL`
- Migrations run in isolation
- Branch deleted on preview teardown

```
slip → Neon API: POST /branches { parent: "main" }
     ← { branch_id: "br-xyz", host: "br-xyz.us-east-1.aws.neon.tech" }
     → Set DATABASE_URL=postgres://...@br-xyz.us-east-1.aws.neon.tech/...
```

**Strategy: `ephemeral`** (Postgres in the pod)
- Preview pod includes its own Postgres container
- Optionally seeded from a snapshot
- Full isolation, no external dependency
- Heavier on resources (each preview = own DB)

slip doesn't know about ORMs or migration frameworks. The `migrate` and `seed` hooks are opaque commands that run in the container. If they fail, the preview fails.

---

## Blue-Green for Pods

### Approach: Versioned Pod Names

```yaml
# Template in pod.yaml:
metadata:
  name: stat-stream            # slip appends: stat-stream-{ulid}

# During deploy, slip renders two copies:
# Active:  stat-stream-01ABCDEF (serving traffic)
# New:     stat-stream-01GHIJKL (starting up, health checking)
```

Flow:
1. Render manifest with new name suffix (`stat-stream-{ulid}`)
2. `podman kube play` new pod
3. Health check new pod's API container
4. Caddy switches to new pod's port
5. Drain timeout
6. `podman kube down` old pod

### Port Management

Pods expose ports via `hostPort` in the YAML. For blue-green, we need two pods on different host ports.

Approach: **Ephemeral ports** — set `hostPort: 0` in manifest, let Podman assign. slip reads the assigned port via `podman pod inspect`.

---

## Architecture Changes

### What changes in slip

```
Phase 1 (current):
  server slip.toml → AppConfig → DockerClient → single container → Caddy

Phase 2 (proposed):
  image /slip/slip.toml + server [[apps]] → merged AppConfig → RuntimeBackend → container OR pod → Caddy
                                                                    |
                                                                    +-- DockerBackend (single containers)
                                                                    +-- PodmanBackend (single containers + pods)
```

### Runtime Backend Trait

```rust
/// Abstraction over container runtimes.
/// Docker supports single containers.
/// Podman supports single containers AND pods.
#[async_trait]
pub trait RuntimeBackend: Send + Sync {
    // ── Image operations ────────────────────────────────────────────
    async fn pull_image(&self, image: &str, tag: &str, creds: Option<Credentials>)
        -> Result<(), RuntimeError>;
    async fn extract_file(&self, image: &str, tag: &str, path: &str)
        -> Result<Option<Vec<u8>>, RuntimeError>;

    // ── Single container operations (both Docker and Podman) ────────
    async fn create_and_start(&self, spec: &ContainerSpec)
        -> Result<ContainerInfo, RuntimeError>;
    async fn stop_and_remove(&self, id: &str) -> Result<(), RuntimeError>;
    async fn is_running(&self, id: &str) -> Result<bool, RuntimeError>;
    async fn exists(&self, id: &str) -> Result<bool, RuntimeError>;
    async fn exec_in_container(&self, id: &str, cmd: &[&str])
        -> Result<ExecResult, RuntimeError>;

    // ── Pod operations (Podman only, Docker returns Unsupported) ────
    async fn deploy_pod(&self, manifest: &Path, name: &str)
        -> Result<PodInfo, RuntimeError>;
    async fn teardown_pod(&self, manifest: &Path)
        -> Result<(), RuntimeError>;
    async fn pod_container_port(&self, pod: &str, container: &str, container_port: u16)
        -> Result<u16, RuntimeError>;
}
```

### Deploy orchestrator changes

```rust
async fn execute_deploy(ctx: DeployContext, backend: &dyn RuntimeBackend) {
    // 1. Pull primary image
    backend.pull_image(&ctx.image, &ctx.tag, creds).await?;

    // 2. Extract repo config from image
    let repo_config = backend.extract_file(&ctx.image, &ctx.tag, "/slip/slip.toml").await?;
    let merged = merge_config(repo_config, server_config);

    // 3. Deploy based on app kind
    match merged.app.kind {
        AppKind::Container => deploy_container(backend, &merged).await,
        AppKind::Pod => {
            let manifest = backend.extract_file(&ctx.image, &ctx.tag, "/slip/pod.yaml").await?;
            deploy_pod(backend, &merged, &manifest).await
        }
    }

    // 4. Run hooks (migrate, seed)
    if let Some(migrate) = merged.hooks.migrate {
        backend.exec_in_container(&container_id, &["sh", "-c", &migrate]).await?;
    }

    // 5. Health check
    // 6. Switch Caddy
    // 7. Tear down old
}
```

### Runtime Detection

```toml
# Server slip.toml
[runtime]
backend = "auto"   # auto-detect (default), "docker", or "podman"
```

Auto-detection:
1. Check for `podman` binary → use Podman backend
2. Check for Docker socket → use Docker backend  
3. Fail with helpful error

---

## Migration Path: slip → Kubernetes

The design explicitly supports graduating to K8s:

| Stage | Tool | Config |
|-------|------|--------|
| 1. Start simple | slip + Docker | `slip.toml` in repo |
| 2. Add services | slip + Podman | `slip.toml` + `pod.yaml` in repo |
| 3. Scale out | k3s/k8s | Same `pod.yaml` + Deployment wrapper + Ingress |

The pod YAML is the portable artifact. slip's TOML is the deploy/routing metadata that maps to K8s Ingress + Deployment in a real cluster.

---

## CLI Commands

### App management (no SSH needed)

```bash
# From your laptop, over Tailscale:
slip apps add stat-stream --domain stat-stream.example.com
slip apps add stat-stream --preview-domain "*.stat-stream.preview.dev"
slip apps list
slip apps edit stat-stream --domain new-domain.com
slip apps rm stat-stream

slip secrets set stat-stream POSTGRES_PASSWORD=hunter2
slip secrets list stat-stream
slip secrets rm stat-stream POSTGRES_PASSWORD
```

### Deploy operations

```bash
slip deploy stat-stream v1.2.3           # manual deploy
slip status                              # all apps
slip status stat-stream                  # single app
slip rollback stat-stream                # deploy previous tag
slip logs stat-stream                    # container/pod logs
```

### Preview operations

```bash
slip previews list stat-stream           # list active previews
slip previews teardown stat-stream pr-42 # manual teardown
slip previews teardown stat-stream --all # teardown all previews
```

### Validation (for CI)

```bash
slip validate                            # validate slip.toml + pod.yaml
slip validate --strict                   # also check image references exist
```

---

## Implementation Plan

### Phase 2a: Config Model + Podman Backend (~1 week)

| Task | Effort |
|------|--------|
| Extract `RuntimeBackend` trait from `ContainerRuntime` | 2 days |
| Implement `PodmanBackend` for single containers (bollard against Podman socket) | 2 days |
| Runtime auto-detection | 0.5 day |
| Config: `[runtime]` section in server slip.toml | 0.5 day |
| Tests for both backends | 2 days |

### Phase 2b: Image Config Extraction + Merge (~1 week)

| Task | Effort |
|------|--------|
| `extract_file` implementation (create tmp container, cp, rm) | 1 day |
| Repo-side `slip.toml` parser (new fields: kind, manifest, preview) | 1 day |
| Config merge logic (repo + server → merged config) | 2 days |
| Fallback to server-only config when no `/slip/slip.toml` in image | 0.5 day |
| `slip validate` CLI command | 0.5 day |
| Tests | 2 days |

### Phase 2c: Pod Deploys (~1.5 weeks)

| Task | Effort |
|------|--------|
| Manifest rendering (env var injection, versioned pod name) | 2 days |
| `deploy_pod` / `teardown_pod` via `podman kube play` | 2 days |
| Pod health checking (target specific container) | 1 day |
| Blue-green for pods (versioned names, port management) | 2 days |
| State tracking for pods | 1 day |
| Tests | 2 days |

### Phase 2d: Preview Deployments (~1.5 weeks)

| Task | Effort |
|------|--------|
| Preview deploy endpoint (preview context in webhook) | 1 day |
| Preview routing (dynamic subdomains via PR number, Caddy wildcard) | 2 days |
| Preview lifecycle (TTL timer, max limit, eviction of oldest) | 2 days |
| Post-deploy hooks (`exec_in_container` for migrate/seed) | 1 day |
| Preview teardown endpoint (`DELETE /v1/previews/:app/:id`) | 1 day |
| Preview resource limits (repo requests, server caps) | 1 day |

### Phase 2e: Database Branching (~1 week)

| Task | Effort |
|------|--------|
| Database strategy abstraction | 1 day |
| Neon provider (branch create/delete API) | 2 days |
| Supabase provider (branch create/delete API) | 1 day |
| DATABASE_URL injection into preview deploys | 1 day |
| Tests | 1 day |

### Phase 2f: CLI + App Management (~1 week)

| Task | Effort |
|------|--------|
| `slip apps add/list/edit/rm` | 2 days |
| `slip secrets set/list/rm` | 1 day |
| `slip previews list/teardown` | 1 day |
| `slip validate` | 0.5 day |
| `slip rollback` | 1 day |

### Total: ~7 weeks

Priority order: 2a → 2b → 2c → 2d → 2f → 2e

(Database branching is last because `strategy = "shared"` works without it.)

---

## What We Explicitly Don't Build

- **Compose parsing** — use K8s YAML instead (universal, portable)
- **Service discovery** — pods share localhost, no need
- **Multi-pod dependencies** — that's K8s territory
- **Container building** — use CI for that
- **Image registry** — use GHCR/Docker Hub
- **Log aggregation** — use `podman logs` or journald
- **Metrics/monitoring** — separate concern
- **Migration framework integration** — hooks are opaque commands
- **Multi-replica** — single node = single replica, use K8s for more

## Resolved Decisions

1. **Config model**: Repo owns app definition (`slip.toml` + `pod.yaml` in image), server owns infra (domains, secrets, resources).
2. **Config delivery**: Baked into the container image at `/slip/`. Extracted at deploy time.
3. **Webhook**: Minimal `{app, tag}`. Everything else is in the image or on the server.
4. **Pod orchestration**: `podman kube play` — don't reimplement.
5. **Preview databases**: Pluggable strategies. slip provides hooks, doesn't know about ORMs.
6. **Persistent volumes**: Host paths only. Volume lifecycle is the operator's job.
7. **Preview subdomains**: Use PR number for subdomain (`pr-42.app.preview.dev`). Track commit SHA in deploy metadata for knowing which commit is live.
8. **Preview lifecycle**: CI sends lifecycle webhooks (deploy on PR open/push, teardown on PR close). slip doesn't talk to GitHub directly. PR comments with preview URL are CI's job. A GitHub App can be added later as a nice-to-have.
9. **Multi-image pods**: Tag in webhook applies to the primary image only (the one matching `[app] image`). Sidecars use pinned tags from `pod.yaml`. Optional `images` map in webhook payload for overriding specific sidecar tags when needed.
10. **Preview resources**: Repo declares preview resource requests in `[preview] resources`. Server can override with caps in `[[apps]] preview_resources`. Max preview count + TTL prevents oversubscription. Production resources are reserved separately.

## Open Questions

1. **Wildcard TLS for preview domains** — Caddy supports DNS challenge for wildcard certs. Which DNS providers to support out of the box? (Cloudflare is most common.)
