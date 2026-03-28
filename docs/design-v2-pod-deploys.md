# Design: slip v2 — From Static Sites to Pod Deploys

**Status:** Draft  
**Author:** MJP  
**Date:** March 2026

---

## Vision

slip should be the easiest way to deploy anything on a VPS — from a static Astro site to a multi-container application with databases. Same tool, same workflow, progressive complexity.

```
Simple                                                     Complex
  |                                                           |
  v                                                           v

Static site     Single container     Container + sidecar     Full pod
(Astro, Hugo)   (API, web app)       (app + redis)           (app + pg + redis + workers)

  slip deploy     slip deploy          slip deploy             slip deploy
  (just works)    (just works)         (just works)            (just works)
```

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

## App Tiers

### Tier 1: Single Container (today)

A static site, simple API, or any single-process app.

```toml
# apps/blog.toml
[app]
name = "blog"
image = "ghcr.io/me/blog"

[routing]
domain = "blog.example.com"
port = 3000
```

Deploy: Pull image → start container → health check → switch Caddy → stop old.

**No changes needed.** This is what slip does today.

### Tier 2: Pod Deploy (new)

A multi-container app defined as a Kubernetes Pod YAML.

```toml
# apps/stat-stream.toml
[app]
name = "stat-stream"
kind = "pod"                              # NEW: signals pod mode
manifest = "pods/stat-stream.yaml"        # NEW: path to K8s YAML

[routing]
domain = "stat-stream.example.com"
container = "api"                         # NEW: which container to route to
port = 8000

[health]
path = "/v1/status"
container = "api"                         # NEW: which container to health check
```

```yaml
# pods/stat-stream.yaml — standard K8s Pod spec
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
          hostPort: 0    # slip assigns ephemeral port
      env:
        - name: DATABASE_URL
          value: "postgres://statstream:${POSTGRES_PASSWORD}@localhost:5432/statstream"
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

    - name: dagster-daemon
      image: ghcr.io/me/statstream-dagster:latest
      env:
        - name: DATABASE_URL
          value: "postgres://statstream:${POSTGRES_PASSWORD}@localhost:5432/statstream"

  volumes:
    - name: pgdata
      hostPath:
        path: /var/lib/statstream/postgres
        type: DirectoryOrCreate
```

Deploy flow:
1. `podman kube play pod.yaml` → creates pod with all containers  
2. Health check the `api` container
3. Switch Caddy route to new pod's API port
4. `podman kube down old-pod.yaml` → tear down old pod

**Why this works:**
- Containers in a pod share `localhost` — api talks to postgres at `localhost:5432`
- Podman manages the full lifecycle as a unit
- The YAML is valid K8s — copy it to a cluster later if needed
- Secrets handled via K8s Secret objects or slip's env injection

### Tier 3: Future — Multi-pod with dependencies (not in scope)

Multiple pods with dependency ordering (e.g., database pod starts before app pod). This is where you'd graduate to k3s. We explicitly don't build this.

## Architecture Changes

### What changes in slip

```
Current:
  slip.toml → AppConfig → DockerClient → single container → Caddy

Proposed:
  slip.toml → AppConfig → RuntimeBackend → container OR pod → Caddy
                              │
                              ├── DockerBackend (single containers)
                              └── PodmanBackend (single containers + pods)
```

### Runtime Backend Trait

```rust
/// Abstraction over container runtimes.
/// Docker supports single containers.
/// Podman supports single containers AND pods.
#[async_trait]
pub trait RuntimeBackend: Send + Sync {
    // ── Single container operations (both Docker and Podman) ────────
    async fn pull_image(&self, image: &str, tag: &str, creds: Option<Credentials>)
        -> Result<(), RuntimeError>;
    async fn create_and_start(&self, spec: &ContainerSpec)
        -> Result<ContainerInfo, RuntimeError>;
    async fn stop_and_remove(&self, id: &str) -> Result<(), RuntimeError>;
    async fn is_running(&self, id: &str) -> Result<bool, RuntimeError>;
    async fn exists(&self, id: &str) -> Result<bool, RuntimeError>;
    
    // ── Pod operations (Podman only, Docker returns Unsupported) ────
    async fn deploy_pod(&self, manifest: &Path, name: &str)
        -> Result<PodInfo, RuntimeError>;
    async fn teardown_pod(&self, manifest: &Path)
        -> Result<(), RuntimeError>;
    async fn pod_container_port(&self, pod: &str, container: &str, container_port: u16)
        -> Result<u16, RuntimeError>;
}

pub struct ContainerInfo {
    pub id: String,
    pub host_port: u16,
}

pub struct PodInfo {
    pub name: String,
    pub containers: Vec<ContainerInfo>,
}
```

### Config Changes

```rust
#[derive(Deserialize)]
pub struct AppConfig {
    pub app: AppInfo,
    pub routing: RoutingConfig,
    pub health: HealthConfig,
    pub deploy: DeployConfig,
    // ... existing fields ...
}

#[derive(Deserialize)]
pub struct AppInfo {
    pub name: String,
    pub image: Option<String>,        // Required for single container
    pub secret: Option<String>,
    pub kind: Option<AppKind>,        // NEW: "container" (default) or "pod"
    pub manifest: Option<PathBuf>,    // NEW: path to K8s YAML for pods
}

#[derive(Deserialize, Default)]
pub enum AppKind {
    #[default]
    Container,
    Pod,
}

#[derive(Deserialize)]
pub struct RoutingConfig {
    pub domain: String,
    pub port: u16,
    pub container: Option<String>,    // NEW: which container in pod to route to
}
```

### Deploy Flow Changes

```
Single container (unchanged):
  1. Pull image
  2. Create + start container
  3. Health check container
  4. Switch Caddy to container port
  5. Stop old container

Pod deploy (new):
  1. Render manifest (inject env vars, set pod name with version suffix)
  2. podman kube play rendered-manifest.yaml
  3. Find host port for the routable container
  4. Health check the routable container
  5. Switch Caddy to new pod's port
  6. podman kube down old-manifest.yaml
```

### Runtime Detection

```toml
# slip.toml
[runtime]
backend = "auto"   # auto-detect (default), "docker", or "podman"
# socket = "/run/user/1000/podman/podman.sock"  # override socket path
```

Auto-detection:
1. Check for `podman` binary → use Podman backend
2. Check for Docker socket → use Docker backend
3. Fail with helpful error

### Podman Backend Implementation

For **single containers**, Podman's API is Docker-compatible. We can use bollard with Podman's socket.

For **pods**, we shell out to `podman kube play` / `podman kube down`. This is intentional:
- The CLI is the stable interface
- No need to reimplement pod orchestration
- `--replace` flag handles updates atomically

```rust
impl RuntimeBackend for PodmanBackend {
    async fn deploy_pod(&self, manifest: &Path, name: &str) -> Result<PodInfo, RuntimeError> {
        // Render manifest with unique pod name for blue-green
        let rendered = self.render_manifest(manifest, name)?;
        
        // Deploy via CLI
        let output = Command::new("podman")
            .args(["kube", "play", &rendered.to_string_lossy()])
            .output()
            .await?;
            
        if !output.status.success() {
            return Err(RuntimeError::PodDeployFailed(
                String::from_utf8_lossy(&output.stderr).to_string()
            ));
        }
        
        // Inspect to get container ports
        self.inspect_pod(name).await
    }
    
    async fn teardown_pod(&self, manifest: &Path) -> Result<(), RuntimeError> {
        Command::new("podman")
            .args(["kube", "down", &manifest.to_string_lossy()])
            .output()
            .await?;
        Ok(())
    }
}
```

## Blue-Green for Pods

The key challenge: how do we run two pods simultaneously for zero-downtime?

### Approach: Versioned Pod Names

```yaml
# Template in pods/stat-stream.yaml:
metadata:
  name: stat-stream            # slip appends: stat-stream-abc123

# During deploy, slip renders two copies:
# Active:  stat-stream-v1 (serving traffic)
# New:     stat-stream-v2 (starting up, health checking)
```

Flow:
1. Render manifest with new name suffix (`stat-stream-{ulid}`)
2. `podman kube play` new pod
3. Health check new pod's API container
4. Caddy switches to new pod's port
5. Drain timeout
6. `podman kube down` old pod

### Port Management

Pods expose ports via `hostPort` in the YAML. For blue-green, we need two pods on different host ports:

Option A: **Ephemeral ports** — set `hostPort: 0` in manifest, let Podman assign
Option B: **slip-managed ports** — slip rewrites `hostPort` in rendered manifest

Recommendation: **Option A** — simpler, Podman handles port allocation.

## Static Site Support

For Tier 1, static sites like Astro/Hugo are already supported — they just need a container:

```dockerfile
# Dockerfile for Astro site
FROM node:20-alpine AS build
WORKDIR /app
COPY package*.json .
RUN npm ci
COPY . .
RUN npm run build

FROM caddy:2-alpine
COPY --from=build /app/dist /srv
COPY Caddyfile /etc/caddy/Caddyfile
```

```toml
# apps/blog.toml
[app]
name = "blog"
image = "ghcr.io/me/blog"

[routing]
domain = "blog.example.com"
port = 80

[resources]
memory = "64m"
cpus = "0.1"
```

No special handling needed — it's just a container.

## Migration Path: slip → Kubernetes

The design explicitly supports graduating to K8s:

| Step | Tool | Config |
|------|------|--------|
| 1. Start simple | slip + Docker | `apps/myapp.toml` |
| 2. Add services | slip + Podman | `apps/myapp.toml` + `pods/myapp.yaml` |
| 3. Scale out | k3s/k8s | Same `pods/myapp.yaml` + Helm chart |

The pod YAML is the portable artifact. slip's TOML is just the routing/deploy metadata that maps to K8s Ingress + Deployment in a real cluster.

## Implementation Plan

### Phase 2a: Podman Backend for Single Containers

| Task | Effort | Description |
|------|--------|-------------|
| Abstract `RuntimeBackend` trait | 2 days | Extract from current `ContainerRuntime` |
| Implement `PodmanBackend` (single container) | 2 days | Use bollard against Podman socket |
| Runtime auto-detection | 1 day | Check for podman/docker |
| Config: `[runtime]` section | 0.5 day | Backend selection |
| Tests | 2 days | Mock both backends |
| **Total** | ~1 week | |

### Phase 2b: Pod Deploys

| Task | Effort | Description |
|------|--------|-------------|
| Config: `kind = "pod"`, `manifest` field | 1 day | Parse new fields |
| Manifest rendering (env var injection, name suffix) | 2 days | Template + write rendered YAML |
| `deploy_pod` / `teardown_pod` implementation | 2 days | Shell out to `podman kube play` |
| Pod health checking (target specific container) | 1 day | Find container port, check health |
| Blue-green for pods | 2 days | Two pods, port management, Caddy switch |
| State tracking for pods | 1 day | Track pod name + manifest in AppRuntimeState |
| Tests | 2 days | Mock podman CLI output |
| **Total** | ~1.5 weeks | |

### Phase 2c: Secrets Management

| Task | Effort | Description |
|------|--------|-------------|
| `slip secrets set/list/rm` CLI | 2 days | Manage K8s Secret YAML files |
| Secret injection into pod manifests | 1 day | `--configmap` flag to `kube play` |
| **Total** | ~3 days | |

### Total: ~3 weeks for pod deploy support

## What We Explicitly Don't Build

- **Compose parsing** — use K8s YAML instead (universal, portable)
- **Service discovery** — pods share localhost, no need
- **Multi-pod dependencies** — that's K8s territory
- **Container building** — use CI for that
- **Image registry** — use GHCR/Docker Hub
- **Log aggregation** — use `podman logs` or journald
- **Metrics/monitoring** — separate concern

## Open Questions

1. **Should slip manage persistent volumes?** Or just reference host paths in the YAML?
   - Recommendation: Host paths only. Volume lifecycle is the operator's job.

2. **Should slip support `podman kube play --replace`?** This updates in-place without blue-green.
   - Recommendation: Not for stateless services. Maybe as `deploy.strategy = "replace"` for databases that can't run two copies.

3. **How to handle pod secrets?** K8s Secrets are base64-encoded YAML files.
   - Recommendation: `slip secrets` CLI generates K8s Secret YAML, `podman kube play --configmap` injects them.

4. **Should we support Deployments (replicas > 1)?** Podman sets replicas to 1.
   - Recommendation: No. Single node = single replica. Use K8s for multi-replica.
