# slip

> Zero-downtime container deploys from CI, without Kubernetes.

**slip** is a lightweight deployment daemon written in Rust. It runs on your server, accepts signed webhooks from CI, and manages zero-downtime container deployments using Caddy as the reverse proxy.

No SSH keys in CI. No PaaS overhead. No Kubernetes.

```
GitHub Actions → signed webhook → slipd → pull → health check → swap route → stop old
```

## Features

- **Zero-downtime deploys** — blue-green (start new, swap, drain old) or recreate (stop old, start new)
- **HMAC-SHA256 auth** — CI gets one secret per app, no SSH keys on runners
- **Caddy integration** — automatic HTTPS, dynamic route management via admin API
- **Pod support** — multi-container pods via `podman kube play` (init containers, shared volumes, per-container env)
- **Worker apps** — non-HTTP workloads (pipelines, daemons) with container-liveness health checks
- **Multiple routes** — one app, multiple Caddy hostnames (e.g. `api.example.com` + `dagster.example.com`)
- **Persistent volumes** — host-path bind mounts that survive redeploys
- **Multi-image deploys** — one webhook, multiple container images (`${tag}` placeholders + per-container overrides)
- **Preview environments** — ephemeral deploys with TTL, subdomain routing, wildcard TLS
- **SQLite deploy history** — STRICT tables, survives restarts, queryable via API
- **Secrets management** — per-app secret store with restrictive file permissions
- **Per-container health** — mixed HTTP + worker containers in a single pod
- **Structured logging** — JSON logs via `tracing`
- **`slip init`** — 🚧 WIP (currently a stub; see [v1.0 roadmap](https://linear.app/mitchelljphayes/project/slip-v1-0-roadmap-3b6e6e0b0b0b))
- **`slip status`** — 🚧 WIP (currently a stub; see [v1.0 roadmap](https://linear.app/mitchelljphayes/project/slip-v1-0-roadmap-3b6e6e0b0b0b))
- **`slip logs`** — 🚧 WIP (currently a stub; see [v1.0 roadmap](https://linear.app/mitchelljphayes/project/slip-v1-0-roadmap-3b6e6e0b0b0b))

## Install

```bash
curl -sSL https://raw.githubusercontent.com/mitchelljphayes/slip/main/install.sh | bash
```

This downloads a static binary, creates a `slip` service user, sets up directories, and installs a systemd unit.

**Manual install** (if you prefer to build from source):

```bash
git clone https://github.com/mitchelljphayes/slip.git
cd slip
cargo build --release
sudo cp target/release/slipd target/release/slip /usr/local/bin/
```

See [docs/getting-started.md](docs/getting-started.md) for the full setup guide.

## Quick start

### 1. Configure slipd

```bash
sudo tee /etc/slip/slip.toml > /dev/null << 'EOF'
[server]
listen = "127.0.0.1:7890"

[runtime]
backend = "auto"          # auto-detects Podman or Docker

[auth]
secret = "${SLIP_SECRET}"  # global HMAC fallback; per-app [app] secret overrides it

[registry]
# ghcr_token = "${GHCR_TOKEN}"   # optional: token for pulling private images

[caddy]
admin_api = "http://localhost:2019"

[storage]
path = "/var/lib/slip"
EOF
```

> The `[auth]` and `[registry]` sections are **required** (even if `registry` is
> empty). `[auth].secret` is the fallback webhook secret; a per-app `[app] secret`
> in the app TOML overrides it. **`slip secrets set <app> SLIP_SECRET=...` does
> NOT affect webhook auth** — it injects the value as a container env var only.
> See [getting-started.md §6](docs/getting-started.md) for the full distinction.

### 2. Create an app config

```bash
sudo tee /etc/slip/apps/myapp.toml > /dev/null << 'EOF'
[app]
name = "myapp"
image = "ghcr.io/you/myapp"

[routing]
domain = "myapp.example.com"
port = 8080

[health]
path = "/health"
interval = "2s"
timeout = "5s"
retries = 5
start_period = "10s"

[deploy]
strategy = "blue-green"
drain_timeout = "30s"

[resources]
memory = "512m"
cpus = "1.0"
EOF
```

> Each app is a separate file in `/etc/slip/apps/` with a single `[app]` table
> (not `[[apps]]`). The `[health]` section is required; omit `path` to skip the
> HTTP probe and health-check on "container running" instead.

### 3. Set the webhook secret

The webhook signing key is either the **global** `[auth].secret` from `slip.toml`
or a **per-app** `[app] secret` in the app TOML. To set a per-app secret, edit
the app config:

```bash
# Add a per-app webhook signing key to the app TOML
sudo tee -a /etc/slip/apps/myapp.toml > /dev/null << 'EOF'
secret = "your-hmac-key"
EOF
```

> **`slip secrets set <app> SLIP_SECRET=...` does NOT affect webhook auth.**
> That command injects the value as a container environment variable only.
> See [getting-started.md §6](docs/getting-started.md) for the full distinction.

### 4. Start the daemon

```bash
sudo slipd --config /etc/slip --check    # validate config
sudo systemctl enable --now slipd       # start the service
```

### 5. Deploy from CI

```bash
PAYLOAD='{"app":"myapp","tag":"sha-abc123f"}'
SIG=$(echo -n "$PAYLOAD" | openssl dgst -sha256 -hmac "$SLIP_SECRET" | cut -d' ' -f2)

curl -X POST https://deploy.example.com/v1/deploy \
  -H "Content-Type: application/json" \
  -H "X-Slip-Signature: sha256=$SIG" \
  -d "$PAYLOAD"
```

Or use the CLI:

```bash
slip deploy myapp sha-abc123f \
  --server https://deploy.example.com \
  --secret "$SLIP_SECRET"
```

## Comparison

| Feature | slip | Dokku | CapRover | Kamal | k8s |
|---------|------|-------|---------|-------|-----|
| Signed webhooks (no SSH in CI) | ✅ | ❌ | ❌ | ❌ | ❌ |
| Single binary, no runtime deps | ✅ | ❌ | ❌ | ❌ | ❌ |
| Blue-green + recreate strategies | ✅ | ❌ | ❌ | ✅ (blue-green) | ✅ |
| Pod support (kube play) | ✅ | ❌ | ❌ | ❌ | ✅ |
| Worker / non-HTTP apps | ✅ | ❌ | ❌ | ❌ | ✅ |
| Preview deployments | ✅ | ❌ | ✅ | ❌ | ✅ |
| Persistent volumes | ✅ | ✅ | ✅ | ✅ | ✅ |
| Multiple routes per deploy | ✅ | ❌ | ✅ | ❌ | ✅ |
| Cost | Free | Free | Free | Free | $73+/mo |

## App types

### Single-container (blue-green)

```toml
[app]
name = "api"
image = "ghcr.io/you/api"

[routing]
domain = "api.example.com"
port = 8080

[health]
path = "/health"

[deploy]
strategy = "blue-green"
```

### Worker (non-HTTP, e.g. a single-writer service)

The repo's `slip.toml` declares `kind = "worker"`. No domain, no port, health = container running. Pair with `strategy = "recreate"` for single-writer state.

```toml
[app]
name = "pipeline"
image = "ghcr.io/you/pipeline"

[health]
# no path → health-check on "container running"

[deploy]
strategy = "recreate"

[[volumes]]
host_path = "/var/lib/slip/volumes/pipeline/state"
mount_path = "/app/data"
read_only = false
```

### Pod (multi-container)

The repo declares `kind = "pod"` with a `pod.yaml` manifest. slip renders it and runs via `podman kube play`. Multiple routes target containers by name.

```toml
[app]
name = "statstream"
image = "ghcr.io/you/statstream-api"

[health]
path = "/health"

[deploy]
strategy = "recreate"

[[routing.routes]]
hostname = "statstream.example.com"
container = "api"

[[routing.routes]]
hostname = "dagster.example.com"
container = "dagster-webserver"

[[volumes]]
host_path = "/var/lib/slip/volumes/statstream/dagster-home"
mount_path = "/opt/dagster/dagster_home"
```

## Project structure

Cargo workspace with three crates:

| Crate | Description |
|-------|-------------|
| **`slipd`** | Deploy daemon — receives webhooks, manages containers, talks to Caddy |
| **`slip`** | CLI — app management, secrets, status, manual deploys |
| **`slip-core`** | Shared library — config, types, Docker/Podman/Caddy clients |

## API

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/v1/deploy` | POST | Trigger a deploy (signed webhook) |
| `/v1/status` | GET | Daemon health + all app statuses |
| `/v1/deploys/{id}` | GET | Deploy progress and status |
| `/v1/apps/{name}` | GET/PATCH/DELETE | App config management |
| `/v1/apps/{name}/rollback` | POST | Rollback to previous deploy |
| `/v1/secrets/{app}/{key}` | PUT/GET/DELETE | Per-app secrets |

## Development

```bash
# Run tests
cargo test

# Check formatting + lints
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings

# Run smoke test (requires Docker + Caddy)
./scripts/smoke-test.sh
```

## Documentation

- [Getting Started Guide](docs/getting-started.md)
- [Network Coexistence (external infra)](docs/network-coexistence.md)
- [Design Doc (Phase 1)](docs/slip-design.md)
- [Pod Deploys Design (Phase 2)](docs/design-v2-pod-deploys.md)
- [PRD](docs/prd.md)
- [Tech Spec](docs/tech-spec.md)

## Roadmap

- [x] **Phase 1: Core Deploy Loop** — webhook, deploy, health check, Caddy swap
- [x] **Phase 2: Pods, Previews & CLI** — Podman support, pod deploys, preview environments, CLI, volumes, workers, multi-image, multi-route
- [ ] **Phase 3: Production Hardening** — deploy timeout, image pruning, multi-registry, systemd packaging
- [ ] **Phase 4: CI Integration** — reusable GitHub Actions workflow, deploy status callbacks, `slip deploy --wait`

## License

[MIT](LICENSE)