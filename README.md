# slip

> A container dock for your server.

**slip** is a lightweight deployment daemon written in Rust. It runs on your server, accepts deploy webhooks from CI, and manages zero-downtime container deployments using Caddy as the reverse proxy.

No SSH keys in CI. No PaaS overhead. No Kubernetes.

## How it works

```
GitHub Actions → signed webhook → slipd → pull image → start container → health check → update Caddy → stop old
```

1. CI builds your image and pushes to a registry
2. CI sends a signed HTTP POST to your server
3. `slipd` pulls the image, starts a new container, health checks it
4. If healthy: swaps the Caddy route, drains old connections, stops the old container
5. If unhealthy: stops the new container, keeps the old one running

## Features

- **Zero-downtime deploys** — blue-green container swap with health checks
- **HMAC-SHA256 auth** — CI gets one secret, no SSH keys
- **Caddy integration** — automatic HTTPS, dynamic route management via admin API
- **Per-app config** — health checks, resource limits, env vars, secrets
- **Graceful shutdown** — in-flight deploys complete before exit
- **Structured logging** — JSON logs via `tracing`

## Quick start

### On the server

```bash
# 1. Create config
mkdir -p /etc/slip/apps

cat > /etc/slip/slip.toml << 'EOF'
[server]
listen = "0.0.0.0:7890"

[auth]
secret = "${SLIP_SECRET}"

[caddy]
admin_api = "http://localhost:2019"
EOF

cat > /etc/slip/apps/myapp.toml << 'EOF'
[app]
name = "myapp"
image = "ghcr.io/you/myapp"

[routing]
domain = "myapp.example.com"
port = 3000

[health]
path = "/health"
EOF

# 2. Start the daemon
SLIP_SECRET=your-secret-here slipd --config /etc/slip/slip.toml
```

### From CI

```bash
# Deploy with a single curl
PAYLOAD='{"app":"myapp","image":"ghcr.io/you/myapp","tag":"v1.2.3"}'
SIG=$(echo -n "$PAYLOAD" | openssl dgst -sha256 -hmac "$SLIP_SECRET" | cut -d' ' -f2)

curl -X POST https://your-server:7890/v1/deploy \
  -H "Content-Type: application/json" \
  -H "X-Slip-Signature: sha256=$SIG" \
  -d "$PAYLOAD"
```

## Project structure

Cargo workspace with three crates:

| Crate | Description |
|-------|-------------|
| **`slipd`** | Deploy daemon — receives webhooks, manages containers, talks to Caddy |
| **`slip`** | CLI — app management, secrets, status, manual deploys |
| **`slip-core`** | Shared library — config, types, Docker/Caddy clients |

## API

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/v1/deploy` | POST | Trigger a deploy (signed webhook) |
| `/v1/status` | GET | Daemon health + all app statuses |
| `/v1/deploys/{id}` | GET | Deploy progress and status |

## Configuration

### Daemon config (`slip.toml`)

```toml
[server]
listen = "0.0.0.0:7890"      # Bind address

[auth]
secret = "${SLIP_SECRET}"      # HMAC secret (env var resolved)

[caddy]
admin_api = "http://localhost:2019"

[storage]
path = "/var/lib/slip"         # State persistence directory
```

### App config (`apps/myapp.toml`)

```toml
[app]
name = "myapp"
image = "ghcr.io/you/myapp"
# secret = "${MYAPP_SECRET}"   # Per-app secret (overrides global)

[routing]
domain = "myapp.example.com"
port = 3000

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

[env]
DATABASE_URL = "${DATABASE_URL}"

[network]
name = "slip"
```

## Development

```bash
# Setup git hooks
./scripts/setup-hooks.sh

# Run tests
cargo test

# Check formatting + lints
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings

# Run smoke test (requires Docker + Caddy)
./scripts/smoke-test.sh
```

## Roadmap

- [x] **Phase 1: Core Deploy Loop** — webhook, deploy, health check, Caddy swap
- [ ] **Phase 2: Pods, Previews & CLI** — Podman support, pod deploys, preview environments, remote CLI

See [docs/design-v2-pod-deploys.md](docs/design-v2-pod-deploys.md) for the Phase 2 design.

## License

[MIT](LICENSE)
