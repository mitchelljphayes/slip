# slip — lightweight deploy daemon

Design document — March 2026

> A container docking for your server.

**slip** is a lightweight deployment daemon written in Rust. It runs on your server, accepts deploy webhooks from CI, and manages zero-downtime container deployments using Caddy as the reverse proxy. No SSH keys in CI, no PaaS overhead, no Kubernetes.

---

## Table of Contents

- [Problem](#problem)
- [Architecture](#architecture)
- [Components](#components)
- [Deploy Protocol](#deploy-protocol)
- [App Configuration](#app-configuration)
- [Adding a New App](#adding-a-new-app)
- [The Deploy Sequence](#the-deploy-sequence)
- [Caddy Integration](#caddy-integration)
- [Secret Management](#secret-management)
- [CLI](#cli)
- [Observability](#observability)
- [Security Model](#security-model)
- [Prior Art & Lessons](#prior-art--lessons)
- [Crate & Project Naming](#crate--project-naming)
- [Tech Stack](#tech-stack)
- [Build Phases](#build-phases)
- [Open Questions](#open-questions)

---

## Problem

We want to run multiple apps on a single VPS with:

- Automatic HTTPS
- Zero-downtime deploys
- Push-to-deploy from GitHub Actions
- Rollbacks
- Minimal per-app configuration

Existing tools either bundle too much (Dokploy, Coolify — full PaaS with dashboards and bundled reverse proxies), require SSH keys in CI (Kamal, Haloy, peleka), or don't handle routing (DCD, hoister).

We already run Caddy and like it. We want something that sits between CI and Docker, using Caddy for what it's good at (routing + TLS) and Docker for what it's good at (running containers).

---

## Architecture

```
GitHub Actions                          VPS (arrakeen)
                                        ┌──────────────────────────────┐
  ┌──────────┐    HTTPS POST            │                              │
  │ CI Build │──────────────────────────►│  slipd (deploy daemon)      │
  │          │   signed webhook          │  ├── pulls image from GHCR  │
  │ push to  │                           │  ├── starts new container   │
  │ GHCR     │                           │  ├── health checks          │
  └──────────┘                           │  ├── updates Caddy config   │
                                         │  └── stops old container    │
                                         │                              │
                                         │  Caddy                       │
                                         │  ├── :80/:443 (public)       │
                                         │  ├── auto TLS (Let's Encrypt)│
                                         │  └── reverse proxies to apps │
                                         │                              │
                                         │  Containers                  │
                                         │  ├── walden-api:abc123       │
                                         │  ├── walden-web:def456       │
                                         │  └── sh-web:789ghi           │
                                         └──────────────────────────────┘
```

**Key design decisions:**

1. **Webhook-based, not SSH-based.** CI sends a signed HTTPS request. No SSH keys in GitHub Secrets. The daemon only does what it's programmed to do.
2. **Caddy's admin API for routing.** No Caddyfile rewriting. slip talks to `localhost:2019` to add/update/remove routes dynamically.
3. **One daemon, many apps.** slipd manages all apps on the server. Each app is an independent container with its own config.
4. **Docker API via bollard.** No shelling out to `docker` CLI. Direct API calls for pulling, creating, starting, stopping, inspecting containers.

---

## Components

### `slipd` — the daemon

A long-running process on the server. Responsibilities:

- Listen for deploy webhooks on a configurable port
- Authenticate requests via HMAC-SHA256
- Pull Docker images from registries (GHCR, Docker Hub, etc.)
- Manage container lifecycle (create, start, health check, stop)
- Update Caddy routes via the admin API
- Track app state and deploy history
- Serve a status API

### `slip` — the CLI

A local CLI for manual operations and setup. Talks to slipd over its API.

- `slip apps` — list registered apps
- `slip status [app]` — show app status
- `slip deploy <app> <tag>` — trigger a manual deploy
- `slip rollback <app>` — roll back to previous version
- `slip logs <app>` — tail container logs
- `slip init` — initialize slipd config on a new server

### GitHub Actions integration

A reusable workflow or simple `curl` call:

```yaml
- name: Deploy
  run: |
    PAYLOAD='{"app":"walden-api","image":"ghcr.io/mitchelljphayes/walden-api","tag":"${{ github.sha }}"}'
    SIGNATURE=$(echo -n "$PAYLOAD" | openssl dgst -sha256 -hmac "${{ secrets.SLIP_SECRET }}" | cut -d' ' -f2)
    curl -X POST https://deploy.example.com/v1/deploy \
      -H "Content-Type: application/json" \
      -H "X-Slip-Signature: sha256=$SIGNATURE" \
      -d "$PAYLOAD"
```

No custom action needed. It's just a signed HTTP POST.

---

## Deploy Protocol

### Webhook endpoint

```
POST /v1/deploy
Content-Type: application/json
X-Slip-Signature: sha256=<hmac-sha256 of body>

{
  "app": "walden-api",
  "image": "ghcr.io/mitchelljphayes/walden-api",
  "tag": "sha-abc123f"
}
```

### Authentication

HMAC-SHA256 signature verification, same pattern as GitHub webhook secrets:

1. slipd has a shared secret per app (or one global secret)
2. CI computes `HMAC-SHA256(secret, request_body)` and sends it in the `X-Slip-Signature` header
3. slipd recomputes and compares using constant-time comparison

### Response

```json
{
  "deploy_id": "dep_01JQXYZ...",
  "app": "walden-api",
  "tag": "sha-abc123f",
  "status": "accepted"
}
```

The deploy is async. CI gets a 202 Accepted immediately. The actual deploy happens in the background. CI can poll:

```
GET /v1/deploys/dep_01JQXYZ...
```

To get the deploy status: `pulling`, `starting`, `health_checking`, `switching`, `completed`, `failed`, `rolled_back`.

---

## App Configuration

Apps are registered with slipd via a config directory on the server.

```
/etc/slip/
├── slip.toml           # daemon config
└── apps/
    ├── walden-api.toml
    ├── walden-web.toml
    └── sh-web.toml
```

### Daemon config

```toml
# /etc/slip/slip.toml

[server]
listen = "0.0.0.0:7890"
# or listen on Tailscale only:
# listen = "100.91.56.98:7890"

[caddy]
admin_api = "http://localhost:2019"

[auth]
# Global shared secret (apps can override)
secret = "${SLIP_SECRET}"

[registry]
# Default registry credentials
ghcr_token = "${GHCR_TOKEN}"

[storage]
# Where slip stores deploy history, state
path = "/var/lib/slip"
```

### App config

```toml
# /etc/slip/apps/walden-api.toml

[app]
name = "walden-api"
image = "ghcr.io/mitchelljphayes/walden-api"

[routing]
domain = "api.walden.sh"
port = 3000                     # container's internal port

[health]
path = "/health"
interval = "2s"
timeout = "5s"
retries = 5
start_period = "10s"

[deploy]
strategy = "blue-green"         # or "rolling" (future), "recreate"
drain_timeout = "30s"           # time to wait for old connections to finish

[env]
DATABASE_URL = "${DATABASE_URL}"
REDIS_URL = "${REDIS_URL}"

[env_file]
path = "/etc/slip/secrets/walden-api.env"   # optional, loaded at deploy time

[resources]
memory = "512m"
cpus = "1.0"

[network]
name = "slip"                   # docker network for all slip-managed containers
```

### Environment variable resolution

- `${VAR}` references are resolved from slipd's own environment, or from the system environment on the server
- `env_file` is read at deploy time and injected into the container
- Secrets never leave the server. CI doesn't know them.

---

## Adding a New App

### The flow

1. **Create the app config on the server:**

   ```bash
   slip apps add walden-api \
     --image ghcr.io/mitchelljphayes/walden-api \
     --domain api.walden.sh \
     --port 3000 \
     --health-path /health
   ```

   This creates `/etc/slip/apps/walden-api.toml` and registers a Caddy route.

   Or just create the TOML file directly — slipd watches the directory and picks up changes.

2. **Add secrets (if needed):**

   ```bash
   slip secrets set walden-api DATABASE_URL "postgres://..."
   slip secrets set walden-api REDIS_URL "redis://..."
   ```

   This writes to `/etc/slip/secrets/walden-api.env`.

3. **Add the deploy step to your CI:**

   The `curl` call from the Deploy Protocol section. One secret needed in GitHub: `SLIP_SECRET`.

4. **Push to main.** CI builds, pushes to GHCR, calls slipd. App is live.

### What you don't do

- SSH into the server
- Edit a Caddyfile
- Run docker commands
- Think about SSL certificates
- Write per-app deploy scripts

---

## The Deploy Sequence

When slipd receives a valid deploy webhook:

```
1. VALIDATE
   ├── Verify HMAC signature
   ├── Check app exists in config
   └── Check image reference is valid

2. PULL
   ├── Authenticate with registry (GHCR token)
   └── Pull image: ghcr.io/mitchelljphayes/walden-api:sha-abc123f

3. START NEW
   ├── Create container from new image
   │   ├── Inject env vars from config + env_file
   │   ├── Attach to slip network
   │   └── Assign ephemeral host port
   └── Start container

4. HEALTH CHECK
   ├── Poll GET http://localhost:{port}/health
   ├── Retry up to {retries} times at {interval}
   ├── If healthy → continue
   └── If unhealthy after retries → ROLLBACK (stop new, keep old, report failure)

5. SWITCH
   ├── Update Caddy route via admin API:
   │   POST http://localhost:2019/config/apps/http/...
   │   Point domain upstream to new container's port
   └── Wait for drain_timeout (let old connections finish)

6. STOP OLD
   ├── Stop previous container
   ├── Remove previous container
   └── (Keep the image for rollback)

7. RECORD
   ├── Write deploy to history (deploy_id, app, tag, timestamp, status)
   └── Update app state (current_tag, previous_tag, current_container_id)
```

### Rollback

`slip rollback walden-api` or `POST /v1/rollback {"app": "walden-api"}`:

1. Look up `previous_tag` from app state
2. Start a container from the previous image (already cached locally)
3. Health check
4. Switch Caddy route
5. Stop current container

Rollbacks are fast because the image is already on disk.

---

## Caddy Integration

slipd talks to Caddy's admin API at `http://localhost:2019`. This is the key integration point.

### How Caddy's admin API works

Caddy exposes its entire config as a JSON tree at `/config/`. You can GET, POST, PUT, PATCH, DELETE any node in the tree. Changes take effect immediately — no reload needed.

### What slip does

When deploying `walden-api` to `api.walden.sh` with the new container listening on host port `49152`:

```http
POST http://localhost:2019/config/apps/http/servers/slip/routes
Content-Type: application/json

{
  "match": [{"host": ["api.walden.sh"]}],
  "handle": [{
    "handler": "subroute",
    "routes": [{
      "handle": [{
        "handler": "reverse_proxy",
        "upstreams": [{"dial": "localhost:49152"}]
      }]
    }]
  }],
  "terminal": true
}
```

When switching to a new container (port `49153`), slip PATCHes just the upstream:

```http
PATCH http://localhost:2019/config/apps/http/servers/slip/routes/0/handle/0/routes/0/handle/0/upstreams
Content-Type: application/json

[{"dial": "localhost:49153"}]
```

### Caddy bootstrap

slipd needs Caddy to have a server block named `slip` that it controls. On first run, slip creates this:

```http
POST http://localhost:2019/config/apps/http/servers/slip
Content-Type: application/json

{
  "listen": [":443"],
  "routes": []
}
```

Existing Caddy config (like our sietch Caddyfile) is untouched — Caddy supports multiple server blocks. The `slip` server handles all slip-managed domains. Any manually-configured domains stay in the Caddyfile-managed server.

### TLS

Caddy handles TLS automatically. When slip adds a route with `"host": ["api.walden.sh"]`, Caddy will automatically obtain a Let's Encrypt certificate for that domain. For domains that need DNS challenge (like `.dev` domains behind Tailscale), we'd use Caddy's global TLS config or the DNS challenge module we already have.

---

## Secret Management

Secrets are stored **on the server only**. CI never sees them.

### Storage

```
/etc/slip/secrets/
├── walden-api.env      # KEY=value pairs
├── walden-web.env
└── sh-web.env
```

Permissions: `600`, owned by the slip user.

### Setting secrets

```bash
slip secrets set walden-api DATABASE_URL "postgres://user:pass@localhost:5432/walden"
slip secrets set walden-api REDIS_URL "redis://localhost:6379/0"
slip secrets list walden-api
slip secrets rm walden-api OLD_KEY
```

### How they're injected

At deploy time, slipd reads the env file and passes the variables to `docker create` via the `Env` field. They're never written to the image or to any config that leaves the server.

### Future: 1Password integration

Could add a `[secrets]` section to app config:

```toml
[secrets]
source = "1password"
vault = "Infrastructure"
item = "walden-api-prod"
```

slipd would fetch secrets from 1Password at deploy time using the `op` CLI or Connect API. But plain env files are fine for v1.

---

## CLI

### `slipd` — the daemon

```
slipd                       # Start the daemon (foreground)
slipd --config /etc/slip    # Explicit config path
slipd --check               # Validate config and exit
```

Runs as a systemd service in production:

```ini
[Unit]
Description=slip deploy daemon
After=network.target docker.service caddy.service
Requires=docker.service

[Service]
Type=simple
User=slip
ExecStart=/usr/local/bin/slipd --config /etc/slip
Restart=always
RestartSec=5
Environment=SLIP_SECRET=...
EnvironmentFile=/etc/slip/slip.env

[Install]
WantedBy=multi-user.target
```

### `slip` — the CLI

```
slip apps                           # List all apps
slip apps add <name> [options]      # Register a new app
slip apps rm <name>                 # Unregister an app
slip apps show <name>               # Show app details

slip status                         # Overview of all apps
slip status <app>                   # Detailed status of one app

slip deploy <app> <tag>             # Trigger a deploy
slip rollback <app>                 # Roll back to previous version

slip logs <app>                     # Tail container logs
slip logs <app> --since 1h          # Logs from last hour

slip secrets set <app> KEY VALUE    # Set a secret
slip secrets list <app>             # List secret keys (not values)
slip secrets rm <app> KEY           # Remove a secret

slip deploys <app>                  # Deploy history
slip deploys <app> --last 10        # Last 10 deploys

slip init                           # Interactive setup on a new server
```

The CLI talks to slipd's API over HTTP. When running locally on the server, it hits `http://localhost:7890`. Could also work remotely over Tailscale.

---

## Observability

### Deploy history

slipd stores deploy history in a SQLite database at `/var/lib/slip/slip.db`:

```sql
CREATE TABLE deploys (
    id          TEXT PRIMARY KEY,    -- dep_01JQXYZ...
    app         TEXT NOT NULL,
    image       TEXT NOT NULL,
    tag         TEXT NOT NULL,
    status      TEXT NOT NULL,       -- accepted, pulling, starting, health_checking, switching, completed, failed, rolled_back
    started_at  TEXT NOT NULL,
    finished_at TEXT,
    duration_ms INTEGER,
    error       TEXT,
    triggered_by TEXT                -- webhook, cli, rollback
);
```

### Status endpoint

```
GET /v1/status

{
  "daemon": "ok",
  "caddy": "ok",
  "docker": "ok",
  "apps": {
    "walden-api": {
      "status": "running",
      "tag": "sha-abc123f",
      "deployed_at": "2026-03-23T10:30:00Z",
      "container_id": "a1b2c3d4...",
      "health": "healthy"
    }
  }
}
```

### Logs

slipd logs to stdout (captured by systemd journal). Structured JSON logging:

```json
{"level":"info","app":"walden-api","tag":"sha-abc123f","event":"deploy_started","deploy_id":"dep_01JQXYZ"}
{"level":"info","app":"walden-api","event":"image_pulled","duration_ms":3200}
{"level":"info","app":"walden-api","event":"container_started","container_id":"a1b2c3d4","port":49152}
{"level":"info","app":"walden-api","event":"health_check_passed","attempts":2}
{"level":"info","app":"walden-api","event":"caddy_route_updated","upstream":"localhost:49152"}
{"level":"info","app":"walden-api","event":"old_container_stopped","container_id":"e5f6g7h8"}
{"level":"info","app":"walden-api","event":"deploy_completed","duration_ms":8500}
```

### Future: notifications

Could add webhook notifications on deploy success/failure:

```toml
[notifications]
webhook = "https://hooks.slack.com/..."
# or
discord = "https://discord.com/api/webhooks/..."
```

---

## Security Model

### Attack surface

| Vector | Mitigation |
|---|---|
| Deploy endpoint exposed publicly | HMAC-SHA256 verification; optionally bind to Tailscale interface only |
| Stolen SLIP_SECRET | Per-app secrets possible; rotate via CLI; only allows deploys, not shell access |
| Docker socket access | slipd runs as a dedicated `slip` user in the `docker` group; only calls specific Docker API endpoints |
| Caddy admin API | Bound to localhost only (Caddy default); slipd is the only consumer |
| Secrets on disk | `/etc/slip/secrets/` with 600 permissions, owned by `slip` user |
| Supply chain (malicious image) | slip only pulls images matching the registered `image` field for each app — can't deploy an arbitrary image |

### What CI gets access to

Exactly one capability: telling slipd to deploy a specific tag of a pre-registered app. That's it. No shell, no Docker, no secrets, no filesystem access.

Compare this to SSH-based tools where CI gets a private key that provides full shell access to the server.

### Network options

**Option A: Public endpoint behind Caddy**
- slipd listens on localhost, Caddy proxies `deploy.example.com` to it
- HMAC verification on every request
- Rate limiting via Caddy

**Option B: Tailscale only**
- slipd binds to the Tailscale IP
- Only devices on the tailnet can reach it
- GitHub Actions can't reach it directly (need a Tailscale GitHub Action or a public relay)

**Option C: Public deploy endpoint + Tailscale management**
- `/v1/deploy` is public (behind HMAC) — for CI
- `/v1/status`, `/v1/apps`, etc. are Tailscale-only — for the CLI
- Best of both worlds

Recommendation: **Option C** for our setup.

---

## Prior Art & Lessons

| Tool | What we're borrowing | What we're avoiding |
|---|---|---|
| **Kamal** | Blue-green deploy pattern, health-check-gated switch | SSH-based deploys, Ruby dependency, custom proxy |
| **Haloy** | Config-per-app YAML, daemon on server | Server daemon does too much (proxy + deploy + monitoring) |
| **slick-deploy** | Caddy admin API for routing (exact same pattern!) | Abandoned (archived), CLI-only (no daemon for webhooks) |
| **hoister** | Docker labels, auto-rollback on failure | Registry polling (we want push-based), no proxy management |
| **Dokploy** | Full PaaS UX (what we're trying to approximate) | Traefik, heavy runtime, web dashboard overhead |

### Deep dive: slick-deploy

[slick-deploy](https://github.com/scmmishra/slick-deploy) (Go, MIT, archived Jan 2026) is the closest prior art to slip. It was built by [Shivam Mishra](https://shivam.dev/blog/why-i-built-slick-deploy), Lead Product Engineer at Chatwoot, as a side project to learn Go and solve his own deployment pain.

**Why it exists (from his blog post):**
> "I couldn't find a tool that was minimal and had near zero-downtime deploys. All I was looking for something that worked as a slim layer between me and the tools I use to run apps on a VM."

He evaluated Fly.io, Railway, Render, Nomad, and Kamal before building slick. His motivation was identical to ours: the simple problem of "run a container on a VPS with zero downtime" shouldn't require a PaaS or Kubernetes.

**Why it was archived:** Not a technical failure — maintainer bandwidth. He built it, got it working for his own use, the Go learning goal was achieved, but his full-time job at Chatwoot meant it never reached production-readiness. Last commit August 2024, archived January 2026. The README always carried the warning: *"Slick is not ready for production."*

**What to study in the source (`internal/`):**
- **Caddy route switching** — how slick constructs the JSON payload for Caddy's admin API and swaps upstreams during blue-green deploys. This is the exact pattern slip will use.
- **Port management** (`pkg/utils/port.go`) — slick allocated ports from a configurable range. We're going with Docker ephemeral ports instead, but worth understanding the tradeoff.
- **YAML-to-Caddy config conversion** — Shivam noted this was "sub-optimal" in his blog and wished he'd used the admin API more directly. We're avoiding this entirely by talking to the API natively.
- **Health check implementation** — basic but functional, good starting reference.

**What slip does differently:**
1. **Daemon, not just a CLI** — slick was CLI-only (you SSH in and run `slick deploy`). slip runs a daemon that accepts webhooks, eliminating SSH from CI entirely.
2. **Rust, not Go** — single static binary, no runtime deps, fits our stack.
3. **TOML config, not YAML** — Rust-native, less ambiguity.
4. **Deploy history** — slick had no state persistence. slip tracks deploys in SQLite.
5. **Secret management** — slick deferred to external tools. slip manages secrets on-server.

The core architecture validation is the key takeaway: the Caddy admin API approach works. The project died because of maintainer bandwidth, not because the design was wrong.

---

## Crate & Project Naming

| Item | Name |
|---|---|
| Project | slip |
| Daemon binary | slipd |
| CLI binary | slip |
| Crate (crates.io) | slip-deploy |
| GitHub repo | TBD/slip |
| Config dir | /etc/slip/ |
| Systemd service | slipd.service |
| Docker network | slip |
| Container prefix | slip- (e.g. slip-walden-api-abc123f) |

---

## Tech Stack

| Component | Choice | Why |
|---|---|---|
| Language | Rust | Performance, single binary, no runtime deps |
| HTTP server | axum | Tokio-native, lightweight, great ergonomics |
| Docker client | bollard | Async Rust Docker API, well-maintained |
| HTTP client | reqwest | For Caddy admin API + health checks |
| Config | toml + config crate | Rust-native, human-friendly |
| Database | SQLite via rusqlite | Deploy history, zero-ops |
| Logging | tracing + tracing-subscriber | Structured JSON logging, standard in Rust ecosystem |
| Auth | hmac + sha2 crates | HMAC-SHA256 verification |
| IDs | ulid | Sortable, timestamp-embedded unique IDs |
| CLI | clap | Standard Rust CLI framework |
| Serialization | serde + serde_json | For API payloads and config |

---

## Build Phases

### Phase 1: Core deploy loop (MVP)

The minimum viable deploy daemon. One app, one server, happy path only.

- [ ] Project scaffolding (workspace: `slipd`, `slip`, `slip-core`)
- [ ] Config parsing (slip.toml + app TOML files)
- [ ] HTTP server with `/v1/deploy` endpoint
- [ ] HMAC-SHA256 request verification
- [ ] Docker image pull via bollard
- [ ] Container create/start with env injection
- [ ] Health check polling loop
- [ ] Caddy admin API integration (add/update route)
- [ ] Blue-green swap (start new → health check → switch → stop old)
- [ ] Basic error handling (unhealthy → stop new, keep old)
- [ ] Structured logging

**Exit criteria:** Can deploy a single app via `curl` and it goes live with zero downtime.

### Phase 2: CLI + state management

- [ ] `slip` CLI binary (talks to slipd API)
- [ ] `slip apps`, `slip status`, `slip deploy`, `slip logs`
- [ ] SQLite deploy history
- [ ] `slip rollback` command
- [ ] `/v1/status` endpoint
- [ ] `slip secrets set/list/rm`
- [ ] App config hot-reload (watch `/etc/slip/apps/` for changes)
- [ ] `slip init` — interactive server setup

**Exit criteria:** Full CLI workflow for adding apps, deploying, rolling back, checking status.

### Phase 3: Production hardening

- [ ] Drain timeout (graceful connection draining on swap)
- [ ] Deploy locking (prevent concurrent deploys to same app)
- [ ] Deploy timeout (kill stuck deploys)
- [ ] Image cleanup (prune old images, keep last N)
- [ ] Container resource limits (memory, CPU)
- [ ] Systemd service file + install script
- [ ] Multiple registry support (GHCR, Docker Hub, custom)
- [ ] Per-app secrets (override global SLIP_SECRET)

**Exit criteria:** Can run in production without babysitting.

### Phase 4: GitHub Actions + DX

- [ ] Reusable GitHub Actions workflow (`.github/workflows/slip-deploy.yml`)
- [ ] Deploy status callback (POST back to GitHub deployment API)
- [ ] `slip deploy --wait` (block until deploy completes or fails)
- [ ] GitHub deployment environments integration
- [ ] Documentation site

**Exit criteria:** `git push` → app deployed, with deploy status visible in GitHub.

### Phase 5: Nice-to-haves

- [ ] Notification webhooks (Slack, Discord)
- [ ] 1Password secret integration
- [ ] Multiple servers (deploy to N servers in parallel)
- [ ] Docker Compose support (multi-container apps)
- [ ] Web dashboard (read-only status page)
- [ ] Agent skill for Claude Code / OpenCode

---

## Open Questions

1. **Should `slip` support Docker Compose apps?** v1 handles single-container apps. Multi-container (e.g., app + worker + redis) could be a Phase 5 feature. For now, each container is an independent app.

2. **How should Caddy be installed?** Options:
   - User installs Caddy themselves (our current approach on sietch)
   - `slip init` installs it
   - Ship a Docker Compose file that runs Caddy + slipd together
   
   Recommendation: keep them independent. Caddy is a well-documented, mature tool. Don't bundle it.

3. **Should slipd itself run in a Docker container?** Probably not — it needs access to the Docker socket and Caddy's admin API. Running it as a native binary via systemd is simpler and more debuggable.

4. **Port allocation:** When starting a new container, how do we pick the host port? Options:
   - Let Docker assign an ephemeral port (inspect container to find it)
   - Allocate from a configurable range per app
   
   Recommendation: let Docker assign ephemeral ports. Simpler, no collisions.

5. **What if Caddy restarts?** Caddy's admin API config is in-memory by default. If Caddy restarts, all dynamically-added routes are lost. Options:
   - Use Caddy's `--resume` flag (persists config to disk)
   - slipd reconciles on startup (re-registers all routes from app state)
   
   Recommendation: both. Belt and suspenders.

6. **Should we support the `slip.toml` in-repo pattern?** Where the app repo contains its own slip config, and the first deploy auto-registers it. Nice for DX but adds complexity. Phase 2 or 3.

---

## References

- [Caddy admin API docs](https://caddyserver.com/docs/api)
- [bollard (Rust Docker client)](https://github.com/fussybeaver/bollard)
- [slick-deploy (archived, same architecture)](https://github.com/scmmishra/slick-deploy)
- [GitHub webhook signature verification](https://docs.github.com/en/webhooks/using-webhooks/validating-webhook-deliveries)
- [axum](https://github.com/tokio-rs/axum)
- [Kamal](https://kamal-deploy.org/)
- [Haloy](https://haloy.dev/)
- [hoister](https://github.com/HerrMuellerluedenscheid/hoister)
