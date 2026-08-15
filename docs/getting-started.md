# Getting slip Running on a VPS

This guide walks through setting up slip on a Linux VPS (e.g. Arakeen) to deploy your first app.

> **Note:** This guide sets the server up by hand, which is the explicit path.
> `slip server init` performs steps 2 through 5 in one command, and `slip init`
> scaffolds the repo side. Remaining work is tracked in the
> [v1.0 roadmap project](https://linear.app/mitchelljphayes/project/slip-v10-agent-ready-paas-b99757b85655).

## Prerequisites

You need on the server:

1. **A container runtime** — Podman (recommended, for pod support) or Docker
2. **Caddy** — slip manages routes via Caddy's admin API
3. **A Rust toolchain** — required on macOS (the installer builds from source there; no prebuilt binary is published for darwin). On Linux x86_64/aarch64 a prebuilt static binary is downloaded by the installer, so the toolchain is only needed if you prefer the manual build path below.

### Install Podman

```bash
# Debian/Ubuntu
sudo apt update && sudo apt install -y podman

# Or Docker (if you prefer):
# curl -fsSL https://get.docker.com | sh
```

### Install Caddy

```bash
sudo apt install -y debian-keyring debian-archive-keyring apt-transport-https
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | sudo gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | sudo tee /etc/apt/sources.list.d/caddy-stable.list
sudo apt update
sudo apt install -y caddy
```

### Install Rust (to build slip)

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"
```

## 1. Build slipd

The one-command installer handles both platforms:

```bash
curl -sSL https://raw.githubusercontent.com/mitchelljphayes/slip/main/install.sh | sudo bash
```

On Linux x86_64/aarch64 it downloads the prebuilt static binary. On macOS (or
any other host without a prebuilt binary) it builds from source via `cargo`
— that's why the Rust toolchain prerequisite above is required on macOS.
Pass `--version <tag>` to pin a release, or run it from inside a slip
checkout to build the current working tree.

The manual build-from-source path (the advanced alternative):

```bash
git clone https://github.com/mitchelljphayes/slip.git
cd slip
cargo build --release

# Copy the binaries somewhere on PATH
sudo cp target/release/slipd /usr/local/bin/
sudo cp target/release/slip /usr/local/bin/
```

## 2. Create the slip user and directories

```bash
# Create a dedicated user
sudo useradd --system --no-create-home --shell /usr/sbin/nologin slip

# Add slip user to the container runtime group
# For Podman:
sudo usermod -aG podman slip
# For Docker:
sudo usermod -aG docker slip

# Create config and data directories
sudo mkdir -p /etc/slip/apps
sudo mkdir -p /var/lib/slip/state
sudo mkdir -p /var/lib/slip/secrets
sudo mkdir -p /var/lib/slip/volumes

# Set ownership
sudo chown -R slip:slip /var/lib/slip
sudo chown -R slip:slip /etc/slip
```

## 3. Write the main config

```bash
sudo tee /etc/slip/slip.toml > /dev/null << 'EOF'
[server]
listen = "127.0.0.1:7890"

[runtime]
backend = "auto"          # "auto" | "docker" | "podman"

[auth]
secret = "${SLIP_SECRET}"  # global HMAC fallback; per-app [app] secret overrides it

[registries.ghcr]
url = "ghcr.io"
# username = "slip"              # optional: anonymous pull if absent
# token = "${GHCR_TOKEN}"       # optional: prefer `slip registry login ghcr.io`

[caddy]
admin_api = "http://localhost:2019"

[storage]
path = "/var/lib/slip"
EOF
```

> **Required sections:** `[server]`, `[auth]`, `[caddy]`, `[storage]`.
> `[registries.<name>]` is optional (omit it for anonymous pulls); if present,
> each entry needs a `url` (host[:port] only — no scheme, no trailing slash).
> The preferred way to add a registry credential is
> `slip registry login <url>` (no daemon restart needed); a TOML `token` is
> the bootstrap fallback. `[auth].secret` supports `${ENV}` interpolation (set
> `SLIP_SECRET` in slipd's systemd unit). See `docs/registry-runbook.md` for
> the full registry config + GHCR PAT guide.
>
> **Note:** `listen = "127.0.0.1:7890"` means slip only listens on localhost. Caddy will proxy webhook traffic to it on a public-facing route (see step 5). This keeps the webhook endpoint behind TLS.

## 4. Create your first app config

Each app gets its own TOML file in `/etc/slip/apps/`. This is the **server-side** config — it holds infra details (domain, secrets, resources) that aren't baked into the image.

### Simple single-container app (blue-green)

Each app is a single `[app]` table (not `[[apps]]`). The `[health]` section is required — omit `path` to skip the HTTP probe and health-check on "container running" instead. See `docs/health.md` for the full health semantics (readiness patterns, `expect_status` grammar, timeout arithmetic, redirects).

```bash
sudo tee /etc/slip/apps/my-app.toml > /dev/null << 'EOF'
[app]
name = "my-app"
image = "ghcr.io/youruser/my-app"

[routing]
domain = "myapp.yourdomain.com"
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

### Worker app (no HTTP endpoint, e.g. a pipeline)

```bash
sudo tee /etc/slip/apps/pipeline.toml > /dev/null << 'EOF'
[app]
name = "pipeline"
image = "ghcr.io/youruser/pipeline"

# kind = "worker" is declared in the repo's slip.toml (baked into the image).
# Worker apps skip domain, port, and HTTP health checks. Health = container running.

[health]
# no path → health-check on "container running"

[deploy]
strategy = "recreate"        # single-writer state: never run two instances

[resources]
memory = "1g"
cpus = "2.0"

[[volumes]]
host_path = "/var/lib/slip/volumes/pipeline/dlt-state"
mount_path = "/app/data"
read_only = false
EOF
```

### Pod app (multi-container, e.g. stat-stream)

```bash
sudo tee /etc/slip/apps/statstream.toml > /dev/null << 'EOF'
[app]
name = "statstream"
image = "ghcr.io/youruser/statstream-api"

# The repo's slip.toml (baked into the image) declares kind = "pod"
# and points to the pod manifest (pod.yaml).

[health]
path = "/health"

[deploy]
strategy = "recreate"

[[routing.routes]]
hostname = "statstream.yourdomain.com"
container = "api"

[[routing.routes]]
hostname = "dagster.yourdomain.com"
container = "dagster-webserver"

[[volumes]]
host_path = "/var/lib/slip/volumes/statstream/dagster-home"
mount_path = "/opt/dagster/dagster_home"

[[volumes]]
host_path = "/var/lib/slip/volumes/statstream/catalog"
mount_path = "/app/catalog"
EOF
```

## 5. Expose the webhook endpoint

slipd listens on localhost. For CI to reach it, the webhook needs a public
hostname and a certificate. slipd handles both: set `domain` under `[deploy]`
and it registers the Caddy route and the TLS policy itself on startup.

```toml
[caddy]
acme_email = "you@example.com"

[deploy]
domain = "deploy.yourdomain.com"
# tls = "acme"   # the default; see the table below
```

That is the whole step. No `curl` calls against the admin API, and nothing to
re-apply after a Caddy restart — slipd reconciles the route on every boot.

> **Do not add the webhook to your Caddyfile.** slipd creates a Caddy server
> named `slip` on `:443`. A Caddyfile site block (`deploy.yourdomain.com { … }`)
> adapts into a *separate* server on the same port, and Caddy ≥ 2.11 rejects
> the second one: `listener address repeated: tcp/:443 (already claimed by
> server 'slip')`. slipd's bootstrap then fails and the daemon crash-loops
> under `Restart=on-failure`. Configure `[deploy] domain` instead.

### Choosing a TLS strategy

CI runners verify the certificate like any other client, so the default is
`acme` — a publicly trusted Let's Encrypt certificate. Pick a different
strategy only when `acme` cannot work on your host:

| `tls` | Use when | Certificate | Reachable from |
|-------|----------|-------------|----------------|
| `acme` (default) | The domain resolves to this host and ports 80/443 are open to the internet | Publicly trusted | Anywhere |
| `cloudflare-dns01` | Cloudflare DNS, and the host has no inbound reachability (CGNAT, firewalled) | Publicly trusted | Anywhere the host is routable |
| `tailscale` | Tailnet-only host with a `*.ts.net` name | Publicly trusted | Tailnet only |
| `internal` | Local development, or a private network where you control every caller | Self-signed (Caddy local CA) | Anywhere, but callers must trust the CA |

`acme` and `cloudflare-dns01` require `[caddy] acme_email`; slipd refuses to
start without it rather than falling back to a self-signed certificate.

**If your host is tailnet-only**, `acme` cannot issue for it — Let's Encrypt
has no route to complete the challenge. slipd rejects `acme` on a `*.ts.net`
domain at config load with a pointer to `tls = "tailscale"`. Note that the
certificate being publicly trusted does not make the host publicly reachable:
a GitHub-hosted runner still cannot route to a `100.x` tailnet address, so the
workflow must join the tailnet (`tailscale/github-action`) before calling the
webhook.

**`internal` and CI do not mix.** A self-signed certificate makes every public
CI call fail verification, and `--insecure` in a deploy workflow throws away
the authentication that the signed webhook exists to provide. Use `internal`
for local work, not for a runner-facing endpoint.

### Verify the route

```bash
curl -s http://localhost:2019/config/apps/http/servers/slip/routes | python3 -m json.tool
```

You should see a `slip-deploy-webhook` route alongside slipd's `slip-<app>-<n>`
routes. To confirm the certificate is one CI can verify, check it from a
machine that is not this host and not on your tailnet:

```bash
curl -sS -o /dev/null -w '%{http_code}\n' https://deploy.yourdomain.com/v1/deploy
```

A TLS error here means CI will fail the same way. `slip doctor` also flags the
common version of this — a self-signed certificate serving a public hostname —
but it reads the issuer from Caddy locally, so it cannot tell you whether the
host is reachable from where CI actually runs. The `curl` above, from off-host,
is the check that answers that.

## 6. Set up secrets

The CLI subcommand is `slip secrets` (plural). It calls slipd's management API,
which requires the global token (`[auth].secret`). The form is
`slip secrets set <app> KEY=VALUE [KEY=VALUE ...]`.

### Two separate secret systems

It is critical to understand that slip has **two independent secret stores**,
and confusing them is the most common cause of 401 errors:

| Store | Set via | Purpose |
|-------|---------|---------|
| **App TOML `[app] secret`** | Edit `/etc/slip/apps/<name>.toml` | **Webhook HMAC signing** — the key used to verify `X-Slip-Signature` on deploy requests |
| **Secrets store** | `slip secrets set <app> KEY=VALUE` | **Container env injection** — values are written to files under `/var/lib/slip/secrets/` and injected as environment variables at deploy time |

### Webhook auth: how the HMAC secret is resolved

When slipd receives a deploy webhook, it resolves the HMAC signing key in this
order (see `crates/slip-core/src/api.rs:1020`):

1. **Per-app `[app] secret`** in the app TOML — if set, this is used.
2. **Global `[auth].secret`** from `slip.toml` — fallback if no per-app secret.

> **`slip secrets set <app> SLIP_SECRET=…` does NOT affect webhook auth.**
> That command writes to the *env-injection* store. The value is injected into
> the container as an environment variable named `SLIP_SECRET` — it has nothing
> to do with HMAC signature verification. This is the root cause of the 401
> errors documented in [field-report-poi-australia.md §3.1](field-report-poi-australia.md).

To set a per-app webhook secret, add `secret` under `[app]` in the app's
TOML file:

```toml
[app]
name = "my-app"
image = "ghcr.io/youruser/my-app"
secret = "your-hmac-key"   # overrides global [auth].secret for this app

# ... rest of the app config unchanged
```

> **Note:** The per-app `[app] secret` field works today but is **deprecated**
> pending [SLIP-89](https://linear.app/mitchelljphayes/issue/SLIP-89) (per-app
> deploy keys). The long-term design is a dedicated `slip keys create <app>`
> command that generates and manages deploy keys separately from the app config.

### App secrets (env injection)

Use `slip secrets set` for values your app needs at runtime — database URLs,
API tokens, etc. These are **not** used for webhook auth:

```bash
TOKEN="your-global-auth-secret"   # the [auth].secret from slip.toml

# Set app secrets (injected as env vars at deploy time) — multiple at once
sudo slip secrets set my-app \
  DATABASE_URL=postgres://... \
  SECRET_KEY=your-secret-key \
  --token "$TOKEN"

# List keys (values are never returned)
sudo slip secrets list my-app --token "$TOKEN"
```

> Set `SLIP_TOKEN` in your environment to avoid passing `--token` each time.

## 7. Create a systemd service

```bash
sudo tee /etc/systemd/system/slipd.service > /dev/null << 'EOF'
[Unit]
Description=slip deploy daemon
After=network.target podman.service docker.service caddy.service
Wants=network.target

[Service]
Type=simple
User=slip
Group=slip
ExecStart=/usr/local/bin/slipd --config /etc/slip
Restart=on-failure
RestartSec=5
# SLIP-88: a Caddy :443 listener conflict is a config error (exit 78 / EX_CONFIG),
# not a transient failure — don't crash-loop; let the user fix the Caddyfile.
RestartPreventExitStatus=78

# Environment variables for secret resolution
Environment="RUST_LOG=info"
# Environment="GHCR_TOKEN=your-ghcr-token"  # if pulling from GHCR

# Hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=/var/lib/slip /etc/slip
# Container runtime socket access:
# For Docker:  ReadOnlyPaths=/var/run/docker.sock
# For Podman:  socket is per-user via systemd

[Install]
WantedBy=multi-user.target
EOF
```

> **Podman note:** If running slipd as a systemd service with Podman, you may need a user-scoped Podman socket (`systemctl --user enable podman.socket`) or run slipd as root with the root Podman socket. Docker's `/var/run/docker.sock` is simpler for this setup. Adjust the `ReadWritePaths` and socket access accordingly.

## 8. Start slipd

```bash
# Validate config first
sudo slipd --config /etc/slip --check

# Start the service
sudo systemctl daemon-reload
sudo systemctl enable --now slipd

# Check it's running
sudo systemctl status slipd
sudo journalctl -u slipd -f
```

## 9. Trigger your first deploy

### From CI (GitHub Actions / curl)

```bash
# The webhook payload
PAYLOAD='{"app":"my-app","tag":"sha-abc123f"}'

# Compute HMAC signature
SECRET="your-hmac-secret-here"
SIGNATURE=$(echo -n "$PAYLOAD" | openssl dgst -sha256 -hmac "$SECRET" | sed 's/^.* //')

# Send the deploy webhook
curl -X POST https://deploy.yourdomain.com/v1/deploy \
  -H "Content-Type: application/json" \
  -H "X-Slip-Signature: sha256=$SIGNATURE" \
  -d "$PAYLOAD"
```

### Using the CLI

```bash
slip deploy my-app sha-abc123f \
  --server https://deploy.yourdomain.com \
  --secret "your-hmac-secret-here"
```

### Check status

```bash
slip status --server https://deploy.yourdomain.com --secret "your-hmac-secret-here"
```

## 10. Connecting external infrastructure

If your apps need postgres, redis, etc. running as a separate compose stack, join them to slip's network:

```yaml
# docker-compose.infra.yml
services:
  postgres:
    image: postgres:16
    networks: [slip]
    # ...

networks:
  slip:
    external: true
    name: slip
```

Your slip-deployed containers can then reach `postgres:5432` by name. See [docs/network-coexistence.md](network-coexistence.md) for details.

## Troubleshooting

- **`slipd --check` fails** — check TOML syntax, app names match image config
- **Container won't start** — `journalctl -u slipd -f` shows the deploy log
- **Health check fails** — verify your app's `/health` endpoint works inside the container. See `docs/health.md` for readiness patterns and the `expect_status` grammar.
- **Caddy route not created** — check `sudo journalctl -u slipd | grep caddy`, ensure Caddy admin API is on `:2019`
- **Permission denied on Podman socket** — ensure the `slip` user is in the `podman` group, or use Docker's `/var/run/docker.sock`
- **Webhook 401** — verify the HMAC signature matches. The signing key is either the **global** `[auth].secret` from `slip.toml` or the **per-app** `[app] secret` from the app TOML. `slip secrets set <app> SLIP_SECRET=...` does **not** affect webhook auth — it injects the value as a container env var only. See §6 for the full distinction.
- **`missing field 'auth'` / `'registry'` / `'health'`** — those sections are required; see steps 3-4
- **`unrecognized subcommand 'secret'`** — the command is `slip secrets` (plural)