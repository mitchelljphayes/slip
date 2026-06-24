# Getting slip Running on a VPS

This guide walks through setting up slip on a Linux VPS (e.g. Arakeen) to deploy your first app.

## Prerequisites

You need on the server:

1. **A container runtime** — Podman (recommended, for pod support) or Docker
2. **Caddy** — slip manages routes via Caddy's admin API
3. **A Rust toolchain** — to build slipd (or a pre-built binary when releases are available)

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

On the server (or cross-compile locally and copy):

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
backend = "auto"          # auto-detects Podman or Docker

[caddy]
admin_api = "http://localhost:2019"

[storage]
path = "/var/lib/slip"
EOF
```

> **Note:** `listen = "127.0.0.1:7890"` means slip only listens on localhost. Caddy will proxy webhook traffic to it on a public-facing route (see step 5). This keeps the webhook endpoint behind TLS.

## 4. Create your first app config

Each app gets its own TOML file in `/etc/slip/apps/`. This is the **server-side** config — it holds infra details (domain, secrets, resources) that aren't baked into the image.

### Simple single-container app (blue-green)

```bash
sudo tee /etc/slip/apps/my-app.toml > /dev/null << 'EOF'
[[apps]]
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
[[apps]]
name = "pipeline"
image = "ghcr.io/youruser/pipeline"

# kind = "worker" is declared in the repo's slip.toml (baked into the image)
# Worker apps skip domain, port, and HTTP health checks.
# Health = container running.

[deploy]
strategy = "blue-green"

[resources]
memory = "1g"
cpus = "2.0"

[[apps.volumes]]
host_path = "/var/lib/slip/volumes/pipeline/dlt-state"
mount_path = "/app/data"
read_only = false
EOF
```

### Pod app (multi-container, e.g. stat-stream)

```bash
sudo tee /etc/slip/apps/statstream.toml > /dev/null << 'EOF'
[[apps]]
name = "statstream"
image = "ghcr.io/youruser/statstream-api"

# The repo's slip.toml (baked into the image) declares kind = "pod"
# and points to the pod manifest (pod.yaml).

[deploy]
strategy = "recreate"

[[apps.routes]]
hostname = "statstream.yourdomain.com"
container = "api"

[[apps.routes]]
hostname = "dagster.yourdomain.com"
container = "dagster-webserver"

[[apps.volumes]]
host_path = "/var/lib/slip/volumes/statstream/dagster-home"
mount_path = "/opt/dagster/dagster_home"

[[apps.volumes]]
host_path = "/var/lib/slip/volumes/statstream/catalog"
mount_path = "/app/catalog"
EOF
```

## 5. Configure Caddy to proxy the webhook endpoint

slip listens on localhost. To receive webhooks from CI over the public internet, add a Caddy reverse proxy:

```bash
sudo tee /etc/caddy/slip-proxy.json > /dev/null << 'EOF'
{
  "apps": {
    "http": {
      "servers": {
        "slip": {
          "listen": [":443"],
          "routes": [
            {
              "match": [{"host": ["deploy.yourdomain.com"]}],
              "handle": [{
                "handler": "reverse_proxy",
                "upstreams": [{"dial": "127.0.0.1:7890"}]
              }]
            }
          ]
        }
      }
    }
  }
}
EOF
```

Or simpler — add it to your Caddyfile:

```
deploy.yourdomain.com {
    reverse_proxy 127.0.0.1:7890
}
```

```bash
sudo systemctl reload caddy
```

## 6. Set up secrets

```bash
# Set the webhook signing secret (used to verify CI webhooks)
sudo slip secret set my-app/SLIP_SECRET --value "your-hmac-secret-here"

# Set app secrets (injected as env vars at deploy time)
sudo slip secret set my-app/DATABASE_URL --value "postgres://..."
sudo slip secret set my-app/SECRET_KEY --value "your-secret-key"
```

> Use `sudo -u slip slip secret set ...` if the slip user owns the secrets dir.

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
- **Health check fails** — verify your app's `/health` endpoint works inside the container
- **Caddy route not created** — check `sudo journalctl -u slipd | grep caddy`, ensure Caddy admin API is on `:2019`
- **Permission denied on Podman socket** — ensure the `slip` user is in the `podman` group, or use Docker's `/var/run/docker.sock`
- **Webhook 403** — verify the HMAC signature matches; the secret in `slip secret set` must match what CI uses