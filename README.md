# slip

> A container docking for your server.

**slip** is a lightweight deployment daemon written in Rust. It runs on your server, accepts deploy webhooks from CI, and manages zero-downtime container deployments using Caddy as the reverse proxy.

No SSH keys in CI. No PaaS overhead. No Kubernetes.

## How it works

```
GitHub Actions → signed webhook → slipd → pull image → start container → health check → update Caddy → stop old
```

1. CI builds your image and pushes to GHCR
2. CI sends a signed HTTP POST to your server
3. `slipd` pulls the image, starts a new container, health checks it
4. If healthy: swaps the Caddy route, drains old connections, stops the old container
5. If unhealthy: stops the new container, keeps the old one running

## Status

Early development. See [docs/prd.md](docs/prd.md) for the full product spec and [docs/slip-design.md](docs/slip-design.md) for the architecture design doc.

## Project Structure

Cargo workspace with three crates:

- **`slipd`** — the deploy daemon (receives webhooks, manages containers, talks to Caddy)
- **`slip`** — the CLI (app management, secrets, status, manual deploys)
- **`slip-core`** — shared library (config, types, Docker/Caddy clients)

## License

TBD
