# PRD: slip — Lightweight Deploy Daemon

**Status:** Approved  
**Author:** MJP  
**Date:** March 2026  
**Design Doc:** [slip-design.md](./slip-design.md)

---

## Overview

**slip** is a lightweight deployment daemon written in Rust that accepts webhooks from CI, pulls container images, and manages zero-downtime blue-green deployments using Caddy as the reverse proxy. It eliminates SSH keys in CI, avoids PaaS overhead, and lets you run multiple apps on a single VPS with automatic HTTPS and one-command rollbacks.

## Problem Statement

We run multiple apps on a single VPS and need: automatic HTTPS, zero-downtime deploys, push-to-deploy from GitHub Actions, rollbacks, and minimal per-app configuration.

**Existing tools don't fit:**

- **Full PaaS** (Dokploy, Coolify) — heavy, bundle their own reverse proxy, dashboards we don't need
- **SSH-based** (Kamal, Haloy, peleka) — require SSH private keys in CI, giving CI full shell access to the server
- **Minimal tools** (DCD, hoister) — don't handle routing or TLS

We already run Caddy. We want something that sits **between CI and Docker**, using Caddy for routing + TLS and Docker for running containers. Nothing more.

**Key insight from prior art:** [slick-deploy](https://github.com/scmmishra/slick-deploy) validated this exact architecture (Caddy admin API + Docker) but was archived due to maintainer bandwidth, not design failure. The approach works.

## Proposed Solution

A daemon (`slipd`) running on the server that:

1. **Receives signed webhooks** from CI (HMAC-SHA256, no SSH)
2. **Pulls images** from container registries (GHCR, Docker Hub) via the Docker API (bollard)
3. **Runs blue-green deploys** — start new container, health check, swap Caddy route, stop old container
4. **Manages Caddy routes** dynamically via the admin API (no Caddyfile editing)
5. **Stores deploy history** in SQLite for rollbacks and observability

Plus a CLI (`slip`) for manual operations, app registration, secret management, and server status.

### Architecture

```
GitHub Actions → HTTPS webhook → slipd → pulls image → starts container
                                       → health check → updates Caddy → stops old container
```

CI gets exactly one capability: telling slipd to deploy a specific tag of a pre-registered app. No shell, no Docker access, no secrets.

### Key Decisions (Locked In)

| Decision | Choice | Rationale |
|----------|--------|-----------|
| **Repo name** | `slip` | Clean name; crate is `slip-deploy` for crates.io uniqueness |
| **Network model** | Option C: public deploy + Tailscale management | CI needs public endpoint; management stays private |
| **Caddy installation** | Check on `slip init`, prompt to install if missing | Don't bundle, but don't leave user stranded either |
| **slipd runtime** | Native binary + systemd | Simpler than Docker; direct access to Docker socket + Caddy API |
| **Project layout** | Cargo workspace | `slipd`, `slip`, `slip-core` crates |
| **CLI usage** | Local on server AND remote from dev machine | CLI talks to slipd over HTTP; works locally (localhost:7890) or remotely (Tailscale) |

## User Stories

### Deployer (developer pushing code)

- **As a developer**, I want to push to main and have my app deployed automatically, so I don't need to SSH into servers or run manual deploy scripts.
- **As a developer**, I want deploys to be zero-downtime, so users never see errors during deployments.
- **As a developer**, I want to roll back to the previous version in one command, so I can recover from bad deploys quickly.
- **As a developer**, I want to run `slip status` from my own machine (over Tailscale) to see what's running, without SSHing into the server.

### Operator (person managing the server)

- **As an operator**, I want to add a new app with a single CLI command and a few config values, so onboarding new services is fast.
- **As an operator**, I want secrets to stay on the server and never flow through CI, so my attack surface is minimal.
- **As an operator**, I want structured logs and deploy history, so I can debug issues and audit deployments.
- **As an operator**, I want health checks to gate deploys, so bad code never receives traffic.
- **As an operator**, I want `slip init` to check for Caddy and Docker and guide me through setup, so I don't miss prerequisites.

### CI System (GitHub Actions)

- **As CI**, I need only one secret (`SLIP_SECRET`) and a single `curl` call to deploy, so integration is trivial — no custom actions, no SSH keys.

## Functional Requirements

### Phase 1: Core Deploy Loop (MVP)

| ID | Requirement | Acceptance Criteria |
|----|------------|---------------------|
| F1 | **Webhook endpoint** — `POST /v1/deploy` accepts `{app, image, tag}` | Returns 202 with `deploy_id`; rejects unsigned/invalid requests with 401/400 |
| F2 | **HMAC-SHA256 auth** — verify `X-Slip-Signature` header | Constant-time comparison; supports global and per-app secrets |
| F3 | **Image pull** — pull from registry using Docker API (bollard) | Authenticates with GHCR token; rejects images not matching app config |
| F4 | **Container lifecycle** — create, start, stop, remove containers | Injects env vars from config + env_file; attaches to `slip` Docker network; assigns ephemeral host port |
| F5 | **Health checks** — poll container health endpoint before switching | Configurable path, interval, timeout, retries, start_period; fail → stop new container, keep old |
| F6 | **Caddy route management** — add/update routes via admin API | Creates `slip` server block on bootstrap; updates upstream on deploy; preserves existing Caddy config |
| F7 | **Blue-green swap** — start new → health check → switch route → drain → stop old | Zero downtime; configurable drain timeout |
| F8 | **Config parsing** — read `slip.toml` + per-app TOML files from `/etc/slip/` | Validates config on startup; rejects invalid configs with clear errors |
| F9 | **Structured logging** — JSON logs via `tracing` | Every deploy step is a log event with app, tag, deploy_id, duration |
| F10 | **Automatic rollback** — on health check failure, keep old container running | Old container continues serving; deploy marked as `failed` |

### Phase 2: CLI + State Management

| ID | Requirement | Acceptance Criteria |
|----|------------|---------------------|
| F11 | **`slip` CLI binary** communicating with slipd over HTTP | Works locally (localhost) and remotely (Tailscale IP / hostname) |
| F12 | **Core CLI commands** — `slip apps`, `slip status`, `slip deploy`, `slip logs` | Each command returns clear, formatted output |
| F13 | **SQLite deploy history** at `/var/lib/slip/slip.db` | Stores deploy_id, app, tag, status, timestamps, duration, error, trigger source |
| F14 | **`slip rollback <app>`** — deploy previous tag | Uses cached image; completes in < 15s |
| F15 | **`GET /v1/status` endpoint** | Returns daemon health, Caddy status, Docker status, all app statuses |
| F16 | **`slip secrets set/list/rm`** — manage per-app env files | Secrets stored in `/etc/slip/secrets/` with 600 permissions; values never shown in `list` |
| F17 | **App config hot-reload** — watch `/etc/slip/apps/` for changes | New/modified/deleted TOML files picked up without daemon restart |
| F18 | **`slip init`** — interactive server setup | Checks for Docker and Caddy; prompts to install Caddy if missing; creates config dirs; generates initial `slip.toml` |

### Phase 3: Production Hardening

| ID | Requirement |
|----|------------|
| F19 | Drain timeout — graceful connection draining during swap |
| F20 | Deploy locking — prevent concurrent deploys to same app |
| F21 | Deploy timeout — kill stuck deploys |
| F22 | Image cleanup — prune old images, keep last N |
| F23 | Container resource limits (memory, CPU from app config) |
| F24 | Systemd service file + install script |
| F25 | Multiple registry support (GHCR, Docker Hub, custom) |
| F26 | Per-app deploy secrets (override global `SLIP_SECRET`) |

### Phase 4: GitHub Actions + DX

| ID | Requirement |
|----|------------|
| F27 | Reusable GitHub Actions workflow |
| F28 | Deploy status callback to GitHub Deployments API |
| F29 | `slip deploy --wait` — synchronous deploy mode |
| F30 | Documentation site |

## Non-Functional Requirements

| Category | Requirement |
|----------|------------|
| **Performance** | Deploy cycle (pull → health → switch) < 60s for cached images, < 120s for cold pulls. Webhook response < 100ms. |
| **Reliability** | Failed deploys must never take down the running version. Caddy route reconciliation on daemon restart. Use Caddy `--resume` AND slipd reconciliation (belt and suspenders). |
| **Security** | HMAC-SHA256 on all deploy requests. Secrets stored 600-permission on server only. CI gets zero shell access. Image allow-list per app. Management endpoints on Tailscale only. |
| **Operability** | Single static binary, no runtime dependencies. Runs as systemd service. Structured JSON logs to stdout (captured by journald). |
| **Compatibility** | Works with any Docker registry. Doesn't conflict with existing Caddy config (separate server block). Supports Tailscale-only management endpoints. |
| **Resource footprint** | Daemon < 50MB RAM at rest. Event-driven, no background polling. |

## Tech Stack

| Component | Choice | Why |
|-----------|--------|-----|
| Language | Rust | Performance, single binary, no runtime deps |
| HTTP server | axum | Tokio-native, lightweight, great ergonomics |
| Docker client | bollard | Async Rust Docker API, well-maintained |
| HTTP client | reqwest | For Caddy admin API + health checks |
| Config | toml + config crate | Rust-native, human-friendly |
| Database | SQLite (rusqlite) | Deploy history, zero-ops |
| Logging | tracing + tracing-subscriber | Structured JSON logging |
| Auth | hmac + sha2 crates | HMAC-SHA256 verification |
| IDs | ulid | Sortable, timestamp-embedded unique IDs |
| CLI | clap | Standard Rust CLI framework |
| Serialization | serde + serde_json | API payloads and config |

### Project Structure (Cargo Workspace)

```
slip/
├── Cargo.toml              # workspace root
├── Cargo.lock
├── crates/
│   ├── slipd/              # daemon binary
│   │   ├── Cargo.toml
│   │   └── src/
│   ├── slip/               # CLI binary
│   │   ├── Cargo.toml
│   │   └── src/
│   └── slip-core/          # shared types, config, Docker/Caddy clients
│       ├── Cargo.toml
│       └── src/
├── docs/
│   ├── prd.md
│   └── slip-design.md
├── README.md
└── .github/
    └── workflows/
```

## Out of Scope (v1)

- Docker Compose / multi-container apps — each container is an independent app
- Web dashboard — CLI and API only
- Multiple servers — single server deployment
- Rolling deploys — blue-green only
- Built-in metrics / Prometheus — structured logs are sufficient
- 1Password integration — env files on disk for now
- In-repo `slip.toml` — apps are registered server-side only
- Auto-scaling — fixed container count

## Open Questions (Resolved)

| # | Question | Resolution |
|---|---------|------------|
| 1 | Network exposure model? | **Option C** — public deploy endpoint (HMAC) for CI, Tailscale-only management endpoints for CLI |
| 2 | Should `slip init` install Caddy? | **Check and prompt** — detect if Caddy is installed, prompt user to install if missing |
| 3 | Should slipd run in Docker? | **No** — native binary via systemd |
| 4 | CLI usage model? | **Both local and remote** — works on the server (localhost) and from dev machines (over Tailscale) |
| 5 | Project layout? | **Cargo workspace** with `slipd`, `slip`, `slip-core` crates |
| 6 | Caddy persistence on restart? | **Both** — Caddy `--resume` flag AND slipd reconciliation on startup |
| 7 | Port allocation? | **Docker ephemeral ports** — inspect container to discover assigned port |

## Success Metrics

| Metric | Target |
|--------|--------|
| Deploy latency (webhook → live) | < 60s cached, < 120s cold pull |
| Deploy success rate | > 99% (failures are code bugs, not infra) |
| Rollback time | < 15s (image already on disk) |
| Time to add a new app | < 5 minutes (one CLI command + one CI secret) |
| Zero-downtime deploys | 100% — no dropped requests during switch |
| CI integration effort | One `curl` command, one secret |

## Next Steps

1. Initialize git repo and scaffold Cargo workspace
2. Create Linear project with Phase 1 tickets
3. Start building: config parsing → webhook endpoint → Docker integration → health checks → Caddy integration
