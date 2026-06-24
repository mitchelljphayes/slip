# slip Marketing & Launch Plan

## Positioning

**One-liner:** Zero-downtime container deploys from CI, without Kubernetes.

**Longer pitch:** slip is a lightweight deployment daemon that accepts signed webhooks from CI, pulls container images, and manages blue-green or recreate deploys using Caddy as the reverse proxy. No SSH keys in CI, no PaaS overhead, no control plane to manage.

**Who it's for:**
- Solo devs and small teams running 2-15 services on a single VPS
- People currently SSHing in to `docker compose pull && up -d` on every deploy
- Self-hosters who looked at k8s and decided it was too much
- Agencies and freelancers deploying client projects on single boxes

**Who it's NOT for:**
- Teams needing multi-node clustering or horizontal autoscaling (use k8s)
- People who want a managed PaaS (use Render/Fly/Railway)
- Teams without a container registry (slip pulls from GHCR/Docker Hub)

## Key Differentiators

| Feature | slip | Dokku | CapRover | Kamal | k8s |
|---------|------|-------|---------|-------|-----|
| Signed webhooks (no SSH in CI) | ✅ | ❌ (git push) | ❌ (dashboard) | ❌ (SSH) | ❌ |
| Single binary, no runtime deps | ✅ (Rust) | ❌ (Ruby) | ❌ (Docker-in-Docker) | ✅ (Ruby) | ❌ |
| Blue-green + recreate strategies | ✅ | ❌ | ❌ | ✅ (blue-green only) | ✅ |
| Pod support (kube play) | ✅ | ❌ | ❌ | ❌ | ✅ |
| Worker / non-HTTP apps | ✅ | ❌ | ❌ | ❌ | ✅ |
| Preview deployments | ✅ | ❌ | ✅ | ❌ | ✅ |
| Persistent volumes | ✅ | ✅ | ✅ | ✅ | ✅ |
| Multiple routes per deploy | ✅ | ❌ | ✅ | ❌ | ✅ |
| Cost | Free | Free | Free | Free | $73+/mo/node |

## Pre-Launch Checklist

### Must-have before sharing

- [ ] Getting started guide (✅ done — `docs/getting-started.md`)
- [ ] README with quick start and feature list
- [ ] GitHub Releases with pre-built Linux binary (SLIP-69)
- [ ] `slip init` interactive setup (stub exists, needs implementation)
- [ ] A demo (GIF or 60-second video)
- [ ] Comparison table in README
- [ ] Example app + CI workflow (so people can try end-to-end)

### Nice-to-have before sharing

- [ ] Docs site (MkDocs or similar)
- [ ] Homebrew tap / apt repo for easy install
- [ ] Docker image for running slipd itself
- [ ] GitHub Actions reusable workflow

## Launch Activities

### 1. Polish the README (Day 1)

The README is the landing page. It needs:

- **Hero section** — one sentence + a badge (build status, license, Rust version)
- **Quick start** — 3 commands to get a deploy running
- **Feature list** — with checkmarks, not paragraphs
- **Comparison table** — from above
- **Architecture diagram** — simple: CI → webhook → slipd → Docker/Podman → Caddy
- **Link to getting started guide**
- **License** (MIT/Apache-2.0)

### 2. Ship a binary release (Day 1-2)

Nobody wants to install Rust to try a deploy tool. Build a statically linked Linux binary and attach to a GitHub Release:

```bash
# Cross-compile for Linux x86_64 (from macOS)
rustup target add x86_64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl
```

Install script:
```bash
curl -sSL https://raw.githubusercontent.com/mitchelljphayes/slip/main/install.sh | bash
```

This is SLIP-69 (systemd service + install script).

### 3. Create a demo (Day 2-3)

A 60-second video showing:
1. Push to GitHub
2. GitHub Actions builds Docker image, pushes to GHCR
3. Actions sends signed webhook to slip
4. slip pulls image, starts new container, health checks, swaps route
5. App live with zero downtime

Host it as a GIF in the README. This sells itself.

### 4. Example repo (Day 3)

Create a `slip-example` repo with:
- A trivial Go or Python HTTP app with `/health`
- A Dockerfile
- A `slip.toml` repo config
- A GitHub Actions workflow that builds, pushes, and deploys via webhook
- A README showing the full flow

This is the "I want to try this" path for new users.

### 5. Write a launch post (Day 4-5)

A blog post (cross-post to dev.to, Medium, your own blog):

**Title:** "slip: zero-downtime deploys from CI without Kubernetes"

**Structure:**
- The problem: SSH deploys suck, k8s is overkill for one server
- The solution: a daemon that takes webhooks and manages deploys
- How it works: webhook → pull → health check → swap → drain
- Key features: blue-green, recreate, workers, pods, previews, volumes
- Why not [alternative]: comparison table
- Getting started: link to guide
- What's next: roadmap

### 6. Post to communities (Day 5-6)

**Hacker News** — title: "Show HN: slip — zero-downtime deploys from CI without k8s"
- Post on a weekday morning US time (Tuesday-Thursday)
- Lead with the problem, not the solution
- Have the comparison table visible
- Be present in comments for the first 4 hours

**r/selfhosted** — title: "slip: deploy containers from CI with zero downtime, no k8s"
- This audience cares about simplicity and self-hosting
- Emphasize: single binary, no dependencies, runs on any VPS

**r/rust** — title: "slip: a deployment daemon written in Rust"
- This audience cares about the tech choices
- Emphasize: axum, bollard, STRICT SQLite, async patterns

**Lobsters** — if you have an invite, similar angle to HN but more technical

**Twitter/X / Bluesky** — thread with the demo GIF + comparison table

### 7. Dev.to / Medium article (Day 6-7)

A tutorial-style article: "How to deploy a web app from GitHub Actions with zero downtime (without k8s)"

This is more SEO-friendly than a launch post and captures people searching for "CI deploy without kubernetes."

## Ongoing (Post-Launch)

### Week 1-2
- Monitor GitHub issues and respond quickly
- Fix any bugs reported by early adopters
- Write follow-up post: "What I learned launching slip"

### Month 1
- Add Homebrew tap: `brew install slip`
- Create a Docker image: `docker run slip/slipd`
- Implement `slip init` (interactive setup)
- Add more example apps (Rust, Node, Python, Go)

### Month 2-3
- Docs site (mkdocs-material)
- Reusable GitHub Actions workflow (SLIP-27)
- Deploy status callback to GitHub Deployments API (SLIP-28)
- `slip deploy --wait` synchronous mode (SLIP-29)

## Messaging Guide

### Don't say
- "Kubernetes killer" (it's not)
- "Better than k8s" (it's different, not better)
- "Simple" without explaining why (overused)
- "Production-ready" (subjective, let users decide)

### Do say
- "Zero-downtime deploys from CI" (concrete benefit)
- "No SSH keys in your CI" (addresses a real pain point)
- "Single binary, no runtime to install" (low friction)
- "Pod support via podman kube play" (technical differentiator)
- "Runs on a $5 VPS" (cost clarity)

### Elevator pitch (30 seconds)

> "slip is a deployment daemon that takes signed webhooks from CI and manages zero-downtime container deploys. You push to GitHub, CI builds your image and sends a webhook, slip pulls the image, health checks it, and swaps the route. No SSH keys in CI, no Kubernetes, no PaaS fees. It's a single Rust binary that runs on any VPS."

## Success Metrics

What "working" looks like:
- 50+ GitHub stars in first week
- 5+ people actually deploying with it (not just starring)
- 1-2 community contributors
- At least one "I replaced [X] with slip" story

What "great" looks like:
- 500+ stars in first month
- 20+ active deployments
- Community-contributed example apps
- Feature requests from real users (means they're using it)

## Risks & Mitigations

| Risk | Mitigation |
|------|------------|
| Nobody cares | It's a useful tool for your own projects regardless |
| "Just use k8s" comments | Comparison table + "$5 VPS" messaging |
| "Just use Dokku" comments | Highlight webhook model + pod support |
| Bug in early adoption | Fast response, fix-forward, transparent changelog |
| Security concern | Signed webhooks are the pitch — lean into it |
| Maintenance burden | Keep scope small — single server, no clustering |