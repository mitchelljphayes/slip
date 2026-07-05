# Field Report: Deploying poi-australia via slip

A first-hand account of taking a real, non-trivial app (Next.js 15 + Payload CMS 3)
from zero to production on slip, written to feed the slip roadmap. Covers what slip
does today (as observed), the hard edges hit along the way, and the gap between the
current experience and the target UX.

**Target UX we're aiming for** (the yardstick this report measures against):
> SSH into box → install slip → generate an admin key. Then on your local machine:
> `slip init` a new project, generate a **per-app** deploy key, add it to GitHub
> secrets/CI — and the config just works.

---

## 1. What was deployed (the test case)

- **App**: `poi-australia` — Next.js 15 (`output: standalone`) + Payload CMS 3.76, pnpm.
- **Host**: "Arrakeen" — Ubuntu 24.04, single VPS, **rootful Podman** (slip `backend = "podman"`), Caddy (admin API mode), UFW enabled.
- **Supporting services**: Postgres 17 + Garage (S3-compatible) as a separate `podman compose` stack joined to slip's `slip` network.
- **Registry**: private GHCR image.
- **Deploy trigger**: eventually a GitHub Actions webhook over Tailscale to a tailnet-only `deploy.mjph.dev`.

This exercised nearly every slip surface: single-container app, blue-green, secrets,
private registry pull, the `slip` network + external services, Caddy routing + TLS,
and the deploy webhook.

---

## 2. Observed slip model (as of this deploy)

Documenting what I actually saw, so the roadmap starts from a shared picture:

- **Processes**: `slipd` (daemon) + `slip` (CLI). Daemon listens on `127.0.0.1:7890` (deploy + management API).
- **Config**: `/etc/slip/slip.toml` (server, runtime, auth, registry, caddy, storage) + `/etc/slip/apps/<name>.toml` (per-app, **file-based**).
- **State**: `/var/lib/slip/{state,secrets,volumes}` + `slip.db` (SQLite deploy history).
- **Network**: on startup slipd creates a Podman bridge network named `slip` (`attachable`/aardvark DNS). All deployed containers join it.
- **Caddy**: slipd manages routes via Caddy's admin API (`localhost:2019`). Routes are tagged `@id = slip-<app>-<n>` and reconciled on daemon startup.
- **Deploy flow**: `POST /v1/deploy {"app","tag"}` + `X-Slip-Signature: sha256=<hmac>` → pull image → inject secrets as env → create container → health-check the configured path → swap the Caddy route → drain/stop old.
- **Strategies**: `blue-green` and `recreate`.
- **Container naming**: `slip-<app>-<tag>-<ulid>`, and the **tag segment is truncated** (e.g. `slip-poi-manual-20260-01KWN12E` for tag `manual-20260704-081628`).
- **Secrets**: `slip secrets set|list|rm <app> KEY=VALUE --token <global>` — injected as env at deploy.

---

## 3. Hard edges & friction (prioritized)

Severity: 🔴 blocker / confusing enough to cause a wrong turn · 🟠 real friction · 🟡 papercut.

### 🔴 3.1 Webhook auth uses the GLOBAL secret, not per-app — directly blocks the target UX
The docs (getting-started §6) say a per-app `SLIP_SECRET` "overrides" the global
`[auth].secret` for webhook signing. **Empirically it does not.** I set a per-app
`SLIP_SECRET` for `poi`, signed the webhook with it → `401 invalid signature`. Signed
the same payload with the **global** `[auth].secret` → accepted. The existing `quack`
app had no per-app `SLIP_SECRET` at all — it uses the global one.

**Impact**: The target UX ("generate a per-app deploy key to add to CI") is impossible
today. Every app's CI must hold the **global** deploy secret — a "deploy anything on the
box" credential. That's a real security smell for multi-app / multi-repo setups.

**Direction**: Make deploy-webhook auth **per-app** first-class. Each app gets its own
signing key; the global secret (if kept) should only gate the management API. This is the
single most important change for the intended workflow.

### 🔴 3.2 Docs bootstrap (file-based) vs intended API-driven model — caused a wrong turn
getting-started tells you to hand-write `/etc/slip/apps/<name>.toml` on the host. But the
intended design (per the maintainer) is: **deploy config lives in the app repo and is
applied via the API** (`PATCH /v1/apps/{name}`). Following the docs, I copied config onto
the host *and* into an infra repo — both wrong. There's no `slip init` / `slip apps apply`
that reads a repo `slip.toml` and registers it via the API.

**Impact**: The "config just works from the repo" promise isn't wired yet; newcomers will
do the file-copy thing and create drift.

**Direction**: Ship the repo-first path end-to-end: `slip init` scaffolds `slip.toml`;
a CLI/CI command applies it via the API; the file on the host stops being the source of truth.

### 🔴 3.3 New app config isn't live without a `slipd` restart
After dropping `/etc/slip/apps/poi.toml`, `slip secrets set poi ...` failed with
`app 'poi' not found` until I `systemctl restart slipd`. The daemon only loads app configs
at startup — there's no hot-reload of the apps dir, and I found no `slip apps create` that
registers an app at runtime.

**Impact**: Every new app needs an SSH + daemon restart, which is exactly what the target
UX is trying to eliminate.

**Direction**: `PATCH/POST /v1/apps/{name}` should register/update an app live (no restart),
and `slip secrets set` should be able to create-then-set atomically.

### 🟠 3.4 No webhook ingress bootstrap; and the documented approach clobbers slip's routes
`slipd` listens on `127.0.0.1:7890`, but nothing sets up the public/tailnet-facing route
(`deploy.example.com → 127.0.0.1:7890`). getting-started §5 suggests `POST /load` with a
JSON snippet — but `/load` **replaces the whole Caddy config**, which would wipe slip's
dynamically-managed app routes. I instead had to `POST` a single route into
`apps/http/servers/slip/routes` via the admin API with a hand-picked `@id`, and hope slip
wouldn't reconcile it away (it didn't — reconciliation is by `@id`, so foreign routes
survive, but that's undocumented and unguaranteed).

**Direction**: slip should own its own webhook ingress — a `slip expose-webhook <host>`
(or config in `slip.toml`) that creates and maintains the route, including the TLS story below.

### 🟠 3.5 TLS for internal/tailnet endpoints isn't handled
`deploy.mjph.dev` resolves to a **tailnet IP** (Tailscale, non-public). Caddy (driven by
slip's automatic HTTPS) kept trying public Let's Encrypt HTTP-01, which can't validate a
non-public IP → endless failures. I had to explicitly add a `tls` automation policy with
the **internal** (self-signed) issuer for that host; CI then uses `curl --insecure` over
the encrypted tailnet.

**Direction**: slip should recognize internal/tailnet hostnames (or a per-route flag) and
use the internal CA automatically — or support DNS-01. Relatedly, non-public TLDs like the
existing `*.arrakeen.test` apps spam the logs with LE `invalid public suffix` errors; slip
should use the internal CA for those automatically.

### 🟠 3.6 Stuck/staging ACME state was confusing
Caddy had a **staging** ACME account from slip's earlier testing. When the real domain went
live, cert issuance got stuck retrying a stale staging order (10-min backoff) even though the
persisted config defaulted to production. There was no `email` configured either.

**Direction**: slip should configure production ACME + a contact email by default, and offer
a way to clear/renew stuck cert state (a `slip tls renew <host>` or similar). Ship sane
defaults so a first deploy gets a trusted cert without manual intervention.

### 🟠 3.7 Health-check semantics don't prove readiness
The health check hits a path (e.g. `/`). For this app, `/` returns **200 even when the DB is
down** (static homepage), so a broken-DB deploy could pass health. Separately, when I set a
site-password env, `/` began returning **307** and slip still (correctly) treated it as
healthy — but what counts as "healthy" (2xx only? 3xx? a configurable expected status?) isn't
documented.

**Impact**: With migrate-on-boot apps, a naive `/` check can swap traffic before the app is
truly ready. We worked around it app-side (a readiness path + Payload init at boot).

**Direction**: Support a configurable expected status / readiness semantics, document what
counts as healthy, and encourage a real readiness endpoint. Consider a `[health] expect_status`
and/or `ready` vs `live` distinction.

### 🟠 3.8 Container-name↔service DNS silently broken behind UFW
`network-coexistence.md` promises apps resolve `postgres:5432` / `garage:3900` by name on the
`slip` network. On this UFW host it **silently failed** (`getaddrinfo EAI_AGAIN`): UFW's
default-drop `INPUT` chain blocked container→gateway DNS to aardvark on `10.89.0.1:53`. I had
to `ufw allow in on <bridge> to any port 53`. Also hit a **stale aardvark-dns** process once
that needed a kill/restart before it served the current network.

**Impact**: This is the kind of thing that makes "slip networking just works" feel untrue and
costs an hour of debugging. It affects *every* app that talks to a supporting service.

**Direction**: `slip doctor` should check bridge DNS end-to-end (resolve + reach aardvark) and
the installer should add the UFW allow rule for slip's bridge. Detect/repair stale aardvark.

### 🟠 3.9 No lifecycle hooks (pre/post-deploy, one-shot jobs)
Apps that need a migration/seed step before serving have nowhere to put it. We solved
poi's schema via Payload's own `prodMigrations` (runs in-container on boot) + a Postgres
advisory-lock entrypoint to serialize blue-green boots + health-gating. That's a lot of
app-side machinery to compensate for a missing platform primitive.

**Direction**: a slip-native **pre-swap hook / one-shot job** ("run this container/command to
completion; only swap if it exits 0") would generalize migrations, seeds, cache warms, etc.

### 🟡 3.10 Registry auth papercuts
Private GHCR pull works via `[registry] ghcr_token = "${GHCR_TOKEN}"` + an `EnvironmentFile`
in the systemd unit. But `slipd --config /etc/slip --check` run by hand **fails** with
`missing environment variable $GHCR_TOKEN` because it doesn't load the systemd EnvironmentFile
— confusing (the service is fine; the manual check isn't). I also ran `podman login` as a
belt-and-suspenders.

**Direction**: a first-class `slip registry login ghcr.io` (stores creds for the daemon), and
`--check` should warn (not error) on unresolved env, or optionally source an env file.

### 🟡 3.11 Observability requires SSH + podman/journalctl spelunking
I mostly used `podman ps` + `journalctl -u slipd` to see what was happening. Container-name
tag truncation means `podman ps --filter name=<app>-<full-tag>` doesn't match. `slip status`
exists but a richer `slip status <app>` (current tag, health, container id, last deploy,
resolved secret keys, route/cert status) surfaced from the CLI would remove almost all of the
SSH spelunking.

### 🟡 3.12 Shared-services workflow is real but undocumented
slip correctly doesn't manage Postgres/object-store, and `network-coexistence.md` covers
joining the `slip` network. But the practical end-to-end has sharp edges worth a short guide:
the stack must run under the **same runtime as slip** (rootful Podman, so it shares slip's
rootful `slip` network — the Docker network of the same name is a decoy), use `container_name`
for stable DNS, publish **no** host ports, and use `podman compose` (docker-compose provider).
A `slip services` scaffold or doc would save the next person the trial-and-error.

---

## 4. Gap analysis vs the target UX

| Target UX step | Today | Gap |
|---|---|---|
| SSH in, install slip, **generate admin key** | Manual `slip.toml` with a hand-set `[auth].secret` | Add `slip init-server` that generates the admin key + writes config + sets up the webhook ingress |
| Local: **`slip init`** a project | No such command; you hand-write `slip.toml` | Scaffold `slip.toml` in the repo; validate against the schema |
| Local: **generate per-app deploy key** → GH secret | Only a **global** secret works for webhooks (§3.1) | **Per-app deploy keys** (the keystone feature) + `slip keys create <app>` that prints a key for CI |
| **Config just works** from the repo | File-on-host is source of truth; needs restart (§3.2, §3.3) | API-driven `slip apply` from repo `slip.toml`, live (no restart) |
| CI triggers deploy | Works, but: global secret, manual webhook route, self-signed TLS quirk (§3.4, §3.5) | slip-owned webhook ingress + internal-TLS awareness |
| App needs migrations | No primitive; solved app-side | Pre-swap hook / one-shot job (§3.9) |
| "Networking just works" | Silently broke behind UFW (§3.8) | `slip doctor` + installer firewall rule |

---

## 5. Recommended roadmap (prioritized)

**P0 — unblocks the target UX**
1. **Per-app deploy keys** for webhook auth (§3.1). Keystone.
2. **API-driven app registration**, live without restart (§3.2, §3.3): `POST/PATCH /v1/apps`, and `slip init` / `slip apply` on the client reading repo `slip.toml`.
3. **`slip keys create <app>`** → prints a per-app deploy key for CI; pairs with #1.

**P1 — makes first-run "just work"**
4. **Webhook ingress bootstrap** owned by slip (§3.4) — creates + maintains the `deploy.*` route.
5. **TLS smarts** (§3.5, §3.6): production ACME + email by default; internal CA for internal/tailnet/non-public hosts automatically; a way to clear stuck cert state.
6. **`slip doctor`** (§3.8, §3.10): checks bridge DNS/aardvark, UFW rule, runtime socket, registry auth, Caddy admin reachability. Installer adds the UFW allow rule for slip's bridge.
7. **Readiness semantics** (§3.7): configurable expected status; document what "healthy" means; encourage a real readiness endpoint.

**P2 — power & polish**
8. **Pre-swap hook / one-shot job** primitive (§3.9) — generalizes migrations/seeds.
9. **`slip registry login`** (§3.10) + `--check` that doesn't error on unresolved env.
10. **Richer `slip status <app>`** (§3.11): tag, health, container, last deploy, route/cert, secret keys.
11. **Shared-services guide/scaffold** (§3.12) documenting the rootful-Podman-shared-network pattern.
12. **Log hygiene**: use internal CA for non-public TLDs to stop LE `invalid public suffix` spam (§3.5).

---

## 6. What already works well (keep it)

- **The core deploy loop is solid**: pull → secrets-inject → health-check → blue-green swap → drain was reliable once configured. First real deploy went green on attempt 1.
- **Podman backend + the `slip` attachable network** is a good model; joining external stacks to it is the right shape (just needs the DNS/UFW paper cut fixed and a doc).
- **Route reconciliation by `@id`** meant my hand-added webhook route survived restarts — good instinct; just make it a first-class feature instead of an accident.
- **Secrets-as-env injection** is clean and the right default.
- **SQLite deploy history** and the small daemon footprint (single-digit MB RSS) are great for a single-VPS tool.

---

*Compiled from a full poi-australia production bring-up on Arrakeen. Happy to pair with the
slip agent on any of these — several have obvious, small implementations (e.g. the UFW rule,
internal-CA-for-internal-hosts, `--check` env handling) that would remove a lot of first-run pain.*
