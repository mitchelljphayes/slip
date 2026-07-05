# Infrastructure-as-Code with slip — Design Guide (DRAFT)

> **Status:** Draft v2 — reviewed by the infra agent 2026-07-05; §8's open
> questions are now **resolved decisions** and the schema gaps found in review
> (CORS overrides, Caddy build pin, advisory export, DNS validation) are folded
> into the tickets. Describes the *target* model; the "Today (pre-1.0)" section
> covers what to do until the referenced tickets land.
>
> **Traceability:** every capability cites its Linear ticket. Roadmap project:
> [slip v1.0: Agent-Ready PaaS](https://linear.app/mitchelljphayes/project/slip-v10-agent-ready-paas-b99757b85655).
>
> **Related reading:** `docs/field-report-poi-australia.md`,
> `docs/hard-edges-field-report.md` — the dogfooding reports this model is
> designed around.

---

## 1. The core idea

slip splits everything on a box into **four layers with different owners**.
Getting IaC right with slip is mostly about respecting this split — versioning
the right layers in the right repos and *refusing* to version the others.

| Layer | Contents | Source of truth | Versioned? |
|---|---|---|---|
| **App config** | health checks, routing, env, resource needs (`[needs.*]`) | The **app's own repo** (`slip.toml`), applied via API on deploy | ✅ in each app repo — **never** the infra repo |
| **Server config** | deploy webhook domain + TLS strategy, registries, provisioned services (postgres/s3/kv/registry), exposed routes | The **server manifest** in the infra repo, converged via `slip server apply` | ✅ infra repo — this is your layer |
| **Secrets & keys** | admin secret, per-app deploy keys, service credentials, app secrets | slipd's secrets store on the box (mode 600) + your vault (1Password) | ❌ never in git — manifests hold *references*, not values |
| **Runtime state** | deploy history, current tags, provisioned resource records, volumes | slipd (SQLite + `/var/lib/slip`) | ❌ it's state, not config — **back up**, don't version |

**The rule of thumb:** if changing it should trigger a review, it's config —
version it in the repo that owns it. If it's a value someone could steal, it's
a secret — reference it. If slip derived it, it's state — back it up.

### Why this exact split (the war stories)

This model isn't theoretical — each boundary exists because an agent got burned
dogfooding slip:

- **App config in the infra repo → drift.** The poi deployment kept app config
  in three places (app repo, infra repo, host file). The host went stale: it
  health-checked `/` (which returns 200 with the database *down*) months after
  the app repo moved to `/api/healthz`. Nobody noticed because nothing
  converged. App config now lives in the app repo only and is applied on deploy
  (SLIP-94). If you find yourself copying an app's `slip.toml` into the infra
  repo — stop, that's the bug.
- **Server config unversioned → hand-rolled sync scripts.** The Garage/S3
  provisioning session ended with `caddy-manual-routes.py` + a oneshot systemd
  unit re-applying routes after every Caddy restart, synced by hand from the
  infra repo. The server manifest (SLIP-117) + slip's reconcile loop (SLIP-99)
  replace that entire pattern.
- **Secrets in config files → they leak into git and logs.** slip keeps key
  material in a mode-600 store and never echoes values in diffs or status
  output. The manifest carries `op://` references (SLIP-118).

---

## 2. The infra repo layout (target)

```
infra/
├── boxes/
│   ├── arrakeen.slip.toml        # server manifest — one per box
│   └── sietch.slip.toml
├── .github/workflows/
│   └── slip-converge.yml         # dry-run on PR, apply on merge (see §4)
└── docs/
    └── runbooks/…                 # anything slip doesn't own (OS, tailscale, backups)
```

### Anatomy of a server manifest

```toml
# infra/boxes/arrakeen.slip.toml
# Converged by: slip server apply — do not hand-edit the box to match this;
# edit this and apply.

[deploy]
domain = "deploy.mjph.dev"
tls = "internal"                          # tailnet-only box → Caddy local CA

[caddy]
acme_email = "ops@example.com"
build = { version = "2.11.4", plugins = ["cloudflare"] }
# ^ pinned build: `server init --from-file` rebuilds a DNS-01-capable Caddy —
#   without this, a DR rebuild gets stock apt Caddy and dns01 silently breaks
#   (SLIP-115/117)

[registries.ghcr]
url = "ghcr.io"
token = "op://infra/ghcr-pull/token"      # 1Password reference — resolved at apply

[services.postgres]
type = "postgres"
version = "17"

[services.s3]
type = "s3"

[services.kv]
type = "kv"

[[expose]]
service = "s3"
host = "s3.steamtankcoffee.com.au"
tls = "cloudflare-dns01"                  # real LE cert for a tailnet host
dns = { proxied = false }                 # expectation, not management: doctor
                                          # fails if this gets orange-clouded
cors_preset = "s3"                        # baseline; every field overridable:

[expose.cors]                             # the browser-Parquet range-read case
allow_methods = ["GET", "HEAD", "OPTIONS"]
expose_headers = ["ETag", "Accept-Ranges", "Content-Range", "Content-Length", "Last-Modified"]

[[routes]]                                 # escape hatch: non-slip upstreams
host = "ducklake.steamtankcoffee.com.au"
upstream = "127.0.0.1:8123"
tls = "cloudflare-dns01"
dns = { proxied = false }
# [routes.cors] available here too — the escape hatch has the same CORS surface
```

What is deliberately **absent**:

- No app entries. Apps register themselves via `slip apply` from their own
  repos (SLIP-90/94). The manifest doesn't know or care that `poi` exists.
- No secret values. Every credential is an `op://` or `${ENV}` reference
  (SLIP-118).
- No Caddy JSON, no systemd units, no container run commands. Those are slip's
  implementation details; the manifest is intent.

### Never commit these

- `/etc/slip/apps/*.toml` — generated caches, marked "managed by slip." Committing
  them recreates the poi drift bug with extra steps.
- `slip.db`, `/var/lib/slip/**` — runtime state and data volumes. Back up
  instead (see §6).
- Anything printed exactly once by `slip server init` or `slip key` — those are
  secrets; they go in 1Password.

---

## 3. Command surface you'll use (infra-facing)

| Command | What it does | Ticket |
|---|---|---|
| `slip server init` | One-shot box bootstrap: admin key, config, systemd, webhook ingress + TLS. **Emits the initial manifest** for you to commit | SLIP-97 |
| `slip server init --from-file boxes/arrakeen.slip.toml` | Rebuild a box from the committed manifest (disaster recovery) | SLIP-97 |
| `slip server export` | **Advisory** snapshot of live state → manifest form + an explicit "unexpressed" report for anything the schema can't represent (lossy export = distinct exit code). Day-0 adoption + drift inspection | SLIP-117 |
| `slip server apply <file> [--dry-run]` | Validate → diff → converge via API. Dry-run exits 0/1 for CI | SLIP-117 |
| `slip server diff <file>` | Live state vs committed manifest | SLIP-117 |
| `slip services add/list/rm`, `slip services expose` | Imperative sugar over the same declared state — **treat imperative use on a GitOps box as drift** and re-export | SLIP-106/110 |
| `slip doctor [--json] [--fix]` | Diagnose + prescribe: network DNS/UFW, runtime, registry auth, Caddy, TLS/cert state | SLIP-102 |
| `slip status [--json]` | Daemon + per-app truth (incl. drift flags, cert expiry) | SLIP-100 |

All commands: `--json` with stable schemas, contractual exit codes
(0 ok · 3 auth · 4 not-found · 5 deploy-failed · 6 timeout). Build automation
against `--json`, not human output (SLIP-86).

---

## 4. Workflows

### Day 0 — adopt an existing box (arrakeen)

1. Upgrade slip to a version with SLIP-117's `export`.
2. `slip server export > infra/boxes/arrakeen.slip.toml`
3. **Review the "unexpressed" report** — export is advisory, not authoritative.
   Anything it couldn't express (foreign admin-API routes, hand-added TLS
   policies) needs a manual decision: express it via `[[routes]]`, keep it in
   the escape-hatch script, or delete it. Also sanity-check exported values
   against intent — export captures *live state*, including any drift-caused
   bad values.
4. Replace inline secrets with `op://` references; put the values in 1Password.
5. Commit. Verify round-trip: `slip server apply --dry-run boxes/arrakeen.slip.toml`
   → exit 0, zero changes.
6. From then on: **edit the manifest, never the box.**

### Day 2 — change server config

1. PR against `boxes/<host>.slip.toml` (e.g. add `[services.kv]`).
2. CI runs `slip server apply --dry-run` → posts the diff on the PR
   (exit 1 = "would change" is the *expected* signal here).
3. Merge → CI runs `slip server apply` → box converges. No SSH.

```yaml
# .github/workflows/slip-converge.yml (sketch)
on:
  pull_request: { paths: ["boxes/**"] }
  push: { branches: [main], paths: ["boxes/**"] }
jobs:
  converge:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: tailscale/github-action@v3          # tailnet-only management API
        with: { authkey: "${{ secrets.TS_AUTHKEY }}" }
      - name: dry-run (PR) or apply (main)
        env:
          SLIP_TOKEN: ${{ secrets.SLIP_ADMIN_TOKEN }}
          OP_SERVICE_ACCOUNT_TOKEN: ${{ secrets.OP_SERVICE_ACCOUNT_TOKEN }}
        run: |
          MODE=$([ "$GITHUB_EVENT_NAME" = "push" ] && echo "" || echo "--dry-run")
          slip server apply $MODE boxes/arrakeen.slip.toml --json
```

### Continuous — drift detection

Nightly job: `slip server diff boxes/<host>.slip.toml` → non-zero exit opens an
issue / pings the channel. Drift means someone ran imperative commands on the
box — either revert (re-apply) or ratify (re-export + PR).

### Disaster recovery — rebuild a box

Full rebuild = **infra repo + vault + data backup**, nothing else:

1. Fresh VPS: `curl … | bash` (install.sh)
2. `slip server init --from-file boxes/arrakeen.slip.toml`
   (secret refs resolve from 1Password via `op`)
3. Restore data: `/var/lib/slip/volumes` + `/var/lib/slip/services` from backup (§6)
4. Apps redeploy themselves: re-run each app's CI (or `slip deploy` per app) —
   app config re-applies from each app repo (SLIP-94), bindings re-resolve
   (SLIP-107), Caddy routes reconcile (SLIP-99).

Target: steps 1–2 in minutes; total RTO bounded by data restore.

---

## 5. Secrets strategy (1Password)

- **Manifests and app `slip.toml` carry references** (`op://vault/item/field`),
  never values (SLIP-118).
- **Resolution is client-side at apply time**: the laptop or CI runner holds
  the `op` CLI + a service-account token, resolves refs, and pushes values into
  slipd's secrets store over the API. **The daemon never holds vault
  credentials** — compromising the box doesn't compromise the vault.
- **Rotation** = rotate in 1Password → re-run apply → new value injected on the
  next deploy. Per-app deploy keys rotate via `slip key --rotate` (SLIP-93).
- Suggested vault layout: one `infra` vault (admin token, registry pulls,
  CF DNS token, TS auth keys) + per-app items for app-level secrets.
- CI holds exactly three kinds of secret: `TS_AUTHKEY` (reach the tailnet),
  `SLIP_ADMIN_TOKEN` (management API — infra repo only), and
  `OP_SERVICE_ACCOUNT_TOKEN`. App repos hold only their **per-app**
  `SLIP_DEPLOY_SECRET` (SLIP-89) — an app repo compromise can deploy that app,
  nothing else.

---

## 6. What slip does *not* solve (still yours)

Be explicit with yourselves about the boundary — slip is a deploy daemon, not a
Terraform replacement:

- **Provisioning the VPS itself**, OS hardening, users, sshd, unattended
  upgrades, Tailscale enrollment. (Keep your existing runbooks/tooling.)
- **DNS records** at Cloudflare/registrar — slip assumes names already resolve
  and does **not** apply DNS changes (they're slow, propagation-sensitive, and
  don't belong in slip's hot path). But slip **validates** DNS: the manifest
  carries `dns = { proxied = false }` expectations per host, and `slip doctor`
  fails loudly if a tailnet host gets orange-clouded (SLIP-102 check 8 /
  SLIP-117) — because a proxied record silently breaks `internal`/`dns01` TLS
  (the cert still issues; the traffic then dies at Cloudflare's proxy, which
  can't reach `100.x`). Keep the grey/orange-cloud security model notes + any
  DNS-apply scripting in the infra repo.
- **Backups.** slip keeps state in `/var/lib/slip` (SQLite, volumes, service
  data). Define a backup job (restic/borg → offsite) for `/var/lib/slip` +
  `/etc/slip`. A future `slip server backup` may formalize this; don't wait for it.
- **Monitoring/alerting** beyond `slip status`/`doctor` — wire those `--json`
  outputs into whatever you use, but the pager is yours.
- **UFW policy** — slip's installer/doctor will manage the one rule it needs
  (bridge DNS, SLIP-102); the rest of the firewall is yours.

---

## 7. Today (pre-1.0): interim guidance

Until the tickets land, the honest state is: server config is host files +
imperative commands, and app config drifts if you copy it around.

**Do:**
- Keep `slip-arrakeen-notes.md` accurate — it's the manifest's ancestor
  (refresh tracked in SLIP-116).
- Treat the host as source of truth for server config, and document every
  manual change in the notes with a date.
- Maintain the **workaround-retirement checklist** (in SLIP-116): what you can
  delete when each ticket ships —
  `caddy-manual-routes.py`/`.service` → SLIP-87/99/110 · manual GHCR
  package↔repo linking → SLIP-105/111 · `--insecure` webhook curl → SLIP-87 ·
  hand-invented HMAC secrets → SLIP-89/93.
- Put every secret you mint today into 1Password *now*, named the way you'd
  reference it later — makes the SLIP-118 migration a rename, not a hunt.

**Don't:**
- Don't commit `/etc/slip/apps/*.toml` or app `slip.toml` copies to the infra
  repo (the poi drift bug).
- Don't build new automation that edits Caddy via the admin API directly —
  it'll fight slip's reconciler once SLIP-99 lands. If you need a route slip
  can't express yet, add it to `caddy-manual-routes.py` (the one blessed
  workaround) and note it in the retirement checklist.
- Don't invest in a pull-based GitOps operator — `apply` is push-based by
  design for v1.0; revisit post-1.0 if multi-box demands it.

---

## 8. Resolved decisions (infra agent review, 2026-07-05)

The v1 draft posed five open questions; the infra agent answered all five.
Recorded here as decisions with rationale:

1. **Multi-box sharing: duplication until it hurts.** No include/fragment
   system for 2–3 boxes; ~5 duplicated lines of `[registries]` is cheaper than
   a feature. Revisit when a third box means copying the same block a third time.
2. **Caddy binary: manifest-owned.** `[caddy] build = { version, plugins }`
   pins the build; `slip server caddy install` consumes the pin; `--from-file`
   rebuilds match it. Decided by production experience: a rebuild that yields
   stock plugin-less Caddy silently breaks every dns01 endpoint post-recovery.
   Binary replacement on `apply` is consent-gated (`--allow-binary-install`) —
   more invasive than a config PATCH. (SLIP-115/117)
3. **Backups: infra repo's job.** `/var/lib/slip` is a directory tree; existing
   restic/borg tooling covers it. No `slip server backup` ticket — revisit at
   ~5 boxes or if slip's storage layout becomes opaque.
4. **Apply credentials: admin token in infra-repo GH secrets, no role-split
   yet.** The infra repo is high-trust (it's the source of truth), and a leaked
   admin token is already worst-case; a config-apply-only role is future
   hardening for when a second team or less-trusted contributor needs apply
   access. Ticket it when that day comes.
5. **Schema coverage vs `caddy-manual-routes.py`: two gaps found, both closed.**
   Gap A (custom `Access-Control-Expose-Headers` for browser range-reads) and
   Gap B (scoped `Allow-Methods`) → `[expose.cors]` / `[routes.cors]` override
   blocks, presets as defaults (SLIP-110 amendment 2). SLIP-117 now carries an
   explicit AC: the schema must express 100% of the live arrakeen route state.

Plus two review outcomes that changed ticket specs:

- **`slip server export` is advisory** — emits an "unexpressed" report and a
  lossy exit code rather than silently becoming an incomplete source of truth
  (SLIP-117).
- **DNS validation** — slip validates (never applies) DNS expectations;
  `slip doctor` check 8 catches the orange-cloud-breaks-tailnet-TLS failure
  mode (SLIP-102/117).

---

*Draft v2 — planning session of 2026-07-05, synthesizing the three dogfooding
field reports; revised after infra agent review (all §8 questions resolved).
Remaining feedback → comment on SLIP-117/110/102/115 directly.*
