# slip Hard Edges & Onboarding Friction — Field Report

> Source: a real provisioning session on Arrakeen (Jul 2026) that stood up a
> Garage S3 endpoint + Caddy DNS-01 TLS alongside a running slip install, and
> in doing so hit every rough edge in slip's Caddy/TLS/onboarding story. This
> is written for the **slip agent/roadmap** — to make the experience as simple
> as "SSH in, install slip, generate admin key, locally init projects + per-app
> deploy keys → config just works."
>
> Cross-reference: [`docs/getting-started.md`](getting-started.md) (current
> happy path), [`docs/slip-design.md`](slip-design.md),
> `crates/slip-core/src/caddy.rs` (bootstrap/reconcile), `install.sh`.

---

## TL;DR — the gap between the dream and today

**The dream UX:**
```
# on the box, once:
ssh box
curl ... | bash        # install slip
slip init              # generates admin key, writes /etc/slip/slip.toml, sets up caddy

# on your laptop, per project:
slip app init          # scaffolds repo-side slip.toml + slip app config
slip app key           # prints a per-app HMAC deploy key → paste into GH secret
git push               # CI calls webhook → deploy just works
```

**What actually happens today** (sourced from the Arrakeen session):

1. `install.sh` is great (downloads binary, makes user, sets up dirs). ✅
2. But then the user must **hand-write `/etc/slip/slip.toml`**, **hand-write a
   systemd unit**, **hand-install Caddy**, and **hand-configure the deploy
   webhook Caddy route** — and that last step is where it silently breaks (see
   §1). ❌
3. There is **no `slip init` that generates an admin key** — the `Init` CLI
   subcommand exists but its handler is literally
   `println!("slip init — not yet implemented (Phase 2)")`
   (`crates/slip-cli/src/main.rs:797`). The `[auth].secret` is a manual
   `${SLIP_SECRET}` env var you have to invent and wire into the systemd unit
   yourself. ❌
4. There is **no local-side `slip app init` / `slip app key`** — per-app deploy
   keys are `slip secrets set <app> SLIP_SECRET=...` run **on the server**, and
   you have to invent the HMAC secret yourself and copy it to GH secrets. ❌
5. Caddy + TLS for the **deploy webhook on a tailnet-only host** is entirely
   undocumented and, worse, the documented approach (Caddyfile site block)
   **breaks slipd bootstrap** on Caddy v2.11+. ❌❌

The four hard edges below are the things that cost real hours.

---

## Hard edge 1 — Caddyfile site blocks break slipd bootstrap (the big one)

### What happens
slipd's `bootstrap()` (`crates/slip-core/src/caddy.rs:154`) ensures a Caddy
server named **`slip`** listening on `:443` exists. If it doesn't, it reads the
full config, merges in `{"slip": {"listen":[":443"], "routes":[]}}`, and
`POST /load`s it atomically.

Caddy v2.11 **rejects two HTTP servers claiming the same listener**:
```
invalid configuration: server srv0: listener address repeated: tcp/:443
(already claimed by server 'slip')
```

**Any Caddyfile site block** (`deploy.example.com { ... }`,
`s3.example.com { ... }`) adapts into a server named `srv0` (or `srv1`…) on
`:443`. If such a block exists when slipd bootstraps, the `POST /load` fails
with the error above and **slipd crash-loops** (`Restart=on-failure`).

### Why it bites
[getting-started.md §5](getting-started.md) explicitly tells users to add the
deploy webhook route via either an admin-API JSON blob **or** "simpler — add
it to your Caddyfile". The Caddyfile option silently breaks slipd on current
Caddy. The JSON option (POST into `/config/apps/http/servers/slip/routes`)
works but is lost on every Caddy restart (Caddy reloads only the Caddyfile;
slipd only re-applies its own `slip-<app>-<n>` routes on slipd restart).

### What slip should do
- **Own the deploy webhook route.** slipd already creates the `slip` server;
  it should also register the deploy-webhook reverse-proxy route
  (`deploy.<domain>` → `127.0.0.1:7890`) into that server itself, driven by a
  `[deploy] domain = "deploy.example.com"` (or `[server] webhook_domain`)
  field in `slip.toml`. Then users never touch Caddy for the webhook.
- **Document that Caddyfile site blocks are incompatible** with slipd's
  `slip` server on Caddy v2.11+, OR
- **Switch slipd to not hardcode the `slip` server name / `:443`** — e.g.,
  reuse an existing Caddyfile server by name, or use Caddy's
  `auto_https disable_certs` + a single shared server. (Bigger change.)
- At minimum, **bootstrap() should detect the conflict and emit a clear
  error** ("a Caddyfile site block is claiming :443; move it into slip or use
  a different listen address") instead of crash-looping.

---

## Hard edge 2 — TLS for the deploy webhook is undocumented and has no default

### What happens
The deploy webhook host (`deploy.example.com`) needs a TLS cert. slipd
registers **no TLS automation policy** for it. So Caddy falls back to its
default ACME issuer (HTTP-01 / TLS-ALPN-01 challenge).

- **Public host on a public IP** → works (this is the getting-started
  assumption, and why it worked for the original slip dev).
- **Tailnet-only host** (grey-cloud DNS → `100.x` Tailscale CGNAT, the
  documented security model in `slip-arrakeen-notes.md`) → Let's Encrypt
  validators can't reach `100.x` → **Caddy fails to obtain a cert and aborts
  the TLS handshake** (`tlsv1 alert internal error`, `curl` shows
  `http_code=000`). The `--insecure` flag in the webhook caller can't help —
  the server kills the handshake before cert verification even happens.

This is exactly the failure that blocked the steamtank pipeline's deploy
trigger after the Arrakeen cutover. The webhook caller (CI) was using
`--insecure`, which implies the endpoint was *meant* to serve a self-signed
cert — but nothing in slip provisions one.

### What slip should do
slipd should **provision a TLS cert for the webhook host by default**, with a
strategy chosen from `slip.toml`:

```toml
[deploy]
domain = "deploy.example.com"
tls = "internal"          # default for tailnet-only: Caddy self-signed CA
# tls = "cloudflare-dns01"  # real LE cert via DNS-01 (needs CF_API_TOKEN)
# tls = "tailscale"         # `tailscale cert` for a MagicDNS hostname
# tls = "acme"              # public host, HTTP-01 (today's implicit default)
```

- **`internal`** (Caddy's local CA) should be the *default* and requires zero
  config — it matches the `--insecure` webhook-caller intent and works on a
  tailnet-only host with no DNS provider creds. slipd just adds a TLS
  automation policy `{subjects:[deploy.<domain>], issuers:[{module:"internal"}]}`.
- **`cloudflare-dns01`** adds a DNS-01 policy (needs a CF token in Caddy's
  env + the cloudflare plugin in the Caddy binary — see hard edge 3).
- **`tailscale`** shells to `tailscale cert` (needs Tailscale on the box).

This single feature would have saved the entire deploy-trigger debugging
session.

---

## Hard edge 3 — stock Caddy lacks DNS plugins; slip doesn't manage Caddy

### What happens
slip's docs say `sudo apt install caddy`. The **stock Debian/apt Caddy has no
DNS-challenge plugins** (`caddy list-modules` shows no `dns.providers.*`). For
a public host that's fine (HTTP-01 works). For a **tailnet-only host** that
needs DNS-01, the user must:
1. Build/download a custom Caddy with `caddy-dns/cloudflare` (xcaddy or the
   `caddyserver.com/api/download?p=...` endpoint).
2. Replace the apt binary without breaking apt.
3. Mint a scoped Cloudflare API token.
4. Wire it into Caddy's systemd env (`EnvironmentFile=/etc/caddy/env`).
5. Add the TLS automation policy.

None of this is slip's job today, but **slip advertises "automatic HTTPS"**,
and on the tailnet-only security model that slip itself documents, HTTPS
silently doesn't work without all five steps.

### What slip should do (roadmap, not a quick fix)
- **Detect at bootstrap**: `caddy list-modules` — if a tailnet host is
  configured for DNS-01 but the cloudflare plugin is absent, emit a clear
  error ("install a Caddy build with caddy-dns/cloudflare") instead of
  silently failing the challenge.
- Optional: `slip init` could **install a Caddy build with the needed DNS
  plugins** (download via the Caddy download API, like we did on Arrakeen) so
  the user doesn't have to.
- Optional: manage Caddy's env file (`/etc/caddy/env`) for DNS-provider
  tokens, the same way slip manages app secrets.

---

## Hard edge 4 — admin-API routes vanish on Caddy restart; no reconcile-on-Caddy-restart

### What happens
slipd reconciles its `slip-<app>-<n>` routes **only on slipd startup**
(`crates/slipd/src/main.rs:176`). There's no background reconcile loop, and
slipd doesn't watch for Caddy restarts. So:
- **Caddy restarts** (e.g. `systemctl restart caddy`, or a Caddy crash) →
  Caddy reloads the Caddyfile (just the `admin` block) → **all slip routes
  vanish** and stay gone until slipd next restarts.
- Any **non-slip route** added via the admin API (the deploy webhook, a static
  reverse proxy to a shared service like Garage, etc.) is also gone, and
  slipd never brings it back.

On Arrakeen I had to write a `caddy-manual-routes.py` + oneshot systemd
service (`PartOf=caddy.service slipd.service`) to re-apply the manual routes
+ TLS policies after every restart. That script is the only thing keeping the
S3 endpoint and deploy webhook alive across reboots.

### What slip should do
- **Reconcile on a schedule / on Caddy reconnect**, not just at slipd start.
  A 30–60s reconcile tick (or a watch on the Caddy admin API) would make
  Caddy restarts self-healing.
- **Own static routes** (deploy webhook, and a way for users to declare
  non-app reverse proxies like "proxy `s3.example.com` →
  `127.0.0.1:3900` with CORS") so users don't hand-edit the admin API. See
  hard edge 5.

---

## Hard edge 5 — no way to declare non-app reverse proxies / static routes

### What happens
Every slip route is backed by a deployed app container. If you want Caddy to
reverse-proxy `s3.example.com` → a shared Garage container (or any service
not deployed by slip), there's **no slip mechanism** — you have to poke the
Caddy admin API directly, and then fight hard edges 1 + 4 to keep it alive.

### What slip should do
Support a `[[static_routes]]` (or `[[proxy]]`) section in `slip.toml` /
app configs for non-app reverse proxies, with CORS + TLS handled by slip:
```toml
[[static_routes]]
host = "s3.steamtankcoffee.com.au"
upstream = "127.0.0.1:3900"
tls = "cloudflare-dns01"
[static_routes.cors]
allow_origin = "*"
allow_methods = ["GET", "HEAD", "OPTIONS"]
expose_headers = ["ETag", "Accept-Ranges", "Content-Range", "Content-Length"]
```
This would absorb the entire `caddy-manual-routes.py` workaround.

---

## Hard edge 6 — bootstrap/reconcile has a transient race

### What happens
On slipd startup, `reconcile_routes` PATCHes `/id/slip-<app>-0` for each app.
If Caddy's admin API is briefly busy (e.g. still loading the config slipd just
`POST /load`ed), the PATCH fails with `error sending request for url
(http://localhost:2019/id/slip-<app>-0)` and slipd logs
`caddy route reconciliation failed on startup (non-fatal)` — leaving that
app's route missing until the next slipd restart. I saw this intermittently
for `smoke`/`quack`/`poi` across restarts on Arrakeen.

### What slip should do
- Retry the per-route PATCH with backoff (it's idempotent).
- Or re-read the route list after reconcile and re-attempt missing ones.
- The "non-fatal" log should at least name which app failed so it's debuggable.

---

## Hard edge 7 — onboarding has no key-generation / local-init story

### What happens today
- **Admin/global secret**: user invents `[auth].secret`, puts it in
  `slip.toml` as `${SLIP_SECRET}`, and manually sets `SLIP_SECRET` in the
  slipd systemd unit's `Environment=`. No `slip init` to generate it.
  (The `Init` CLI subcommand exists but getting-started doesn't use it for
  keygen — it's underdocumented.)
- **Per-app deploy key**: user invents an HMAC secret, runs
  `slip secrets set <app> SLIP_SECRET=...` **on the server**, then manually
  copies that same secret into GitHub Actions secrets. No local `slip app key`
  that generates + prints a ready-to-paste secret.
- **Local project init**: there's `slip validate ./slip.toml` (repo-side
  config validation) but no `slip app init` that scaffolds the repo-side
  `slip.toml` + a CI workflow template.

### What slip should do (the dream UX, concretely)
1. `slip init` (on the box, run by install.sh or manually):
   - generates `[auth].secret` (and prints it once / writes to a root-only
     file),
   - writes `/etc/slip/slip.toml` with sane defaults,
   - installs the systemd unit with the secret wired in,
   - registers the deploy-webhook Caddy route + a default `tls = "internal"`
     policy (hard edges 1 + 2),
   - optionally installs a DNS-plugin-enabled Caddy build (hard edge 3),
   - starts slipd.
2. `slip app init` (on the laptop, in a repo):
   - scaffolds `slip.toml` (repo-side: `kind`, `image`, `health`, `routing`),
   - scaffolds a GitHub Actions workflow that calls the webhook,
   - prints the server-side snippet to add (`/etc/slip/apps/<name>.toml`).
3. `slip app key` (on the laptop or box):
   - generates a per-app HMAC secret,
   - `slip secrets set <app> SLIP_SECRET=<generated>` against the server,
   - prints the secret + the exact `gh secret set SLIP_SECRET < ...` command
     (or a `--gh` flag that sets it via `gh` directly).

After that, the user's only touch points are: `slip app init` per project,
`slip app key` per project, `git push`. Everything else is slip's job.

---

## Smaller papercuts (sourced)

- **`slip status` is "not yet implemented (Phase 2)"** — observed live on
  Arrakeen. The README lists status as a feature; it isn't usable yet. Either
  implement it or mark it WIP in the README.
- **App config lives only server-side** (`/etc/slip/apps/<name>.toml`) while
  the image `kind`/pod manifest live repo-side — the split is documented but
  fragile (the server-side file references the image, which references the
  repo-side config). A single source of truth (or `slip app init` generating
  both halves) would help.
- **`[caddy.tls]` DNS-01 is gated on `[preview]` being set**
  (`crates/slipd/src/main.rs:145`) — so the TLS config schema exists but is
  effectively preview-only. Generalizing it (per hard edge 2) would reuse
  this code.
- **No `--token`/`SLIP_TOKEN` mention in install.sh** — the management API
  auth story is only in getting-started §6; a fresh install has no token until
  the user reads that section.
- **Podman vs Docker socket permissions** are a known papercut (getting-started
  §7 note) — worth a first-class `slip init` detection + fixup.

---

## What's already good (don't break these)

- `install.sh` — clean, idempotent, `--uninstall` support. Good foundation.
- **HMAC per-app secrets, no SSH keys in CI** — the core security model is
  sound and the thing that makes slip worth using.
- **slipd's bootstrap preserves existing config** (reads full config, merges,
  atomic `POST /load`) — it's *almost* self-healing; it just needs to handle
  the :443 conflict (hard edge 1) and reconcile on Caddy restart (hard edge 4).
- **Route @id scheme `slip-<app>-<n>`** with `remove_routes` only deleting
  `slip-*` ids — non-slip routes *can* coexist safely; the problem is purely
  the server-name/listener conflict, not route ownership.
- **Blue-green + drain + health checks** — the deploy mechanics themselves
  worked flawlessly on Arrakeen (poi, quack, smoke all deploy fine). The
  friction is entirely in the **bootstrap/onboarding/TLS** layer, not the
  deploy engine.
- **SQLite deploy history + secrets store with restrictive perms** — solid.

---

## Suggested roadmap ordering (impact / effort)

1. **slipd owns the deploy-webhook route + `tls = "internal"` default**
   (hard edges 1 + 2). Highest impact, moderate effort. Eliminates the
   Caddyfile conflict and the tailnet TLS failure in one move.
2. **`slip init` keygen + systemd unit + Caddy route setup** (hard edge 7).
   Turns "read 8 getting-started sections" into one command.
3. **Reconcile on a tick / on Caddy reconnect** (hard edge 4). Self-healing.
4. **`slip app init` + `slip app key` (local)** (hard edge 7). The laptop-side
   half of the dream UX.
5. **`[[static_routes]]` with CORS + TLS** (hard edges 5 + 3's route half).
   Absorbs the Garage/S3 workaround.
6. **Reconcile retry/backoff + per-app failure logging** (hard edge 6).
   Polish.
7. **Detect missing Caddy DNS plugins / install a plugin-enabled Caddy**
   (hard edge 3's binary half). Nice-to-have.

— *Field report from the Arrakeen Garage/S3 provisioning session.
Supporting evidence + the `caddy-manual-routes.py` workaround that embodies
these gaps lives in the infra repo at
`.opencode/sessions/2025-07-04_steamtank-garage-provision/`.*