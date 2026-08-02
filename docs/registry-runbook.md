# Registry Runbook (SLIP-105)

How to configure slip to pull images from one or more private container
registries (GHCR, a local registry, Docker Hub, etc.) and how to rotate
credentials without a daemon restart.

## TL;DR

```bash
# 1. Store a credential with slipd (preferred — no token in slip.toml):
echo "$GHCR_TOKEN" | slip registry login ghcr.io --token-stdin
# (or interactively: slip registry login ghcr.io)

# 2. Or declare it in slip.toml (bootstrap fallback — token via env-ref):
#    [registries.ghcr]
#    url = "ghcr.io"
#    username = "slip"
#    token = "${GHCR_TOKEN}"

# 3. Verify:
slip registry list
slipd --check --env-file /etc/slip/slip.env

# 4. Deploy normally — slip resolves the right cred per image.
```

## Config schema: `[registries.<name>]`

Each named registry is a table under `[registries.<name>]`:

```toml
[registries.ghcr]
url       = "ghcr.io"             # host[:port], no scheme, no trailing slash
username  = "slip"                # optional — anonymous pull if absent
token     = "${GHCR_TOKEN}"       # optional — env-ref or literal

[registries.local]
url       = "localhost:5000"     # local registry, no token needed

[registries.hub]
url       = "docker.io"
username  = "myhubuser"
token     = "${DOCKER_HUB_TOKEN}"
```

- **`url`** is the registry host, optionally `:port`. No `https?://` scheme,
  no trailing `/`, **no path components** (`reg.io/team` is rejected —
  per-image namespacing is carried by the image ref, not the registry URL).
- **`username`** is optional. Absent means anonymous pull.
- **`token`** is optional. It's an env-ref like `"${GHCR_TOKEN}"` (resolved at
  config load) or a literal. **Prefer the secrets store** (see below) — a
  TOML `token` is the bootstrap fallback for when you can't run
  `slip registry login` yet.
- An **empty map** (no `[registries]` table at all) is valid — it means
  anonymous pulls only.

### Migration from `[registry]` (SLIP-105, breaking)

The old single-registry shortcut has been **removed**:

```toml
# BEFORE (removed in SLIP-105)
[registry]
ghcr_token = "${GHCR_TOKEN}"

# AFTER
[registries.ghcr]
url = "ghcr.io"
username = "slip"
token = "${GHCR_TOKEN}"
```

The rewrite is 3 lines. See `CHANGELOG.md` for the full breaking-change entry.

## `slip registry login` / `logout` / `list` (preferred)

The preferred way to store a registry credential is via the CLI — the token
is written to the daemon secrets store (0600, under a reserved `__registry`
namespace) and **never appears in slip.toml or on disk in plaintext config**.

### `slip registry login <url> [--username <u>] [--token-stdin]`

```bash
# Pipe the token on stdin (CI / scripts):
echo "$GHCR_TOKEN" | slip registry login ghcr.io --token-stdin

# Interactive prompt (TTY only — uses dialoguer::Password):
slip registry login ghcr.io

# With a username:
echo "$TOKEN" | slip registry login ghcr.io --username slip --token-stdin
```

- The URL must be `host[:port]` only (e.g. `ghcr.io`, `localhost:5000`).
  A URL with a path component (`reg.io/team`) exits with code 2 (USAGE) and a
  prescriptive message.
- There is **no `--token` / `--password` value flag** — passing a secret on
  the argv is a leak vector (shell history, `ps`, audit logs). Use
  `--token-stdin` or the interactive prompt.
- `--json` emits `{"ok":true,"url":"...","username":"..."}` (never the token).

### `slip registry logout <url>`

```bash
slip registry logout ghcr.io
```

Removes the stored credential. 404 (exit 4) if none stored — run
`slip registry list` to see what's there.

### `slip registry list`

```bash
slip registry list
# URL                           USERNAME              HAS CRED      SOURCE
# ghcr.io                       slip                  yes           store
# localhost:5000                -                     no            none
# registry.example.com          ci                    yes           toml

slip registry list --json
# [{"url":"ghcr.io","username":"slip","hasCredential":true,"credentialSource":"store"}, ...]
```

**Never prints or serializes the token/password.** `credentialSource` is one
of `toml` (declared in slip.toml), `store` (`slip registry login`),
`toml+store` (both — store wins at pull time), or `none` (declared but no
credential).

### Precedence: store wins over TOML

If a registry URL has both a TOML `token` and a store credential (via
`slip registry login`), the **store credential wins** at pull time. This lets
you rotate a token with `slip registry login` without editing slip.toml or
restarting slipd — the merged registry table is recomputed every deploy.

## How slip resolves the credential per image

At deploy time, slip builds a merged registry table (TOML-declared +
store-credentialed) and, **for each image**, resolves the credential by
**host match**: the registry whose `url` equals the image's host wins.

- `ghcr.io/me/app:1` → matches a `ghcr.io` registry.
- `localhost:5000/internal/svc` → matches a `localhost:5000` registry.
- `nginx` (bare name) → normalizes to `docker.io/library/nginx` → matches a
  `docker.io` registry.
- `host` and `host:443` are **distinct** — no grandfathering. Key your
  registry by the exact host:port the image ref uses.

This means **two different registries in one deploy cycle** work
out of the box: a main image on `ghcr.io` and a sidecar on `localhost:5000`
each resolve to their own credential.

> **Note (implementation):** slip passes the resolved credential inline to
> the Docker/Podman API `create_image` call. There is no ephemeral
> `--authfile` — the Podman backend uses the Docker-compatible socket API
> (via `bollard`), not the `podman pull` CLI, so there's no `--authfile`
> flag available. The per-image inline cred path satisfies the
> two-registries-in-one-cycle requirement; each image gets its own resolved
> `RegistryCredentials`. (`/run/slipd/auth.json` is not created.)

## Anti-pattern: don't bootstrap with manual `podman push`

**Don't** manually `podman push` an image to a registry and then point slip
at it. This bypasses slip's deploy record, leaves no rollback path, and puts
credentials outside slip's trust boundary. Drift creeps in silently — the
running container no longer matches any `slip deploy` invocation, and the
next deploy may pull a different (or missing) image.

**Instead**: push via your CI (GitHub Actions → `docker push` to GHCR), then
`slip registry login ghcr.io` (once) and `slip deploy` normally. slip records
every deploy, can roll back, and the credential stays in the secrets store.

## GHCR-specific notes

1. **Create a PAT** with `read:packages` scope (classic PAT) — this is the
   token you pipe to `slip registry login ghcr.io --token-stdin`.
2. **Link the package to its repo** in the GHCR UI (Package settings →
   Manage Actions access) so the repo's Actions can push. slip doesn't push;
   this is for your CI.
3. **Key by `ghcr.io`** (host only). slip keys registries by the normalized
   host — `ghcr.io`, not `https://ghcr.io/` or `ghcr.io/org`. The org/user
   is part of the image ref (`ghcr.io/org/app`), not the registry URL.
4. **`docker.io` vs `ghcr.io`**: Docker Hub images (`nginx`, `postgres`) live
   on `docker.io`; GitHub packages live on `ghcr.io`. They're different
   registries with different credentials — declare both if you pull from both.

## `slipd --check --env-file` for systemd deployments

The running slipd gets its env vars from the systemd unit's
`EnvironmentFile=/etc/slip/slip.env`. A manual `slipd --check` without that
file will see unresolved `${GHCR_TOKEN}` placeholders. Use:

```bash
slipd --check --env-file /etc/slip/slip.env
```

This parses the `KEY=value` env file, pre-populates the process env, then
resolves the config — so `--check --env-file` fully resolves and exits 0
clean. Without `--env-file`, `--check` **warns** (exit 0) on unresolved env
rather than hard-failing — the running daemon is fine, the manual check just
doesn't have the env. Structural config errors (parse fail, name mismatch)
still hard-fail (exit 1) regardless of `--env-file`.

See `docs/field-report-poi-australia.md` §3.10 for the field evidence behind
this behaviour.