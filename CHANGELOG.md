# Changelog

All notable changes to slip are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Internal service model and persistence foundation (SLIP-106 Part 1/3).** Adds the domain contracts and SQLite persistence for managed services without any user-facing service commands. `ServiceName` strict lowercase DNS-label validation, `ProviderKind` closed enum (Postgres only), export-ready `ServiceSpec` with canonical JSON hashing, and internal `ServiceState` with CSPRNG instance IDs, generation compare-and-swap, and retained runtime state. Object-safe `ServiceProvider` trait with instance-scoped secret capability. Additive migration 002 (`slip_metadata`, `services`, `service_state`) with CHECK constraints mirroring Rust validators. Typed `ServiceRepository` with transactional desired and state inserts, generation-safe delete and retain, and atomic retained reattach. No CLI, API, runtime backend, or provider implementation changes.

## [0.1.1] - 2026-08-16

Patch release of three backward-compatible fixes to `0.1.0`. **Upgrade every
`0.1.0` install that shares a Caddy instance with Slip. SLIP-125 stops Slip
from deleting TLS automation policies it does not own, but upgrading cannot
restore external policies that `0.1.0` already removed. Re-add those by
hand.**

### Fixed

- **Fix false `tailscale.manager_module` fail in `slip doctor` (SLIP-124).** `slip doctor` now checks the Tailscale Caddy certificate manager via `caddy list-modules` instead of the undocumented admin API `/modules/` endpoint (always 404 on standard Caddy). A present module passes, a confirmed absence fails, and an unavailable inspection warns rather than fails.

- **Preserve externally managed Caddy TLS policies during reconciliation (SLIP-125).** Slip now updates only TLS automation policies it owns, preventing certificate renewal configuration for unrelated routes from being deleted. Upgrading prevents future deletion but does not restore policies already removed by `0.1.0`; re-add those manually.
- **Verify prebuilt archive checksums independent of local filename (SLIP-123).** `install.sh` downloaded the release archive as `slip.tar.gz` while the published `.sha256` sidecar named the release asset (`slip-<target>.tar.gz`), so `sha256sum -c` looked for a file that did not exist and verification always failed. The installer now extracts the expected digest from the sidecar, computes the archive digest under its local name, and compares them directly: the sidecar filename field is treated as untrusted and ignored. Malformed or mismatched digests fail with a prescriptive error before extraction or installation.

## [0.1.0] - 2026-08-15

First tagged release. Everything below describes changes made during
pre-release development on `main`, so the "Changed (breaking)" entries are
relative to earlier unreleased states rather than to a published version —
a fresh install of 0.1.0 has nothing to migrate.

### Changed (breaking)

- **`[deploy] tls` now defaults to `acme`, was `internal` (#53).** The deploy
  webhook is called from CI, and `internal` issues a Caddy self-signed
  certificate that public runners cannot verify — so the default configuration
  was incompatible with the workflow slip exists to serve. The new default
  issues a publicly trusted Let's Encrypt certificate.

  Current behaviour replaced: `[deploy] domain` with no `tls` set produced a
  self-signed certificate. It now attempts ACME issuance, which requires the
  domain to resolve to the host with ports 80/443 reachable, and requires
  `[caddy] acme_email` — slipd refuses to start without it rather than falling
  back to self-signed. Hosts that cannot satisfy that must set `tls`
  explicitly: `cloudflare-dns01` (no inbound reachability needed),
  `tailscale` (`*.ts.net` hosts), or `internal` (local/private use).

  `slip server init --tls` defaults to `acme` to match. See
  `docs/getting-started.md` §5 for the strategy table.

- **`[registry]` → `[registries.<name>]` (SLIP-105).** The single
  `[registry] ghcr_token` field is **removed**. Replace it with a named
  `[registries.<name>]` table:

  ```toml
  # before (removed)
  [registry]
  ghcr_token = "${GHCR_TOKEN}"

  # after
  [registries.ghcr]
  url = "ghcr.io"
  username = "slip"
  token = "${GHCR_TOKEN}"
  ```

  `url` is `host[:port]` (no scheme, no trailing slash, no path). `username`
  is optional (anonymous pulls if absent). `token` is an env-ref like
  `"${GHCR_TOKEN}"` or a literal, resolved at load time. An empty map (no
  `[registries]` table) is valid — anonymous pulls. Multiple named registries
  are supported. See `docs/registry-runbook.md` and `slip registry login --help`.

### Fixed

- **`slip apply` 422 on any config with a duration (#52).** The CLI serialized
  durations as floats (`"drain_timeout": 30.0`) while the daemon deserializes
  them through `duration_serde`, which reads a string (`"30s"`) — so a
  `slip.toml` that passed `slip validate` could not be pushed. Create and
  update payloads now emit the canonical string form. This affected
  `deploy.drain_timeout`, `deploy.timeout`, and `health.interval` /
  `health.timeout` / `health.start_period`.
- **`SLIP_TOKEN` is now read (#51).** `resolve_token` only ever checked the
  `--token` flag, while the help text, `docs/cli.md`, and
  `docs/getting-started.md` all documented an env fallback. An
  exported-but-empty `SLIP_TOKEN` still fails the auth check rather than
  sending an empty bearer token.
- **Sub-second durations survive serialization.** `duration_serde` serialized
  via `as_secs()`, so a `500ms` health interval came back as `"0s"`. Values
  below a second now render as milliseconds, so `slip apply` no longer reports
  drift that cannot converge.
- **`acme` / `cloudflare-dns01` on a `*.ts.net` host now fail at config load**
  with a pointer to `tls = "tailscale"`, instead of failing later at issuance:
  a public CA cannot validate a Tailscale domain.

### Added

- `slip_core::format_duration(&Duration) -> String` — renders the canonical
  wire form (`"30s"`, `"1500ms"`) that `parse_duration` accepts.

- `slip_core::RegistriesConfig` / `RegistryEntry` config types (replace
  `RegistryConfig`).
- `slip_core::normalize_registry_url(url) -> Result<String, ConfigError>` —
  normalizes a registry URL (strips scheme + trailing slash, rejects path
  components).
- **`slip registry login` / `logout` / `list` (SLIP-105)** — CLI to store
  registry credentials in the daemon secrets store (0600, `__registry`
  namespace). `login <url> [--username <u>] [--token-stdin]` reads the token
  from stdin (preferred) or an interactive `dialoguer::Password` prompt; no
  `--token`/`--password` value flag (anti-leak). `logout <url>` removes;
  `list` prints a table or `--json` array (never the token). Exit codes:
  0 ok · 2 usage (bad url) · 3 auth · 4 not-found · 1 generic/conn-error.
- **Management API: `PUT/DELETE/GET /v1/registries[...]` (SLIP-105)** —
  store/list/remove registry credentials (Bearer admin auth). `GET
  /v1/registries` merges TOML-declared + store creds; `hasCredential` +
  `credentialSource` (camelCase `--json`); never echoes the password.
- **Per-image credential resolution (SLIP-105)** — slip resolves the correct
  credential for each image at pull time via host match against the merged
  registry table (TOML tokens + store creds). Store creds override TOML
  tokens on URL-match; the merged table is recomputed every deploy so
  `slip registry login` takes effect without a daemon restart. Two
  registries in one deploy cycle (main on `ghcr.io`, sidecar on
  `localhost:5000`) each get their own resolved credential. See
  `docs/registry-runbook.md`.
- **`slipd --check` warn-mode + `--env-file` (SLIP-105)** — `--check` now
  warns (exit 0) on unresolved `${ENV}` instead of hard-failing (exit 1),
  matching the `resolve_env_vars_warn` doc comment and field report §3.10.
  New `--env-file <path>` parses a systemd `KEY=value` EnvironmentFile and
  pre-populates the process env before resolving config placeholders, so
  `--check --env-file /etc/slip/slip.env` fully resolves and exits 0 clean.
  Structural errors (parse fail, name mismatch) still hard-fail (exit 1).
  Production `load_config` (non-check) is unchanged.
- `slip_core::load_config_check`, `load_config_with_mode`, `parse_env_file`,
  `ResolveMode` (config API for warn-mode + env-file parsing).
- `docs/registry-runbook.md` — GHCR + multi-registry runbook, the
  `[registries.<name>]` migration, and the "don't bootstrap with manual
  `podman push`" anti-pattern warning.
