# Changelog

All notable changes to slip are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed (breaking)

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

### Added

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