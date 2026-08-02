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