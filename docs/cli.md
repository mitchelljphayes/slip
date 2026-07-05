# slip CLI Reference

## Command Grammar (v1.0)

```
slip <verb> [<args>] [--json] [--server <url>] [--token <token>]
slip <noun> <subcommand> [<args>] [--json] [--server <url>] [--token <token>]
```

### Top-level verbs (hot path)

| Command | Status | Description |
|---------|--------|-------------|
| `slip init` | 🚧 Phase 2 | Initialize slip on this machine (repo scaffold) |
| `slip link` | 🚧 Phase 2 | Link a local repo to a remote slipd server |
| `slip key` | 🚧 Phase 2 | Manage deploy keys |
| `slip apply [<app>]` | ✅ Working | Apply a `slip.toml` config (create or update an app) |
| `slip deploy <app> <tag>` | ✅ Working | Trigger a deploy (applies config by default) |
| `slip status [<app>]` | 🚧 Phase 2 | Show app or daemon status |
| `slip logs <app>` | 🚧 Phase 2 | Tail container logs |
| `slip rollback <app>` | ✅ Working | Roll back to the previous version |
| `slip validate [<path>]` | ✅ Working | Validate a repo-side `slip.toml` config file |

### Noun groups (subcommands)

| Command | Status | Description |
|---------|--------|-------------|
| `slip server init` | 🚧 Phase 2 | Bootstrap slipd on a new server |
| `slip server status` | 🚧 Phase 2 | Show server status |
| `slip services list` | 🚧 Phase 3 | List registered services |
| `slip secrets list <app>` | ✅ Working | List secret keys for an app |
| `slip secrets set <app> KEY=VALUE...` | ✅ Working | Set one or more secrets for an app |
| `slip secrets rm <app> <key>` | ✅ Working | Remove a secret from an app |
| `slip previews list <app>` | ✅ Working | List active previews for an app |
| `slip previews teardown <app> [<id>]` | ✅ Working | Tear down preview deployments |
| `slip registry login` | 🚧 Phase 2 | Log in to a container registry |
| `slip doctor` | 🚧 Phase 2 | Diagnose slipd health and configuration |

### Deprecated aliases

| Command | Status | Replacement |
|---------|--------|-------------|
| `slip apps list` | ✅ Hidden, still works | `slip apply` (SLIP-94) |
| `slip apps add <name> <image> <domain>` | ✅ Hidden, still works | `slip apply` (SLIP-94) |
| `slip apps edit <name>` | ✅ Hidden, still works | `slip apply` (SLIP-94) |
| `slip apps rm <name>` | ✅ Hidden, still works | `slip apply` (SLIP-94) |

All `slip apps` subcommands print a deprecation warning on stderr before executing.

---

## Exit Codes

Every command exits with one of these codes. The `--json` flag changes the output
format but **does not** change the exit code.

| Code | Name | Meaning |
|------|------|---------|
| 0 | `OK` | Success |
| 1 | `GENERIC` | Generic error / not yet implemented |
| 1 | `CHANGES_PRESENT` | `slip apply --dry-run`: diff found (kubectl diff convention) |
| 2 | `USAGE` | Invalid arguments or missing required flags |
| 3 | `AUTH` | Authentication or authorization failure |
| 4 | `NOT_FOUND` | Resource not found (app, secret, preview, etc.) |
| 5 | `DEPLOY_FAILED` | Deploy rejected or failed |
| 6 | `TIMEOUT` | Operation timed out |
| 7 | `DRY_RUN_FAILURE` | `slip apply --dry-run`: generic error during dry-run |

Exit codes 1 and 7 have **dry-run-specific semantics** for `slip apply --dry-run`:
- Exit 1 (`CHANGES_PRESENT`) means the dry-run completed successfully and found
  changes that would be applied. This follows the kubectl diff convention.
- Exit 7 (`DRY_RUN_FAILURE`) means the dry-run itself failed (e.g. missing
  `slip.toml`, validation errors, network errors). Exit 1 is reserved for
  "changes present" in dry-run mode, so generic failures use a separate code.
- Outside `--dry-run`, `slip apply` uses the normal contract (1 = generic error).

---

## `slip apply`

Reads `slip.toml` from the current directory, validates it, fetches the current
server state via `GET /v1/apps/{name}`, computes an RFC 6902 JSON Patch diff,
and pushes changes via `PATCH` (or `POST` for first-time creation).

**Flags:**

| Flag | Description |
|------|-------------|
| `[<app>]` | App name (positional; defaults to `[remote].app` from `slip.toml`) |
| `--dry-run` | Show what would change without applying (exit 0 = no changes, 1 = changes) |
| `--no-redact` | Show environment variable values in the diff (redacted by default) |
| `--json` | Emit JSON output with `schema: "slip.apply.diff/v1"` envelope |

**Create-on-first-apply:** If the app doesn't exist on the server, `slip apply`
creates it via `POST /v1/apps`. The `[app] image` and `[routing] domain` fields
in `slip.toml` are required for creation. If either is missing, a prescriptive
error tells you what to add.

**Env redaction:** Environment variable values are shown as `(redacted)` in both
human and `--json` output by default. Use `--no-redact` to reveal them. The
wire PATCH/POST payload is never redacted.

**Full-replace semantics:** `env` and `volumes` are replaced wholesale on every
apply. Keys absent from `slip.toml` are removed from the server. If you have
server-side-only env vars, the first `slip apply` will remove them.

---

## `slip deploy`

Triggers a deploy via `POST /v1/deploy` with an HMAC-signed webhook.

**Flags:**

| Flag | Description |
|------|-------------|
| `<app>` | App name (required positional) |
| `<tag>` | Image tag to deploy (required positional) |
| `--image <container>=<image>` | Per-container image overrides (repeatable) |
| `--secret <key>` | App secret for HMAC signing (or `SLIP_SECRET` env var) |
| `--wait` | Wait for the deploy to reach a terminal state |
| `--wait-timeout <duration>` | Max time to wait (e.g. "10m", "300s"; default 10 minutes) |
| `--apply` | Apply `slip.toml` config before deploying (default: on) |
| `--no-apply` | Skip applying `slip.toml` config before deploying |

**Apply-before-deploy:** By default, `slip deploy` runs `slip apply` first to
ensure the server config matches the repo before triggering the deploy. This
requires the admin token (`--token` or `SLIP_TOKEN` env var) in addition to the
deploy key (`--secret` or `SLIP_SECRET`). Use `--no-apply` to skip the apply
step and deploy with only the deploy key.

---

## `--json` Convention

Every command accepts a `--json` global flag. When set:

- **Working commands** emit a stable serde-serialized JSON object on **stdout**
  instead of human-readable text.
- **Stub commands** (Phase 2) emit:
  ```json
  {"status":"not_implemented","command":"<name>"}
  ```
  and exit with code 1.
- **Error paths** emit the same JSON error shape regardless of `--json` (the
  prescriptive-error helper always writes to stderr).

The JSON schemas for working commands are stable within a minor version.
Breaking changes to JSON output are reserved for major version bumps.

---

## Prescriptive Error Convention

When a command fails because of a specific, actionable problem, it prints:

```
error: <description of what went wrong>
  → <what the user should do to fix it>
```

The message goes to **stderr** and the process exits with the appropriate
exit code from the table above.

### Examples

```
$ slip deploy nonexistent-app v1.0
error: app 'nonexistent-app' not found
  → run `slip apply` to register it
```

```
$ slip secrets list my-app --token ""
error: authentication failed
  → set SLIP_TOKEN or pass --token with a valid management token
```

```
$ slip apply --dry-run
error: no admin token
  → set --token or the SLIP_TOKEN env var, or use --no-apply to skip config application
```
