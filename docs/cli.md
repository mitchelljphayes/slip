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
| `slip apply` | 🚧 Phase 2 | Apply a `slip.toml` config (create or update an app) |
| `slip deploy <app> <tag>` | ✅ Working | Trigger a deploy |
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
| 2 | `USAGE` | Invalid arguments or missing required flags |
| 3 | `AUTH` | Authentication or authorization failure |
| 4 | `NOT_FOUND` | Resource not found (app, secret, preview, etc.) |
| 5 | `DEPLOY_FAILED` | Deploy rejected or failed |
| 6 | `TIMEOUT` | Operation timed out |

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
