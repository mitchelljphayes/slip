# Health checks: healthy vs ready

This is the canonical source of truth for slip's health-check semantics. The
`slip validate` warning, the scaffold `slip.toml`, and the scaffold `AGENTS.md`
all link here rather than duplicate the rationale.

## 1. Healthy vs ready

Aligning with Kubernetes terminology:

- **Healthy / liveness** — "the process is running and not wedged." A liveness
  probe failing means *restart the container*. It should be cheap and must not
  depend on external systems (a DB outage must not kill your process).
- **Ready / readiness** — "the process can serve traffic *right now*." A
  readiness probe failing means *stop routing traffic to it* (but don't
  restart). It **must** exercise the dependencies that real requests need:
  DB/ORM pool initialized, migrations complete, cache warm, downstream
  services reachable.

For slip's blue-green deploy, the health gate is acting as a **readiness**
gate: it decides whether to swap traffic to the new replica. The configured
endpoint should be a readiness endpoint, not a liveness one. This is the core
lesson from `docs/field-report-poi-australia.md` §3.7: `/` returned 200 while
Postgres was down, and a broken deploy swapped.

## 2. Why `/` is risky

Concrete failure modes (all observed in the field):

1. **Static frontends / SPAs** — `/` serves `index.html` with 200 regardless of
   backend state. A dead API still "passes" health.
2. **Catch-all routers** — many web frameworks 404→200 (serving an SPA) or
   404→307 (redirect to a canonical path). Either way `/` doesn't reflect
   backend health.
3. **Auth middleware** — a site-password or auth middleware returns `307` to
   `/login` (the §3.7 bug) or `401`. Under the old 2xx-after-follow-redirects
   check, the 307→/login→200 chain *passed*. Under the new `Policy::none()` +
   `200-399` default, a 307 *passes* (it's in range) — still wrong for an app
   whose `/` should be 200. Under `expect_status="200"` it correctly fails.
4. **CDN/cache intermediaries** — a CDN may serve a cached 200 for `/` even
   when the origin is down.

## 3. The `/healthz` pattern

- A dedicated, **unauthenticated** readiness endpoint (e.g. `/healthz` or
  `/api/healthz`).
- It performs the cheapest possible check that proves "I can serve a real
  request": a `SELECT 1` against Postgres (or a pool `acquire()`/`PING`), a
  `PING` to Redis, etc.
- Returns `200` only when all critical dependencies are reachable and
  initialized; `503` otherwise.
- **Does not** check the user DB schema version on every call (that's a
  startup/migration concern — see §8). Just connectivity + pool readiness.

Pseudocode:

```rust
use std::sync::atomic::{AtomicBool, Ordering};

static READY: AtomicBool = AtomicBool::new(false);

// Set during startup after migrations + pool warm-up:
pub fn mark_ready() { READY.store(true, Ordering::SeqCst); }

async fn healthz() -> impl IntoResponse {
    if READY.load(Ordering::SeqCst) {
        (StatusCode::OK, "ok")
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, "starting")
    }
}
```

Wire it as `path = "/healthz"` in `slip.toml` and leave `expect_status`
unset (the default `200-399` is correct for most apps).

## 4. `expect_status` grammar

```
expect_status = 1#status_item
status_item   = status_code [ "-" status_code ]
status_code   = 3DIGIT       ; 100-599 (RFC 9110 §15)
```

- Comma-separated list of single codes (`"200"`), inclusive ranges
  (`"200-299"`), or any mix (`"200-299,503"`).
- Optional whitespace (spaces/tabs) around `,` and `-` is ignored:
  `"200, 204"` == `"200,204"` == `" 200 , 204 "`.
- At least one item required; empty string is a **hard error** (never
  "accept everything").
- Codes must be in `100..=599` (RFC 9110 §15). Out-of-range (`99`, `600`,
  `200-999`) → parse error, config fails to load.
- Reversed ranges (`400-200`) → parse error (typo — never silently swapped).
- Trailing garbage (`200abc`, `200-`, `200,,`) → parse error.
- **Duplicates and overlapping ranges are merged canonically at parse time**
  (`200,200` → `200`; `200-299,250-302` → `200-302`). The canonical form is
  the stable string `--json` reports as `expected`; the raw user string is
  never emitted in structured output.

Examples:

| `expect_status` | Accepts |
|---|---|
| `"200"` | only 200 |
| `"200,204"` | 200 or 204 |
| `"200-399"` (default) | 200 through 399 (Kubernetes-compatible) |
| `"200-299,503"` | 2xx, or 503 (healthy OR explicitly draining) |

## 5. Redirects

slip's probe client is built with `reqwest::redirect::Policy::none()` — the
**original** response status is evaluated against `expect_status`. Redirects
are **not** followed.

- Default `200-399` accepts a `307` (it's in range). This preserves the prior
  "redirect resolves to success" behavior under the new no-redirect policy.
- Explicit `expect_status = "200"` rejects a `307` → deploy fails with
  `health_unexpected_status` (the `docs/field-report-poi-australia.md` §3.7
  fix). Use this when `/` is behind an auth middleware that 307s to `/login`.
- Better still: put the readiness endpoint at a dedicated, unauthenticated
  `/healthz` that bypasses the auth middleware. Then the default `200-399`
  works and you don't need to narrow `expect_status`.

## 6. Timeout arithmetic

`[health]` has four timing fields. They map onto Kubernetes probes:

| slip | Kubernetes | Meaning |
|---|---|---|
| `start_period` | `initialDelaySeconds` | **One-time** grace delay before the *first* probe. Not per-attempt. Covers cold-start + migration time. |
| `retries` | `failureThreshold` | Max number of probe attempts. slip loops `1..=retries`. |
| `interval` | `periodSeconds` | Sleep between **failed** attempts only — not after the last. |
| `timeout` | `timeoutSeconds` | Per-request deadline (`tokio::time::timeout`). |

**Worst-case wall time** for the health phase:

```
start_period + retries × timeout + (retries − 1) × interval
```

Example: `start_period=15s, retries=4, timeout=3s, interval=5s` →
`15 + 12 + 15 = 42s` worst case.

This **must fit inside `[deploy].timeout`** or the deploy will be hard-killed
(SLIP-91 terminal `[health_check_timeout]` reason, exit code 5). Budget
accordingly.

slip currently requires only **1 success** to pass (no `success_threshold`).
This means a briefly-healthy window during a flapping 503 storm can let a
broken deploy swap. Mitigate by tuning `retries`/`interval` so the probe
window is wider than the flap period. A future enhancement (not SLIP-103)
may add `success_threshold` (N consecutive successes) — for now, treat
`retries` as a budget, not a guarantee of stability.

## 7. Forward-compatible migrations behind the readiness gate

- Run DB migrations as part of container startup, **non-interactively** (no
  `rails db:migrate` interactive prompt; fail fast if `MIGRATE=true` and a
  migration errors).
- The readiness endpoint returns `503` while migrations are in progress,
  `200` when complete. `start_period` gives the migration grace window;
  `retries × interval` covers the tail.
- Pattern: app boots → runs migrations → initializes the ORM pool → flips an
  `AtomicBool ready` → `/healthz` returns 200. Before the flip, `/healthz`
  returns 503.
- Expand/contract: never make backward-incompatible schema changes in a
  single deploy. Add the new column/state (expand) → ship the new code that
  writes both → ship the cleanup that removes the old → ship the schema
  cleanup. The readiness endpoint checks connectivity, **not** schema version
  on the hot path — schema-version checks flap during migration.

## 8. Non-interactive startup

The container must not block on human input (no `read` from stdin, no
`systemctl reload` prompt). If a required env var or secret is missing,
**fail fast and non-zero** — the container exits, health never passes, the
deploy rolls back. Don't write "waiting for operator…" to stderr and spin;
that turns a 5-second failure into a `start_period`-long hang.

## 9. Dependency checks

- **What to ping**: DB `SELECT 1` (or pool `acquire()`); Redis `PING`;
  downstream service's `/healthz`. Use the cheapest check that proves
  "I can serve a real request."
- **What not to ping**: schema version on every call (flaps during
  migration); downstream services that aren't on the hot path (adds latency
  and false-failure surface).

## 10. Reason taxonomy

When a deploy fails at the health gate, the SLIP-91 `error` field carries a
machine-readable bracketed tag plus human detail. Exit code is **5**
(`DEPLOY_FAILED`) for all deploy-failed health reasons.

| Reason tag | When | Structured detail |
|---|---|---|
| `[health_unexpected_status]` | At least one probe attempt received an HTTP response whose status was not in `expect_status` | `expected` (canonical string), `actual` (u16), `url`, `attempts` |
| `[health_check_failed]` | Every attempt failed at the network layer (connect refused, DNS, TLS, hyper error) — no response ever received | `retries`, `url` (existing semantics preserved) |
| `[health_check_timeout]` | Deploy-level hard timeout (`[deploy].timeout`) hit before health ever passed | the configured timeout value |

**Never** are response bodies, response headers, `Retry-After` values,
redirect targets, request headers, or any auth material logged. A 500 from
a health endpoint may contain a stack trace with env values; logging it is a
secret leak. slip logs only the status code.