# AGENTS.md — working on the slip repo

Process notes for agents (and humans) working in this repository. These are
learned rules from real sessions — each one exists because violating it cost
time. Follow them.

## Version control: plain git

This repo uses ordinary git branches. It was previously managed by GitButler
virtual branches; that integration was removed in August 2026, along with the
`gitbutler/*` branches and the `GITBUTLER_MANAGED_HOOK_V1` wrapper that had
been committed into `.githooks/`. Ignore any `but` commands in older notes or
commit messages — the CLI is no longer part of this repo's workflow.

### The branch lifecycle

```bash
# 1. Branch from an up-to-date main. --no-track matters: branching from
#    origin/main without it sets upstream to main, and a later bare
#    `git push` then targets main directly.
git fetch origin
git switch --no-track -c slip-<ticket>-<short-desc> origin/main

# 2. Edit, then verify (all three must be green)
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test --workspace

# 3. Commit + push (pre-commit/pre-push hooks run the test suite)
git add -A
git commit -m "feat(scope): message [SLIP-NN]"
git push -u origin slip-<ticket>-<short-desc>

# 4. Open the PR
gh pr create --base main --head slip-<ticket>-<short-desc> --title "..." --body "..."

# 5. Merge (squash is this repo's convention)
gh pr merge <N> --squash --delete-branch

# 6. Clean up
git switch main && git pull && git remote prune origin
```

### Hard rules

- **NEVER push directly to `main`.** Every change goes through a PR. Check
  with `git branch -vv` that your branch is not tracking `origin/main` before
  the first push.
- Rename an auto-generated branch (e.g. `claude/<name>-<suffix>`) to the
  `slip-<ticket>-<short-desc>` form **before** the first push. Renaming after
  pushing means deleting the remote branch, which breaks an open PR.
- Keep secrets out of commits; the secrets store and `SLIP_TOKEN` env are the
  only homes for key material.

## Parallel work

Separate branches are independent working trees' worth of state, so parallel
work no longer cross-contaminates the way it did under GitButler's composed
workspace. `git worktree` is fine, and is the usual way to run two branches at
once.

One dependency rule still applies: before building on an API or type that
another in-flight branch introduced, wait for that branch to merge. Your branch
is checked out alone in CI, so referencing something that only exists on a
sibling branch fails there with "no variant/field/method named X" even though
your local checkout is fine.

## Verification contract

Every change, before commit:

```bash
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test --workspace
```

CI additionally runs (on every PR): the Caddy contract tests against a real
Caddy (`cargo test -p slip-core --test caddy_contract -- --ignored`) and the
end-to-end smoke test (`scripts/smoke-test.sh`).

Known flakes (retry before assuming your change broke them):

- `test_live_app_update_persists` (slip-core) — order-dependent, passes in
  isolation. Needs a fix (shared-tempdir race); until then, rerun.
- `set_and_remove_routes_on_real_caddy` (Caddy contract, CI-only) — occasional
  `IncompleteMessage` when the GET races a Caddy reload. Rerun the job.

## CLI conventions (the SLIP-86 contract)

All `slip` commands must:

- Support `--json` with stable serde schemas (via `crates/slip-cli/src/output.rs`)
- Use the contractual exit codes: 0 ok · 1 generic · 2 usage · 3 auth ·
  4 not-found · 5 deploy-failed · 6 timeout
- Emit **prescriptive errors** — name the remedy, not just the failure
  ("app 'poi' not found — run `slip apply` to register it")
- Stubs exit non-zero with "not yet implemented" on stderr (never
  `println!` + exit 0 — a green exit from a stub is lying state)

Auth model: management API = admin token (Bearer, `--token`/`SLIP_TOKEN`);
deploy webhook = per-app deploy key (HMAC `X-Slip-Signature`,
`--secret`/`SLIP_SECRET`). Don't conflate them. The deploy key appears in
exactly one place: the `PUT /v1/apps/{name}/key` create/rotate response.

## Branch naming

`slip-<ticket-number>-<short-description>` (e.g. `slip-93-slip-key-cli`).
No usernames. Commit messages: conventional commits with the ticket ID:
`feat(slip-cli): slip key command [SLIP-93]`.

## Roadmap context

The v1.0 roadmap lives in Linear ("slip v1.0: Agent-Ready PaaS" project,
milestones M1–M4). Tickets carry full context: spec, acceptance criteria,
file:line refs, and citations to the field reports in `docs/` (the dogfooding
evidence this roadmap is built on):

- `docs/field-report-poi-australia.md`
- `docs/hard-edges-field-report.md`
- `docs/draft-iac-with-slip.md` (IaC design, reviewed by the infra agent)

Read the ticket AND its cited field-report sections before building.
