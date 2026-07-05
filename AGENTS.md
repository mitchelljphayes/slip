# AGENTS.md — working on the slip repo

Process notes for agents (and humans) working in this repository. These are
learned rules from real sessions — each one exists because violating it cost
time. Follow them.

## Version control: GitButler (NOT plain git)

This repo is managed by **GitButler virtual branches**. The workspace lives on
the `gitbutler/workspace` branch and composes all applied virtual branches.

### The branch lifecycle (follow exactly)

```bash
# 1. Create a virtual branch (from a clean, up-to-date workspace)
but branch new slip-<ticket>-<short-desc>

# 2. Edit files, then assign every changed file to your branch IMMEDIATELY
but rub <path> slip-<ticket>-<short-desc>

# 3. Verify (all three must be green)
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test --workspace

# 4. Commit + push (pre-commit/pre-push hooks run the test suite)
but commit slip-<ticket>-<short-desc> -m "feat(scope): message [SLIP-NN]"
but push slip-<ticket>-<short-desc>

# 5. Open the PR
gh pr create --base main --head slip-<ticket>-<short-desc> --title "..." --body "..."

# 6. Merge (squash is this repo's convention)
gh pr merge <N> --squash --delete-branch

# 7. Reconcile the workspace — ORDER MATTERS (see below)
git fetch origin
but pull                                        # EXPECTED to fail ("Chosen resolutions…") — this rebuilds the stack state
but unapply slip-<ticket>-<short-desc>          # now succeeds; removes the integrated branch
but pull                                        # fast-forwards the base cleanly
git remote prune origin
```

### ⚠️ Post-squash reconciliation — the order matters

We squash-merge PRs (clean main history). Because a squash commit is a new
commit (the branch tip is never an ancestor of main), the GitButler CLI can't
auto-archive the integrated branch, and needs this exact sequence (validated
empirically on PR #41, after the naive orders all failed on PRs #30–40):

1. `git fetch origin` — get the squash commit
2. `but pull` — **expect it to FAIL** with
   `Error during integration: Chosen resolutions do not match quantity of applied virtual branches`.
   This failure is load-bearing: the pull attempt rebuilds the internal stack
   state so the next step can find the branch. (Running `but unapply` before
   this fails with "not found in any applied stack".)
3. `but unapply <branch>` — now succeeds ("Unapplied stack with branches …")
4. `but pull` — fast-forwards the base cleanly
5. `git remote prune origin` — clear the deleted remote ref

Cosmetic errors from `but status` during this dance ("Could not find branch
CLI id '' in IdMap") clear themselves once the next branch is created.

### Recovery: if the sequence above still doesn't reconcile

Last resort (should not be needed if the order above is followed):

1. Edit `.git/gitbutler/virtual_branches.toml`, find the branch's
   `[branches.<uuid>]` block, set `in_workspace = true` → `in_workspace = false`
2. `but pull` (now fast-forwards)
3. `git remote prune origin`

The GitButler GUI handles this integration dialog natively, so reconciling
from the GUI is also always an option.

### Hard rules

- **NEVER** `git commit`, `git add`, `git checkout`, or `git rebase` in the
  workspace — they corrupt GitButler state.
- **NEVER** use `git worktree` for feature work. It bypasses GitButler
  entirely, leaves phantom branch metadata, and the "isolated verification"
  it buys is better achieved by keeping branches file-disjoint (below). This
  was tried; the cleanup cost more than the isolation saved.
- **Don't let files sit unassigned** — `but rub` immediately after editing,
  or hunks can get claimed by the wrong branch.
- Keep secrets out of commits; the secrets store and `SLIP_TOKEN` env are the
  only homes for key material.

## Parallel work: file-disjoint or sequential

GitButler composes all applied branches into ONE working tree. Two branches
touching the same file will cross-contaminate: code compiles in the combined
workspace but **fails CI in isolation** (each branch is checked out alone).
This produced real CI failures (missing enum variants, struct fields that only
existed on a sibling branch).

Rules:

- **Same file (or same crate hot-spots like `slip-cli/src/main.rs`,
  `slip-core/src/api.rs`, `caddy.rs`) → one branch at a time.** Merge before
  starting the next.
- **Disjoint files → parallel virtual branches are fine** (that's GitButler's
  strength).
- Before building on an API/type another in-flight branch added: **wait for it
  to merge**. If CI fails on your branch with "no variant/field/method named
  X" that exists in your workspace — that's cross-branch contamination; the
  thing you referenced lives on a sibling branch, not yours.

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
