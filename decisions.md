# Decisions — Issue #38 (Resolve PR #32 conflicts)

## D1: Prefer main’s AICAC-1 tree; rewrite AgentOps artifacts only

**Decision:** Accept all auto-merged product/test/CI files from `main`.
Resolve every add/add conflict in AgentOps markdown/JSON by writing
issue #38 content (or keeping main’s runner log).

**Why:**
- PR #32’s only commits were blocked AICAC-2 handoffs when AICAC-1 was
  absent on `main@3c36f1f`.
- `main` now has AICAC-1 (composer + PHPUnit + `phpunit.yml` + `.gitignore`).
- Keeping PR #32’s stale “BLOCKED / no suite” narrative would mis-describe
  both the repo and this job.

## D2: Merge main into PR head (do not rewrite history)

**Decision:** Resolve conflicts with a merge commit on
`agentops/implement-L0OJiW_IwpCZ`, not a force-push rebase.

**Why:** AgentOps / bot branches may be referenced elsewhere; merge is the
safest reversible update for an open draft PR. Control plane publishes;
we do not force-push.

## D3: Do not implement AICAC-2 under issue #38

**Decision:** Conflict resolution only. No new lint workflow, PHPCS
config, or release.yml documentation for AICAC-2 acceptance criteria.

**Why:** Approved work item #38 is “Resolve conflict #32”. Expanding into
issue #20 / AICAC-2 would be unapproved product scope. AICAC-1 landing
unblocks a **new** AICAC-2 implement job; it does not expand #38.

## D4: No production plugin code changes

**Decision:** Do not modify `includes/*`, the main plugin bootstrap, or
runtime options as part of conflict resolution.

**Why:** Approved scope is conflict resolution only. Product behavior for
AICAC-1 is already on `main`; AICAC-2 is deferred.
