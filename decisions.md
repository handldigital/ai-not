# Decisions — Issue #36 (Resolve PR #33 conflicts)

## D1: Prefer main’s AICAC-1 suite over PR #33’s earlier draft

**Decision:** On every add/add conflict for test/config files, keep the
`main` version.

**Why:**
- `main` already merged AICAC-1 via PR #34 (`b73f4b6`) and follow-up PR #35.
- Main’s `PolicyEvaluateTest` is a strict superset of PR #33’s (adds
  `tool_armed` and `audit_only` coverage).
- Main also adds `OperationsFamilyTest`, `phpunit.yml`, and release zip
  excludes that PR #33 lacked.
- Reverting to the PR #33 19-test suite would regress coverage already on main.

## D2: Merge main into PR head (do not rewrite history)

**Decision:** Resolve conflicts with a merge commit on
`agentops/implement-yh1aNLkXZhj1`, not a force-push rebase.

**Why:** AgentOps / bot branches may be referenced elsewhere; merge is the
safest reversible update for an open draft PR. Control plane publishes;
we do not force-push.

## D3: Refresh handoff artifacts for #36; do not preserve stale AICAC-1 copy

**Decision:** Replace conflicted `implementation-plan.md`, `decisions.md`,
`test-results.md`, and `developer-handoff.md` with issue #36 content.

**Why:** Those files are AgentOps process artifacts, not product runtime.
Keeping either side’s AICAC-1 narrative would mis-describe this job.

## D4: No production plugin code changes

**Decision:** Do not modify `includes/*`, the main plugin bootstrap, or
runtime options as part of conflict resolution.

**Why:** Approved scope is conflict resolution only. Product behavior for
AICAC-1 is already on `main`.
