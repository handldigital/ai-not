# Implementation Plan — Issue #36 (Resolve PR #33 conflicts)

## Work item

**Issue:** https://github.com/handldigital/ai-not/issues/36  
**Target:** Resolve merge conflicts on https://github.com/handldigital/ai-not/pull/33  
**PR head:** `agentops/implement-yh1aNLkXZhj1` (`bae0f09` Implement #19)  
**Base:** `main` (includes PR #34 / #35 — AICAC-1 already landed)

## Objective

Make PR #33 mergeable against current `main` without regressing the
AICAC-1 suite already on `main`.

## Approach (smallest correct change)

1. Merge `main` into the PR #33 head branch.
2. Resolve add/add conflicts by keeping **main’s** versions for shared
   implementation files (main is a strict superset of the PR #33 suite).
3. Refresh AgentOps handoff artifacts for this conflict-resolution job.
4. Re-run `composer test` to confirm the merged tree matches main’s green suite.

## Conflict inventory

| File | Resolution |
|------|------------|
| `tests/Unit/PolicyEvaluateTest.php` | Keep **main** (adds `tool_armed` + `audit_only` tests) |
| `.gitignore` | Keep **main** (also ignores `.agentops-meta.json` / `.agentops-result.json`) |
| `.agentops-runner-log.json` | Keep **main** (runtime log noise) |
| `implementation-plan.md` | Rewrite for issue #36 |
| `decisions.md` | Rewrite for issue #36 |
| `test-results.md` | Rewrite with post-merge command evidence |
| `developer-handoff.md` | Rewrite for issue #36 |

Auto-merged / already from main (no conflict markers):

- `.github/workflows/phpunit.yml` (new on main)
- `.github/workflows/release.yml` (test/vendor excludes)
- `tests/Unit/OperationsFamilyTest.php` (new on main)

## Acceptance-criteria mapping

| Criterion | Implementation | Test / evidence |
|-----------|----------------|-----------------|
| PR #33 conflicts resolved | Merge commit on PR head with no conflict markers | `git status` clean; no `<<<<<<<` |
| No regression of AICAC-1 suite | Keep main’s 31-test suite | `composer test` → OK (31/62) |
| PR becomes mergeable vs main | Branch contains merge of current main | Diff vs main is handoff-only / empty of product code |

## Risks

- PR #33 is superseded by merged PR #34/#35 for issue #19; after conflict
  resolution the unique product diff vs main is empty. Closing or merging
  PR #33 as a no-op merge is a Product/Human decision.
- Credential-free workspace cannot push; control plane must publish the
  updated PR head branch.

## Out of scope

- Re-implementing AICAC-1 features already on main.
- Closing or merging PR #33 (Quality / Human).
- AICAC-2 observability work.
