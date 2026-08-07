# Implementation Plan — Issue #38 (Resolve PR #32 conflicts)

## Work item

**Issue:** https://github.com/handldigital/ai-not/issues/38  
**Target:** Resolve merge conflicts on https://github.com/handldigital/ai-not/pull/32  
**PR head:** `agentops/implement-L0OJiW_IwpCZ` (`e75d445` Implement #20 — AICAC-2 blocked)  
**Base:** `main` (includes AICAC-1 via PR #34 / #35, plus PR #37 conflict-resolution for #33)

## Objective

Make PR #32 mergeable against current `main` without regressing the
AICAC-1 suite already on `main`. Do **not** expand into unapproved
AICAC-2 product scope under this conflict-resolution issue.

## Approach (smallest correct change)

1. Merge `main` into the PR #32 head branch.
2. Resolve add/add conflicts in AgentOps artifacts by rewriting them for
   issue #38 (keep main’s runtime product/test tree).
3. Prefer main’s `.agentops-runner-log.json` (runtime noise).
4. Re-run `composer test` to confirm the merged tree matches main’s green suite.

## Conflict inventory

| File | Resolution |
|------|------------|
| `.agentops-result.json` | Rewrite for issue #38 job outcome |
| `.agentops-runner-log.json` | Keep **main** |
| `implementation-plan.md` | Rewrite for issue #38 |
| `decisions.md` | Rewrite for issue #38 |
| `test-results.md` | Rewrite with post-merge command evidence |
| `developer-handoff.md` | Rewrite for issue #38 |

Auto-merged from main (no conflict markers):

- `composer.json`, `composer.lock`, `phpunit.xml.dist`
- `tests/**` (PolicyEvaluate, OperationsFamily, ModelForceResolveRoute)
- `.github/workflows/phpunit.yml`
- `.github/workflows/release.yml` (test/vendor excludes)
- `.gitignore`

## Acceptance-criteria mapping

| Criterion | Implementation | Test / evidence |
|-----------|----------------|-----------------|
| PR #32 conflicts resolved | Merge commit on PR head with no conflict markers | `git status` clean; no `<<<<<<<` |
| No regression of AICAC-1 suite | Keep main’s test harness and suite | `composer test` → OK |
| PR becomes mergeable vs main | Branch contains merge of current main | Diff vs main is handoff-only |

## Risks

- PR #32 originally tracked blocked AICAC-2 (#20). After conflict resolution
  the unique product diff vs main is empty; Product/Human should close or
  no-op-merge #32 and re-queue AICAC-2 (#20) as a fresh implement job.
- Credential-free workspace cannot push; control plane must publish the
  updated PR head.

## Out of scope

- Implementing AICAC-2 (php -l, PHPCS/WPCS, release.yml CI documentation).
- Closing or merging PR #32 / issue #20 (Quality / Product / Human).
