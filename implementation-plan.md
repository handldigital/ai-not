# Implementation Plan — #22 (PR #42 remediation / AICAC-3 coverage lock)

## Work item

**Issue:** #22 — Remediate Quality P2 on PR #42 (origin #21 / AICAC-3)  
**Scope:** `tests/Unit/AdminAuthzCoverageTest.php` only (test correctness)  
**Constraint:** No changes to `includes/class-handl-aicac-admin.php` or other production authz code. F-AICAC-3-2 remains Informational / no-action (D2).

## Objective

Make the static coverage lock actually fail when a new `handl_aicac_action` dispatch branch appears. Today `test_no_unknown_handl_aicac_action_string_literals_in_dispatch` only asserts each approved literal still exists; unknown literals (e.g. `delete_all`) are ignored.

## Approach (smallest correct change)

1. Extract a helper that discovers dispatch action string literals from source via comparison patterns against `$posted_action` / `$_POST['handl_aicac_action']`.
2. Assert discovered set **equals** the approved inventory (sorted arrays / set equality), not merely “approved ⊆ found”.
3. Add a regression test that feeds a fixture containing an unknown action (`delete_all`) and asserts discovery includes it and therefore differs from the approved set.
4. Align the approved list with `mutating_action_provider` via a shared constant to avoid inventory drift.
5. Correct the test docblock so it no longer overclaims.

## Acceptance-criteria mapping

| Criterion | Implementation | Test |
|-----------|----------------|------|
| Discover dispatch literals from source | `discover_dispatch_action_literals()` | Used by equality + regression tests |
| Discovered set equals approved set | `test_no_unknown_handl_aicac_action_string_literals_in_dispatch` | `assertSame( approved, discovered )` |
| Regression for unknown action | `test_dispatch_literal_discovery_detects_unknown_action` | Fixture with `delete_all` must be discovered and ≠ approved |
| No production authz changes | Diff limited to test + AgentOps artifacts | Inspect final diff |
| F-AICAC-3-2 unchanged (Informational) | No mutator / gate edits | Prior D2 stands |

## Risks

- Over-broad token scraping could false-positive on form `value="…"` emitters; discovery is limited to comparison patterns used in dispatch branches.
- Under-broad patterns could miss alternate comparison styles; if dispatch is refactored, update the helper patterns and inventory together.
- Low overall risk: test-only change.

## Out of scope

- Defense-in-depth re-checks in private mutators (F-AICAC-3-2).
- Production admin class changes.
- New product actions or authz behavior.
