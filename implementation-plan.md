# Implementation Plan — AICAC-104 (#25) Quality remediation

## Work item

**Issue:** #25 / AICAC-104 (PR #45)
**Scope:** Remediate Quality and Release Gate findings on the existing webhook PR — not new product scope.
**Trigger:** Product unblock triage set `NEXT_OWNER=DEVELOPER` with `STATUS: CHANGES_REQUESTED`.

## Objective

Close blocking P2 (authz inventory test gap) and batch P3 (Markdown trailing whitespace) with evidence so Quality can re-review. Staging smoke tests and human production approval remain process gates outside agent authority.

## Approach (smallest correct change)

1. **P2:** Rewrite `AdminAuthzCoverageTest::test_no_unknown_handl_aicac_action_string_literals_in_dispatch` so any quoted token on a `handl_aicac_action` / `posted_action` line that is not in the known mutating-action inventory (or a tiny non-action allowlist) fails the test. Derive `$known` from `mutating_action_provider()` to avoid inventory drift.
2. **P3:** Remove Markdown two-space hard-break trailing whitespace in `developer-handoff.md` and `implementation-plan.md` so `git diff --check` is clean.
3. Prove P2 with a temporary unknown action injection (expect failure), restore source, then run full `composer test`.
4. Document remaining release-gate items (staging smoke + human production approval) as open HUMAN process risks — do not waive.

## Acceptance-criteria mapping

| Criterion | Implementation | Test / evidence |
|-----------|----------------|-----------------|
| P2: test rejects unknown `handl_aicac_action` / `posted_action` literals | Assert `array_keys($unknown) === []`; known set from provider | Inject `totally_new_mutating_action` → fail @ L127; clean tree → pass |
| P3: no trailing whitespace in touched Markdown | Strip trailing spaces on STATUS / plan header lines | `git diff --check` exit 0 |
| Release gate: staging smoke + human prod approval | No code change (outside agent authority) | Documented as remaining risks / NEXT notes |

## Risks

- Non-action allowlist includes `hidden` (HTML `type="hidden"` on form lines). A future quoted token that is not an action and not allowlisted will correctly fail CI until allowlisted or the scanner is narrowed.
- SSRF-adjacent admin webhook URL and dual-channel digest retry remain from the original PR (not in this remediation scope).
- Staging smoke + human production approval still block merge/release until HUMAN records them.

## Out of scope

- New product features; waiving Quality findings; deploying; staging smoke execution; production approval.
