# Implementation Plan — AICAC-3 (#21)

## Work item

**Issue:** #21 — AICAC-3: Verify authorization (nonce + capability) coverage on all admin state-mutating handlers  
**Scope:** `includes/class-handl-aicac-admin.php` (settings/save surface)  
**Constraint:** Findings are documented for Quality and Release Gate — **do not fix** authz gaps under this story.

## Objective

Produce a complete, testable inventory of every settings-save / action handler in the admin class, identify the nonce and capability mechanism for each (including shared wrappers; Settings API if any), and emit severity + failure-scenario findings for any handler lacking checks. Route those findings to Quality; leave production plugin behavior unchanged except for verification evidence (static unit test + audit artifact).

## Approach (smallest correct change)

1. Static-read `class-handl-aicac-admin.php` and related includes for alternate entry points (`wp_ajax_*`, `admin_post_*`, `register_setting`).
2. Enumerate every POST `handl_aicac_action` dispatch and every private mutator it calls, with file:line.
3. Map capability (`current_user_can` / menu capability) and nonce (`check_admin_referer` / form `wp_nonce_field`) per handler; record **not found** explicitly where absent.
4. Classify gaps (if any) with severity + concrete failure scenario; otherwise document that the sparse match count is explained by a shared wrapper.
5. Add a PHPUnit static-source test that locks the inventory and fails if a new POST action branch appears without a matching nonce check, or if the shared capability gate disappears.
6. Do **not** add defense-in-depth re-checks or otherwise “fix” findings in production code under this story.

## Acceptance-criteria mapping

| Criterion | Implementation | Test / evidence |
|-----------|----------------|-----------------|
| Every settings-save/action handler enumerated with file:line | `aicac-3-authz-coverage.md` inventory table | `AdminAuthzCoverageTest` asserts known action keys + dispatch line anchors |
| Nonce/capability mechanism identified per handler (shared wrappers / Settings API / not found) | Coverage matrix in audit artifact | Test asserts shared `manage_options` gate, per-action `check_admin_referer`, and Settings API = not found |
| Handlers without checks → severity + concrete failure scenario | Findings section in audit + developer-handoff | Quality reviews findings; no silent omission |
| Findings routed through Quality, not fixed under this story | No production authz code changes | Diff limited to audit + test + AgentOps handoffs |

## Risks

- Static source tests can drift if dispatch is refactored into helpers; inventory comments in the test must stay aligned with the audit.
- Credential-free workspace cannot push; control plane publishes the branch for Quality review.
- Informational defense-in-depth notes must not be misread as confirmed CVEs.

## Out of scope

- Adding nonce/capability re-checks inside private mutators.
- Changing cron / runtime policy mutation paths outside the admin HTTP surface.
- Implementing AICAC-1/2 work or unrelated refactors.
