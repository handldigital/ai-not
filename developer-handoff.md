# Developer Handoff — AICAC-102 (#23)

## Work item ID

Issue #23 — AICAC-102: Export and import policy/rules configuration as JSON

## Summary of behavior implemented

On the Rules tab, admins with `manage_options` can **Download rules (JSON)** (full current policy option plus `plugin_version` / `exported_at`) and **Import rules (JSON)** via upload-only file input (≤1MB). A valid upload shows a preview of added/changed/removed per-plugin rules, capability-family settings, kill switch, denied tools, and model-force pins **before** any write. Confirm performs a documented **full replace** through `Policy::save_policy` (same sanitize path as Rules save) and shows a success notice. Invalid JSON or missing `plugin_version`/`exported_at` is rejected with a specific error and live policy unchanged. Unknown newer fields are ignored with a notice. No secrets/credentials exist in the policy option to exclude.

## Files changed

- `includes/class-handl-aicac-policy-transfer.php` — **new** export/parse/diff/save-prep helpers
- `includes/class-handl-aicac-admin.php` — UI + `export_rules` / `import_rules_preview` / `import_rules_confirm` handlers
- `includes/class-handl-aicac-plugin.php` — require transfer class
- `tests/bootstrap.php` — load transfer class for unit tests
- `tests/Unit/PolicyTransferTest.php` — **new** AC-focused unit tests
- `tests/Unit/AdminAuthzCoverageTest.php` — extended for new mutating actions + import path locks
- `handl-ai-connector-access-control.php`, `readme.txt` — version **1.0.15** + changelog
- `implementation-plan.md`, `decisions.md`, `test-results.md`, `developer-handoff.md`, `.agentops-result.json`

## Acceptance-criteria-to-test mapping

| Acceptance criterion | Evidence |
|----------------------|----------|
| AC1 Download = full policy + `plugin_version` + `exported_at` | `PolicyTransferTest::test_build_export_includes_policy_plus_metadata`; `handle_export_rules` streams JSON attachment |
| AC2 Preview added/changed/removed before write | `test_diff_policies_*`; preview UI; `test_import_confirm_uses_policy_save_policy` asserts preview has no `save_policy(` |
| AC3 Confirm full replace + success notice | Confirm → `Policy::save_policy`; redirect `handl_aicac_imported=1`; UI “Mode: full replace” |
| AC4 Invalid JSON / missing keys → error, no write | `test_parse_import_rejects_*`; error redirects; preview never saves |
| AC5 Unknown fields ignored + notice | `test_parse_import_ignores_unknown_fields`; preview/success notices list ignored keys |
| AC6 No secrets exported | `test_export_contains_no_secret_field_names`; decisions D5 |
| Security (cap, nonce, upload-only, 1MB) | Shared `manage_options`; three new `check_admin_referer`s; `$_FILES` only; `MAX_UPLOAD_BYTES` |

## Commands executed

```bash
export PATH="/home/ubuntu/php-runtime:$PATH"
composer install --no-interaction
composer test
php -l includes/class-handl-aicac-policy-transfer.php
php -l includes/class-handl-aicac-admin.php
php -l includes/class-handl-aicac-plugin.php
php -l handl-ai-connector-access-control.php
```

## Test results

```
OK (56 tests, 233 assertions)
```

Full capture: `test-results.md`.

## Data or schema changes

- No DB migrations.
- Export JSON schema: policy option keys + required `plugin_version` (string) + `exported_at` (ISO-8601 string).
- Pending import stored in user transient `handl_aicac_import_{user_id}` (TTL 900s); cleared on confirm.

## Configuration changes

- Plugin version bumped **1.0.14 → 1.0.15**.

## Security considerations

- Both directions require `manage_options` (shared page gate) and action-specific nonces.
- Import accepts uploaded files only (`is_uploaded_file`); no server path field; 1MB cap.
- Write path is `Policy::save_policy` only (sanitize/validate), not a parallel option writer.
- Confirmed: policy option has no provider API keys/credentials today.

## Known limitations

- Unit tests do not boot WordPress; download headers / multipart upload / CSRF are covered by static authz locks + transfer logic tests, not browser integration.
- Full replace overwrites Activity-tab fields that share `OPTION_KEY` (logging, alerts, rates, weekly report) when present in the export — documented in UI.
- Model-force pins imported while force is unused remain stored but inert (empty force = off convention), per story edge case.

## Rollback considerations

- Revert to 1.0.14 removes transfer UI/handlers; existing policy options remain valid.
- No irreversible migration; discard pending import transients after TTL or by clearing options cache.

## Remaining risks

- Operators may not realize full replace includes non-Rules fields stored in the same option — mitigated by UI copy, still worth Quality UX check.
- `aicac-3-authz-coverage.md` inventory text still describes the pre-102 handler set; `AdminAuthzCoverageTest` is the live lock (7 actions).

## Requested next action

Quality and Release Gate: review implementation against AC1–AC6 using `test-results.md` / unit tests, and spot-check Rules-tab download → preview → confirm in a WordPress admin environment.

---

STATUS: READY  
WORK_ITEM: #23 / AICAC-102  
COMPLETED: Rules JSON export/import with preview+confirm full replace via Policy::save_policy; AC1–AC6 covered by unit + authz locks; version 1.0.15  
EVIDENCE: implementation-plan.md; decisions.md; test-results.md; developer-handoff.md; `composer test` OK (56 tests, 233 assertions); php -l clean on changed PHP  
DECISIONS: Full replace; flat export + metadata; Policy_Transfer + save_policy only; transient preview; no secret denylist needed today  
RISKS: Full replace spans shared option fields; AICAC-3 markdown inventory stale vs updated PHPUnit lock  
NEXT_ACTION: Quality review AICAC-102 against AC1–AC6 and reproduce validation  
NEXT_OWNER: QUALITY
