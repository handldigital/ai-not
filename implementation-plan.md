# Implementation Plan — AICAC-102 (#23)

## Work item

**Issue:** #23 — AICAC-102: Export and import policy/rules configuration as JSON  
**Scope:** Rules-tab transfer UI + pure transfer/validate/diff helpers; write via existing `Policy::save_policy` sanitization.  
**Out of scope:** Cross-site sync, push-to-all-sites (AICAC-105), audit-log export (AICAC-101), WP-CLI bulk import (AICAC-103).

## Objective

Let a `manage_options` admin download the current `Plugin::OPTION_KEY` policy as JSON (with `plugin_version` / `exported_at`), upload a prior export, preview added/changed/removed governance fields, and confirm a full-replace import that reuses the same sanitize path as Rules save — rejecting invalid JSON without mutating live policy.

## Approach (smallest correct change)

1. Add `includes/class-handl-aicac-policy-transfer.php` with pure helpers: build export payload, parse/validate upload JSON, strip unknown fields, compute AC2 diff sections, prepare array for `Policy::save_policy`.
2. Wire Rules-tab UI: Download form; Import upload → preview (transient) → confirm; document full-replace in UI.
3. Dispatch POST actions in `Admin::render_page` after the existing `manage_options` gate: `export_rules`, `import_rules_preview`, `import_rules_confirm` — each with `check_admin_referer`; upload-only; ~1MB size cap.
4. Confirm no secrets/credentials in the policy option before shipping (AC6).
5. Unit-test transfer parse/diff/unknown-field behavior; update `AdminAuthzCoverageTest` for new mutating actions.
6. Minor version bump + changelog documenting JSON schema metadata fields.

## Acceptance-criteria mapping

| Criterion | Implementation | Test / evidence |
|-----------|----------------|-----------------|
| AC1 Download includes full policy + `plugin_version` + `exported_at` | `Policy_Transfer::build_export` + admin export handler | Unit: export shape; manual download path exists on Rules |
| AC2 Valid upload shows preview of added/changed/removed (plugins, operations, kill-switch, denied-tools, model-force) before write | `Policy_Transfer::diff_policies` + preview UI; write only on confirm | Unit: diff cases; preview action does not call `save_policy` |
| AC3 Confirmed import full-replaces via sanitize path + success notice | Confirm → `Policy::save_policy`; UI documents full replace | Unit: `policy_for_save` strips meta; success redirect query arg |
| AC4 Invalid JSON / missing required keys → error, live policy unchanged | `parse_import` rejects; no save on failure | Unit: invalid JSON, missing keys |
| AC5 Unknown fields ignored with notice listing them | parse strips unknown; notice on preview/confirm | Unit: unknown keys listed in `ignored` |
| AC6 No secrets exported | Static confirm: option has no API keys/credentials | Documented in decisions + handoff |
| Security: manage_options, nonce, upload-only, 1MB | Shared gate + per-action nonces; `$_FILES` only | Authz coverage test updated |

## Risks

- Full replace overwrites Activity-tab fields stored in the same option (log/alerts/rates) when present in the export — intentional and documented in UI.
- `AdminAuthzCoverageTest` match counts change with new handlers; AICAC-3 inventory text may lag the test until refreshed.
- Credential-free workspace: no push; control plane publishes for Quality.

## Files

- `includes/class-handl-aicac-policy-transfer.php` (new)
- `includes/class-handl-aicac-admin.php` (UI + handlers)
- `includes/class-handl-aicac-plugin.php` (require transfer class)
- `handl-ai-connector-access-control.php` / `readme.txt` (version + changelog)
- `tests/Unit/PolicyTransferTest.php` (new)
- `tests/Unit/AdminAuthzCoverageTest.php` (extend inventory)
- `tests/bootstrap.php` (load transfer class)
