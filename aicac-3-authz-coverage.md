# AICAC-3 — Admin authz coverage verification

**Work item:** #21 (AICAC-3)  
**Target file:** `includes/class-handl-aicac-admin.php`  
**Verification date:** 2026-08-07  
**Method:** Static source review of all POST action dispatches and private mutators; cross-check for `wp_ajax_*` / `admin_post_*` / `register_setting` entry points in this file and the rest of `includes/`.

> **Amendment (AICAC-101 / #22):** Added privileged POST action `export_csv` with
> `check_admin_referer( 'handl_aicac_export_csv', 'handl_aicac_nonce' )` and private
> `handle_export_csv`. Shared `manage_options` gate unchanged. Combined inventory is now
> **1×** `current_user_can` + **5×** `check_admin_referer` (locked in `AdminAuthzCoverageTest`).

## Architecture summary

All admin HTTP state mutations for this plugin enter through a **single options-page callback**:

| Layer | Location | Mechanism |
|-------|----------|-----------|
| Menu registration capability | `register_menu` | `add_options_page( …, 'manage_options', … )` — WordPress refuses the page for users lacking the cap |
| Shared capability wrapper | `render_page` | `current_user_can( 'manage_options' )` then `wp_die` — runs **before** any `$_POST` handling |
| Per-action CSRF nonces | `render_page` | `check_admin_referer( <action>, 'handl_aicac_nonce' )` immediately before each mutate/export path |
| Settings API | — | **not found** (no `register_setting` / `settings_fields` / `options.php` save flow) |
| AJAX / `admin_post_*` | — | **not found** in `class-handl-aicac-admin.php` (or other includes for this UI) |

GET / `$_REQUEST` query args used in this file (`handl_aicac_tab`, filters, flash flags) only affect rendering; they do **not** persist policy.

---

## Handler inventory (dispatch → mutator)

### H1 — `quick_rule` (set per-plugin allow/deny + redirect)

| Field | Value |
|-------|-------|
| Dispatch | `handl_aicac_action === 'quick_rule'` in `render_page` |
| Mutator | `handle_quick_rule_redirect` → `Policy::set_plugin_rule` |
| Capability | Shared wrapper (`manage_options`); menu cap |
| Nonce | `check_admin_referer( 'handl_aicac_quick_rule', 'handl_aicac_nonce' )` |
| Settings API | **not found** |
| Gap? | **No** |

### H2 — `send_denial_digest`

| Field | Value |
|-------|-------|
| Dispatch | `handl_aicac_action === 'send_denial_digest'` |
| Mutator | `Alerts::send_digest()` |
| Capability | Shared wrapper |
| Nonce | `check_admin_referer( 'handl_aicac_send_digest', 'handl_aicac_nonce' )` |
| Gap? | **No** |

### H3 — `undo_quick_rule`

| Field | Value |
|-------|-------|
| Dispatch | `handl_aicac_action === 'undo_quick_rule'` |
| Mutator | `handle_undo_quick_rule` |
| Capability | Shared wrapper |
| Nonce | `check_admin_referer( 'handl_aicac_undo_quick_rule', 'handl_aicac_nonce' )` |
| Gap? | **No** |

### H4 — `save` (rules or log settings by tab)

| Field | Value |
|-------|-------|
| Dispatch | `handl_aicac_action === 'save'` |
| Mutator | `handle_save_log` (activity) / `handle_save_rules` (rules) |
| Capability | Shared wrapper |
| Nonce | `check_admin_referer( 'handl_aicac_save_policy', 'handl_aicac_nonce' )` |
| Gap? | **No** |

### H5 — `export_csv` (AICAC-101)

| Field | Value |
|-------|-------|
| Dispatch | `handl_aicac_action === 'export_csv'` |
| Mutator | `handle_export_csv` → `Log_Csv::document` (read-only download; exits) |
| Capability | Shared wrapper (`manage_options`) |
| Nonce | `check_admin_referer( 'handl_aicac_export_csv', 'handl_aicac_nonce' )` |
| Form emitter | `render_log_export_control` via `wp_nonce_field( 'handl_aicac_export_csv', … )` |
| Settings API | **not found** |
| Gap? | **No** |

---

## Findings (unchanged conclusions from AICAC-3)

- **F-AICAC-3-1:** No confirmed missing nonce/capability on current handlers (shared wrapper + per-action nonces).
- **F-AICAC-3-2 (Informational):** Private mutators do not re-check capability/nonce locally.
- **F-AICAC-3-3:** Settings API implicit authz **not found**.
