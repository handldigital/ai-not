# AICAC-3 — Admin authz coverage verification

**Work item:** #21 (AICAC-3)  
**Target file:** `includes/class-handl-aicac-admin.php` (2,723 lines)  
**Verification date:** 2026-08-07  
**Method:** Static source review of all POST action dispatches and private mutators; cross-check for `wp_ajax_*` / `admin_post_*` / `register_setting` entry points in this file and the rest of `includes/`.

## Architecture summary

All admin HTTP state mutations for this plugin enter through a **single options-page callback**:

| Layer | Location | Mechanism |
|-------|----------|-----------|
| Menu registration capability | `register_menu` L59–66 | `add_options_page( …, 'manage_options', … )` — WordPress refuses the page for users lacking the cap |
| Shared capability wrapper | `render_page` L70–72 | `current_user_can( 'manage_options' )` then `wp_die` — runs **before** any `$_POST` handling |
| Per-action CSRF nonces | `render_page` L104–144 | `check_admin_referer( <action>, 'handl_aicac_nonce' )` immediately before each mutate path |
| Settings API | — | **not found** (no `register_setting` / `settings_fields` / `options.php` save flow) |
| AJAX / `admin_post_*` | — | **not found** in `class-handl-aicac-admin.php` (or other includes for this UI) |

The issue’s historical “only 5 combined matches” signal (AICAC-3) was explained by consolidation: **1×** `current_user_can` + **4×** `check_admin_referer`. **AICAC-104** added `send_test_webhook` → inventory is now **1×** capability + **5×** nonces (locked in `AdminAuthzCoverageTest`). That count alone is **not** evidence of missing coverage.

GET / `$_REQUEST` query args used in this file (`handl_aicac_tab`, filters, flash flags) only affect rendering; they do **not** persist policy.

---

## Handler inventory (dispatch → mutator)

### H1 — `quick_rule` (set per-plugin allow/deny + redirect)

| Field | Value |
|-------|-------|
| Dispatch | `includes/class-handl-aicac-admin.php:104–108` (`handl_aicac_action === 'quick_rule'`) |
| Mutator | `handle_quick_rule_redirect` L2150 → `Policy::set_plugin_rule` L2179 |
| Capability | Shared wrapper L70 (`manage_options`); menu cap L63 |
| Nonce | `check_admin_referer( 'handl_aicac_quick_rule', 'handl_aicac_nonce' )` **L107** |
| Form emitters | L876 (`dashboard` Block), L2336 (`render_quick_rule_buttons`) via `wp_nonce_field( 'handl_aicac_quick_rule', … )` |
| Settings API | **not found** |
| Gap? | **No** |

### H2 — `send_denial_digest` (send queued denial digest mail / clear queue on success)

| Field | Value |
|-------|-------|
| Dispatch | L110–122 (`handl_aicac_action === 'send_denial_digest'`) |
| Mutator | Inline `Alerts::instance()->send_digest()` L112 (side effect: mail + digest option clear on success) |
| Capability | Shared wrapper L70; menu cap L63 |
| Nonce | `check_admin_referer( 'handl_aicac_send_digest', 'handl_aicac_nonce' )` **L111** |
| Form emitter | L1268 |
| Settings API | **not found** |
| Gap? | **No** |

### H3 — `undo_quick_rule` (restore prior plugin rule after dashboard block)

| Field | Value |
|-------|-------|
| Dispatch | L124–126 |
| Mutator | `handle_undo_quick_rule` L2199 → `Policy::set_plugin_rule` L2205 |
| Capability | Shared wrapper L70; menu cap L63 |
| Nonce | `check_admin_referer( 'handl_aicac_undo_quick_rule', 'handl_aicac_nonce' )` **L125** |
| Form emitter | L194 |
| Settings API | **not found** |
| Gap? | **No** |

### H4 — `save` → rules path (default policy, plugin rules, operations, denied tools, kill switch, model force)

| Field | Value |
|-------|-------|
| Dispatch | L137–143 when `handl_aicac_action === 'save'` and tab ≠ `activity` |
| Mutator | `handle_save_rules` L1799 → `apply_kill_switch_settings_from_post` L2074, `apply_model_force_settings_from_post` L1843 → `Policy::save_policy` L1837 |
| Capability | Shared wrapper L70; menu cap L63 |
| Nonce | `check_admin_referer( 'handl_aicac_save_policy', 'handl_aicac_nonce' )` **L138** |
| Form emitter | L248 (rules form shell) |
| Settings API | **not found** |
| Gap? | **No** |

### H5 — `save` → activity/log path (learn mode, log retention, alerts, weekly report prefs, cost rates)

| Field | Value |
|-------|-------|
| Dispatch | L137–140 when `handl_aicac_action === 'save'` and tab === `activity` |
| Mutator | `handle_save_log` L2353 → `apply_log_settings_from_post` L2094 → `Policy::save_policy` L2358 |
| Capability | Shared wrapper L70; menu cap L63 |
| Nonce | Same as H4: **L138** (`handl_aicac_save_policy`) |
| Form emitter | L1257 |
| Settings API | **not found** |
| Gap? | **No** |

### Private helpers (not independent HTTP entry points)

These are `private` and only reachable from H1–H5 after the shared capability gate and the matching nonce check:

| Method | Line | Called from |
|--------|------|-------------|
| `handle_save_rules` | 1799 | H4 |
| `handle_save_log` | 2353 | H5 |
| `handle_quick_rule_redirect` | 2150 | H1 |
| `handle_undo_quick_rule` | 2199 | H3 |
| `apply_kill_switch_settings_from_post` | 2074 | H4 via `handle_save_rules` |
| `apply_model_force_settings_from_post` | 1843 | H4 via `handle_save_rules` |
| `apply_log_settings_from_post` | 2094 | H5 via `handle_save_log` |

Independent capability/nonce inside these helpers: **not found** (by design — shared wrapper).

---

## Findings for Quality and Release Gate

### F-AICAC-3-1 — No confirmed missing nonce/capability on admin mutating handlers

| Field | Value |
|-------|-------|
| Severity | **None** (verification result: covered) |
| Outcome | Every enumerated POST action (H1–H5) has `check_admin_referer` **and** inherits `manage_options` from L70 + menu registration |
| Failure scenario | N/A — unauthorized caller without `manage_options` is refused by WP menu + `wp_die`; forged POST without a valid per-action nonce dies in `check_admin_referer` |
| Remedia­tion under this story | **None** (do not change product code) |
| Note | Original “5 matches” scan is consistent with shared-wrapper design, not with an authz hole |

### F-AICAC-3-2 — Private mutators rely solely on caller authz (defense-in-depth observation)

| Field | Value |
|-------|-------|
| Severity | **Informational** |
| Outcome | Helpers listed above contain **not found** for their own `current_user_can` / `check_admin_referer` |
| Concrete failure scenario | If a **future** change makes a private mutator public, or adds a second call site (e.g. REST/AJAX) that invokes `handle_save_rules` / `Policy::save_policy` without repeating capability + nonce checks, an unauthorized or CSRF’d request could flip kill switch / allow-deny / learn mode |
| Current exploitability | **Not demonstrated** — methods are `private`; only call sites are post-check in `render_page` |
| Remedia­tion under this story | **Do not fix here** — Quality may open a follow-up if Product wants defense-in-depth re-checks |

### F-AICAC-3-3 — Settings API implicit authz **not found**

| Field | Value |
|-------|-------|
| Severity | **None** (informational classification only) |
| Outcome | Plugin does not use `register_setting` / Options API save; custom POST + explicit nonces are the sole mechanism |
| Failure scenario | N/A |

---

## Out-of-scope surfaces (explicitly not admin UI handlers in this file)

- Cron: `Alerts` / `Weekly_Report` cron hooks (server-side schedule, not admin POST).
- Runtime: `Policy` / `Model_Force` / `Shadow_AI` option writes during AI Client requests.
- Admin notice only: `Model_Force::maybe_admin_health_notice` L647 (`current_user_can` for display, no mutation).

---

## Evidence anchors (combined match count)

In `class-handl-aicac-admin.php`:

| Pattern | Lines |
|---------|-------|
| `current_user_can` | 70 |
| `check_admin_referer` | 107, 111, 125, 138 |
| `wp_verify_nonce` | **not found** (uses `check_admin_referer` instead) |
| `wp_nonce_field` (emitters) | 194, 248, 876, 1257, 1268, 2336 |

**Total capability + verify matches in the admin class: 5** — matches the issue premise; inventory above shows each mutating handler is covered.
