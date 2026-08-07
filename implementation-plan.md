# Implementation Plan — AICAC-105 (#26)

## Work item

**Issue:** #26 — AICAC-105: Network admin read-only rollup of per-site AI Client denial activity (multisite)  
**Scope:** New network-admin UI + pure rollup helpers; minor version bump; readme note  
**Out of scope:** Network-level policy writes, bulk apply, single-site behavior changes

## Objective

Give network admins a read-only Network Admin page that lists sites where this plugin is active, with per-site kill-switch, learn/logging state, denial count in the retained log window, last-activity timestamp, and a link to that site’s Activity tab — without changing single-site installs.

## Approach (smallest correct change)

1. Add `includes/class-handl-aicac-network-admin.php` with a `Network_Admin` singleton.
2. Register the page only when `is_multisite()` (hook `network_admin_menu`, capability `manage_network_options`).
3. Paginate `get_sites()` at **50 sites per page** (documented constant); for each site on the page, skip if the plugin is not active (network-active or site `active_plugins`); otherwise `switch_to_blog` / `restore_current_blog` (try/finally) to read `Plugin::OPTION_KEY` and `Plugin::LOG_OPTION_KEY`.
4. Build rows from raw options (not `Policy::get_policy()`) to avoid loading alert/weekly/force side paths for a read-only rollup.
5. Link each row to `get_admin_url( $blog_id, 'options-general.php?page=…&handl_aicac_tab=activity' )`.
6. When `wp_supports_ai` exists and returns false on that site, show **AI disabled** instead of a bare denial count.
7. No POST/forms that mutate policy (AC5).
8. Wire `Network_Admin::instance()->init()` from `Plugin::init()`.
9. Minor bump `1.0.14` → `1.1.0`; changelog + Description note that multisite rollup is read-only.
10. Unit-test pure helpers (denial count, newest ts, row summary, pagination math, basename) and static source locks (multisite gate, capability, no mutators, SITES_PER_PAGE=50).

## Acceptance-criteria mapping

| Criterion | Implementation | Test / evidence |
|-----------|----------------|-----------------|
| AC1: Non-multisite → no menu/page | `Network_Admin::init()` returns before `add_action` when `! is_multisite()` | Static/source + unit stub: init without multisite does not register menu |
| AC2: List URL, kill, logging/learn, denials, newest ts | `collect_page_rows` + `summarize_site_data` | Unit tests for summary fields from fixture policy/log |
| AC3: Inactive sites omitted | `is_plugin_active_on_site` filter before switch | Unit test: inactive → not included when building from site list fixtures |
| AC4: Link to site Activity tab | `activity_admin_url( $blog_id )` via `get_admin_url` | Unit test asserts path/query shape |
| AC5: Read-only | Render table + pagination GET only; no policy forms | Static test: no `handl_aicac_action` / `update_option` in network-admin class |
| AC6: Cap 50 | `Network_Admin::SITES_PER_PAGE = 50`; paginate `get_sites` | Constant asserted; pagination offset helper tested; documented in UI + decisions |
| Edge: `wp_supports_ai` false | Row `ai_disabled` → display “AI disabled” | Unit test summary marks ai_disabled and suppresses misleading zero presentation |

## Risks

- Large networks: pagination is over **network sites** (50/request), not “active-only” count — a page may show fewer than 50 rows when many sites lack the plugin; documented.
- `switch_to_blog` must always restore — try/finally mitigates early returns.
- Credential-free workspace: no live multisite smoke test; Quality must verify on a real network.

## Files to touch

- `includes/class-handl-aicac-network-admin.php` (new)
- `includes/class-handl-aicac-plugin.php` (require + init)
- `handl-ai-connector-access-control.php` (version)
- `readme.txt` (stable tag, description, changelog)
- `tests/Unit/NetworkAdminRollupTest.php` (new)
- `tests/bootstrap.php` (require network-admin class for pure helpers)
- AgentOps artifacts: `implementation-plan.md`, `decisions.md`, `test-results.md`, `developer-handoff.md`, `product-handoff.md`
