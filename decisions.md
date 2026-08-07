# Decisions — AICAC-105 (#26)

## D1: Separate `Network_Admin` class (not extend site `Admin`)

**Decision:** Implement the rollup in `class-handl-aicac-network-admin.php` rather than expanding `Admin`.

**Why:** Site admin mutators, tabs, and `manage_options` gates must stay isolated from the network read-only surface. Keeps AICAC-3 authz inventory and single-site behavior unchanged (AC1).

## D2: Paginate network sites at 50; filter inactive per page

**Decision:** `SITES_PER_PAGE = 50` applies to `get_sites( number/offset )`. Sites without the plugin active are skipped for display and for `switch_to_blog`. Pagination total is the network site count.

**Why:** Bounds `switch_to_blog` (and option reads) per request (AC6) without a second unbounded scan to build an “active-only” index. Documented in the UI so empty-looking pages on sparse activation are expected.

## D3: Read raw options, not `Policy::get_policy()`

**Decision:** Rollup reads `get_option( Plugin::OPTION_KEY )` / `LOG_OPTION_KEY` and interprets `kill_switch`, `audit_only`, `log_enabled` as booleans locally.

**Why:** Avoids pulling Alerts/Weekly_Report/Model_Force/Cost normalization on every site switch for a summary that only needs three flags plus the log. Matches story dependency note (“reads existing … options”).

## D4: Denial count matches Dashboard semantics

**Decision:** Count retained rows where `decision === 'deny'` and `channel !== 'direct_http'` (same as Dashboard / weekly report).

**Why:** Network rollup and per-site Dashboard must not disagree on what a “denial” is. Learn-mode “would deny” rows are not counted as denials (they use allow + would_decision).

## D5: Capability `manage_network_options`

**Decision:** Menu and page gate use `manage_network_options` (not `manage_options`).

**Why:** Story requires network-admin capability distinct from and in addition to per-site `manage_options`.

## D6: Minor version 1.1.0

**Decision:** Bump `1.0.14` → `1.1.0` with changelog + Description note that multisite support is read-only.

**Why:** Product rollout asks for a minor bump when introducing the network surface.
