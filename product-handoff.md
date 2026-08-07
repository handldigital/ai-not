# Product handoff (AICAC-105 excerpt)

Copied for this implement job from the approved backlog story. Full multi-story handoff lived in the product-scan workspace; only AICAC-105 is in scope here.

## AICAC-105 — Network admin read-only rollup of per-site AI Client denial activity (multisite)

**Actor:** Network admin on a WordPress multisite install managing multiple client/team sites from one network dashboard.

**Desired behavior:** A read-only network-admin page (visible only under Network Admin, only when the site is part of a multisite network) that lists every site in the network where this plugin is active, with a summary row per site: kill-switch state, learn-mode/logging state, denial count in the retained window, and last-activity timestamp — each row linking to that site's own Activity tab for detail.

**Value:** Today an admin managing several sites in a network must log into each site individually to see denial/governance activity; this gives a single at-a-glance rollup, directly serving the agency/multi-site persona already implied by the plugin's per-plugin (not per-network) governance model.

**Preconditions:** `is_multisite()` is true. User has network-admin capability (`manage_network_options` or equivalent). Plugin is network-activated or individually active on at least one site in the network.

**Acceptance criteria:**
- AC1: Given a single-site (non-multisite) WordPress install, no network-admin page or menu item is registered — zero behavior change for the majority of current installs.
- AC2: Given a multisite network where this plugin is active on 2+ sites, the network-admin page lists each site with: site URL, kill-switch on/off, logging/learn-mode on/off, denial count from that site's retained log, and newest log timestamp.
- AC3: Given a site in the network where the plugin is installed but never activated, that site does not appear in the rollup (only sites with the plugin active are listed).
- AC4: Clicking a site's row/link navigates to that site's own wp-admin Activity tab (standard multisite cross-site admin link pattern), not an inline cross-site data view.
- AC5: This page is strictly read-only in this story — no controls to change any site's policy from the network admin screen (that is explicitly out of scope, see Exclusions).
- AC6: Page load does not exceed a reasonable bound for large networks — define and document a cap (e.g. paginate beyond 50 sites) so this doesn't become an unbounded per-request loop over `switch_to_blog()` for every site in a large network.

**Edge cases:** A site where AI is disabled site-wide via `wp_supports_ai` (existing honesty-banner condition) — the rollup row should reflect "AI disabled" rather than reporting a misleadingly empty/zero denial count as if governance were simply quiet.

**Error/empty states:** Zero sites have the plugin active → page shows an empty state explaining none are active yet, not a blank table.

**Permissions/security:** Requires network-admin capability, distinct from and in addition to the existing per-site `manage_options` gate — a per-site admin without network-admin rights must not see this page or other sites' data. Cross-site reads must use `switch_to_blog()`/`restore_current_blog()` correctly paired to avoid leaking one site's option context into another's request.

**Dependencies:** None new; reads existing per-site `Plugin::OPTION_KEY` and `Plugin::LOG_OPTION_KEY` options via multisite's standard cross-site option access.

**Exclusions:** Any network-level policy enforcement or bulk-apply-rules-to-all-sites action; writing to any site's policy from the network screen; non-multisite installs get nothing changed.

**Release/rollout:** Minor version bump; changelog entry; readme note that multisite network support is new and read-only in this release.
