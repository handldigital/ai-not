# Product Handoff — HandL AI Connector Access Control
Generated: 2026-08-07 · Source: product_scan (first scan, no prior artifacts existed)

All 5 stories below are **proposed**, not yet approved for a sprint. None has been picked up by Developer or Quality. See `research.md` for sourcing/confidence and `backlog.yaml` for prioritized order.

---

## AICAC-101 — CSV export of the retained audit log

**Actor:** Site admin with `manage_options` capability, viewing the Activity tab.

**Desired behavior:** An "Export CSV" button on the Activity (recent-call log) tab downloads the currently retained log rows (respecting any active filters) as a CSV file.

**Value:** The ring buffer has no TTL and a hard entry cap (20–1000, default 200) — once full, old rows are silently overwritten. CSV export lets an admin retain evidence for compliance/incident review outside the buffer's lifetime.

**Preconditions:** Logging or learn mode has been on for at least one entry to exist in the log; user has `manage_options`.

**Acceptance criteria:**
- AC1: Given at least one retained log row, when the admin clicks "Export CSV" on the Activity tab, a `.csv` file downloads containing every column currently rendered in the log table (timestamp, decision, plugin, operation, capability family, provider, model, token counts, est-$, prompt preview truncation as already governed by existing display logic).
- AC2: Given active log filters (plugin, decision, date range, etc. — whatever filters `render_log_filters` supports today), the exported CSV contains only the filtered rows, matching what is on-screen.
- AC3: Given zero retained log rows, the Export CSV control is disabled or hidden, with a visible reason ("no log entries yet").
- AC4: The CSV's first row is a header row naming each column.
- AC5: Fields containing commas, quotes, or newlines (e.g., prompt preview) are RFC 4180-quoted/escaped so the file opens correctly in Excel and Google Sheets.
- AC6: Export request is a `POST` behind the same nonce/capability check pattern already used for other admin-post actions in `class-handl-aicac-admin.php` (e.g. `handle_save_rules`).

**Edge cases:**
- Direct-HTTP shadow-AI rows (`channel=direct_http`, decision=`observe`) export with their host/path fields; AI Client rows export with their own field set — do not fabricate blank vs N/A inconsistently, follow whatever the existing table already renders per row type.
- Log rows collapsed via the chatty-host `count` mechanism export as one row with the aggregate `count`, not expanded per underlying call (matches on-screen behavior).

**Error/empty states:** No log entries → disabled control with inline explanation (AC3). Export triggered without `manage_options` or a valid nonce → standard WP `wp_die` / permission failure, no partial file.

**Permissions/security:** Requires `manage_options` (same as rest of admin page). Nonce-verified POST. No new capability introduced. Export must not include any field this plugin does not already display in wp-admin (do not widen the data surface beyond what's already retained/rendered).

**Analytics/telemetry:** None required — this plugin does not phone home; do not add any external telemetry call as part of this story.

**Dependencies:** None — reads from the existing `Plugin::LOG_OPTION_KEY` option and existing filter-parsing (`parse_log_filters`).

**Exclusions (out of scope this story):** Scheduled/automatic recurring export; export formats other than CSV; exporting policy/rules config (see AICAC-102); increasing the ring buffer size or adding TTL controls.

**Release/rollout:** Standard minor version bump; changelog entry; no migration needed (read-only feature, no new option schema).

---

## AICAC-102 — Export and import policy/rules configuration as JSON

**Actor:** Site admin or agency developer managing rules across multiple sites/environments.

**Desired behavior:** A "Download rules (JSON)" action on the Rules tab exports the current policy option (`Plugin::OPTION_KEY`) as a downloadable JSON file. An "Import rules (JSON)" action lets the admin upload a previously exported file, preview a diff/summary of what will change, and confirm before it overwrites the live policy.

**Value:** Lets an agency configure once and roll the same governance rules to staging, production, or sibling client sites without re-clicking through the Rules tab per site — reduces configuration drift and setup time.

**Preconditions:** User has `manage_options`. For import: uploaded file is valid JSON matching this plugin's exported schema and version.

**Acceptance criteria:**
- AC1: Given the admin clicks "Download rules (JSON)" on the Rules tab, a file downloads containing the full current policy option, plus a `plugin_version` and `exported_at` field for forward compatibility checks.
- AC2: Given the admin uploads a valid exported JSON file on the Import screen, the admin sees a preview listing which per-plugin rules, capability-family settings, kill-switch state, denied-tools list, and model-force pins will change, added, or be removed — before any write happens.
- AC3: Given the admin confirms the import, the policy option is atomically replaced (or merged, per whichever behavior is chosen — default to full replace, documented in the UI) and the admin sees a success notice with a link back to Rules.
- AC4: Given an uploaded file that is not valid JSON, or is valid JSON but missing required top-level keys, the import is rejected with a specific error message (not a silent no-op or fatal error) and the live policy is left unchanged.
- AC5: Given an uploaded file exported from a newer plugin version with fields this version doesn't recognize, unknown fields are ignored (not fatally rejected) and the admin is shown a notice listing which fields were ignored.
- AC6: Import does not import secrets or credentials (this plugin doesn't store any provider API keys, so nothing to exclude here — confirm no such field exists before shipping; if one is ever added later, it must be excluded from export).

**Edge cases:** Importing a file exported from the EXPERIMENTAL model-force feature when model-force is off on the target site — imported pins are stored but inert (respecting existing "empty force fields = off" convention), not silently dropped.

**Error/empty states:** Empty file upload → validation error, no write. Import of an empty ruleset (valid but zero rules) is allowed if the admin explicitly confirms (this is a legitimate "reset to defaults" path) — but must show the preview making that scope obvious (AC2).

**Permissions/security:** `manage_options` required for both export and import. Import is a privileged write path — must use nonce verification and must not accept arbitrary file paths (upload only, no server-side path input). File size capped (define a sane limit, e.g. 1MB, given policy option is small JSON).

**Analytics/telemetry:** None — no phone-home.

**Dependencies:** None new; reads/writes `Plugin::OPTION_KEY` through the same validated write path `handle_save_rules` already uses (reuse existing sanitization, do not bypass it for the import path).

**Exclusions:** No scheduled/automatic sync between sites; no multi-site "push to all sites" button (that's AICAC-105's territory and is out of scope here); does not export the audit log (see AICAC-101).

**Release/rollout:** Minor version bump; changelog entry documenting the JSON schema/version field for forward compatibility.

---

## AICAC-103 — WP-CLI command to list and set per-plugin allow/deny rules

**Actor:** Agency developer or DevOps engineer provisioning a site via a deploy script.

**Desired behavior:** Two new WP-CLI commands: `wp aicac rule list` (prints current per-plugin/family rules as a table or JSON) and `wp aicac rule set <plugin-basename> <family> <allow|deny|inherit>` (sets a single rule and persists it through the existing validated write path).

**Value:** Lets teams provision AI governance rules as part of a scripted deploy (e.g. WP-CLI in a CI pipeline or provisioning script) instead of requiring manual wp-admin clicks per site — directly serves the same agency/multi-site persona as AICAC-102 but for automation rather than GUI-driven promotion.

**Preconditions:** WP-CLI is available in the hosting environment (not guaranteed — many shared hosts don't provide SSH/WP-CLI; this is an assumption to validate, see research.md). Plugin is active.

**Acceptance criteria:**
- AC1: Given the plugin is active, `wp aicac rule list` prints every plugin currently known to the policy (from the plugins list used by the Rules tab) with its current family-level allow/deny/inherit state, in a table by default and `--format=json` when requested.
- AC2: Given `wp aicac rule set acme-plugin text deny`, the command validates `acme-plugin` is a recognized plugin basename and `text` is a recognized capability family, writes the rule through the same sanitize/validate function `handle_save_rules` uses (not a parallel/duplicate write path), and exits 0 with a confirmation line.
- AC3: Given an unrecognized plugin basename or capability family, the command exits non-zero with a clear error identifying which argument was invalid, and does not write anything.
- AC4: Given `wp aicac rule set` with a missing required argument, WP-CLI's standard usage/help output is shown (exit non-zero), no write occurs.
- AC5: Commands are read (`list`) or single-field write (`set`) only in this story — no bulk-import command (that overlaps AICAC-102's JSON import and should reuse it later, not duplicate it now).

**Edge cases:** Setting a rule for a plugin that exists in the option data but is no longer installed/active (already-configured-then-deactivated plugin) — command should still allow listing/setting it, consistent with how the Rules tab already handles inactive plugins with prior rules (verify current admin behavior and match it, do not diverge).

**Error/empty states:** No plugins detected at all (fresh install, nothing else installed) → `list` prints an empty table/`[]`, not an error.

**Permissions/security:** WP-CLI commands run with filesystem/shell access already equivalent to admin — no additional WP capability gate needed beyond what WP-CLI itself implies, consistent with how other WP-CLI commands in the ecosystem behave. Must reuse the existing validated sanitize path so CLI-set rules cannot bypass constraints the UI enforces (e.g. valid family names only).

**Analytics/telemetry:** None.

**Dependencies:** Requires `WP_CLI` class to be present (standard WP-CLI bootstrap check, `if ( defined( 'WP_CLI' ) && WP_CLI )`); reuses existing policy read/write functions in `class-handl-aicac-policy.php` — do not fork new logic.

**Exclusions:** No CLI commands for kill-switch, model-force, denied-tools, or alert settings in this story — scope is the core per-plugin×family allow/deny matrix only, the highest-value/most-used rule type. Broader CLI coverage is a candidate for a future story if this one validates demand.

**Release/rollout:** Minor version bump; changelog entry; document the two commands in `readme.txt`.

---

## AICAC-104 — Outgoing webhook channel for denial alerts (Slack/Teams-compatible)

**Actor:** Site admin or security team who already monitors Slack/Teams for operational alerts (not just email inbox).

**Desired behavior:** A new "Webhook URL" field alongside the existing denial-alert email settings (Settings/Rules tab). When set, denial alerts that would trigger an email (immediate rate-limited, respecting existing rate-limit logic) also POST a JSON payload to the configured webhook URL, using the same trigger conditions and content scope as the existing email alert (no prompt text, no user identity, per current privacy posture).

**Value:** Routes denial signals into chat-ops tooling teams already watch in real time, alongside the existing `wp_mail`-only channel, closing the gap between "governance event happened" and "someone on the team notices."

**Preconditions:** Denial alerts (`alert_on_deny`) must be enabled — webhook rides the same trigger path as email, it is not a separate always-on channel. User has `manage_options`.

**Acceptance criteria:**
- AC1: Given a webhook URL is configured and denial alerts are on, when a prompt is denied and the existing rate-limit logic permits an alert, a POST is sent to the webhook URL with a JSON body containing the same fields the email alert already includes (timestamp, calling plugin, operation, capability family, denial reason, matched tools, provider/model if known, path only — no prompt preview, no user identity), matching the documented Privacy/Data scope for alert mail.
- AC2: Given no webhook URL is configured, no webhook POST is attempted — only the existing email path runs, unchanged.
- AC3: Given the webhook endpoint returns a non-2xx response or times out, the failure is logged/surfaced the same way `wp_mail` failures are already contained today (does not throw, does not block or fail-close the AI Client denial itself — governance decision and notification delivery remain independent).
- AC4: Webhook delivery uses the same deferred-to-shutdown dispatch pattern the email alert already uses, so it cannot add latency to the blocked AI Client call.
- AC5: A "Send test webhook" button on the settings screen sends a sample payload immediately (bypassing rate limiting, clearly labeled as a test) so the admin can verify the URL before relying on it.
- AC6: The webhook URL field validates as a URL (`http`/`https` only) before saving; invalid values are rejected with an inline error, not silently stored.

**Edge cases:** Digest mode (hourly digest) — decide and document whether webhook mirrors immediate-only or also fires on digest; default to mirroring whatever mode is configured for email (same on/off state, not a separate toggle), since users configuring "immediate" vs "digest" expect both channels to follow it.

**Error/empty states:** Webhook URL field empty → feature inert (AC2). Malformed URL → validation error on save (AC6).

**Permissions/security:** `manage_options` required to view/edit the URL. The URL itself is a potential SSRF-adjacent value (server-side POST to an admin-supplied URL) — validate scheme is `http`/`https`, and note in code/comments that this is an intentional admin-supplied outbound integration (same trust model as `wp_mail` recipient, which is already admin-configurable). Do not follow redirects blindly if avoidable; use WP's `wp_remote_post` which has WordPress's standard HTTP API protections.

**Analytics/telemetry:** None beyond the payload itself, which is the feature.

**Dependencies:** Reuses the existing denial-alert trigger/rate-limit logic in `class-handl-aicac-alerts.php` — this is an additional delivery channel on the same trigger, not a new trigger.

**Exclusions:** No webhook for the weekly report email in this story (could be a follow-up once this pattern is validated); no per-webhook custom payload templating (Slack-specific `blocks` formatting, etc.) — ship a generic JSON payload first, formatting-specific adapters are future scope if requested.

**Release/rollout:** Minor version bump; Privacy/Data section of `readme.txt` updated to document the new opt-in egress channel (mirrors how F3/F7 documented their own exit surfaces).

---

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

**Analytics/telemetry:** None.

**Dependencies:** None new; reads existing per-site `Plugin::OPTION_KEY` and `Plugin::LOG_OPTION_KEY` options via multisite's standard cross-site option access.

**Exclusions (explicitly out of scope this story):** Any network-level policy enforcement or bulk-apply-rules-to-all-sites action (that would be a much larger, higher-risk story combining this with AICAC-102's import — do not build it here); writing to any site's policy from the network screen; non-multisite installs get nothing changed.

**Release/rollout:** Minor version bump; changelog entry; readme note that multisite network support is new and read-only in this release, so expectations aren't oversold.

---

## Cross-cutting notes for Developer

- Every story above must reuse existing validated read/write paths (`class-handl-aicac-policy.php`, `handle_save_rules`, alert dispatch in `class-handl-aicac-alerts.php`) rather than introducing parallel logic — this plugin already has a strong pattern of "fail closed, reuse the one validated path" (see F1–F7 changelog) and these stories should follow it.
- None of these stories should widen what data leaves the site beyond what is explicitly stated in each story's Privacy/Data note. Any new egress (webhook, CSV, export) must get a corresponding `readme.txt` Privacy/Data update, matching how F3/F6/F7 documented their own exit surfaces.
- No story here has been validated with real customer feedback (no issue tracker was accessible from this workspace) — treat priority order as this agent's proposal, not a committed roadmap, until a human or PR discussion confirms demand.

## Required tests (for Quality and Release Gate, all stories)

- Unit/integration coverage for each new read/write path (WP-CLI command, export/import round-trip, webhook dispatch, CSV generation, network rollup query) mirroring the existing test conventions in this codebase (check for a `tests/` directory or PHPUnit setup before assuming one exists — none was found in this scan; Quality should confirm current test tooling before implementation starts).
- Manual verification in a real multisite install for AICAC-105 (cannot be meaningfully verified on a single-site dev environment).
- Manual verification of CSV file opening cleanly in Excel/Google Sheets for AICAC-101 (RFC 4180 edge cases: commas, quotes, newlines in prompt-preview fields).

## Open questions (escalate to human owner before implementation)

1. Is there a maintained issue tracker/roadmap outside this repo (e.g. private board) that already covers or conflicts with these 5 proposals? This scan had no access to one.
2. Does the plugin have any automated test suite today? None was found in this repository snapshot — Quality and Release Gate should confirm before committing to "required tests" above.
3. Priority order (101→105) is this agent's judgment based on effort/risk-reduction only, not validated customer demand — confirm before sprint planning.

---

STATUS: READY
WORK_ITEM: AICAC-101, AICAC-102, AICAC-103, AICAC-104, AICAC-105
COMPLETED: First product scan of handl-ai-connector-access-control (no prior artifacts existed). Reviewed plugin code (includes/*.php), readme.txt changelog (F1–F7), and git history to identify delivered scope and confirm (via grep, zero matches) that CSV export, policy import/export, WP-CLI, multisite awareness, and webhook alerting do not currently exist. Authored research.md, backlog.yaml, and this product-handoff.md with 5 fully specified stories meeting the User Story Standard.
EVIDENCE: research.md (sourcing/confidence); backlog.yaml (prioritized list); grep across includes/*.php for is_multisite, WP_CLI, export/import, csv, webhook — zero matches confirming gaps; readme.txt changelog F1.0.6–1.0.14 confirming delivered feature set; git log --all --oneline confirming F1–F7 build order.
DECISIONS: Proposed 5 stories prioritized by risk-reduction/value vs effort, not by validated customer demand (none available in this workspace). Scoped AICAC-105 as read-only-only to avoid the much larger blast radius of network-level policy writes. Scoped AICAC-103 (WP-CLI) to the core allow/deny matrix only, not full settings coverage, to keep it independently testable.
RISKS: No access to an external issue tracker or customer feedback channel to validate real demand for any of these 5 stories — flagged as an open question. No confirmed test suite in the repo — Quality should verify tooling before Developer starts. AICAC-104 (webhook) introduces an admin-configurable outbound HTTP call; SSRF-adjacent risk is called out explicitly in its Permissions/security section and must be reviewed by Quality/Security before merge.
NEXT_ACTION: Human owner reviews the 5 proposed stories and priority order, confirms or corrects against any external roadmap/issue tracker, and approves stories to enter a sprint.
NEXT_OWNER: HUMAN
