=== HandL AI Connector Access Control ===
Contributors: haktansuren
Tags: ai, governance, security, handl, ai client
Requires at least: 7.0
Tested up to: 7.0
Requires PHP: 7.4
Stable tag: 1.3.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

See which WordPress plugins use AI. Control access. Track estimated spend before it becomes a surprise.


== Description ==

Know when your WordPress plugins use AI.

See activity. Control access. Track estimated spend.

= Avoid surprise AI bills =

* See estimated spend by plugin.
* Add your own provider rates.
* Estimates are not bills.
* This plugin does not sell AI usage or add AI charges.
* Your AI provider controls actual billing.

= What it does =

* Shows which plugin made each AI Client request.
* Shows whether each request was allowed or blocked.
* Shows the AI task, provider, model, tokens, and estimated spend.
* Lets you allow or deny each plugin.
* Lets you control text, image, speech, and video separately.
* Includes Learn mode so you can watch first.
* Includes Emergency stop for urgent shutdowns.

= Who it is for =

* WordPress site owners.
* WordPress administrators.
* Multisite teams that manage rules one site at a time.

No developer experience is required.

= How it works =

1. Install the plugin.
2. Open Settings → HandL AI Connector Access Control.
3. Turn on Learn mode.
4. Review Activity.
5. Add rules after you know which plugins need AI.

= Everyday controls =

* **Plugin rules:** Allow, deny, or use the site default.
* **Temporary allow:** Optional expiry on Allow rules (auto-reverts to the site default).
* **AI type rules:** Control text, image, speech, and video separately.
* **Learn mode:** Record activity without enforcing deny rules.
* **Emergency stop:** Block AI Client calls across the site.
* **Blocked AI tools:** Stop prompts that offer blocked tools.
* **Role gate:** Choose which WordPress roles may start AI operations.

= More controls =

* **Denial alerts:** Get an optional email when a request is blocked.
* **Weekly report:** Review activity, denials, and estimated spend by email.
* **Estimated spend:** Use token counts and your provider rates.
* **Plugin AI profile:** Open a plugin from Activity or Dashboard estimated spend to see its usage, incidents, estimated spend alerts, and current rules in one read-only view. Rule changes and CSV exports stay on their existing screens.
* **Rules transfer:** Export or import rules as JSON.
* **Activity limits:** Control how many entries are saved and for how long.
* **Audit report:** Print a governance summary (rules + activity) as PDF from your browser.
* **Multisite overview:** View status and activity for each site.
* **WP-CLI:** List and update AI type rules from the command line.

= Important limits =

* AI Client calls are allowed by default until you change a rule.
* This plugin governs calls made through the WordPress AI Client.
* Version 1.2.0 can observe some direct AI connections. It does not block them.
* The known-provider list is not complete.
* Caller identification is best effort.
* Experimental model force is not a spending guarantee.
* Activity may be empty when WordPress disables AI site-wide.

= Privacy =

* Activity stays on your WordPress site by default.
* Logging, denial alerts, and webhooks are optional.
* The weekly report is selected by default.
* It sends only while logging or Learn mode is on.

See Privacy / Data below for every stored or transmitted field.

== Privacy / Data ==

By default, this plugin does not send data to HandL Digital. Features that send data outside your site are optional and require an explicit setting or onboarding choice. The weekly report uses your site’s configured email system and runs only while logging or Learn mode is on.

If you enable **recent-call logging** in Settings → HandL AI Connector Access Control, it stores a local log in the WordPress options table containing:

- Timestamp
- Allow/deny decision (AI Client rows) or observe (direct-HTTP AI observations)
- AI Client operation (e.g. `generate_text`, `is_supported_for_text_generation`) — or `direct_http` for shadow observations
- Capability family (text / image / speech / tts / video / unknown) for AI Client rows
- Provider and model when set on the prompt builder (or model preferences)
- In learn mode: whether a configured model pin matched, and the provider/model you pinned
- Truncated prompt preview and selected generation config (best-effort; AI Client rows only)
- Input and output token counts when the AI Client completes a generation (best-effort)
- Best-effort calling plugin (plugin basename) and source file
- Current user id and display name
- Initiating WordPress role slug(s) when a user context exists (role gate / audit; no usernames beyond display name already listed)
- Full request URI (including query string, kept only on this site) for AI Client admin-request context
- For **direct-HTTP AI observations** only: request **host** and **path** (query string stripped). No request body, no Authorization headers, no API keys. Channel label `direct_http` and matched provider id when known.

Logs are kept as a **single shared entry-based ring buffer** (default 200 entries, configurable 20–1000) for both AI Client rows and direct-HTTP AI observations. An optional **maximum log age (days)** setting also drops rows older than the threshold on the next read or append; when both the count cap and the time-based TTL apply, the stricter limit wins. Leave maximum age empty for entry-count-only retention. Repeated direct-HTTP **calls** from the same attributed plugin + host (or the same unattributed file + host) that stay active within ~5 minutes of idle time are collapsed into one row whose `count` is the number of HTTP **calls** (same unit as AI Client rows). Active clusters move to the newest slot so a chatty bypass does not erase the rest of the log, and the log does not drop the chatty cluster ahead of idle rows.


If you set an **estimated spend alert** threshold (Activity → Estimated spend alerts), the plugin may send a message via WordPress `wp_mail` when the retained log’s estimated total first crosses that amount (site-wide or per-plugin). The email includes the threshold, current estimated total, dated log window, and (for per-plugin alerts) the plugin name. It states that the figure is estimated (token × rate placeholder), not billing. No prompt text or user identity is included. Empty thresholds never send mail. Delivery failures are contained and never change allow/deny.

If you enable **denial email alerts**, the plugin sends a message via WordPress `wp_mail` when enforcement blocks a prompt (immediate rate-limited mail, or an hourly digest). The recipient is the address you configure, or the site `admin_email` if left empty — that may be any address you enter, and mail is delivered through whatever transport your site uses (core PHP mail or an SMTP / transactional-mail plugin). Alert messages include:

- Timestamp
- Calling plugin (best-effort basename)
- AI Client operation and capability family
- Denial reason and any matched blocked tools
- Provider and model when known (may be labeled inferred)
- Request path only (query string is stripped before mail; full URI stays in the local log if logging is enabled)

Alert mail does **not** include prompt preview or user identity. Digest rows waiting to send are stored in a local options queue (path-only URI) and are removed when alerts are turned off or the plugin is uninstalled.

If you enable **shadow-AI email alerts** (Activity tab; off by default), the plugin sends a message via WordPress `wp_mail` the first time a given attributed plugin+host (or unattributed file+host) pair appears as a `direct_http` observe row in the retained log window — immediate rate-limited mail, or the same hourly digest queue, using the same recipient and mode as denial alerts. Messages are explicitly labeled **observe / not blocked** and include:

- Timestamp
- Best-effort calling plugin, file, or method
- Request host
- Path only (query string stripped — same redaction as denial alerts)

Shadow-AI alerts do **not** block HTTP and are **not** posted to the webhook. They require logging or learn mode, and are suppressed when AI is disabled site-wide via `wp_supports_ai`. Chatty-cluster collapse (~5 minutes idle) and the retained-window pair check prevent duplicate alerts for the same pair.

If you also set a **Webhook URL** (Activity → denial alert settings), the plugin POSTs a generic JSON body with the **same fields** as the denial email alert to that http(s) URL whenever a denial alert would fire (same `alert_on_deny` gate, rate limit, and immediate/digest mode — not a separate toggle). Delivery uses WordPress `wp_remote_post` (timeouts/non-2xx are contained like `wp_mail` failures and never change allow/deny). The URL is an intentional admin-supplied outbound integration (same trust model as the alert recipient). Empty URL means no webhook POST is attempted. A **Send test webhook** control posts a sample payload clearly labeled as a test (bypasses rate limiting). Weekly report email and shadow-AI observe alerts are **not** sent to the webhook in this release.

If you enable the **weekly report email** (Activity tab), the plugin sends one message per week via WordPress `wp_mail` with Dashboard-style **aggregates** from the retained local log. This is the first surface where retained log data can leave the WordPress site (through your site’s mail transport into an inbox). The weekly report includes only:

- Dated window from the oldest and newest retained log timestamps (self-dating so a late WP-cron send stays honest)
- Coverage call counts (through the AI Client vs outside — not governed by these rules)
- Deny count in the retained window; default policy and learn-mode / kill-switch state labels
- Estimated spend total and top plugins by estimated $ (token × rate placeholders — not billing)
- Pin-hold counts when experimental force rules are configured
- Plugin display names (or basenames) for top estimated-spend rows

Weekly report mail does **not** include prompt preview, user identity, request paths, hosts, denial reason detail rows, or any per-call URI. Recipient is the same address as denial alerts (or site `admin_email` if empty). Every email includes a link to turn the report off. The weekly cron is cleared when the report is disabled, logging is off, or the plugin is uninstalled.

During first-run setup, you can optionally agree to receive product news and related offers from HandL Digital. The checkbox is off by default. If you agree and finish setup, the plugin sends your alert email address, site URL, plugin version, and consent time to HandL Digital. HandL Digital stores this information on its server for those emails. If you leave the box unchecked, the plugin sends nothing to HandL Digital for this purpose. You can unsubscribe at any time by emailing support@handldigital.com. This registration is separate from denial alerts, webhooks, and the weekly report.

== Installation ==

1. Upload the plugin folder to `/wp-content/plugins/handl-ai-connector-access-control/`
2. Activate the plugin through the Plugins screen in WordPress
3. Go to Settings → HandL AI Connector Access Control to configure plugin rules

== Frequently Asked Questions ==

= How is this different from the WordPress AI plugin’s Connector Approvals? =
Connector Approvals in the WordPress AI plugin controls which plugins and themes can use configured AI connector credentials. HandL AI Connector Access Control governs AI Client prompts through `wp_ai_client_prevent_prompt`, adding per-plugin allow/deny rules, a **capability-family matrix**, **tool-arming denial**, **shadow-AI detection** for direct connections outside the AI Client, and **estimated spend / denial alerting**. Both can run together because they govern different layers. See Dashboard → “Beyond Connector Approvals”.

= Does this stop all AI usage? =
Only AI calls made through the WordPress AI Client APIs that pass through `wp_ai_client_prevent_prompt`. The shadow-AI detector can **observe** direct HTTP to known AI hosts (when logging or Learn mode is on) and, if you enable **Block direct calls to known AI providers**, can **block** those requests with optional per-plugin exceptions. AI Client traffic is never treated as shadow traffic.

= What does “outside the AI Client” mean on Audit & log? =
A plugin (or other PHP code) issued a WordPress HTTP request to a known AI provider host without going through the AI Client path this plugin gates. With blocking off, those rows are labeled observe. With **Block direct calls to known AI providers** on, they may be denied or allowed as an exception. Plugin Allow/Deny rules still apply only to AI Client traffic.

= Is attribution perfect? =
No. It is best-effort and may be unknown or ambiguous for some execution paths (cron, REST bootstraps, shared libraries, MU plugins). Experimental model force uses the same attribution: a pin follows the **detected** caller, not a guarantee of which product “owns” the spend.

= Does experimental model force guarantee cost control per plugin? =
No. It pins the route for calls we attribute to that plugin’s nearest stack frame. Unattributed calls are unforced by default (configurable). Misattribution can apply another plugin’s pin without failing closed — existence of a resolved plugin is not proof it is the right one.

= Can I manage rules with WP-CLI? =
Yes. With WP-CLI available and this plugin active:

`wp aicac rule list` — table of every installed plugin (active and inactive) with family-level allow/deny/inherit state. Use `--format=json` for machine-readable output.

`wp aicac rule set <plugin-basename> <family> <allow|deny|inherit>` — set one capability-family cell (text, image, speech, tts, video). Writes through the same sanitized policy path as the Rules tab. Plugin basename must match an installed plugin file (e.g. `acme-plugin/acme-plugin.php`), including inactive plugins.

== Screenshots ==

1. Dashboard — coverage of known AI activity (through the AI Client vs outside), safety, estimated spend, and block-that-one.
2. Activity — Outside AI Client / shadow lane observe rows alongside governed AI Client traffic.
3. Insights — entry vs call units and usage breakdowns from the retained log.
4. Rules — kill-switch Exceptions as a scrollable checkbox list (still follows normal allow/deny rules).
5. Activity — OBSERVE direct_http rows contrasted with governed AI Client decisions.

== Changelog ==

= Unreleased =
* Create a rule from an Activity call: open the Rules form pre-filled with that plugin, AI type, and provider/model. Already-covered plugins show a status instead of adding a second rule.
* Added a read-only **Plugin AI profile**. Click a plugin in Activity or Dashboard estimated spend to see usage by day, operation, and model; blocked calls; direct connections outside the AI Client; estimated spend alerts; and the rules that currently apply. Rule results use the same decision process as enforcement. Links open the existing Rules and CSV export screens.
* Added an optional, unchecked onboarding choice to receive product news and related offers from HandL Digital. If selected, the plugin sends the alert email address, site URL, plugin version, and consent time to HandL Digital. Privacy / Data documents the transmission and opt-out method.
* Compare a previous JSON rules export with your current policy on the Rules tab. See every setting that differs before you import. Unknown fields from a newer export are listed as not comparable. Nothing is changed until you use Import.

= 1.3.0 =
* Insights: weekly call and estimated-spend trends (last 8 weeks) with per-plugin sparklines and week-over-week change. Weeks with no retained log data show as “no data kept,” not zero.
* Optional monthly email of the printable audit report, off by default. It sends a short summary and HTML attachment starting on the first of each month. If no activity was retained, it sends a no-activity note without an attachment.
* Restore a previous policy from the Rules tab. The plugin keeps the last 5 versions of your rules and settings, and shows what will change before you restore.
* Scan active plugins for possible embedded AI API keys. Possible findings appear on the Dashboard and in Site Health. The Dashboard shows only the last 4 characters, and full keys are never stored.

= 1.2.2 =
* Temporary Allow rules that expire on their own, with remaining/expired status and one-click renew for 7 days.
* Policy presets on the Rules tab, with a preview of every setting that will change before you apply.
* WordPress Dashboard widget for mode, Emergency stop, last-24-hour activity and estimated spend, plus a Review policy link.
* Printable audit report with current rules, activity, and estimated spend compared with alert thresholds. Save it as a PDF from your browser. Nothing leaves the site.
* Estimated month-end spend on the Dashboard and Insights after at least three days of logged activity, with a Dashboard warning and optional monthly email if the projection crosses an alert threshold.
* Dashboard and Site Health visibility when alert emails or webhooks fail repeatedly, with buttons that send tests through the existing email and webhook paths.
* One-time What’s new notice after each update, with a short in-plugin highlights panel.

= 1.2.1 =
* Added a first-run setup wizard. Watch activity, set up alerts, and send a test email.
* Added a policy simulator. Preview how unsaved rules would handle a sample AI call.
* Added read-only REST API endpoints for policy, activity summaries, and Site Health.
* Added optional blocking for direct calls to known AI providers. It is off by default.
* Added optional usage spike alerts. They compare today's call volume and estimated spend with the recent daily average.
* Added optional estimated-spend alerts for site-wide and per-plugin thresholds.
* Added optional email alerts for direct AI provider connections. Choose immediate alerts or an hourly summary.
* Added test email buttons for blocked-call alerts and weekly reports.
* Added CSV exports for the activity log and rules.
* Added a Site Health check for AI access control.
* Improved bulk-action and Emergency stop warnings.
* Added clear guidance about how HandL differs from Connector Approvals in WordPress AI.
* Rewrote the WordPress.org description with shorter sentences and clearer estimated-spend language. Estimates are not bills.
* Strengthened permission and security checks for admin actions.
* Fixed plus-addressed emails such as user+tag@example.com in test-email confirmations.

= 1.2.0 =
* Rewrote the WordPress.org listing in plain language so site owners can quickly understand what the plugin does.
* Rewrote admin screens and emails in clearer, shorter language.
* Added optional rates for each AI provider when calculating estimated spend. Estimates are not bills.
* Added an optional maximum age for Activity entries, alongside the entry limit.
* Select multiple plugins on the Rules tab and set them to Allow or Deny together.
* Limit AI Client access by WordPress role. Off by default, so every role is allowed.
* On multisite, view sites where the plugin is active, check their status, and open each site's Activity screen. View only; no network-wide rule changes.
* Send optional blocked-call alerts to a webhook. The payload follows the same privacy limits as email alerts, and you can send a test.
* Use WP-CLI to list and set per-plugin AI type rules.
* Export and import Rules as JSON with a preview and confirmation. The Activity log is not included.


= 1.0.14 =
* F7: Weekly report email — Dashboard aggregates via wp_mail on a weekly cron (coverage, denials, estimated spend, pins).
* Aggregates only: no prompt text, user names, or request paths leave the site in the report.
* Selected by default; reports sent only while logging or learn mode is on; Settings toggle + footer link in every email.
* Self-dating window from retained log timestamps (WP-cron lateness acceptable for a summary).
* Privacy / Data documents the weekly report exit surface (ships with this feature).
* Screenshot captions updated for the current Dashboard / Activity / Insights / Exceptions UI.
* A11y: aria-describedby on kill-switch Exceptions group (#16).

= 1.0.13 =
* Rules: kill-switch Exceptions is a scrollable checkbox list (no Cmd/Ctrl multi-select). Name and plugin path on separate lines.
* Exceptions are dimmed while the kill switch is off, with a note. Exception selections still save if kill is off.
* Copy diet: label “Exceptions”; one line — excepted plugins still follow normal allow/deny and capability-family rules.

= 1.0.12 =
* F5: Dashboard-first admin (Dashboard / Rules / Activity / Insights). Coverage tile measures known AI activity (through AI Client vs outside — not governed by these rules) with log window, span, and saturation notice.
* F5: Pin-hold tile (X of Y attempted forces) plus separate unattributed never-evaluated count; learn-mode pin_matched observation (not would-succeed).
* F5: Block-that-one from Dashboard (single-click deny + undo). Shadow callers listed as not governable.
* F5: Settings demoted under Rules collapsible panel. Cleanup: unforced count branch, has_any_force_rules bool check. F6 known limits: first-of-N on user, keep observation ts on flush, _n for first-of-N.


= 1.0.11 =
* Shadow-AI detector (observe only): log plugins that call known AI provider hosts over WordPress HTTP while bypassing the AI Client.
* Curated host list (OpenAI, Anthropic, Google Generative Language, Cohere, Mistral, Groq, Together, Fireworks, Perplexity, xAI, DeepSeek, OpenRouter, …); not a complete inventory.
* Excludes core AI Client / php-ai-client stack traffic (those paths already hit `wp_ai_client_prevent_prompt`).
* Retained rows: `channel=direct_http`, host, path-only (no query), shadow provider id, decision `observe` — no body, no Authorization headers.
* STORAGE: direct_http rows share the same ring buffer as AI Client rows (one window so coverage buckets can sum).
* Chatty-host collapse: same attributed plugin+host (or unattributed file+host) with ~5 min idle timeout adds incoming call tallies into one row; active clusters move to the tail; first file/caller/path kept; `count` = HTTP **calls** (not page loads) via in-request tally + shutdown flush.
* Same log gate as other observability (log_enabled or learn mode).
* Audit filter “Outside AI Client”; Insights one-line sum of call counts only (does not invent a second coverage %; sums collapsed `count`s).
* Privacy / Data section documents host + path-only retention for direct-HTTP observations (ships with the PR that starts retaining the field).
* Lisa gate-1 follow-up: count unit = calls; collapse moves to tail; unattributed keys include file; first observation fields retained.

= 1.0.10 =
* EXPERIMENTAL: per-plugin force of AI Client generations to a provider/model (Rules table columns; empty = off; labeled EXPERIMENTAL in the UI).
* Unattributed calls: explicit control (default don’t force; optional force to an admin-picked provider/model — not a site-wide pin for attributed plugins).
* Pins follow detected caller (best-effort nearest plugin frame) — not a spend guarantee; readme/UI state the bound.
* Unforced-count surface from retained audit rows when pins exist and callers resolve unknown.
* Guardrails: clone-compat cheap pre-check (not the safety); final-route verification with exact provider matching (no substring); fail-closed (throw → WP_Error) on mismatch; health option writes only on status transition; persistent admin health warning when unhealthy; does not change allow/deny.
* Uninstall removes model-force health option.
* Does not send data off-site (force is local routing preference only).

= 1.0.9 =
* Denial email alerts (opt-in): immediate rate-limited mail or hourly digest via wp_mail; attributed to HandL AICAC.
* Privacy section documents what alerts transmit, that they are opt-in/off by default, and that mail uses the site's transport.
* Alert mail uses path-only URI (query string stripped); full URI remains local-log only.
* wp_mail failures are contained (throwing SMTP replacements cannot fatal a denied AI call).
* Alert send deferred to shutdown so the AI Client denial filter path does not block on SMTP (connection release is not claimed — FastCGI typically holds until shutdown completes).
* Immediate-mode failures and rate-limit overflow drain via the same hourly cron safety net (scheduled whenever alert_on_deny is on, not only in digest mode).
* Digest queue cleared when alerts are disabled; uninstall removes digest queue, rate option, and cron event.
* Digest cron self-heals on init if the scheduled event was lost.
* Honesty banner when AI is disabled site-wide via wp_supports_ai (audit intentionally empty because core short-circuits before our filter).
* Estimated-$ column on the recent-call log from retained token counts × configurable $/1M rates (observability only; labeled est./default rates).
* Inferred provider/model values labeled "inferred" in the audit UI (observability honesty — not enforcement).
* PHP 7.4 nested-POST filter_input path for the operation matrix verified PASS on PHP 7.4.33 cgi.

= 1.0.8 =
* AI tool arming (caller intent): deny prompts that arm denied tools (`functionDeclarations` — WordPress abilities and custom tools) at prevent time.
* Denied tools list on Rules tab; registered abilities shown as a helper subset (not an enumeration of everything matchable).
* Case-insensitive matching; entries that match no currently registered ability are flagged (still saved — pre-listing is allowed).
* Loud denials: log `denial_reason` and `matched_tools` on every denial (including non-tool denials that also armed a blocked tool).
* Snapshot extracts `armed_tools` from model config without reflection.
* Option key `denied_tools` (migrates legacy `denied_abilities` on read).

= 1.0.7 =
* Per-plugin × capability-family operation matrix (Text / Image / Speech / TTS / Video) on the Rules tab.
* `is_supported_for_*` and matching `generate_*` / `convert_text_to_speech*` map to the same family rule.
* Generic `is_supported` / `generate_result` resolve family via core capability inference (no silent unknown bypass).
* TTS prefix heuristics run before Text so unmapped TTS method names cannot misclassify as Text.
* Snapshot is taken before the allow/deny decision so the operation is known at prevent time.
* Explicit unknown-operation fallback (inherit plugin rule, allow, or deny).
* Kill-switch exceptions fall through to normal plugin + family rules (do not widen access).
* Recent-call log records and displays capability family.
* Suggested-rules column renamed to "Plugin-level would enforce" (honest: not full matrix).

= 1.0.6 =
* Recent-call log records input (prompt) and output (completion) token counts via `wp_ai_client_after_generate_result` when logging is enabled.
* Usage insights tab: aggregated call counts and token sums/peaks by plugin, provider, model, and operation from the retained log.
* Learn mode (Activity tab): log every AI Client call without blocking; suggested rules from the log; “would enforce” decision in the audit trail.
* Emergency kill switch: block all AI Client calls with optional per-plugin exceptions.
* Quick actions on the recent-call log: allow or deny a plugin in one click.

= 1.0.5 =
* Added WordPress.org plugin directory banners and screenshots.

= 1.0.4 =
* Enriched recent-call log with provider, model, operation, and truncated prompt preview; improved admin log table and documented count-based retention (no TTL).

= 1.0.3 =
* Added logos + branding

= 1.0.2 =
* Renamed plugin to HandL AI Connector Access Control (slug `handl-ai-connector-access-control`). Prefixed options, constants, menus, and forms per WordPress.org guidelines. Migrates settings from previous plugin slugs when present.

= 1.0.0 =
* Initial release (submitted as AI Not).
