=== HandL AI Connector Access Control ===
Contributors: haktansuren
Tags: ai, governance, security, handl, ai client
Requires at least: 7.0
Tested up to: 7.0
Requires PHP: 7.4
Stable tag: 1.2.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

See AI activity from WordPress plugins, decide what each plugin may do, and block unwanted prompts through the WordPress AI Client.


== Description ==

HandL AI Connector Access Control helps you **see AI activity from WordPress plugins, decide what each plugin may do, and block unwanted prompts sent through the WordPress AI Client.**

The WordPress AI Client is a shared API that plugins can use for AI features. This plugin gives site administrators one place to see and control calls made through that API.

Plugins are **allowed by default** until you change a rule.

= What it does =

* Shows which plugin made an AI Client call, what type of AI task it requested, and whether it was allowed or blocked.
* Lets you set a simple rule for each plugin: **Allow**, **Deny**, or follow the site default.
* Lets you allow one type of AI task while blocking another. For example, a plugin may use text generation but not image generation.
* Includes **Learn mode** so you can watch AI Client activity before you start blocking anything.
* Includes an emergency stop for AI Client calls, with exceptions for plugins you choose.

= Who it is for =

This plugin is for WordPress site owners and administrators who want a clear view of AI activity and simple per-plugin controls. It also supports multisite, but rules are still managed one site at a time.

You do **not** need to be a developer to use the main controls.

= How it works =

1. Install the plugin and open **Settings → HandL AI Connector Access Control**.
2. Turn on **Learn mode** to observe AI Client activity without enforcing deny rules.
3. Review the Dashboard, then set rules for each plugin on the Rules tab.
4. Review the optional logging, alert, and reporting settings. The weekly email option is selected by default, but it sends only while logging or Learn mode is on and can be turned off at any time.

Caller identification is **best-effort**. Calls made through cron, REST requests, shared libraries, or must-use plugins may appear as unknown.

= Everyday controls =

* **Plugin rules:** Allow, deny, or use the site default for each installed plugin. You can also select several plugins and update them together.
* **Capability rules:** Allow or deny Text, Image, Speech, TTS, or Video separately for the same plugin.
* **Learn mode:** Log AI Client activity without enforcing deny rules, so you can watch first and block later.
* **Emergency stop:** Block AI Client calls across the site except for plugins you list as exceptions. Exceptions still follow their normal plugin and capability rules.
* **Direct AI connections:** Optional block of WordPress HTTP calls to known AI provider hosts outside the AI Client (off by default). List plugins that may still call those hosts directly.
* **Blocked AI tools:** Stop a prompt when it tries to use a blocked WordPress ability or custom tool. The activity log shows which tool triggered the block.
* **Role gate:** Optionally limit which WordPress roles may start AI Client operations. Off by default (all roles). When enabled, signed-in users whose role is unchecked are denied through the normal deny path. Cron, WP-CLI, and other no-user requests are not affected.

= More controls when you need them =

* **Estimated spend alerts:** Optional email when estimated spend in the saved log crosses a site-wide or per-plugin dollar threshold (off when empty). Uses the same recipient as denial alerts. Estimates only, not billing.
* **Usage spike alerts:** Optional email when a plugin’s AI Client call volume or estimated spend is much higher than its previous 7-day daily average (off by default). Uses the same recipient and optional webhook as blocked-call alerts. Does not block calls.
* **Denial alerts:** Send an optional email when a prompt is blocked, either immediately or in an hourly digest. You can also send the same privacy-scoped data to a webhook URL for services such as Slack or Teams.
* **Weekly report:** Receive a summary of coverage, denials, estimated spend, and model-pin activity. The option is selected by default, sends only while logging or Learn mode is on, and can be turned off at any time.
* **Estimated spend:** View a rough estimate based on token counts and the rates you provide, including optional rates by provider. This is an estimate, **not billing**.
* **Rules export and import:** Download your rules as JSON or replace the current rules by importing a JSON file. The audit log is not included.
* **Log retention:** Limit the activity history by number of entries and, optionally, by maximum age.
* **Multisite overview:** Network administrators get a read-only list of sites where the plugin is active, with status and activity links for each site. This release does not provide network-wide enforcement or bulk editing.
* **WP-CLI:** List and update capability rules from the command line when WP-CLI is available.

= Honest limits =

* This plugin governs AI calls made through the **WordPress AI Client**. It does not control every possible AI request made by WordPress code.
* The **Shadow-AI detector** records direct WordPress HTTP requests to a curated list of known AI provider hosts when logging or Learn mode is on. Blocking those requests is **off by default**; turn on **Block direct calls to known AI providers** on the Rules tab to short-circuit matched hosts (with optional plugin exceptions). The host list is not complete.
* Caller identification is best-effort and may be wrong or missing.
* **EXPERIMENTAL model force** can steer an allowed call toward a provider and model for the detected caller. It is not a spend guarantee and depends on best-effort caller identification.
* If WordPress has disabled AI across the site, the activity log may be empty. The plugin displays a notice when this happens.

= Advanced details =

For developers and integrators:

* Enforcement uses the WordPress AI Client prevent filter: `wp_ai_client_prevent_prompt`.
* Capability rules apply the same family rule to support checks and matching generation methods. Unknown operations, such as music or embeddings, use a configurable inherit, allow, or deny fallback.
* The optional role gate denies via the normal policy path with reason `role` and records initiating role slug(s) in the audit log when a user context exists (not usernames).
* Experimental model force relies on unsupported shallow-clone behavior in the prevent hook, checks the final provider and model before the provider call, and fails closed on a mismatch. Prefer official WordPress routing filters when they become available.
* Shadow observations store the request host and path only. They do not store the query string, request body, Authorization headers, or API keys.

= Privacy =

See the **Privacy / Data** section below for the complete list of information that may be stored locally or sent through optional alerts, webhooks, and reports.

By default, this plugin does **not** send data to any external service.

== Privacy / Data ==

By default this plugin does **not** send data to any external service. Features that store or transmit call metadata are **opt-in** (logging, denial alerts / webhook, shadow-AI observe alerts) or **default-on only while logging/learn mode is on** (weekly report) — each has an explicit Settings toggle.

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
* Opt-in **Usage spike alerts** (Activity tab, off by default): email when a plugin’s AI Client call volume or estimated spend is much higher than its previous 7-day daily average (3× multiplier and floors by default). Reuses denial-alert recipient and optional webhook; 24-hour per-plugin per-metric dedupe. Pauses with a plain notice when logging is off or activity age is under 7 days.
* Opt-in **Block direct calls to known AI providers** (Rules tab, off by default): short-circuit WordPress HTTP to curated AI hosts outside the AI Client, with optional per-plugin exceptions. Recommend Learn mode first. Fail-open on internal errors.
* Read-only REST API (`handl-aicac/v1`): policy summary, activity aggregates, and Site Health verdict for external dashboards. Requires manage_options (application passwords work). No write endpoints in v1.
* Optional estimated-spend threshold email alerts (site-wide and per-plugin; empty = off). Reuses the denial-alert recipient; no enforcement.
* Opt-in Direct AI connection email alerts (off by default) when a plugin connects directly to an AI provider outside the AI Client — immediate or hourly summary; labeled Observed, not blocked; email-only.
* AICAC-11: In-product messaging that differentiates HandL from the WordPress AI plugin’s Connector Approvals experiment (Dashboard callout, settings subtitle, Rules note, FAQ).




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
