=== HandL AI Connector Access Control ===
Contributors: haktansuren
Tags: ai, governance, security, handl, ai client
Requires at least: 7.0
Tested up to: 7.0
Requires PHP: 7.4
Stable tag: 1.1.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Control which plugins may execute prompts via the WordPress AI Client.

== Description ==

HandL AI Connector Access Control lets administrators allow/deny AI Client prompt execution on a per-plugin basis using the `wp_ai_client_prevent_prompt` filter introduced with the WordPress AI Client.

Default behavior is **allow**.

**Multisite (read-only network rollup):** On WordPress multisite, network administrators get a Network Admin → Settings page listing sites where this plugin is active (kill switch, logging/learn mode, retained denial count, last activity) with links into each site’s Activity tab. This release does **not** enforce or bulk-edit policy from the network screen — governance remains per-site.

**Per-plugin × capability matrix** (Rules tab) refines access by family — Text, Image, Speech, TTS, Video — so you can allow text generation while denying image generation for the same plugin. Support checks (`is_supported_for_*`) and matching `generate_*` methods share the same family rule. Unknown operations (music, embeddings, generic methods) use a configurable fallback (inherit / allow / deny).

**AI tool arming (caller intent)** denies a prompt when it arms a blocked WordPress ability via the AI Client (`using_abilities` → `functionDeclarations`). This is not MCP visibility and does not unregister abilities site-wide. Denials are logged under this plugin’s name with the blocked ability ids.

**Learn mode** (Activity tab) logs every AI Client call without blocking, so you can discover callers before enabling deny rules on the Rules tab.

**Emergency kill switch** blocks all AI Client calls except plugins you list as exceptions.

**Denial email alerts** (opt-in) notify an admin when enforcement blocks a prompt — immediate (rate-limited) or hourly digest. An optional **Webhook URL** on the same settings posts the same privacy-scoped JSON to an http(s) endpoint (Slack/Teams-compatible) on the same trigger, rate limit, and digest mode. **Weekly report email** mails Dashboard aggregates (coverage, denials, estimated spend, pins) via the same `wp_mail` path; selected by default; reports are sent only while logging or learn mode is on, and it is always toggleable. **Estimated $** on the audit log and in the weekly report is a rough token × rate placeholder (optional per-provider overrides; otherwise a global fallback), not billing. When WordPress disables AI site-wide via `wp_supports_ai`, an honesty banner explains why the audit log may be empty.

**EXPERIMENTAL per-plugin model force** (Rules tab; empty force fields = off) can pin allowed AI Client generations to a provider/model **per detected caller**. Pins follow the nearest plugin frame on the PHP backtrace (best-effort) — not who initiated the call, and **not a spend guarantee**. Unattributed calls (cron, REST bootstraps, shared libraries, MU plugins, etc.) run unforced by default; admins can opt into an explicit unattributed target via the same “Unknown operations”-style control. Force relies on unsupported shallow-clone behaviour in the AI Client prevent hook, verifies the final route with exact provider/model matching before the provider call, and fail-closes on mismatch. Prefer official core routing filters when available.

**Shadow-AI detector (observe only):** when logging or learn mode is on, the plugin watches WordPress HTTP for requests to a curated list of known AI provider hosts (OpenAI, Anthropic, Google Generative Language, Cohere, Mistral, Groq, Together, Fireworks, Perplexity, xAI, DeepSeek, OpenRouter, …). Traffic that already flows through the core AI Client is ignored. Direct bypasses are retained as `observe` rows (`channel=direct_http`) so you can see AI activity **outside** what these rules control — they do **not** block HTTP. This is a curated list, not a complete inventory of every AI host on the internet.

Caller attribution is best-effort and is determined by inspecting the PHP call stack and mapping file paths to installed plugins. When force is configured, the retained log surfaces how many calls could not be attributed and ran unforced.

== Privacy / Data ==

By default this plugin does **not** send data to any external service. Features that store or transmit call metadata are **opt-in** (logging, denial alerts / webhook) or **default-on only while logging/learn mode is on** (weekly report) — each has an explicit Settings toggle.

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
- Full request URI (including query string, kept only on this site) for AI Client admin-request context
- For **direct-HTTP AI observations** only: request **host** and **path** (query string stripped). No request body, no Authorization headers, no API keys. Channel label `direct_http` and matched provider id when known.

Logs are kept as a **single shared entry-based ring buffer** (default 200 entries, configurable 20–1000) for both AI Client rows and direct-HTTP AI observations. There is **no time-based TTL**—older rows drop only when the buffer is full. Repeated direct-HTTP **calls** from the same attributed plugin + host (or the same unattributed file + host) that stay active within ~5 minutes of idle time are collapsed into one row whose `count` is the number of HTTP **calls** (same unit as AI Client rows). Active clusters move to the newest slot so a chatty bypass does not erase the rest of the log, and the log does not drop the chatty cluster ahead of idle rows.

If you enable **denial email alerts**, the plugin sends a message via WordPress `wp_mail` when enforcement blocks a prompt (immediate rate-limited mail, or an hourly digest). The recipient is the address you configure, or the site `admin_email` if left empty — that may be any address you enter, and mail is delivered through whatever transport your site uses (core PHP mail or an SMTP / transactional-mail plugin). Alert messages include:

- Timestamp
- Calling plugin (best-effort basename)
- AI Client operation and capability family
- Denial reason and any matched blocked tools
- Provider and model when known (may be labeled inferred)
- Request path only (query string is stripped before mail; full URI stays in the local log if logging is enabled)

Alert mail does **not** include prompt preview or user identity. Digest rows waiting to send are stored in a local options queue (path-only URI) and are removed when alerts are turned off or the plugin is uninstalled.

If you also set a **Webhook URL** (Activity → denial alert settings), the plugin POSTs a generic JSON body with the **same fields** as the email alert to that http(s) URL whenever a denial alert would fire (same `alert_on_deny` gate, rate limit, and immediate/digest mode — not a separate toggle). Delivery uses WordPress `wp_remote_post` (timeouts/non-2xx are contained like `wp_mail` failures and never change allow/deny). The URL is an intentional admin-supplied outbound integration (same trust model as the alert recipient). Empty URL means no webhook POST is attempted. A **Send test webhook** control posts a sample payload clearly labeled as a test (bypasses rate limiting). Weekly report email is **not** sent to the webhook in this release.

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

= Does this stop all AI usage? =
Only AI calls made through the WordPress AI Client APIs that pass through `wp_ai_client_prevent_prompt`. The shadow-AI detector **observes** direct HTTP to known AI hosts; it does not block those requests in this version.

= What does “outside the AI Client” mean on Audit & log? =
A plugin (or other PHP code) issued a WordPress HTTP request to a known AI provider host without going through the AI Client path this plugin gates. Those rows are labeled observe — seen, not governed by allow/deny/force rules.

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

= 1.1.0 =
* AICAC-105: Read-only Network Admin rollup for multisite — lists sites where the plugin is active with kill-switch, logging/learn mode, retained denial count, and last activity.
* Each row links to that site’s own Activity tab (no inline cross-site policy view).
* Visible only on multisite; requires `manage_network_options`. Single-site installs unchanged.
* Paginated at 50 network sites per page to bound `switch_to_blog()` work on large networks.
* Sites with AI disabled via `wp_supports_ai` show “AI disabled” instead of a misleading zero denial count.
* No network-level policy writes or bulk apply in this release.

= 1.0.15 =
* AICAC-104: Optional denial-alert Webhook URL (http/https) alongside email — same trigger, rate limit, and immediate/digest mode.
* Generic JSON POST via wp_remote_post (path-only fields; no prompt preview or user identity); failures contained like wp_mail.
* Send test webhook button (sample payload labeled as a test; bypasses rate limiting).
* Privacy / Data documents the opt-in webhook egress surface.
* WP-CLI: `wp aicac rule list` and `wp aicac rule set <plugin> <family> <allow|deny|inherit>` for the per-plugin × capability-family matrix.
* List supports table (default) and `--format=json`; includes inactive installed plugins (same set as the Rules tab).
* Set validates plugin basename and family, persists via Policy::sanitize_operations + save_policy (same path as Rules save). No bulk import in this release.
* AICAC-102: Export / import Rules as JSON on the Rules tab (Download rules / Import with preview + confirm).
* Export includes the full policy option plus `plugin_version` and `exported_at` for forward compatibility.
* Import is a documented full replace through the same sanitize/save path as Rules save; invalid JSON is rejected without changing live policy; unknown newer fields are ignored with a notice.
* Does not export the audit log; no secrets/credentials are stored in the policy option.

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
