=== HandL AI Gate ===
Contributors: haktansuren
Tags: ai, governance, security, handl, ai client
Requires at least: 7.0
Tested up to: 7.0
Requires PHP: 7.4
Stable tag: 1.0.1
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Control which plugins may execute prompts via the WordPress AI Client.

== Description ==

HandL AI Gate lets administrators allow/deny AI Client prompt execution on a per-plugin basis using the `wp_ai_client_prevent_prompt` filter introduced with the WordPress AI Client.

Default behavior is **allow**.

Caller attribution is best-effort and is determined by inspecting the PHP call stack and mapping file paths to installed plugins.

== Privacy / Data ==

This plugin does not send data to any external service.

If you enable **recent-call logging** in Settings → HandL AI Gate, it stores a local log in the WordPress options table containing:

- Timestamp
- Best-effort calling plugin (plugin basename) and source file
- Allow/deny decision
- Current user id
- Request URI

Logging is **disabled by default**.

== Installation ==

1. Upload the plugin folder to `/wp-content/plugins/handl-ai-gate/`
2. Activate the plugin through the Plugins screen in WordPress
3. Go to Settings → HandL AI Gate to configure plugin rules

== Frequently Asked Questions ==

= Does this stop all AI usage? =
Only AI calls made through the WordPress AI Client APIs that pass through `wp_ai_client_prevent_prompt`.

= Is attribution perfect? =
No. It is best-effort and may be unknown or ambiguous for some execution paths (cron, REST bootstraps, shared libraries, MU plugins).

== Changelog ==

= 1.0.1 =
* Renamed plugin to HandL AI Gate (slug `handl-ai-gate`). Prefixed options, constants, menus, and forms per WordPress.org guidelines. Migrates settings from the previous `ai-not` / `ai_not_*` options when present.

= 1.0.0 =
* Initial release (submitted as AI Not).
