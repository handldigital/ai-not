# Decisions — AICAC-104 (#25)

## D1: Additional delivery channel on the existing denial-alert trigger

**Decision:** Webhook rides `Alerts::maybe_notify_denial` / immediate flush / digest cron — not a separate on/off toggle or trigger.

**Why:** Spec requires the same `alert_on_deny`, rate-limit, and immediate/digest mode as email. Reusing the validated path avoids divergent flood guards.

## D2: Generic JSON payload from `summarize_event` fields

**Decision:** POST `{ source, event, site, site_url, …summary fields }`; digest uses `event=denial_digest` + `denials[]`. No Slack Block Kit / Teams Adaptive Cards.

**Why:** Spec excludes provider-specific templating; email field set is the privacy contract.

## D3: `wp_remote_post` with `redirection => 0`, scheme allowlist

**Decision:** Sanitize to http/https only; POST via WP HTTP API; do not follow redirects; contain WP_Error / non-2xx / Throwable like `safe_wp_mail`.

**Why:** Admin-supplied URL is SSRF-adjacent under the same trust model as `alert_email`; mitigations match the Permissions/security section.

## D4: Invalid webhook URL rejected without overwriting prior value

**Decision:** `validate_webhook_url_input` on Activity save; on failure set admin error notice and keep the previously stored sanitized URL (empty clears intentionally).

**Why:** AC6 forbids silently storing invalid values; clearing a good URL on a typo would be worse than keeping prior.

## D5: Email clear/rate semantics preserved when both channels configured

**Decision:** Rate slot / digest queue clear still keyed primarily off email success when a recipient exists; webhook-only installs use webhook success. Document that digest retry after email failure may re-POST the webhook.

**Why:** “Email path unchanged” (AC2) when webhook is absent; dual-channel edge is an accepted limitation vs inventing per-row delivery receipts.

## D6: Quality P2 — unknown action literals must fail CI

**Decision:** `test_no_unknown_handl_aicac_action_string_literals_in_dispatch` now fails if any quoted `[a-z0-9_]+` token on a `handl_aicac_action` / `posted_action` line is outside the known mutating-action set (from `mutating_action_provider`) and outside a fixed non-action allowlist (`handl_aicac_action`, `handl_aicac_nonce`, `hidden`). Do not waive P2; staging smoke / human production approval stay HUMAN process items.

**Why:** The prior test only asserted known actions were present, so a new mutating branch (the exact regression class AICAC-3 exists to catch) could ship without an inventory/nonce update. Quality correctly blocked on that gap.
