# Implementation Plan — AICAC-104 (#25)

## Work item

**Issue:** #25 — AICAC-104: Outgoing webhook channel for denial alerts (Slack/Teams-compatible)  
**Scope:** Denial-alert delivery in `class-handl-aicac-alerts.php` + Activity audit settings UI/save in `class-handl-aicac-admin.php` + policy sanitize/persist + Privacy/`readme.txt` + minor version bump.  
**Spec source:** Issue body; product-handoff § AICAC-104 (copied from approved product scan — not present in this workspace at job start).

## Objective

Add an optional admin-configured HTTP(S) webhook URL alongside denial email alerts. When set, the same denial trigger/rate-limit/digest path also POSTs a generic JSON payload (privacy-scoped like email) via `wp_remote_post`, without changing allow/deny or adding latency on the filter path.

## Approach (smallest correct change)

1. Policy key `alert_webhook_url` — sanitize to `http`/`https` only; empty clears the channel.
2. Extend `Alerts`: resolve URL, build JSON from existing `summarize_event` fields, `safe_wp_remote_post` (try/catch, 2xx-only success, `redirection => 0`), fire from immediate + digest paths after the same gates as email; no POST when URL empty.
3. Keep deferred shutdown flush for production denials (AC4). Test button POSTs immediately and bypasses rate limit (AC5).
4. Admin Activity settings: Webhook URL field + inline reject notice on invalid save (AC6) + “Send test webhook” form (nonce + `manage_options` shared gate).
5. Update `AdminAuthzCoverageTest` for the new mutating action.
6. Unit-test sanitize/validate, payload field set, empty-URL no-POST, failure containment stubs, digest mode mirroring.
7. Bump to **1.0.15**; document Privacy/Data egress + changelog.

## Acceptance-criteria mapping

| Criterion | Implementation | Test / evidence |
|-----------|----------------|-----------------|
| AC1 POST same field set as email | Immediate (+ digest) webhook body from `summarize_event` | `AlertsWebhookTest` asserts payload keys; no prompt/user |
| AC2 no URL → no POST | `resolve_webhook` empty short-circuit | Test stubs `wp_remote_post` not called |
| AC3 non-2xx/timeout contained | `safe_wp_remote_post` try/catch + code check | Test WP_Error / 500 → false, no throw |
| AC4 deferred to shutdown | Reuse `hook_flush` / `flush_deferred` | Source/assert production path only queues then flush |
| AC5 Send test webhook | Admin action `send_test_webhook` → `Alerts::send_test_webhook` | Authz coverage lock; method sets `test: true` |
| AC6 http/https validate; reject inline | `validate_webhook_url_input` + admin notice; prior URL kept | Unit cases for ftp/javascript/empty/valid |
| Digest mirrors email mode | `send_digest` also POSTs when URL set | Test digest payload shape |

## Risks

- Admin-supplied outbound URL is SSRF-adjacent (same trust model as `alert_email`); mitigate with scheme allowlist + `wp_remote_post` + no redirect follow.
- Dual-channel digest retry after email failure may re-POST webhook (documented limitation; email clear semantics unchanged).
- Credential-free workspace cannot push; control plane publishes.

## Out of scope

- Weekly report webhook; Slack/Teams Block Kit templating; separate webhook on/off toggle.
