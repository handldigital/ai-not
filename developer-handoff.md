# Developer Handoff — AICAC-104 (#25)

## Work item ID

Issue #25 — AICAC-104: Outgoing webhook channel for denial alerts (Slack/Teams-compatible)

## Summary of behavior implemented

Added optional `alert_webhook_url` (http/https) beside denial email settings on Activity. When configured and `alert_on_deny` is on, denials that pass the existing rate-limit/digest path also POST generic JSON (same privacy-scoped fields as email) via `wp_remote_post`, deferred to shutdown. Empty URL leaves email-only behavior. Failures are contained. “Send test webhook” posts a labeled test payload immediately (bypasses rate limit). Invalid URLs are rejected with an inline admin error and not stored. Version **1.0.15**; Privacy/Data + changelog updated.

## Files changed

- `includes/class-handl-aicac-alerts.php` — sanitize/validate, payloads, safe POST, immediate/digest/test delivery
- `includes/class-handl-aicac-policy.php` — persist `alert_webhook_url`
- `includes/class-handl-aicac-admin.php` — UI field, reject notice, test action + nonce
- `tests/Unit/AlertsWebhookTest.php` — AC coverage
- `tests/Unit/AdminAuthzCoverageTest.php` — `send_test_webhook` inventory
- `tests/bootstrap.php` — WP HTTP / mail / option stubs for alerts tests
- `handl-ai-connector-access-control.php`, `readme.txt` — 1.0.15 + Privacy/changelog
- `aicac-3-authz-coverage.md` — note fifth nonce
- `implementation-plan.md`, `decisions.md`, `test-results.md`, `developer-handoff.md`, `.agentops-result.json`

## Acceptance-criteria-to-test mapping

| Criterion | Evidence |
|-----------|----------|
| AC1 same field set / path-only / no prompt or user | `AlertsWebhookTest::test_summary_fields_match_email_privacy_scope`, `test_maybe_notify_defers_webhook_until_shutdown_flush` |
| AC2 no URL → no POST; email unchanged | `test_no_webhook_post_when_url_empty_email_path_still_runs`, empty-URL cases in `test_safe_wp_remote_post_*` |
| AC3 non-2xx/timeout contained | `test_safe_wp_remote_post_success_and_failure_contained` |
| AC4 deferred to shutdown | `test_maybe_notify_defers_webhook_until_shutdown_flush` |
| AC5 test button / labeled test / bypass rate limit | Admin action + `test_test_payload_is_labeled_as_test`, `test_send_test_webhook_*`; authz lock |
| AC6 http/https validate; reject inline | `test_sanitize_*`, `test_validate_*`; admin notice on reject |
| Digest mirrors email mode | `send_digest` POSTs when URL set; `test_digest_payload_includes_summaries` |

## Commands executed

```bash
composer install --no-interaction
composer test
php -l includes/class-handl-aicac-alerts.php
php -l includes/class-handl-aicac-admin.php
php -l includes/class-handl-aicac-policy.php
php -l tests/Unit/AlertsWebhookTest.php
php -l tests/bootstrap.php
```

## Test results

```
OK (53 tests, 205 assertions)
```

Full capture: `test-results.md`.

## Data or schema changes

- Policy option key `alert_webhook_url` (string URL or empty) inside existing `handl_aicac_policy` option. No new options table keys. No migration required (absent key → empty).

## Configuration changes

- None beyond the stored policy field and UI on Activity audit settings.

## Security considerations

- `manage_options` required (shared admin gate + new nonce `handl_aicac_send_test_webhook`).
- Scheme allowlist http/https; `wp_remote_post` with `redirection => 0`.
- Admin-supplied outbound URL — same trust model as alert email recipient (documented in code + readme).
- Payload omits prompt preview and user identity (path-only URI).

## Known limitations

- No Slack/Teams-specific Block Kit formatting (generic JSON only).
- Weekly report is not delivered to the webhook.
- If email is configured and fails while webhook succeeds, digest retry may POST the webhook again (email clear semantics preserved).

## Rollback considerations

- Revert to prior release / remove `alert_webhook_url` usage; empty URL disables the channel without uninstall. Stored URL in policy is inert if code is rolled back.

## Remaining risks

- SSRF-adjacent admin URL still requires Quality security review of scheme/redirect choices.
- Live Slack/Teams acceptance not exercised in this workspace (stubs only).

## Requested next action

Quality and Release Gate: review AC1–AC6 against `AlertsWebhookTest` + admin UI, confirm Privacy/Data wording, and approve merge of 1.0.15 webhook channel.

---

STATUS: READY  
WORK_ITEM: #25 / AICAC-104  
COMPLETED: Webhook URL setting + deferred JSON POST on denial alert path (immediate/digest), test button, http(s) validation with inline reject, Privacy/readme 1.0.15, unit tests green (53/205)  
EVIDENCE: implementation-plan.md; decisions.md; test-results.md; developer-handoff.md; `composer test` OK (53 tests, 205 assertions)  
DECISIONS: Channel on existing trigger; generic JSON from summarize_event; wp_remote_post no redirects; invalid URL keeps prior; email clear/rate semantics preserved  
RISKS: SSRF-adjacent admin URL; possible duplicate webhook on digest retry after email failure; no live endpoint verification here  
NEXT_ACTION: Quality review AC mapping and security posture, then release gate  
NEXT_OWNER: QUALITY
