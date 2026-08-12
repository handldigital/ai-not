# PR #181 — WEBHOOK-TEST QA transcript

- Pull request: `handldigital/ai-not#181`
- Commit tested: `75832a50a7b42974d9ad07727406bc28a0e3c7ea`
- Date: 2026-08-12

## Acceptance coverage

1. **Send test webhook success** — controlled HTTP 204 result returned `ok: true`, HTTP 204, and zero retries.
2. **Retry and failure visibility** — controlled HTTP 503 caused exactly one automatic retry; the final result was failed, HTTP 503, and `retries: 1`.
3. **Delivery log** — the failed/retried result appeared in the delivery log; adding 25 extra rows retained exactly the newest 20.
4. **Failure email** — after the retried failure, the authorized plus-address fixture captured one failure email using the shared multipart template and the approved retry wording.
5. **Regression** — full PHPUnit suite passed: 457 tests / 2048 assertions at the tested commit.

## Captured result

```json
{
  "success_ok": true,
  "success_http": 204,
  "success_retries": 0,
  "failure_ok": false,
  "failure_http": 503,
  "failure_retries": 1,
  "http_attempts": 3,
  "failure_log_present": true,
  "failure_email_count": 1,
  "failure_email_multipart": true,
  "failure_email_copy": true,
  "log_cap": 20
}
```

All HTTP requests were intercepted in the sandbox after configuring a valid HandL-owned URL, so no endpoint was contacted. Policy, alert-health, delivery-log, and failure-email throttle state were restored afterward. The prior sandbox checkout was also restored.
