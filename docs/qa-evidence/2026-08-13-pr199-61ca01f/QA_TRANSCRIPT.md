# PR #199 QA transcript — Policy change history

Tested pull request: https://github.com/handldigital/ai-not/pull/199  
Tested commit: `61ca01f70a721378ea467359f14e9fb78b4c22ce`

## Acceptance coverage

1. A policy save creates a history row and exposes a meaningful same-count per-plugin rule change (`Allow` to `Deny`).
2. Secret values are never written to history: the alert-email and webhook rows report configuration state only.
3. Sub-cent budget values use canonical `<$0.01` formatting.
4. Budget mode uses the product label `Observe-only when reached`.
5. The default history retention cap is 200.
6. Full PHPUnit suite passed: 494 tests and 2255 assertions.

Controlled sandbox fixture result:

```json
{
  "history_rows": 1,
  "plugin_diff": true,
  "subcent": true,
  "observe_label": true,
  "email_masked": true,
  "webhook_masked": true,
  "default_cap": true
}
```

The fixture restored its original sandbox policy, full-snapshot, and policy-history options after the check.
