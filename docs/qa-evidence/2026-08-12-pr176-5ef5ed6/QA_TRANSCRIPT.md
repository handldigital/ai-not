# PR #176 — BUDGET-C QA transcript

- Pull request: `handldigital/ai-not#176`
- Commit tested: `5ef5ed686bb1bf1d600298451b3800c90d58894c`
- Date: 2026-08-12

## Acceptance coverage

1. **Blocking mode** — a plugin with $12.50 current-period estimated spend against a $10.00 budget returned the `budget` gate with `prevent: true`.
2. **Observe-only mode** — the same over-budget plugin returned `prevent: false` and `mode: observe`.
3. **Budget-hit email** — controlled sandbox mail capture contained the approved estimated-budget text and multipart alternatives. Repeated evaluation generated one message only, confirming per-period de-duplication.
4. **Site Health** — the live snapshot returned `over_budget`, `recommended`, and the approved estimated-budget label.
5. **Regression** — full PHPUnit suite passed: 449 tests / 1991 assertions at the tested commit.

## Captured result

```json
{
  "deny_prevents": true,
  "deny_reason": "budget",
  "observe_prevents": false,
  "observe_mode": "observe",
  "email_count_deduped": 1,
  "email_multipart": true,
  "email_contains_estimated_copy": true,
  "site_health_issue": "over_budget",
  "site_health_status": "recommended",
  "site_health_label": "One or more plugins reached their estimated budget"
}
```

All sandbox options, spend state, fired-alert state, and activity log state were restored after the fixture. The approved plus-address fixture was used only inside the controlled mail capture; no address is present in this artifact.
