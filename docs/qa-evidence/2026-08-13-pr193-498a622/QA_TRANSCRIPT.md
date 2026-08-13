# PR #193 — SCORE QA transcript

- Pull request: `handldigital/ai-not#193`
- Commit tested: `498a62209c021b4fce9931074914a62f6be68df3`
- Date: 2026-08-13

## Acceptance coverage

1. **Empty site normalization** — no saved Activity correctly marked explicit rules and budgets Not applicable, excluded their weights from the denominator, and returned 38/100 from the applicable 40-point denominator (not the prior misleading 75/100).
2. **Check states** — the empty state shows drift as done, alert email and retention as applicable but incomplete, and rules/budgets as not applicable rather than Done.
3. **Complete configuration** — applicable rules, alert email, budget where spend exists, drift, and finite retention returned 100/100 with every check done.
4. **Regression** — full PHPUnit suite passed: 490 tests / 2241 assertions.

## Captured result

```json
{
  "empty_score": 38,
  "empty_max_applicable": 40,
  "full_score": 100,
  "full_max_applicable": 100,
  "full_earned_applicable": 100,
  "full_all_done": true
}
```

The initial partial fixture intentionally surfaced a missing budget for a plugin with sub-cent recorded spend, correctly yielding 90 rather than falsely reporting full coverage. The fully covered fixture then returned 100. Sandbox state and the prior checkout were restored.
