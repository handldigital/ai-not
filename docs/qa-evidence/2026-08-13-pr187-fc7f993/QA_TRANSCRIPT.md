# PR #187 — RETENTION QA transcript

- Pull request: `handldigital/ai-not#187`
- Commit tested: `fc7f9930a5d8402cbd37297dc287b32ea0affc29`
- Date: 2026-08-13

## Acceptance coverage

1. **Export-before-cleanup** — reducing the retention period with expired rows set the gate. The first batch returned `waiting_export` and removed zero rows.
2. **Explicit export completion** — after marking export complete, the cleanup batch removed the maximum 100 expired rows; a second pass returned no-op once remaining expired rows had been removed.
3. **Boundary preservation** — the row exactly at the 30-day cutoff and a recent row were retained.
4. **Batching** — cleanup is capped at 100 rows per run, preventing an unbounded cron operation.
5. **Regression** — full PHPUnit suite passed: 471 tests / 2120 assertions.

## Captured result

```json
{
  "waiting_status": "waiting_export",
  "waiting_removed": 0,
  "deferred": true,
  "first_status": "pruned",
  "first_removed": 100,
  "first_remaining": 0,
  "second_status": "noop",
  "edge_kept": true,
  "fresh_kept": true
}
```

Sandbox policy, activity log, and retention metadata were restored after the fixture, as was the prior clean checkout.
