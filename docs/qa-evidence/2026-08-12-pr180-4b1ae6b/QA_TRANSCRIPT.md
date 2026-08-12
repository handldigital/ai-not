# PR #180 — WP-CLI audit QA transcript

- Pull request: `handldigital/ai-not#180`
- Commit tested: `4b1ae6bf089994e369506f1dd2078559c63903e6`
- Date: 2026-08-12

## Acceptance coverage

1. **Fresh policy list** — `wp handl-aicac policy list` rendered the default `allow` policy and 177 installed-plugin rows; `--format=json` returned the matching structured payload.
2. **Configured policy list** — with a temporary deny default and an explicit allow rule for this plugin, both table and JSON output reported `default: deny`, `rule: allow`, and `effective: allow`.
3. **Activity summary** — a two-row controlled activity fixture rendered `Calls: 2`, `Blocked: 1`, and an estimated spend of `$0.01`; JSON reported 2 calls, 1 denial, 0.0113 estimated USD, and one top plugin.
4. **Logging-disabled behavior** — `wp handl-aicac log summary` clearly reported that logging and Learn mode were off, then returned zero calls, blocks, and spend.
5. **Multisite** — sandbox exposes one primary site only, so `--url=` could not be meaningfully exercised against a second site.
6. **Regression** — full PHPUnit suite passed: 458 tests / 2050 assertions at the tested commit.

## Terminal evidence

```text
Default: deny | Emergency stop: off | Exceptions: 0
...
Calls: 2 | Blocked: 1 | Estimated spend: $0.01
Top plugins by estimated spend:
handl-ai-connector-access-control/handl-ai-connector-access-control.php
  HandL AI Connector Access Control  2  0.0113

Activity logging and Learn mode are off — summary shows zero calls.
Calls: 0 | Blocked: 0 | Estimated spend: $0.00
Top plugins by estimated spend: (none)
```

All temporary policy and retained-log state was restored after the commands completed.
