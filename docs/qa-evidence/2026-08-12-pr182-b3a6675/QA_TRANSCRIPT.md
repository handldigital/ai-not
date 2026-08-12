# PR #182 — 1.5.0 release-triad QA transcript

- Pull request: `handldigital/ai-not#182`
- Commit tested: `b3a6675cb2e6b2e9cba988c6faec78406f356963`
- Date: 2026-08-12

## Release gates

- Prerequisite PR #181 was merged before this verification.
- Copy gate was approved for the tested commit.
- PR #182 was clean, mergeable, and its Policy / enforcement suite was successful.

## Acceptance coverage

1. **Version triad** — plugin header, `HANDL_AICAC_VERSION`, and `readme.txt` Stable tag each reported `1.5.0`.
2. **Live sandbox metadata** — WordPress `get_plugin_data()` reported plugin version `1.5.0` and the loaded constant was `1.5.0`.
3. **What’s New** — the live catalog returned exactly five 1.5.0 highlights: estimated budgets, weekly digest, provider/model changes, webhook delivery log/retry, and WP-CLI audit.
4. **Regression** — full PHPUnit suite passed: 458 tests / 2050 assertions.

## Captured result

```json
{
  "plugin_version": "1.5.0",
  "version_constant": "1.5.0",
  "whats_new_count": 5
}
```

The sandbox QA checkout was restored to its prior clean branch after testing.
