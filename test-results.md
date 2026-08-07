# Test Results — AICAC-1

## Environment

- **Date:** 2026-08-07
- **OS:** Linux (AgentOps workspace)
- **PHP:** PHP 8.2.28 (cli) via `/home/ubuntu/php-runtime/php`
- **Composer:** available at `~/.local/bin/composer`
- **PHPUnit:** 9.6.35 (from `composer.lock`)
- **Working directory:** repo root

## Prerequisites (one-time)

```bash
composer install
```

Requires PHP >= 7.4 with `dom` / `xml` / `mbstring` (or equivalent) extensions.

## Single documented command

```bash
composer test
```

Equivalent: `vendor/bin/phpunit`

## Command results (observed)

### `composer test`

```
PHPUnit 9.6.35 by Sebastian Bergmann and contributors.

...................                                               19 / 19 (100%)

Time: 00:00.002, Memory: 6.00 MB

OK (19 tests, 41 assertions)
```

**Exit code:** 0

### Suite breakdown

| File | Tests | Focus |
|------|-------|--------|
| `tests/Unit/PolicyEvaluateTest.php` | 15 | default-allow, explicit deny/allow, family override, unknown-op inherit/allow/deny, kill-switch + exceptions, unattributed, empty policy |
| `tests/Unit/ModelForceResolveRouteTest.php` | 4 | pinned plugin, unattributed gap, unattributed force, no_rule |

**Total:** 19 tests, 41 assertions — all passed.

## Failures

None.

## Notes

- Tests do not boot WordPress; see `decisions.md` D1.
- `vendor/` is gitignored; CI/local must run `composer install` before `composer test`.
