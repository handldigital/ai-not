# Test Results — AICAC-1

## Environment

- **Date:** 2026-08-07
- **OS:** Linux (AgentOps workspace)
- **PHP:** PHP 8.2.28 (cli) via `/home/ubuntu/php-runtime/php`
- **Composer:** `~/.local/bin/composer`
- **PHPUnit:** 9.6.35 (from `composer.lock`)
- **Working directory:** repo root

## Prerequisites

```bash
export PATH="/home/ubuntu/php-runtime:$PATH"   # AgentOps image only
composer install --no-interaction
```

## Commands executed

### `composer update --no-interaction`

Exit code: **0**  
Wrote `composer.lock` and installed 28 packages (phpunit/phpunit 9.6.35).

### `composer test`

```
PHPUnit 9.6.35 by Sebastian Bergmann and contributors.

...............................                                   31 / 31 (100%)

Time: 00:00.003, Memory: 6.00 MB

OK (31 tests, 62 assertions)
```

**Exit code:** 0

## Suite breakdown

| File | Tests | Focus |
|------|-------|--------|
| `tests/Unit/PolicyEvaluateTest.php` | 18 | allow/deny, family, unknown-op, kill-switch + exceptions, tool_armed, audit_only, empty policy |
| `tests/Unit/OperationsFamilyTest.php` | 9* | family maps, TTS-before-text, inference, capability normalize |
| `tests/Unit/ModelForceResolveRouteTest.php` | 4 | pin / unattributed / no_rule |

\* Includes 5 data-provider cases counted by PHPUnit as separate tests.

**Total:** 31 tests, 62 assertions — all passed.

## Formatter / linter / type checker / build

- No project PHP CS / Psalm / PHPStan config present; not run.
- Plugin production files unchanged; no plugin build step beyond existing release zip workflow.
- Dependency security: `composer update` reported “No security vulnerability advisories found.”

## CI workflow (not executed in this sandbox)

`.github/workflows/phpunit.yml` is configured to run the same
`composer install` + `composer test` steps on `pull_request` / `push` to
`main` with PHP 8.2. This credential-free workspace cannot trigger GitHub
Actions; a green check on PR #33 is expected after the control plane
publishes the branch.

## Failures

None.
