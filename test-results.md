# Test Results — AICAC-1

## Environment

- **Date:** 2026-08-07 (verification re-run in job `LSGXqZfUipdR`)
- **OS:** Linux (AgentOps workspace)
- **PHP:** PHP 8.2.28 (cli) via `/home/ubuntu/php-runtime/php`
- **Composer:** `~/.local/bin/composer`
- **PHPUnit:** 9.6.35 (from `composer.lock`)
- **Working directory:** repo root (`main` @ `b8f98be`, includes `b73f4b6` Implement #19)

## Documented single command

```bash
export PATH="/home/ubuntu/php-runtime:$PATH"   # AgentOps image only
composer install --no-interaction
composer test
```

## Commands executed

### `composer install --no-interaction`

Exit code: **0**  
Installed 28 packages from lock file (phpunit/phpunit 9.6.35).

### `composer test`

```
PHPUnit 9.6.35 by Sebastian Bergmann and contributors.

...............................                                   31 / 31 (100%)

Time: 00:00.002, Memory: 6.00 MB

OK (31 tests, 62 assertions)
```

**Exit code:** 0

## Suite breakdown

| File | Tests | Focus |
|------|-------|--------|
| `tests/Unit/PolicyEvaluateTest.php` | 18 | default-allow, explicit deny/allow, capability_family, unknown_operation, kill-switch + exceptions, tool_armed, audit_only, empty policy |
| `tests/Unit/OperationsFamilyTest.php` | 9* | family maps, TTS-before-text, inference, capability normalize |
| `tests/Unit/ModelForceResolveRouteTest.php` | 4 | pin / unattributed / no_rule |

\* Includes 5 data-provider cases counted by PHPUnit as separate tests.

**Total:** 31 tests, 62 assertions — all passed.

## Formatter / linter / type checker / build

- No project PHP CS / Psalm / PHPStan config present; not run.
- Plugin production files unchanged this cycle; no plugin build step beyond existing release zip workflow.

## CI workflow (not executed in this sandbox)

`.github/workflows/phpunit.yml` runs the same `composer install` + `composer test`
steps on `pull_request` / `push` to `main` with PHP 8.2. This credential-free
workspace cannot trigger GitHub Actions.

## Failures

None.
