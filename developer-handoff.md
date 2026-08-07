# Developer Handoff — AICAC-1

## Work item ID

AICAC-1 (https://github.com/handldigital/ai-not/issues/19)

## Summary of behavior implemented

Composer + PHPUnit 9 harness is on `main` (merged PR #34 / `b73f4b6`).
Unit tests cover every required `Policy::evaluate()` allow/deny branch
(default-allow, explicit deny, per-capability-family override,
unknown-operation fallback, kill-switch with exceptions), plus `tool_armed`,
Operations family mapping, and Model_Force route resolution. A PR-triggered
GitHub Actions job runs `composer test`. No production plugin behavior was
changed. This cycle re-verified the suite on a clean checkout: **31 tests,
62 assertions, OK**.

## Files changed

**Already on `main` (no new production diff this cycle):**

- `composer.json`, `composer.lock`
- `.gitignore`
- `phpunit.xml.dist`
- `tests/bootstrap.php`
- `tests/Unit/PolicyEvaluateTest.php`
- `tests/Unit/OperationsFamilyTest.php`
- `tests/Unit/ModelForceResolveRouteTest.php`
- `.github/workflows/phpunit.yml`
- `.github/workflows/release.yml` — exclude vendor/tests/Composer/`*.md` from zip

**Updated this cycle (handoff artifacts only):**

- `implementation-plan.md`, `decisions.md`, `test-results.md`, `developer-handoff.md`

**Unchanged:** all `includes/*`, main plugin file, runtime options.

## Acceptance-criteria-to-test mapping

| Acceptance criterion | Evidence |
|----------------------|----------|
| `composer.json` defines `test` script that runs PHPUnit | `"test": "phpunit"`; `composer test` → PHPUnit 9.6.35 |
| default-allow | `test_default_allow_permits_unknown_plugin` |
| explicit deny | `test_explicit_plugin_deny` |
| per-capability-family override | `test_capability_family_deny_overrides_plugin_allow`, `test_capability_family_deny_covers_support_check` |
| unknown-operation fallback | `test_unknown_operation_fallback_{inherit_allows,allow,deny}` |
| kill-switch with exceptions | `test_kill_switch_blocks_all_with_empty_exceptions`, `test_kill_switch_exception_*` |
| Tests pass via single documented command | `composer install && composer test` → OK |
| Test run output as Quality evidence | `test-results.md` (this file set) |
| CI job on PRs to main (product/backlog AC) | `.github/workflows/phpunit.yml` |

## Commands executed

```bash
export PATH="/home/ubuntu/php-runtime:$PATH"
composer install --no-interaction
composer test
```

## Test results

```
OK (31 tests, 62 assertions)
```

Full capture: `test-results.md`.

## Data or schema changes

None.

## Configuration changes

- Composer / PHPUnit tooling (dev only) — already on `main`.
- CI workflow `phpunit.yml` — already on `main`.
- Release zip excludes — already on `main`.
- No wp_options / runtime config changes.

## Security considerations

- Test-only stubs; production authz unchanged.
- No secrets introduced.
- Vendor not shipped in release zip.
- Decision engine default-allow on empty policy remains documented existing behavior (asserted).

## Known limitations

- No full WordPress / DB integration suite (by design — `decisions.md` D1).
- Admin UI, weekly report, alerts not covered (AICAC-1 exclusions; AICAC-2 separate).
- Remote Actions green check not observable inside this credential-free workspace.

## Rollback considerations

Remove added test/Composer/CI files and revert `release.yml` exclude list.
No migration or option rollback. Production behavior unchanged.

## Remaining risks

- Branch protection making the PHPUnit check required is human/repo-admin owned.
- Stub vs real `sanitize_text_field` divergence is low-risk for branch tests.
- AICAC-2 (wp_mail / cron observability) remains backlog.

## Requested next action

Quality and Release Gate: independently re-run `composer install && composer test`
on `main` (or confirm the `PHPUnit` workflow green on recent pushes) and close
or approve AICAC-1 / issue #19.

---

STATUS: READY  
WORK_ITEM: AICAC-1  
COMPLETED: Verified PHPUnit harness + policy allow/deny branch coverage already on main; `composer test` → OK (31 tests, 62 assertions); CI workflow present  
EVIDENCE: implementation-plan.md, decisions.md, test-results.md, developer-handoff.md; `composer test` OK (31/62); `.github/workflows/phpunit.yml`; merge `b73f4b6` / PR #34  
DECISIONS: Lightweight stubs over wp-phpunit; PHPUnit 9; CI on PHP 8.2; AICAC-2 out of scope; no further code change this cycle (already merged)  
RISKS: Required-status-check enforcement is human-owned; no WP integration suite; AICAC-2 still open  
NEXT_ACTION: Quality independently verify suite / close issue #19  
NEXT_OWNER: QUALITY
