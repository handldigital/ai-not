# Developer Handoff — AICAC-1

## Work item ID

AICAC-1

## Summary of behavior implemented

Added a Composer + PHPUnit 9 harness and unit tests for the policy decision engine and model-force route resolution. No production plugin behavior changed. Maintainers run tests with `composer test` after `composer install`.

## Files changed

**Added:**

- `composer.json` — PHPUnit ^9.6, `"test": "phpunit"` script
- `composer.lock` — locked deps
- `.gitignore` — `vendor/`, cache, common junk
- `phpunit.xml.dist` — suite config
- `tests/bootstrap.php` — ABSPATH + WP stubs + class requires
- `tests/Unit/PolicyEvaluateTest.php` — policy allow/deny branches
- `tests/Unit/ModelForceResolveRouteTest.php` — force route matching
- `implementation-plan.md`, `decisions.md`, `test-results.md`, `developer-handoff.md`

**Unchanged:** all `includes/*`, main plugin file, release workflow.

## Acceptance-criteria-to-test mapping

| Acceptance criterion | Evidence |
|----------------------|----------|
| `composer.json` defines a `test` script that runs PHPUnit | `composer.json` → `"test": "phpunit"`; `composer test` invokes PHPUnit 9.6.35 |
| default-allow | `PolicyEvaluateTest::test_default_allow_permits_unknown_plugin` |
| explicit deny | `PolicyEvaluateTest::test_explicit_plugin_deny` (+ default-deny / explicit-allow companions) |
| per-capability-family override | `test_capability_family_deny_overrides_plugin_allow`, `test_capability_family_deny_covers_support_check` |
| unknown-operation fallback inherit/allow/deny | `test_unknown_operation_fallback_{inherit_allows,allow,deny}` |
| kill-switch with exceptions | `test_kill_switch_blocks_all_with_empty_exceptions`, `test_kill_switch_exception_falls_through_to_normal_rules`, `test_kill_switch_exception_with_allow_permits` |
| Tests run and pass via a single documented command | `composer test` → OK (19 tests, 41 assertions); see `test-results.md` |
| Test run output captured for Quality | `test-results.md` (this handoff) |

Edge coverage also included: unattributed caller, empty policy array (documented default allow).

## Commands executed

```bash
composer update --no-interaction   # initial lock + install
composer test                      # twice; both exit 0
```

## Test results

```
OK (19 tests, 41 assertions)
```

Full capture: `test-results.md`.

## Data or schema changes

None.

## Configuration changes

- New Composer project files for local/CI test tooling only.
- No wp_options / runtime config changes.

## Security considerations

- Test-only stubs; production authz/capability checks untouched.
- No secrets introduced.
- Decision engine still fail-open to documented default-allow when policy array is empty (existing product behavior; asserted by test).

## Known limitations

- No full WordPress / DB integration suite (by design — see `decisions.md` D1).
- Admin UI, shadow-AI detector, and alerts not covered (story exclusions).
- Local PHP must be on PATH (this AgentOps image uses `/home/ubuntu/php-runtime`).

## Rollback considerations

Remove added test/Composer files (`.gitignore`, `composer.json`, `composer.lock`, `phpunit.xml.dist`, `tests/`, docs). No migration or option rollback required. Production zip packaging unaffected if release process does not ship `vendor/` or `tests/` (confirm release.yml exclude list if needed).

## Remaining risks

- AICAC-2 still needed to gate releases on this suite in CI.
- Stub vs real `sanitize_text_field` divergence is low-risk for branch tests but not a substitute for WP integration tests later.

## Requested next action

Independent Quality and Release Gate review of AICAC-1 (reproduce with `composer install && composer test`).

---

STATUS: READY  
WORK_ITEM: AICAC-1  
COMPLETED: PHPUnit harness + policy/model-force unit tests; `composer test` passes (19/19)  
EVIDENCE: implementation-plan.md, decisions.md, test-results.md, developer-handoff.md; command `composer test` → OK (19 tests, 41 assertions)  
DECISIONS: Lightweight stubs over wp-phpunit; PHPUnit 9 for PHP 7.4; include Model_Force route tests; no production code changes  
RISKS: No WP integration suite yet; CI gate is AICAC-2  
NEXT_ACTION: Quality review and reproduce `composer test`  
NEXT_OWNER: QUALITY
