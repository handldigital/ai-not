# Developer Handoff — AICAC-1

## Work item ID

AICAC-1 (https://github.com/handldigital/ai-not/issues/19, PR #33)

## Summary of behavior implemented

Added a Composer + PHPUnit 9 harness, unit tests for every
`Policy::evaluate()` decision branch (including kill-switch exceptions and
`tool_armed`), Operations family mapping tests, Model_Force route tests, and
a PR-triggered GitHub Actions job that installs PHP 8.2 and runs
`composer test`. No production plugin behavior changed. Release packaging
now excludes test/Composer artifacts from the plugin zip.

## Files changed

**Added:**

- `composer.json`, `composer.lock`
- `.gitignore`
- `phpunit.xml.dist`
- `tests/bootstrap.php`
- `tests/Unit/PolicyEvaluateTest.php`
- `tests/Unit/OperationsFamilyTest.php`
- `tests/Unit/ModelForceResolveRouteTest.php`
- `.github/workflows/phpunit.yml`
- `implementation-plan.md`, `decisions.md`, `test-results.md`, `developer-handoff.md`

**Updated:**

- `.github/workflows/release.yml` — exclude vendor/tests/Composer/`*.md` from zip

**Unchanged:** all `includes/*`, main plugin file, runtime options.

## Acceptance-criteria-to-test mapping

| Acceptance criterion | Evidence |
|----------------------|----------|
| PHPUnit + runnable config (composer.json + phpunit.xml) | Files present; `composer test` → OK |
| Allow / block / exception-listed branches each have a test | `test_default_allow_*`, `test_explicit_plugin_deny`, `test_kill_switch_exception_*` |
| One test per decision-logic branch | kill_switch, plugin, capability_family, unknown_operation, tool_armed (+ audit_only via `should_prevent`) |
| Operations decision paths | `OperationsFamilyTest` |
| CI job installs PHP + deps and runs suite on PRs to main | `.github/workflows/phpunit.yml` (`pull_request` → `main`) |
| Passing run as release evidence | Local: OK (31 tests, 62 assertions); CI run after publish |

## Commands executed

```bash
export PATH="/home/ubuntu/php-runtime:$PATH"
composer update --no-interaction
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

- New Composer / PHPUnit tooling (dev only).
- New CI workflow `phpunit.yml`.
- Release zip excludes updated.
- No wp_options / runtime config changes.

## Security considerations

- Test-only stubs; production authz unchanged.
- No secrets introduced.
- Vendor not shipped in release zip.
- Decision engine default-allow on empty policy remains documented existing behavior (asserted).

## Known limitations

- No full WordPress / DB integration suite (by design — `decisions.md` D1).
- Admin UI, weekly report, alerts not covered (AICAC-1 exclusions; AICAC-2 separate).
- Green GitHub Actions check cannot be observed inside this credential-free workspace.

## Rollback considerations

Remove added test/Composer/CI files and revert `release.yml` exclude list.
No migration or option rollback. Production behavior unchanged.

## Remaining risks

- Until the control plane publishes and Actions runs green on PR #33, Quality’s
  P1 release-evidence gate may still wait on the remote check.
- Stub vs real `sanitize_text_field` divergence is low-risk for branch tests.
- AICAC-2 (wp_mail / cron observability) remains backlog.

## Requested next action

Quality and Release Gate: re-review PR #33 once the `PHPUnit` workflow check
is green; confirm local reproduction with `composer install && composer test`.

---

STATUS: READY  
WORK_ITEM: AICAC-1  
COMPLETED: PHPUnit harness + policy/operations/model-force unit tests (31/31); PR CI workflow `phpunit.yml`; release zip excludes for test tooling  
EVIDENCE: implementation-plan.md, decisions.md, test-results.md, developer-handoff.md; `composer test` → OK (31 tests, 62 assertions); `.github/workflows/phpunit.yml`  
DECISIONS: Lightweight stubs over wp-phpunit; PHPUnit 9; CI on PHP 8.2 via new workflow; AICAC-2 out of scope; cover tool_armed branch  
RISKS: Remote Actions green check pending publish; no WP integration suite yet  
NEXT_ACTION: Quality re-review PR #33 after CI check is green  
NEXT_OWNER: QUALITY
