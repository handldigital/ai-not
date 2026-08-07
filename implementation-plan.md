# Implementation Plan — AICAC-1

## Work item

**AICAC-1:** Establish automated PHPUnit test suite for policy/enforcement logic

## Goal

Add a Composer-driven PHPUnit harness and unit tests that cover every required allow/deny branch in `Policy::evaluate()`, plus model-force route matching named in the story’s desired behavior.

## Approach (smallest architecture)

1. Add `composer.json` with PHPUnit as a dev dependency and a `test` script (`vendor/bin/phpunit`).
2. Add `phpunit.xml.dist` and `tests/bootstrap.php`.
3. Bootstrap defines `ABSPATH` and minimal WordPress stubs (`sanitize_text_field`, etc.) so production classes load without a full WordPress install.
4. Autoload / require `Operations`, `Policy`, and `Model_Force` for pure unit tests against `Policy::evaluate()` and `Model_Force::resolve_route()`.
5. Do **not** introduce wp-phpunit / WP_UnitTestCase in this increment — those need WordPress core + DB and are out of scope for a local single-command policy unit suite. Documented in `decisions.md`.
6. Document the run command in `readme.txt` (Developer notes) or a short TESTING note in developer handoff; keep product surface unchanged beyond a minimal “Development” note if needed.

## Files to add

| File | Purpose |
|------|---------|
| `composer.json` | PHPUnit + `test` script |
| `composer.lock` | Locked deps (from `composer update`) |
| `.gitignore` | Ignore `vendor/`, Composer artifacts |
| `phpunit.xml.dist` | Suite config |
| `tests/bootstrap.php` | ABSPATH + WP stubs + class requires |
| `tests/Unit/PolicyEvaluateTest.php` | Policy allow/deny branches |
| `tests/Unit/ModelForceResolveRouteTest.php` | Model-force route matching |
| `implementation-plan.md` | This plan |
| `decisions.md` | Technical decisions |
| `test-results.md` | Command evidence |
| `developer-handoff.md` | Review handoff |

## Acceptance criteria → implementation → tests

| AC | Implementation | Test |
|----|----------------|------|
| `composer.json` defines `test` script running PHPUnit | `"scripts": { "test": "phpunit" }` | Verified by running `composer test` |
| default-allow | N/A (existing engine) | `test_default_allow_permits_unknown_plugin` |
| explicit deny | N/A | `test_explicit_plugin_deny` |
| per-capability-family override | N/A | `test_family_deny_overrides_plugin_allow`; allow other family on same plugin |
| unknown-operation fallback inherit/allow/deny | N/A | three tests for inherit/allow/deny |
| kill-switch with exceptions | N/A | deny all; exception falls through; empty exceptions |
| Tests pass via one documented command | `composer test` | Captured in `test-results.md` |
| Evidence for Quality | `test-results.md` + handoff | Artifact |

## Risks

- Stubbed WP helpers could diverge from core behavior for edge sanitization — acceptable for decision-engine unit tests; CI story (AICAC-2) can later add optional integration jobs.
- PHP not present in bare AgentOps images — document install prerequisite (`php-cli`, `composer`).

## Out of scope

- Admin UI / JS tests
- Shadow-AI detector
- Full WordPress integration / DB bootstrap
- CI workflow (AICAC-2)
