# Implementation Plan — AICAC-1

## Work item

**AICAC-1:** Establish automated PHPUnit test suite for policy/enforcement logic  
**Issue:** https://github.com/handldigital/ai-not/issues/19  
**Landed:** merged to `main` via PR #34 (`b73f4b6` Implement #19)

## Objective

Deliver a Composer-driven PHPUnit suite covering policy/enforcement decision
branches, plus a GitHub Actions job that installs PHP and runs that suite on
pull requests to `main`.

## Approach (smallest correct change)

Already implemented on `main` (verified this cycle; no further production
code changes required):

1. `composer.json` / `composer.lock` with `phpunit/phpunit: ^9.6` and a
   `test` script (`phpunit`).
2. `phpunit.xml.dist` and `tests/bootstrap.php` with minimal WP stubs
   (`ABSPATH`, `sanitize_text_field`, `__`) — not a full wp-phpunit install.
3. Unit tests for every `Policy::evaluate()` decision branch required by AC
   (default-allow, explicit deny, capability-family override,
   unknown-operation fallback, kill-switch with exceptions), plus
   `tool_armed`, Operations family mapping, and `Model_Force::resolve_route()`.
4. `.github/workflows/phpunit.yml` on `pull_request` / `push` to `main`.
5. Release zip excludes for `vendor/`, `tests/`, and Composer artifacts.
6. AICAC-2 (wp_mail / cron observability) remains out of scope.

## Files

| File | Status |
|------|--------|
| `composer.json` | Present (`scripts.test` → `phpunit`) |
| `composer.lock` | Present |
| `.gitignore` | Present |
| `phpunit.xml.dist` | Present |
| `tests/bootstrap.php` | Present |
| `tests/Unit/PolicyEvaluateTest.php` | Present |
| `tests/Unit/OperationsFamilyTest.php` | Present |
| `tests/Unit/ModelForceResolveRouteTest.php` | Present |
| `.github/workflows/phpunit.yml` | Present |
| `.github/workflows/release.yml` | Excludes updated |

No production PHP class behavior changes in this story.

## Acceptance-criteria mapping

| Criterion | Implementation | Test / evidence |
|-----------|----------------|-----------------|
| `composer.json` `test` script runs PHPUnit | `composer.json` scripts | `composer test` |
| default-allow | `PolicyEvaluateTest` | `test_default_allow_permits_unknown_plugin` |
| explicit deny | `PolicyEvaluateTest` | `test_explicit_plugin_deny` |
| per-capability-family override | `PolicyEvaluateTest` | `test_capability_family_deny_*` |
| unknown-operation fallback | `PolicyEvaluateTest` | `test_unknown_operation_fallback_*` |
| kill-switch with exceptions | `PolicyEvaluateTest` | `test_kill_switch_*` |
| Single documented local command | `composer install && composer test` | `test-results.md` |
| CI on PRs to main | `.github/workflows/phpunit.yml` | workflow YAML |
| Evidence for Quality | Passing local suite | `test-results.md`, this handoff |

## Risks

- Full WP/db scaffold deferred; stub sanitization may diverge on edge strings
  (decision-engine branches do not depend on those edges).
- Credential-free workspace cannot observe the remote Actions green check;
  workflow is present and identical to the local command.
- `composer.lock` / CI use PHP 8.2.

## Out of scope

- AICAC-2 observability for `safe_wp_mail` / weekly cron failures.
- Admin UI, weekly report rendering, alerts UI coverage.
- Branch-protection “required check” enforcement (human / repo admin).
