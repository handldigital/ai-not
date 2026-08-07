# Implementation Plan — AICAC-1

## Work item

**AICAC-1:** Establish automated PHPUnit test suite for policy/enforcement logic  
**Issue:** https://github.com/handldigital/ai-not/issues/19  
**PR:** https://github.com/handldigital/ai-not/pull/33

## Objective

Deliver a Composer-driven PHPUnit suite covering policy/enforcement decision
branches, plus a GitHub Actions job that installs PHP and runs that suite on
pull requests to `main` (release-evidence gap that blocked Quality).

## Approach (smallest correct change)

1. Add `composer.json` / `composer.lock` with `phpunit/phpunit: ^9.6` and a
   `test` script (`phpunit`).
2. Add `phpunit.xml.dist` and `tests/bootstrap.php` with minimal WP stubs
   (`ABSPATH`, `sanitize_text_field`, `__`) — not a full wp-phpunit install.
3. Add unit tests for every `Policy::evaluate()` decision branch, including
   the previously missing `tool_armed` path, plus `Operations` family mapping
   and `Model_Force::resolve_route()` coverage carried from prior work.
4. Add `.github/workflows/phpunit.yml` triggered on `pull_request` (and push)
   to `main`: setup PHP → `composer install` → `composer test`.
5. Exclude `vendor/`, `tests/`, and Composer artifacts from the release zip
   in `release.yml` so test tooling is never shipped in the plugin package.
6. Do **not** implement AICAC-2 (wp_mail / cron observability).

## Files

| File | Action |
|------|--------|
| `composer.json` | Add |
| `composer.lock` | Add |
| `.gitignore` | Add (`vendor/`, cache, junk) |
| `phpunit.xml.dist` | Add |
| `tests/bootstrap.php` | Add |
| `tests/Unit/PolicyEvaluateTest.php` | Add |
| `tests/Unit/OperationsFamilyTest.php` | Add |
| `tests/Unit/ModelForceResolveRouteTest.php` | Add |
| `.github/workflows/phpunit.yml` | Add |
| `.github/workflows/release.yml` | Update excludes |
| `implementation-plan.md`, `decisions.md`, `test-results.md`, `developer-handoff.md` | Add |

No production PHP class behavior changes.

## Acceptance-criteria mapping

| Criterion | Implementation | Test / evidence |
|-----------|----------------|-----------------|
| PHPUnit + runnable config | `composer.json`, `phpunit.xml.dist`, bootstrap | `composer install && composer test` |
| Allow / block / exception branches | `PolicyEvaluateTest` | default-allow, plugin deny/allow, kill-switch + exceptions |
| One test per decision-logic branch | `PolicyEvaluateTest` | kill_switch, plugin, capability_family, unknown_operation, tool_armed |
| Operations decision paths | `OperationsFamilyTest` | mapped ops, TTS-before-text, capability inference, unknown |
| CI job on PRs to main | `.github/workflows/phpunit.yml` | workflow YAML; local suite green |
| Release evidence | Passing local + CI-ready job | `test-results.md` |

## Risks

- Full WP/db scaffold deferred; stub sanitization may diverge on edge strings
  (decision-engine branches do not depend on those edges).
- This workspace cannot push to GitHub; control plane publishes. A green
  Actions run on PR #33 is produced after publish, not inside this sandbox.
- `composer.lock` generated on PHP 8.2; CI will use PHP 8.2 to match.

## Out of scope

- AICAC-2 observability for `safe_wp_mail` / weekly cron failures.
- Admin UI, weekly report rendering, alerts UI coverage.
