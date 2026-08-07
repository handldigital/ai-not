# Implementation Plan — AICAC-2

**Work item:** AICAC-2 — Add CI quality gate (lint + test) before release packaging  
**Issue:** #20  
**Status:** BLOCKED (precondition unmet)  
**Date:** 2026-08-07

## Story sources

- Issue body (AgentOps task) and audit backlog at sibling workspace `AHF0uaV32MDu/backlog.yaml` (AICAC-2).
- No `product-handoff.md` was present in this workspace at job start.

## Acceptance criteria (approved)

| ID | Criterion |
|----|-----------|
| AC1 | `.github/workflows/ci.yml` (or similar) runs `php -l` over `includes/` and the root plugin file on every push/PR to `main`. |
| AC2 | Same workflow runs PHPCS against WordPress Coding Standards; fails on errors (warnings may be non-blocking, documented). |
| AC3 | Same workflow runs the PHPUnit suite from AICAC-1 and fails on any test failure. |
| AC4 | `.gitignore` covers at minimum `vendor/`, `dist/`, `.DS_Store`, and `node_modules/`. |
| AC5 | `release.yml` documented as depending on CI passing on `main` for the tagged commit; branch-protection notes in `decisions.md` if applicable. |

## Preconditions (from backlog)

- AICAC-1 test suite exists and is runnable via a single command (`composer test` or equivalent).

## Inspection results

Verified on `main` @ `3c36f1f`:

- No `composer.json`, `phpunit.xml`, `phpunit.xml.dist`, or `tests/` directory.
- No references to PHPUnit / `WP_UnitTestCase` / `wp-phpunit` in the tree.
- Only CI workflow is `.github/workflows/release.yml` (tag → zip → GitHub Release; no lint/test).
- No `.gitignore`.

**Conclusion:** AICAC-1 has not landed. AC3 cannot be implemented without expanding into unapproved AICAC-1 scope. Shipping CI that invokes a missing test suite would fail every push/PR.

## Proposed approach (when unblocked)

Do **not** implement until Product confirms AICAC-1 is merged (or explicitly expands this issue to include AICAC-1).

1. Add `.gitignore` (`vendor/`, `dist/`, `.DS_Store`, `node_modules/`).
2. Add `.github/workflows/ci.yml` on `push`/`pull_request` to `main` with jobs/steps:
   - Checkout + PHP setup
   - `composer install` (dev deps from AICAC-1)
   - `php -l` over root plugin file + `includes/**/*.php` (+ `uninstall.php` if desired for consistency)
   - PHPCS with WordPress Coding Standards; errors fail the job; document warning policy
   - `composer test` (or documented AICAC-1 command); fail on test failure
3. Comment `release.yml` (and note in `decisions.md`) that releases assume the tagged commit already passed CI on `main`; branch protection / required checks need a human repo admin.
4. Exclude `vendor/`, `dist/`, `.github/`, tests, and tooling from the release zip if not already covered (verify against current `rsync` excludes).

## AC → implementation → test mapping (deferred)

| AC | Implementation step | Verification |
|----|---------------------|--------------|
| AC1 | `ci.yml` lint step | Workflow YAML review + dry-run / CI run on PR |
| AC2 | `ci.yml` PHPCS step + ruleset | Same; document warning vs error policy in `decisions.md` |
| AC3 | `ci.yml` PHPUnit step | Requires AICAC-1; run suite in CI and capture log |
| AC4 | Root `.gitignore` | File content review |
| AC5 | Comments on `release.yml` + `decisions.md` | Diff review; note human-owned branch protection |

## Risks if implemented now without AICAC-1

- Broken main CI (no `composer test` target).
- Scope creep into AICAC-1 (unapproved).
- PHPCS against current codebase may produce a large error baseline; needs a ruleset strategy after lint tooling lands (may need a follow-up to fix or baseline — out of AICAC-2 unless Product says otherwise).

## Out of scope (per backlog)

- WP.org SVN deployment automation.
- Configuring GitHub branch protection (repo-admin / human).
