# Decisions — AICAC-1

## D0: No further production diff this cycle

**Decision:** Treat AICAC-1 as complete on `main` (PR #34 / `b73f4b6`);
re-verify with `composer test` and refresh handoff artifacts only.

**Why:** This implement job was queued against issue #19 after a prior
AgentOps implement already landed the harness, suite, and CI workflow.
Re-implementing would duplicate scope and risk unrelated churn.

## D1: Lightweight PHPUnit stubs instead of wp-phpunit

**Decision:** Unit-test `Policy::evaluate()`, `Operations::*`, and
`Model_Force::resolve_route()` under PHPUnit 9 with a minimal bootstrap
(`ABSPATH` + `sanitize_text_field` / `__` stubs), not a full WordPress
test install.

**Why:** Acceptance criteria allow “wp-phpunit or equivalent.” Pure
decision methods need only a policy array / operation string. Full WP core
+ DB would slow first CI runs without improving branch coverage for this
story. Stubs are the smallest reversible harness.

**Trade-off:** Sanitization stubs may diverge from core on exotic strings.
Decision-engine branching does not depend on those edges.

## D2: PHPUnit 9.6 (not 10+)

**Decision:** Require `phpunit/phpunit: ^9.6`.

**Why:** Plugin declares `Requires PHP: 7.4`. PHPUnit 10+ needs PHP 8.1+.
PHPUnit 9 keeps the suite conceptually aligned with the declared minimum.

## D3: CI uses PHP 8.2

**Decision:** `.github/workflows/phpunit.yml` runs on PHP 8.2 (same as the
AgentOps validation image / lockfile platform).

**Why:** `composer.lock` resolves modern PHPUnit 9 transitive deps that
prefer PHP 8.x. One green PR job satisfies the release-evidence AC; a 7.4
matrix can be added later without changing the suite.

## D4: New `phpunit.yml` workflow (do not alter release trigger)

**Decision:** Add a dedicated workflow for PR/push to `main`; leave
`release.yml` tag-triggered publish path intact aside from packaging excludes.

**Why:** Product handoff: release.yml only builds/publishes a tagged zip —
CI for tests is a new job/workflow, not a modification of the release path.

## D5: Exclude test tooling from release zip

**Decision:** `release.yml` rsync excludes `vendor/`, `tests/`, Composer
files, `phpunit.xml.dist`, and `*.md`.

**Why:** Prevents shipping PHPUnit/vendor into the WordPress.org plugin zip.

## D6: AICAC-2 stays out of this PR

**Decision:** Do not persist wp_mail / cron failures in this change.

**Why:** Product explicitly split P2 into AICAC-2 so it does not block the
PHPUnit harness / CI evidence for AICAC-1.

## D7: Cover all evaluate() reason branches including tool_armed

**Decision:** Add deny-at-arming tests (`tool_armed`) and
`OperationsFamilyTest` in addition to prior allow/deny/kill-switch coverage.

**Why:** AC requires at least one test per decision-logic branch;
`evaluate()` documents five reasons including `tool_armed`.
