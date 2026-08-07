# Decisions — AICAC-1

## D1: Lightweight PHPUnit stubs instead of wp-phpunit / WP_UnitTestCase

**Decision:** Unit-test `Policy::evaluate()` and `Model_Force::resolve_route()` under PHPUnit 9 with a minimal bootstrap (`ABSPATH` + `sanitize_text_field` / `__` stubs), not a full WordPress test install.

**Why:**
- Acceptance criteria require a single local command covering policy allow/deny branches; those methods are pure given a policy array.
- wp-phpunit needs WordPress core checkout, DB, and heavier CI setup — deferred to a later story if integration coverage is needed.
- Desired behavior mentioned “wp-phpunit or WP_UnitTestCase”; AC does not require that scaffold. Stubs satisfy AC with the smallest reversible harness.

**Trade-off:** Sanitization stubs may diverge from WordPress core edge cases. Decision-engine branching does not depend on those edges.

## D2: PHPUnit 9.6 (not 10+)

**Decision:** Require `phpunit/phpunit: ^9.6`.

**Why:** Plugin declares `Requires PHP: 7.4`. PHPUnit 10+ needs PHP 8.1+. PHPUnit 9 keeps the suite runnable on the declared minimum.

## D3: Include Model_Force route tests beyond formal AC bullets

**Decision:** Add `ModelForceResolveRouteTest` covering pinned plugin, unattributed gap, unattributed force opt-in, and no_rule.

**Why:** Story desired_behavior explicitly names model-force route matching alongside the policy engine. Cost is four small pure-unit tests; no production code change.

## D4: Do not modify production plugin code for testability

**Decision:** No production changes to Policy / Model_Force / visibility of private methods.

**Why:** AC permissions_security says do not weaken controls to make code testable. Public `evaluate()` / `resolve_route()` already expose the decision surface.

## D5: Documented command is `composer test`

**Decision:** Single documented command is `composer test` (maps to `vendor/bin/phpunit` via composer scripts). Requires `composer install` once and PHP 7.4+ with xml/dom extensions.
