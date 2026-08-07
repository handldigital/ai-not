# Decisions — AICAC-3 (#21)

## D1: Verification-only; do not remediate under this story

**Decision:** Document authz coverage and findings; leave production
`class-handl-aicac-admin.php` (and related includes) unchanged except for
adding a static PHPUnit lock and the audit artifact.

**Why:** Acceptance criteria explicitly route findings through Quality and
Release Gate and forbid fixing gaps under AICAC-3. Changing nonce/capability
placement would expand unapproved product scope.

## D2: Treat shared `render_page` gate as valid capability coverage

**Decision:** Count `current_user_can( 'manage_options' )` at
`render_page` L70 (plus `add_options_page` menu capability) as the
capability mechanism for every POST mutator, rather than requiring each
private helper to re-check.

**Why:** All mutating POST branches execute only after that gate inside the
same method; private helpers have no other call sites. WordPress also
enforces the menu capability before invoking the page callback. Requiring
duplicate checks would be a defense-in-depth product change (see finding
F-AICAC-3-2), not a current coverage failure.

## D3: Settings API = explicit “not found”

**Decision:** Record Settings API implicit nonce/capability handling as
**not found** for every handler.

**Why:** The plugin never calls `register_setting` / `settings_fields`;
saves are custom POST + `check_admin_referer`. Stating “not found” satisfies
the acceptance criterion’s distinct outcome requirement.

## D4: Encode inventory in a static source unit test

**Decision:** Add `tests/Unit/AdminAuthzCoverageTest.php` that reads the
admin class source and asserts shared gate, per-action nonces, match count
(5), private mutators, and absence of Settings API / AJAX / admin-post
hooks.

**Why:** Makes the acceptance criteria reproducible without a full WordPress
install, and fails CI if a new `handl_aicac_action` branch appears without an
adjacent `check_admin_referer`. Complements the human-readable
`aicac-3-authz-coverage.md` inventory for Quality.
