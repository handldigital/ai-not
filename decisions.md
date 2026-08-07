# Decisions — AICAC-102 (#23)

## D1: Full replace (not merge) for confirmed import

**Decision:** Confirmed import atomically replaces the entire `Plugin::OPTION_KEY` value via `Policy::save_policy`, after stripping export metadata. UI copy documents “full replace.”

**Why:** Product default for AC3; avoids ambiguous per-key merge semantics across environments. Agencies promoting a known-good ruleset expect the target to match the source, including empty rulesets used as an explicit reset (with preview).

## D2: Flat export schema with top-level metadata

**Decision:** Export is a single JSON object: current policy keys plus required `plugin_version` and `exported_at` at the top level (not nested under a `policy` wrapper).

**Why:** Matches AC1 wording (“full current policy option, plus …”). Required-key validation (AC4) checks those two metadata fields. Unknown keys beyond meta + known policy keys are ignored with a notice (AC5).

## D3: Pure `Policy_Transfer` helpers; write only through `Policy::save_policy`

**Decision:** Parse/diff/build live in `Policy_Transfer`; admin handlers never `update_option` the policy directly. Confirm calls `Policy::save_policy` (same sanitize path as `handle_save_rules`).

**Why:** Story dependency forbids a bypass write path. Keeps unit tests free of WordPress option I/O while still locking the confirm→`save_policy` wiring in `AdminAuthzCoverageTest`.

## D4: Preview via per-user transient; upload-only

**Decision:** Valid upload stores pending policy in a user-scoped transient (15 min); confirm reads it. No server filesystem path input; max upload size 1MB.

**Why:** Separates preview (no write) from confirm (write); avoids posting large JSON back in a hidden field; satisfies permissions/security constraints.

## D5: AC6 secrets confirmation

**Decision:** Ship without an export denylist. Known policy keys contain no API keys, passwords, or credentials. `alert_email` is an operator contact address (not a secret) and is part of the shared policy option, so it is included in full-replace transfer.

**Why:** Grep + unit test over `known_policy_keys()`; if secrets are added later they must be excluded from `build_export`.
