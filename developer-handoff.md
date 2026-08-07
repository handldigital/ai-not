# Developer Handoff — AICAC-103 (#24)

## Work item ID

Issue #24 — AICAC-103: WP-CLI command to list and set per-plugin allow/deny rules

## Summary of behavior implemented

Added WP-CLI commands `wp aicac rule list` (table default, `--format=json`) and `wp aicac rule set <plugin> <family> <allow|deny|inherit>`. List covers every installed plugin from `get_plugins()` (active and inactive) with family-level state. Set validates basename against that set and family against `Operations::families()`, then persists via `Policy::apply_family_rule_to_policy()` → `sanitize_operations()` → `save_policy()` (same sanitize/save path as `Admin::handle_save_rules`). No bulk import. Plugin version bumped to 1.0.15; FAQ + changelog document the commands.

## Files changed

- `includes/class-handl-aicac-cli.php` — new CLI command class (`aicac rule` list/set)
- `includes/class-handl-aicac-policy.php` — `apply_family_rule_to_policy`, `set_family_rule`, `family_rule_rows_for_plugins`
- `includes/class-handl-aicac-plugin.php` — load/register CLI when `WP_CLI` is defined
- `handl-ai-connector-access-control.php` — version 1.0.15
- `readme.txt` — stable tag, FAQ, changelog
- `tests/Unit/FamilyRuleCliTest.php` — unit coverage for AC helpers
- `product-handoff.md` — copied story source for reviewers
- `implementation-plan.md`, `decisions.md`, `test-results.md`, `developer-handoff.md`

## Acceptance-criteria-to-test mapping

| Criterion | Evidence |
|-----------|----------|
| AC1 list every known plugin family state; table / `--format=json` | `family_rule_rows_for_plugins` tests; CLI `list_` uses table or `WP_CLI::print_value` json |
| AC2 set validates + writes via sanitize/save + confirmation | `test_apply_family_rule_sets_deny`; `set_confirmation_message`; `set_family_rule` → `save_policy` |
| AC3 unrecognized plugin/family → error, no write | `test_cli_validate_rejects_*`; `test_apply_family_rule_rejects_unknown_family` |
| AC4 missing required args → WP-CLI usage, no write | Declared `<plugin> <family> <rule>` positionals on `set`; defensive count check |
| AC5 single-field only | `test_cli_public_subcommands_are_list_and_set_only` |

## Commands executed

```bash
export PATH="/home/ubuntu/php-runtime:$PATH"
composer install --no-interaction
composer test
php -l includes/class-handl-aicac-cli.php
php -l includes/class-handl-aicac-policy.php
php -l includes/class-handl-aicac-plugin.php
php -l tests/Unit/FamilyRuleCliTest.php
php -l handl-ai-connector-access-control.php
```

## Test results

```
OK (54 tests, 158 assertions)
```

Full capture: `test-results.md`.

## Data or schema changes

None. Reuses existing `handl_aicac_policy` option `operations` map shape.

## Configuration changes

None (runtime feature gated on WP-CLI presence).

## Security considerations

- CLI trust model: shell/WP-CLI access (no extra capability gate), per story.
- Writes cannot bypass UI family allowlist: only `Operations::families()`; invalid keys dropped by `sanitize_operations`.
- No secrets logged; confirmation messages use basename/family/rule only.

## Known limitations

- End-to-end `wp` binary not exercised in this workspace — Quality should smoke-test list/set on a WP install.
- Plugin-level (outer gate) allow/deny is not exposed on CLI (family matrix only).
- Story example `acme-plugin` is shorthand; operators must pass full basename `dir/file.php`.

## Rollback considerations

- Revert the listed files / version bump. Existing options remain valid; unused CLI registration has no effect when code is removed.

## Remaining risks

- Live WP-CLI arg parsing / `format_items` behavior needs install smoke (especially `@subcommand list` / `list_` mapping).
- Uninstalled plugins with leftover option rows are not listable/settable (intentional Rules-tab parity).

## Requested next action

Quality and Release Gate: review diff + `FamilyRuleCliTest`, then smoke `wp aicac rule list`, `list --format=json`, successful `set`, invalid plugin/family (non-zero, no write), and missing-arg usage on a WordPress + WP-CLI environment.

---

STATUS: READY  
WORK_ITEM: #24 / AICAC-103  
COMPLETED: WP-CLI `aicac rule list|set` via Policy sanitize/save path; inactive-plugin parity; unit tests; v1.0.15 readme; composer test OK (54/158)  
EVIDENCE: implementation-plan.md; decisions.md; test-results.md; developer-handoff.md; tests/Unit/FamilyRuleCliTest.php; `composer test` OK (54 tests, 158 assertions); php -l clean on touched PHP  
DECISIONS: Shared apply+sanitize+save_policy; known plugins=get_plugins() incl. inactive; full basename required; unit helpers only (no live wp)  
RISKS: No live WP-CLI smoke in workspace; list_→list mapping should be verified on install  
NEXT_ACTION: Quality review + WP-CLI smoke of list/set success and error paths  
NEXT_OWNER: QUALITY
