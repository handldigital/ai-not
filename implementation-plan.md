# Implementation Plan — AICAC-103 (#24)

## Work item

**Issue:** #24 — AICAC-103: WP-CLI command to list and set per-plugin allow/deny rules  
**Spec:** `product-handoff.md` § AICAC-103  
**Scope:** Core per-plugin × capability-family allow/deny/inherit matrix via WP-CLI only.

## Objective

Add `wp aicac rule list` and `wp aicac rule set <plugin-basename> <family> <allow|deny|inherit>` that read/write through the same `Policy::sanitize_operations` + `Policy::save_policy` path used by `Admin::handle_save_rules`, with no parallel write logic and no bulk import (AICAC-102).

## Approach (smallest correct change)

1. Add `Policy::apply_family_rule_to_policy()` — pure mutate of `operations[basename][family]`, then `sanitize_operations` (inherit clears the field). Invalid family/rule → failure without mutation semantics for callers.
2. Add `Policy::set_family_rule()` — `get_policy` → apply → `save_policy` (same persistence path as Rules save).
3. Add `Policy::family_rule_rows_for_plugins()` — rows for every installed plugin (`get_plugins()` shape, including inactive), family columns as `allow`/`deny`/`inherit`.
4. Add `includes/class-handl-aicac-cli.php` behind `defined( 'WP_CLI' ) && WP_CLI`, register `aicac rule` with `list` / `set` subcommands.
5. Load CLI from `Plugin::init()` when WP-CLI is present.
6. Unit-test apply/list helpers and CLI arg validation without requiring a full WP-CLI binary.
7. Minor version bump + `readme.txt` changelog / command docs.

## Acceptance-criteria mapping

| Criterion | Implementation | Test |
|-----------|----------------|------|
| AC1 list table/json for every Rules-tab plugin with family state | CLI `list` + `family_rule_rows_for_plugins` | Unit: rows cover all plugins; inherit default; `--format=json` path asserted via formatter helper / row shape |
| AC2 set validates basename+family, writes via sanitize/save, exit 0 + confirmation | CLI `set` → `set_family_rule` / `apply_family_rule_to_policy` | Unit: apply writes deny; confirmation message builder; basename must be in known plugin map |
| AC3 unrecognized plugin/family → non-zero, no write | CLI validates before write | Unit: invalid plugin/family return error, policy unchanged |
| AC4 missing args → WP-CLI usage, non-zero, no write | Declared positional args on `set` | Documented; WP-CLI enforces (no custom write on incomplete invoke) |
| AC5 single-field set only | No bulk/import subcommands | Static: only `list`/`set` registered |

## Risks

- Full WP-CLI integration cannot be executed end-to-end in this credential-free unit-test workspace; Quality should smoke-test `wp aicac rule list|set` on a WP install with WP-CLI.
- `save_policy` side effects (cron schedule helpers) remain unchanged; CLI must not fork a lighter write path.
- Example basename `acme-plugin` in the story is shorthand; real keys are WordPress plugin basenames (`dir/file.php`) as used by the Rules tab.

## Out of scope

- Kill-switch, model-force, denied-tools, alerts CLI.
- Bulk JSON import (AICAC-102).
- Plugin-level (outer gate) allow/deny via CLI — story is family matrix only.
