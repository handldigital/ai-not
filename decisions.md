# Decisions — AICAC-103 (#24)

## D1: Shared Policy mutation + save_policy (no forked CLI write path)

**Decision:** CLI `set` calls `Policy::apply_family_rule_to_policy()` then `Policy::save_policy()`. The apply helper ends in `sanitize_operations()` — the same sanitizer `Admin::handle_save_rules` assigns into `$policy['operations']` before save.

**Why:** Acceptance criteria forbid a parallel write path. Reusing sanitize + save keeps family allowlists and allow|deny-only storage identical to the Rules tab.

## D2: Known plugins = `get_plugins()` (includes inactive)

**Decision:** `list` and `set` recognition use installed plugin basenames from `get_plugins()`, including inactive plugins. Uninstalled basenames that only linger in the option are rejected on `set` and omitted from `list`.

**Why:** Matches the Rules tab matrix (all installed plugins). The story edge case (“configured then deactivated”) means inactive-but-installed, not deleted. Diverging would allow CLI writes the UI cannot edit.

## D3: Basename is the WordPress plugin file key

**Decision:** `<plugin>` must be the full basename (e.g. `acme-plugin/acme-plugin.php`). The story’s `acme-plugin` example is treated as shorthand, not a directory-only alias.

**Why:** Rules tab and policy storage keys use `get_plugins()` keys. Directory-only matching would add ambiguous resolution outside approved scope.

## D4: Unit-test pure helpers; defer live WP-CLI smoke to Quality

**Decision:** PHPUnit covers `apply_family_rule_to_policy`, `family_rule_rows_for_plugins`, CLI `validate_set_args` / confirmation / public subcommand surface. No end-to-end `wp` binary run in this workspace.

**Why:** Credential-free AgentOps workspace has PHPUnit but not a WordPress + WP-CLI install. AC4 (missing-arg usage) is enforced by WP-CLI’s declared positionals; document for Quality smoke.
