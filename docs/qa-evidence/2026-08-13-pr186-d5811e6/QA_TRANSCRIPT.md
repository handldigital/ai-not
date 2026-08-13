# PR #186 — TEMPLATES QA transcript

- Pull request: `handldigital/ai-not#186`
- Commit tested: `d5811e637d5910b8cf7ea956299e683544cfadd9`
- Date: 2026-08-13

## Acceptance coverage

1. **Export-first data** — the policy-export payload contained both required `plugin_version` and `exported_at` metadata.
2. **Preview/diff** — Strict, Balanced, and Observe-first each returned a successful non-empty preview (6, 3, and 4 changed rows respectively).
3. **Apply semantics** — all three packs applied successfully, then returned no-op on a repeat apply.
4. **Behavior** — Strict set the deny default and seeded an active plugin Allow; Observe-first enabled audit/Observe-only mode; all packs retained logging.
5. **Conflict safety** — a pre-existing explicit deny rule stayed deny across all pack applications.
6. **Invalid input** — an unknown pack was rejected with `error: unknown_pack`.
7. **Regression** — full PHPUnit suite passed: 473 tests / 2149 assertions.

## Captured result

```json
{
  "export_valid": true,
  "strict": { "apply": "applied", "noop": "noop", "default": "deny" },
  "balanced": { "apply": "applied", "noop": "noop", "default": "allow" },
  "observe_first": { "apply": "applied", "noop": "noop", "audit_only": true },
  "unknown_status": "error",
  "unknown_error": "unknown_pack"
}
```

Sandbox policy and activity state, plus the prior clean checkout, were restored after the fixture.
