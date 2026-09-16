# PR #266 — MCP gate QA evidence

**Issue:** #239 AICAC-MCP-GATE

## Live CLI evidence

`CLI_TRANSCRIPT.txt` is captured on `https://handl-sandbox/` with the live plugin at `0e79a7a1609b21a21f94d26d5c43b470affbd89a`.

It demonstrates the v1 CLI behavior:

- A clean state reports `inherit` (which allows) and no per-plugin rules.
- A temporary non-installed fixture plugin accepts a `deny` rule and `get` reports it.
- Setting that fixture back to `inherit` removes it; the final `get` returns to the clean state.

The full PHPUnit suite also passed at this SHA: 805 tests, 4,279 assertions.
