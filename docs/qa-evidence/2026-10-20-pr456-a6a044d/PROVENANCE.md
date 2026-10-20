# PR456 evidence @ a6a044d

- Exact SHA: `a6a044d7c1d55bee4bb2f135837e44f577fa8cdd`
- Capture method: CLI `Fineprint::render_page()` from the exact detached worktree, rendered by isolated Chrome headless profiles.
- `01-empty-ledger.png`: enabled settings, provider URLs, hashes-only/read-only wording, the unchecked-provider table, and empty change ledger.
- `02-changed-ledger.png`: successful provider checks and the dated OpenAI hash-change ledger entry.
- Validation: full PHPUnit suite passed at this SHA: 1,172 tests / 7,365 assertions.
