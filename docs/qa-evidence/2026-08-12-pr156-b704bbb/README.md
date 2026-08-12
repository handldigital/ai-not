# QA evidence — PR #156 / #150 AICAC-STORAGE

- **Plugin HEAD:** `b704bbb`
- **Sandbox:** https://handl-sandbox/ (qa-admin Playwright; bridge down)
- **Scope:** Activity settings retention hints only (no Save)

## Captures
| File | Shows |
|------|--------|
| 01 / 01a | Footprint + oldest age + retention estimates |
| 02 / 02a / 02b | Suggested 56-day prefill (field=`56`); no Save |
| 03 / 03a | Insights retention-gap warning after typing `7` |

## Policy integrity
`handl_aicac_policy` sha256 `3b060411db2af45713a5cec95a6802607a562225485a58f55ccb8056cd3a310d` unchanged before → after prefill → after warning UI → after navigate-away. See `NO_POLICY_CHANGE_TRANSCRIPT.txt`.
