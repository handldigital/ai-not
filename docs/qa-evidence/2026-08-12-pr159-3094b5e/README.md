# QA evidence — PR #159 / #132 AICAC-HOURS

- **Plugin HEAD:** `3094b5e`
- **Sandbox:** https://handl-sandbox/ (qa-admin Playwright; bridge down)
- **Live fixture:** Deny window `QA Deny window` active now (site TZ UTC). Observe + all-day windows staged on other weekdays in Activity settings.
- **Decision-path transcript:** `DECISION_PATH_TRANSCRIPT.txt`
- **PHPUnit QuietHours (DST + overnight):** `PHPUNIT_QUIET_HOURS.txt`

## Captures
| File | Shows |
|------|--------|
| 01 | Dashboard — Deny active / blocked-until banner |
| 02 / 02a | Activity — Deny settings + blocked row tag |
| 03 | Dashboard — Observe/logging banner (normal rules still in effect) |
| 04 | Activity — Observe settings + tagged allow/rule-deny rows |
| 05 | Dashboard — equal-time all-day Deny |
| 06 | Activity — all-day settings |
| 07 | Dashboard — live Deny fixture left for open-verify |
| 08 | Activity — three windows staged (Deny today + Observe/all-day other days) |

## Restore
`wp eval-file` restore from options `handl_aicac_qa132_policy_backup` / `handl_aicac_qa132_log_backup` when QA is done.
