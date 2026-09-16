# PR #261 — Auditor role QA evidence

**Issue:** #183 AICAC-AUDITOR-ROLE
**PR:** https://github.com/handldigital/ai-not/pull/261

## Captures

| File | Tested state | Acceptance criteria covered |
| --- | --- | --- |
| `01-admin-role-grant.png` | `95a2356d74481d6690e2a7f43c964dade3aacd2c` | An administrator can grant the Editor role view-only access; the matrix shows Editor as view-only and not manage. |
| `02-editor-rules-read-only.png` | `7390deaa6ddad7e3bde33949c17bdbd5ed852426` | An Editor with `handl_aicac_view` reaches Rules, sees the read-only notice, and mutation controls are disabled. A real forged save POST returned `You do not have permission to change AI Access Control settings.` |
| `03-editor-activity-export.png` | `7390deaa6ddad7e3bde33949c17bdbd5ed852426` | The same Editor can open Activity and use Download CSV. The request returned `200`, `text/csv; charset=utf-8`, and a CSV attachment. |
| `04-editor-site-health-info.png` | `7390deaa6ddad7e3bde33949c17bdbd5ed852426` | The same Editor can open WordPress Site Health → Info; the page returned HTTP `200`. |

The editor fixture was `aicacqa183` with email `haktan+auditor-role@handldigital.com` and only the Editor role.
