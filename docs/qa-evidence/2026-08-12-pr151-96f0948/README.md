# QA evidence — PR #151 / #141 AICAC-NEWPLUGIN

- **HEAD:** `96f0948`
- **Sandbox deploy:** `/Users/handl/Sites/localhost/handl-sandbox/wp-content/plugins/handl-ai-connector-access-control` @ `96f0948`
- **QA identity:** `qa-admin` (dedicated; owner admin not used)
- **Captured:** 2026-08-12 via Playwright headless (qa-admin session)

## Fixtures (staged then decision-pathed)

| Mode | Plugin | Basename | First-seen interim | Rule while pending | evaluate prevent |
|------|--------|----------|--------------------|--------------------|------------------|
| Block | Companion Auto Update | `companion-auto-update/companion-auto-update.php` | deny | `deny` | yes |
| Allow-and-log | Bit Form | `bit-form/bitforms.php` | observe | (none) / Default | no |

## AC map

| Evidence file | Acceptance criteria |
|---------------|---------------------|
| `01-dashboard-pending-review.png` | Dashboard: “2 plugins awaiting AI access review” with Bit Form + Companion links |
| `02-settings-allow-and-log.png` | Settings: **New plugins require review** ON; **Before you review** = Allow and log AI calls |
| `03-settings-block-ai-calls.png` | Same block with **Block AI calls** selected (interim option labels) |
| `04-rules-needs-review-both.png` | Rules matrix: both fixtures show **Needs review** badge; Companion Deny; Bit Form Default |
| `05-rules-bit-form-default-observe.png` | Bit Form row: Needs review + Default (observe interim, no forced deny) |
| `06-rules-companion-deny-block.png` | Companion row: Needs review + Deny (block interim first-seen) |
| `07-admin-notice-writing.png` | Admin notice on non-AICAC screen: “2 new plugins need an AI access decision.” |
| `08-dashboard-before-decision.png` | Pre-decision pending count = 2 |
| `09-dashboard-after-allow-companion.png` | Decision path Block→Allow: pending drops to Bit Form only |
| `10-badges-after-allow-companion.png` | Companion badge cleared; Bit Form still Needs review |
| `11-dashboard-after-both-decisions.png` | Decision path Allow-and-log→Deny: no pending banner |
| `12-badges-after-both-decisions.png` | No Needs review badges remain |

## Decision path results

1. **Block → Allow** on Companion: pending cleared, rule=allow, evaluate prevent=no.
2. **Allow-and-log → Deny** on Bit Form: pending cleared, rule=deny, evaluate prevent=yes.
3. Final: pending list empty.

## Notes

- Settings live under Rules → collapsible **Settings** `<details>` panel.
- `plugins.php` is blocked for qa-admin on this sandbox (file-mod restriction); admin notice captured on **Settings → Writing** instead.
- Credentials: `/Users/handl/.buzz/.scratch/sandbox-qa-admin.credentials` (mode 600). Do not post password to channel/PR.
