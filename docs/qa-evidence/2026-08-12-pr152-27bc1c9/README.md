# QA evidence — PR #152 / #146 AICAC-DIFF

- **HEAD (feature):** `27bc1c9`
- **Sandbox deploy:** `/Users/handl/Sites/localhost/handl-sandbox/wp-content/plugins/handl-ai-connector-access-control` @ `27bc1c9`
- **QA identity:** `qa-admin` (dedicated; owner admin not used)
- **Captured:** 2026-08-12 via Playwright headless (qa-admin session)
- **Fixtures:** `/Users/handl/.buzz/.scratch/aicac-146-qa-fixtures/`

## AC map

| Evidence file | Acceptance criteria |
|---------------|---------------------|
| `01-rules-compare-control.png` | Rules tab shows **Compare with current** + Compare button (read-only help text) |
| `02-valid-compare-diff-and-version-notice.png` | Valid export → **Compare with uploaded backup** + Setting/Current/In backup table + version-recognition notice |
| `02a-version-recognition-notice.png` | Unknown keys `another_new_key`, `future_feature_x` called out |
| `02b-diff-table.png` | Diff rows only (Default policy Allow→Deny, Learn mode Off→On, etc.) |
| `03-invalid-compare-error.png` | Invalid export → Compare failed / not a valid HandL rules export; rules unchanged |
| `READ_ONLY_TRANSCRIPT.txt` | Policy option sha256 unchanged across valid + invalid compares |

## Read-only proof

`handl_aicac_policy` sha256 stayed `4897c40659ef90688a051668f21955ff2f37124a0e316e87207c6894040859ee` before, after valid compare, and after invalid compare. No Apply / Confirm button on compare preview.

## Notes

- Bridge/browser discovery was down; Database captured via qa-admin Playwright for Frink Luna to open-verify public renders.
- Credentials: `/Users/handl/.buzz/.scratch/sandbox-qa-admin.credentials` (mode 600). Do not post password to channel/PR.
