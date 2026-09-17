# PR #270 — cost receipt QA

Tested deployed plugin SHA `9667e6331b7b6e381c970bac17165ca7465cddcb` on `https://handl-sandbox/`.

- `INSIGHTS_BUNDLED_AND_NA.png` shows current and previous calendar-month estimate columns, bundled model totals, and `n/a` for an unknown model excluded from totals.
- `INSIGHTS_MODEL_OVERRIDE.png` shows the same real Activity rows recalculated immediately after the temporary `gpt-4o-mini` model-rate override.
- `DASHBOARD_MONTH_TOP_SPENDER.png` shows the month estimate tile and the top-spender sentence.
- `DIGEST_TEST_SENT.png` shows the deployed test-digest send accepted for `haktan+aicac-cost-receipt@handldigital.com`.
- `DIGEST_BODY.txt` is the generated deployed-runtime digest body, including the calendar-month receipt and top-spender lines. The local MailHog HTTP endpoint returned 404, so it could not be used to inspect the post-send message.
- Full suite under the sandbox PHP 8.3 runtime: `795 tests, 4252 assertions` passed.

The temporary policy, model-rate override, retained Activity fixture, and digest-send state were restored after capture.
