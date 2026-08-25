# PR #231 — inbox email actions QA transcript

- PR: #231 / issue #225
- Deployed SHA: `04d2059b92b18a4bb7787cb1b535ebaf5e034805`
- Fixture: disposable WordPress install at `http://127.0.0.1:8893`
- Date: 2026-08-25

## Acceptance evidence

| Acceptance criterion | Executed result |
|---|---|
| Denial email includes signed actions | A real denial email was sent to `haktan+inbox-actions@handldigital.com` and captured in local MailHog. Its plain-text and HTML parts included Allow 24h, Snooze 7d, and Open rule signed links. |
| Login and confirmation precede changes | Authenticated HTTP GET of each state-changing link rendered `Confirm this email action`; no state change occurred until the confirmation POST. |
| Allow 24h works | Confirm POST rendered `This plugin is allowed for 24 hours.` Policy persisted the target plugin as `allow` with an expiry within the expected 24-hour window. |
| Snooze 7d works | Confirm POST rendered `Alerts for this plugin are snoozed for 7 days.` The stored snooze was within the expected 7-day window. |
| Expired link is safe | A MailHog-captured signed link minted 49 hours in the past rendered `This link has expired. Nothing was changed.` |
| Replay is safe | Re-opening the consumed Allow link rendered `This link was already used. Nothing was changed.` |

The fixture used a QA-only mu-plugin SMTP override to send to local MailHog at `127.0.0.1:1025`; product code was unchanged.

## Regression suite

`vendor/bin/phpunit` at the deployed SHA: **639 tests, 3484 assertions, passing**.
