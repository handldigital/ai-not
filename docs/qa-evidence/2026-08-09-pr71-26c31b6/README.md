# AICAC-25 test-email QA evidence

- PR: #71
- Issue: #51
- Tested tip: `26c31b6a0bacfba23cb95227150bbf63666801b1`
- Environment: `https://handl-sandbox/` on MAMP PHP 8.3.30 with local MailHog

## Evidence

- `cooldown.png` shows both detached **Send test email** controls beside their intended settings, the saved plus-address recipient, and the shared one-minute cooldown notice after an immediate second request. This covers the control placement and rate-limit/error-path acceptance criteria.
- `success-notice.png` shows the normal success notice for the actual `sent` result returned by the MailHog-backed test send, including the explicit distinction between WordPress accepting the message and inbox delivery.
- `mailhog-denial.png` shows the denial-alert path received by MailHog at the saved recipient. It is explicitly a test, states that no denial occurred, and contains no prompt, user, or call data.
- `mailhog-weekly.png` shows the weekly-report path received by MailHog at the same saved recipient. It is distinctly labelled as a test weekly report and contains no prompt, user, or call data.

The WordPress-admin clicks initially returned the intended failure notice because this sandbox's default From value, `wordpress@handl-sandbox`, is invalid under PHPMailer. MailHog itself is healthy. To verify the two successful backend sends without changing sandbox configuration, the plugin's actual `Alerts::send_test_email()` paths were run through the same MAMP PHP configuration with a process-local valid From filter; both messages arrived in MailHog. The UI cooldown was exercised separately in the browser.

## Automated verification

At the tested tip, `vendor/bin/phpunit` completed successfully: **138 tests, 549 assertions**.

## Media validation

- `cooldown.png`: 2560 × 1289 PNG, SHA-256 `9ecb8aa92b163853d03d6251677de9702ea374342f313a09ce6347ea0a0e856d`.
- `success-notice.png`: 2560 × 1289 PNG, SHA-256 `99a9a058d629119500314df0fbed4a082643b24858aa38339c54b961ccb04219`.
- `mailhog-denial.png`: 2560 × 1233 PNG, SHA-256 `7bf8c7db5c493c1de514ac6c0f35734924941ab8a7d8cef8e3a7bf55db5924aa`.
- `mailhog-weekly.png`: 2560 × 1233 PNG, SHA-256 `977b6989211c25d5f16391df811d7de5ee49aa7b3868347df3d214a9e1b3414e`.
