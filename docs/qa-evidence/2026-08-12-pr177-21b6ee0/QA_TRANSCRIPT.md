# PR #177 — DIGEST QA transcript

- Pull request: `handldigital/ai-not#177`
- Commit tested: `21b6ee0b5ff4b339f660dd9d4c7b6cb0cf6ad54b`
- Date: 2026-08-12

## Acceptance coverage

1. **Weekly digest delivery** — enabled digest with retained AI activity sent successfully through the controlled sandbox mail path.
2. **Weekly de-duplication** — a second attempt in the same week returned `already_sent`.
3. **Email format and copy** — the message was multipart, included the approved previous-seven-days wording, and included the estimate disclaimer.
4. **Empty week** — with the explicit empty-week option enabled, the digest sent successfully with no activity retained.
5. **Test email** — the digest test-email path returned `sent`.
6. **Regression** — full PHPUnit suite passed: 451 tests / 2006 assertions at the tested commit.

## Captured result

```json
{
  "first_sent": true,
  "second_status": "already_sent",
  "multipart": true,
  "body_has_previous_7_days": true,
  "body_has_estimate_disclaimer": true,
  "empty_week_sent": true,
  "empty_week_status": "sent",
  "test_status": "sent",
  "mail_count": 3
}
```

The authorized plus-address fixture was used only within controlled mail capture. Sandbox policy, retained log, and sent-week state were restored after the fixture; no recipient address or message body is published here.
