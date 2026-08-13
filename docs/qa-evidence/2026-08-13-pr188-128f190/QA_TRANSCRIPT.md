# PR #188 — scheduled policy backup QA transcript

- Pull request: `handldigital/ai-not#188`
- Commit tested: `128f19054deab4f8f887ae9d2568f13ded6e7c0a`
- Date: 2026-08-13

## Acceptance coverage

1. **Weekly opt-in schedule** — enabled backup scheduled its weekly cron; disabling it removed the schedule.
2. **Delivery** — the first due run returned `sent`; the same-week repeat returned `already_sent` and did not send a second message.
3. **Mail and attachment** — controlled delivery used the shared multipart email template and carried one JSON attachment.
4. **Latest backup** — the stored latest backup was present, valid JSON, and retained the tested deny default for later download/compare.
5. **Regression** — full PHPUnit suite passed: 473 tests / 2146 assertions.

## Captured result

```json
{
  "scheduled": true,
  "first_status": "sent",
  "second_status": "already_sent",
  "mail_count": 1,
  "multipart": true,
  "attachment_count": 1,
  "latest_present": true,
  "latest_json_valid": true,
  "latest_policy_default": "deny",
  "disabled_unscheduled": true
}
```

The approved plus-address was used only inside controlled mail capture. Sandbox options and the prior clean checkout were restored after testing.
