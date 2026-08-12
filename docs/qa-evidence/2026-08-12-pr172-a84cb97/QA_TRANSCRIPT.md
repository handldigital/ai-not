# PR #172 — EMAIL-BRAND QA transcript

- Pull request: `handldigital/ai-not#172`
- Commit tested: `a84cb9798220402939b530efaeb9d76ea83a5a7f`
- Date: 2026-08-12

## Acceptance coverage

1. **Shared email chrome** — sandbox composition produced the approved product/site header, intro, and footer in both alternatives.
2. **Multipart delivery** — the controlled WordPress `safe_wp_mail()` path emitted `multipart/alternative` with both `text/plain; charset=UTF-8` and `text/html; charset=UTF-8` parts.
3. **Existing content preserved and private** — the exact two-line content block was recoverable between the HandL content markers; the recipient was absent from the rendered body.
4. **Real transport** — one authorized plus-addressed sandbox QA message was handed to the configured WordPress mail transport, which returned accepted.

## Captured result

```json
{
  "accepted": true,
  "multipart": true,
  "plain_part": true,
  "html_part": true,
  "content_exact": true,
  "recipient_absent_from_body": true,
  "shared_intro": true,
  "shared_footer": true,
  "transport_accepted": true
}
```

## Notes

MailHog was not running on the local sandbox (`localhost:8025` refused the connection), so a controlled `pre_wp_mail` capture was used for the visual-equivalent multipart inspection. The live WordPress transport acceptance was exercised separately with the approved QA fixture. No recipient address or message content is included in this public artifact.
