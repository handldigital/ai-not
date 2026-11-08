# PR505 / #496 AICAC-TAINT WordPress Injection screen evidence @ 792163e

- Exact SHA: `792163e3207fb52eeade8d3da1867a9559affdf9`
- Method: Live sandbox plugin checked out to force-asserted SHA 792163e; WP-CLI qa-admin + Taint::render_page() / Deny_Receipt::render_page() HTML with inlined wp-admin CSS; Playwright local serve of the real wrap. Live SHA restored to 0b2e12a after capture.
- Live plugin path: `/Users/handl/Sites/localhost/handl-sandbox/wp-content/plugins/handl-ai-connector-access-control`
- Restored live SHA: `0b2e12a64ae453532c56aa7905adfbaf9b26771f` (capture-start `0b2e12a64ae453532c56aa7905adfbaf9b26771f` / `0b2e12a64ae453532c56aa7905adfbaf9b26771f`)
- Artifacts: `01-off.png`, `02-warn.png`, `03-deny.png`, `04-receipt-no-matched-text.png`
