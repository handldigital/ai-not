# PR516 / #501 AICAC-OPTOUT WordPress AI request flags evidence @ 1a62d00

- Exact SHA: `1a62d00c8a2443471d618ee37a33928be1413c33`
- Method: Live sandbox plugin checked out to force-asserted SHA 1a62d00; WP-CLI qa-admin + Optout::render_page() / apply/preempt + Deny_Receipt::render_page HTML with inlined wp-admin CSS; Playwright local serve of the real wrap. Live SHA restored to 0b2e12a after capture.
- Live plugin path: `/Users/handl/Sites/localhost/handl-sandbox/wp-content/plugins/handl-ai-connector-access-control`
- Restored live SHA: `0b2e12a64ae453532c56aa7905adfbaf9b26771f` (capture-start `0b2e12a64ae453532c56aa7905adfbaf9b26771f` / `0b2e12a64ae453532c56aa7905adfbaf9b26771f`)
- Artifacts: `01-openai-flag-added.png`, `02-unsupported-warn-unchanged.png`, `03-strict-deny-receipt.png`, `04-feature-off-unchanged.png`
