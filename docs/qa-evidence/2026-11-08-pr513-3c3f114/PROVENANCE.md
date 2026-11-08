# PR513 / #497 AICAC-TRIPWIRE WordPress Secret tripwire evidence @ 3c3f114

- Exact SHA: `3c3f114560fdba4a883213b83a9fd67d68aac55b`
- Method: Live sandbox plugin checked out to force-asserted SHA 3c3f114; WP-CLI qa-admin + Tripwire::render_page() / apply_to_event + Deny_Receipt::render_page HTML with inlined wp-admin CSS; Playwright local serve of the real wrap. Live SHA restored to 0b2e12a after capture.
- Live plugin path: `/Users/handl/Sites/localhost/handl-sandbox/wp-content/plugins/handl-ai-connector-access-control`
- Restored live SHA: `0b2e12a64ae453532c56aa7905adfbaf9b26771f` (capture-start `0b2e12a64ae453532c56aa7905adfbaf9b26771f` / `0b2e12a64ae453532c56aa7905adfbaf9b26771f`)
- Artifacts: `01-default-on.png`, `02-warn-override.png`, `03-db-password-deny.png`, `04-provider-key-deny.png`, `05-warn-alert-digest.png`
