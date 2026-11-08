# PR509 / #506 AICAC-LITMUS WordPress Pattern test evidence @ 65622fd

- Exact SHA: `65622fdedfea81d028b7982dea4c1f1e956bc4f7`
- Method: Live sandbox plugin checked out to force-asserted SHA 65622fd; WP-CLI qa-admin + Taint::render_page() / Litmus::render_section() HTML with inlined wp-admin CSS; Playwright local serve of the real Pattern test wrap. Live SHA restored to 0b2e12a after capture.
- Live plugin path: `/Users/handl/Sites/localhost/handl-sandbox/wp-content/plugins/handl-ai-connector-access-control`
- Restored live SHA: `0b2e12a64ae453532c56aa7905adfbaf9b26771f` (capture-start `0b2e12a64ae453532c56aa7905adfbaf9b26771f` / `0b2e12a64ae453532c56aa7905adfbaf9b26771f`)
- Artifacts: `01-empty-test.png`, `02-class-only-matches.png`, `03-mode-preview.png`, `04-input-limit.png`
