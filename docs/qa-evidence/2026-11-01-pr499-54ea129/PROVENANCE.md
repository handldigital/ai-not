# PR499 / #475 AICAC-LUGGAGE WordPress Outbound media evidence @ 54ea129

- Exact SHA: `54ea12908be7ebd0c809a6d49691f0b3791b04ed`
- Method: Live sandbox plugin checked out to force-asserted SHA 54ea129; WP-CLI qa-admin + Luggage::render_page() HTML with inlined wp-admin CSS; Playwright local serve of the real Outbound media wrap. Admin HTTP 500 is Spot_Check::maybe_sample TypeError on init (empty-string from do_action). Live SHA restored after capture.
- Live plugin path: `/Users/handl/Sites/localhost/handl-sandbox/wp-content/plugins/handl-ai-connector-access-control`
- Restored live SHA: `befdfa2cf9ca088d7ebedb04b1ac6cf73d3eb0e3` (`database/489-detour`)
- Artifacts: `01-wired-init.png`, `02-file-upload-detected.png`, `03-url-and-homebody.png`, `04-payload-never-stored.png`
