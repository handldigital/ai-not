# PR340 / #334 exact-SHA live evidence

- Live plugin: `/Users/handl/Sites/localhost/handl-sandbox/wp-content/plugins/handl-ai-connector-access-control`
- HEAD: `82ac58f961f06174fd0831d8ee2ac56440ade94f`
- Capture: Playwright + Chrome screenshot of live-plugin `Admin::render_page()` HTML (Alerts → Estimated spend) served from a local static server. Apache FastCGI on handl-sandbox returned incomplete headers (500) for authenticated `wp-admin` during this session (objc/php-cgi worker crashes); CLI path uses the same plugin files + site DB.
- Seed: `.scratch/pr340-seed-rates.php` / `.scratch/pr340-render-alerts.php` / `.scratch/pr340-rates-capture-cli.mjs`
- Panels: none stored; version `2026-10-12-qa` stored; air-gap feed off
- CLI: `wp handl-aicac threat-feed status` rate-table lines in `CLI_TRANSCRIPT.txt`
