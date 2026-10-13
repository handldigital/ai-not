# PR432 / #427 POSTCARD evidence @ 4d6e2d7

- Product SHA: `4d6e2d787d98a17e46d3764acd80dd7c336e6f19`
- Live plugin path: `/Users/handl/Sites/localhost/handl-sandbox/wp-content/plugins/handl-ai-connector-access-control`
- Capture: CLI `Postcard::render_page` + `build_subject`/`build_body` HTML served locally; Playwright screenshots.
- Seed: alert_email=alerts@gmail.com, webhook=https://hooks.example-automation.com/..., postcard enabled+outbound; findings assert domain/host only.
- Panels: 01 findings+exhaust inventory table; 02 [POSTCARD] alert redaction (categories, no sample content / full addresses).
