# PR338 / #302 exact-SHA live evidence

- Live plugin: `/Users/handl/Sites/localhost/handl-sandbox/wp-content/plugins/handl-ai-connector-access-control`
- HEAD: `93da95e05400b7543cd96f1c99e310d233b9514f`
- Capture: Playwright + Chrome `--host-resolver-rules=MAP handl-sandbox 127.0.0.1`
- Seed: `.scratch/pr338-seed-latency.php` / `.scratch/pr338-latency-capture.mjs`
- Panels: empty rolling-hour state; openai Timed calls / Median / 95th percentile row
- Copy: Krusty PASS at 93da95e; recovery/re-cross dedupe covered by LatencyAlertTest
