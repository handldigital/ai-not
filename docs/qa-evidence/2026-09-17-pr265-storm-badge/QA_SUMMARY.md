# PR #265 — storm badge QA

Tested deployed plugin SHA `ae75d1822eedfd858264829d97f4abdc1565efbd` on `https://handl-sandbox/`.

- `ACTIVITY_STORM_NORMAL.png` is a browser capture of Activity showing a normal deny row without a storm badge and a collapsed retry-storm row with `REPEATED 2 MORE TIMES`.
- `CSV_EXPORT_TRANSCRIPT.json` is the authenticated `Download CSV` response from that Activity screen. It records HTTP 200 / `text/csv`, the `retry_storm_count` header, `0` for the normal fixture row, and `2` for the collapsed storm row.
- Full suite under the sandbox PHP 8.3 runtime: `791 tests, 4241 assertions` passed at the tested SHA.

The temporary QA fixture and altered runtime settings were restored immediately after capture.
