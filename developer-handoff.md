# Developer Handoff — AICAC-101 (#22)

## Work item ID

Issue #22 — AICAC-101: CSV export of the retained audit log

## Summary of behavior implemented

Activity tab gains an **Export CSV** control. With ≥1 retained log row, a
`manage_options`-gated POST (`export_csv` + `handl_aicac_export_csv` nonce)
downloads an RFC 4180 `.csv` of all retained rows matching active
`parse_log_filters` filters (newest first; not capped at the table’s 50-row
window). Zero retained rows disables the control with “No log entries yet.”
`direct_http` rows include host/URI; chatty-host collapsed rows export as one
row with aggregate `count`. Version bumped to **1.0.15**.

## Files changed

- `includes/class-handl-aicac-log-csv.php` — new CSV builder
- `includes/class-handl-aicac-admin.php` — export UI, dispatch, `handle_export_csv`
- `includes/class-handl-aicac-plugin.php` — require Log_Csv
- `tests/Unit/LogCsvExportTest.php` — AC coverage unit tests
- `tests/Unit/AdminAuthzCoverageTest.php` — inventory + empty-state lock
- `tests/bootstrap.php` — load Cost + Log_Csv
- `handl-ai-connector-access-control.php`, `readme.txt` — 1.0.15 + changelog
- `aicac-3-authz-coverage.md` — amended for H5 `export_csv`
- `implementation-plan.md`, `decisions.md`, `test-results.md`, `developer-handoff.md`

## Acceptance-criteria-to-test mapping

| AC | Evidence |
|----|----------|
| AC1 columns for retained rows | `LogCsvExportTest::test_headers_cover_log_table_data_columns`, `test_prompt_preview_with_comma_is_quoted_in_document` |
| AC2 filters limit export | `test_active_filters_limit_exported_rows`, `test_handle_export_csv_uses_log_option_and_filters` |
| AC3 empty → disabled + reason | `AdminAuthzCoverageTest::test_export_csv_empty_state_is_disabled_with_reason` |
| AC4 header first | `test_document_starts_with_header_row` |
| AC5 RFC 4180 | `test_rfc4180_escapes_comma_quote_and_newline`, prompt fixture |
| AC6 POST nonce/cap | `AdminAuthzCoverageTest` `export_csv` / `handl_aicac_export_csv`; shared `manage_options` gate |
| Edge direct_http / count | `test_direct_http_collapsed_row_exports_host_uri_and_count`, `test_collapsed_row_stays_one_line_not_expanded` |

## Commands executed

```bash
export PATH="/home/ubuntu/php-runtime:$PATH"
composer install --no-interaction
php -l includes/class-handl-aicac-log-csv.php
php -l includes/class-handl-aicac-admin.php
php -l includes/class-handl-aicac-plugin.php
composer test
```

## Test results

```
OK (52 tests, 190 assertions)
```

See `test-results.md`.

## Data or schema changes

None. Read-only of `Plugin::LOG_OPTION_KEY`; no new options.

## Configuration changes

None.

## Security considerations

- Requires `manage_options` (shared `render_page` gate) + per-action nonce.
- Does not widen the data surface beyond fields already retained/rendered in wp-admin (uses stored `prompt_preview`, not raw prompts).
- No external telemetry / phone-home.
- Invalid nonce / missing cap → WordPress `check_admin_referer` / `wp_die` before any file body.

## Known limitations

- No date-range filter exists in `parse_log_filters` today; AC2 “date range, etc.” means current filters only.
- Export includes all matching retained rows (may exceed the 50 shown in the table) — intentional; UI note when filters active.
- Unit tests do not boot WordPress or assert HTTP `Content-Disposition` headers at runtime.

## Rollback considerations

- Revert the listed files / bump version back; no migration to undo.
- Removing the action leaves prior admin behavior intact.

## Remaining risks

- Large ring buffers (up to 1000 rows with long prompt previews) stream in one response; acceptable for current caps but watch memory if limits rise later.
- AICAC-3 inventory counts changed; Quality should treat amended `aicac-3-authz-coverage.md` as current.

## Requested next action

Quality and Release Gate: review AC mapping, re-run `composer test`, and spot-check Activity Export CSV in a WP admin with sample AI Client + `direct_http` rows.

---

STATUS: READY  
WORK_ITEM: #22 / AICAC-101  
COMPLETED: Activity Export CSV (filtered retained rows, RFC 4180, empty-state disable, POST nonce/cap); unit + authz tests; 1.0.15 changelog; composer test OK (52/190)  
EVIDENCE: implementation-plan.md; decisions.md; test-results.md; developer-handoff.md; tests/Unit/LogCsvExportTest.php; `composer test` OK (52 tests, 190 assertions)  
DECISIONS: Log_Csv helper; export all filtered retained rows (not 50-row UI cap); disable only when stored count=0; host/count columns; extend AICAC-3 inventory  
RISKS: No WP runtime download test in CI; large prompt previews within 1000-row cap  
NEXT_ACTION: Quality review AICAC-101 implementation and validation evidence  
NEXT_OWNER: QUALITY
