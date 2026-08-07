# Implementation Plan — AICAC-101 (#22)

## Work item

**Issue:** #22 — AICAC-101: CSV export of the retained audit log  
**Actor:** Site admin (`manage_options`) on the Activity tab  
**Spec:** product-handoff.md § AICAC-101 (copied from sibling workspace; not in this repo root)

## Objective

Add an Activity-tab **Export CSV** control that downloads currently retained audit-log rows (honoring active `parse_log_filters` filters) as an RFC 4180 CSV, behind the same POST nonce + `manage_options` pattern as other admin handlers.

## Approach (smallest correct change)

1. Add `includes/class-handl-aicac-log-csv.php` with pure static helpers:
   - RFC 4180 field escaping / line building
   - Header column list matching the on-screen log table data surface
   - Row formatting for AI Client and `direct_http` rows (host, URI/path, aggregate `count`)
2. Wire into `class-handl-aicac-admin.php`:
   - POST action `export_csv` + `check_admin_referer( 'handl_aicac_export_csv' )` early in `render_page` (after capability gate)
   - `handle_export_csv()`: load `Plugin::LOG_OPTION_KEY`, filter via existing `log_row_matches_filters`, stream CSV + `exit`
   - Export control next to Recent calls; disabled + “No log entries yet.” when stored count is 0
3. Require the new class from `Plugin::init()`.
4. Extend `AdminAuthzCoverageTest` inventory for the new action/nonce (AICAC-3 lock stays accurate).
5. Unit-test CSV escaping, headers, filter-limited output, direct_http host/count, collapsed rows.
6. Minor version bump + changelog (read-only feature; no schema migration).

## Acceptance-criteria mapping

| Criterion | Implementation | Test |
|-----------|----------------|------|
| AC1 ≥1 row → CSV with every rendered data column | `Log_Csv::headers()` / `format_row()`; Export button | `LogCsvExportTest` column set + sample row |
| AC2 filters limit export | Reuse `log_row_matches_filters` + filter hiddens on form | Filter exclusion unit test (Admin reflection or export builder input) |
| AC3 zero retained → disabled + reason | Disabled control + description in `render_log_tab` | Static/source or documented UI branch; handler still safe if forced |
| AC4 header row first | `Log_Csv::document()` prepends headers | Unit assert first line |
| AC5 RFC 4180 quoting | `Log_Csv::escape_field()` | Comma / quote / newline cases |
| AC6 POST + nonce/cap like `handle_save_rules` | `export_csv` + `handl_aicac_export_csv` after `manage_options` | `AdminAuthzCoverageTest` updated inventory |
| Edge: direct_http host/path; collapsed `count` | Columns `host`, `uri`, `count` | Unit fixtures |

## Risks

- UI shows at most 50 newest matching rows; export intentionally includes **all** matching retained rows (compliance value). Filters match on-screen; the 50-row cap does not.
- `parse_log_filters` has no date-range today; AC2 “date range, etc.” means whatever filters exist now.
- Adding a fifth `check_admin_referer` updates the AICAC-3 match-count lock (expected).
- Prompt preview in CSV is the already-truncated stored `prompt_preview` (does not widen data surface).

## Out of scope

Scheduled export; non-CSV formats; policy/rules JSON (AICAC-102); buffer size/TTL changes; external telemetry.
