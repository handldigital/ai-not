# Decisions — AICAC-101 (#22)

## D1: Pure `Log_Csv` helper; Admin owns HTTP/authz

**Decision:** Put RFC 4180 formatting and row mapping in `includes/class-handl-aicac-log-csv.php`; keep POST handling, capability/nonce, filtering, and UI in `Admin`.

**Why:** Matches existing Cost/Operations helpers; keeps CSV logic unit-testable without a WordPress boot; preserves the shared `manage_options` + `check_admin_referer` pattern (AC6).

## D2: Export all filtered retained rows, not the 50-row UI window

**Decision:** Export applies `log_row_matches_filters` to the full ring buffer (newest first) and ignores the Activity table’s display cap of 50.

**Why:** AC2 requires filter parity with on-screen criteria; the product value is compliance beyond the buffer lifetime, which needs every matching retained row. UI copy clarifies this when filters are active.

## D3: Disabled control when stored count is 0 (not when filters match zero)

**Decision:** Disable/hide enablement based on `count( $log ) === 0` with reason “No log entries yet.” If rows exist but filters match none, Export stays enabled and downloads a header-only CSV.

**Why:** Matches AC3 wording (“zero retained log rows”). Header-only under active filters remains a valid empty matching set.

## D4: Include host/count as explicit CSV columns; omit Actions

**Decision:** CSV headers mirror table data fields and add Host + Count for `direct_http` / chatty-host collapse; omit the Actions column (interactive UI only).

**Why:** Edge cases require host/path and aggregate count; Actions (quick-rule buttons) are not retained log data and would widen nothing useful. Path maps to the existing URI column.

## D5: Extend AICAC-3 authz inventory for `export_csv`

**Decision:** Update `AdminAuthzCoverageTest` to expect five `check_admin_referer` calls and known action `export_csv` / nonce `handl_aicac_export_csv`.

**Why:** Export is a privileged POST that must stay locked in the same inventory; leaving the old “4 nonces” assertion would false-fail CI after this story.
