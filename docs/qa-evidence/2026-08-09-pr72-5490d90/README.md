# PR #72 QA failure evidence

Commit under test: `5490d901815419d97b07843b32961a21ee82e30f`.

The Activity screen has the expected filtered-export control. With the **Allow**
filter active, it reports **50 of 136 matching entries**, so this is a valid
over-50-row export scenario.

![Filtered Activity export control](filtered-activity-ui.png)

## Failure observed

Submitting **Download CSV** produced `handl-aicac-audit-20260810-044831.csv`,
but the downloaded file is an HTML document beginning with `<!DOCTYPE html>`
rather than a CSV header. Parsing it as CSV yields one HTML header field and
276 malformed-width rows; no audit-log CSV was delivered.

Expected: a CSV with the current Allow-filtered retained rows (136 here), not
limited to the 50 rows rendered in the table.
