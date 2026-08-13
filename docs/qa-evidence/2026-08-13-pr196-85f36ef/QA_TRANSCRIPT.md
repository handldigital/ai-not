# PR #196 QA transcript — Rule notes

Tested pull request: https://github.com/handldigital/ai-not/pull/196  
Tested commit: `85f36ef20711825d277608e7d66cfc612a9567bd`

## Acceptance coverage

1. An explicit plugin rule snapshots its Rule note into the Activity event.
2. Editing that rule later does not rewrite the event's saved historical note.
3. Deleting that rule later does not rewrite the event's saved historical note.
4. A higher-priority budget decision does not inherit a plugin Rule note.
5. CSV exports the Activity-row snapshot, not the current live policy note.
6. Policy export/import preserves `plugin_notes`.

Controlled sandbox fixture result:

```json
{
  "snapshot": "original compliance rationale",
  "survives_edit": "original compliance rationale",
  "survives_delete": "original compliance rationale",
  "higher_priority_note": "",
  "csv_has_snapshot": true,
  "csv_has_live_note": false,
  "round_trip_ok": true,
  "round_trip_note": "round-trip note"
}
```

Full PHPUnit suite on the tested commit: 493 tests, 2238 assertions, passing.

The fixture restored its original sandbox policy and Activity state after the check.
