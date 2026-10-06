# PR 293 QA Transcript

Exact SHA `0b0f3061078a12e39934544959bc1bef91a6bee5` (`Incident` class, no admin UI).

PHPUnit at this SHA: **891/891 OK** (4793 assertions).

## Fixture

Synthetic Activity log in one window:

1. allow `acme/acme.php`
2. retry-storm deny `acme/acme.php`
3. freeze_started
4. policy_restored
5. deny `acme/acme.php`
6. deny `other/other.php` (unrelated; must stay out)

## Results

| Criterion | Result |
|-----------|--------|
| Empty log returns none | `Incident::group([])` => 0 incidents |
| One incident for storm + freeze + policy restore | incident_count = 1 |
| Five related rows kept | event_count = 5 |
| Unrelated plugin excluded | plugins = `acme/acme.php` only |
| JSON export labels | reasons include `retry_storm`, `freeze_started`, `policy_save` |
| Text export labels | `Retry storm`; `Panic freeze started`; `Policy saved or restored` |

Machine-readable dump: `QA_TRANSCRIPT.json` in this folder.

## Text export

```
Incident inc_ae25c3f711c7
Started: 2023-11-14T22:13:20Z
Ended: 2023-11-14T22:15:50Z
Plugins: acme/acme.php
Detection: Panic freeze started; Policy saved or restored; Retry storm

Timeline:
2023-11-14T22:13:20Z Allow acme/acme.php
2023-11-14T22:13:50Z Retry storm acme/acme.php
2023-11-14T22:14:50Z Panic freeze started
2023-11-14T22:15:20Z Policy saved or restored
2023-11-14T22:15:50Z Deny acme/acme.php
```
