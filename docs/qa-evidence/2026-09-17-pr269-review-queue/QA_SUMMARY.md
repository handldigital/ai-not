# PR #269 — Rules review queue QA

Tested deployed plugin SHA `bf74b0581e9811fe23be3c5ee8512af3bd166d06` on `https://handl-sandbox/`.

- `RULES_DUE_QUEUE.png` shows two real installed-plugin Rules entries due for review, their unchanged Allow/Deny values, and the select, confirm, confirm-all, and snooze controls.
- `SNOOZE_NOTICE.png` shows the server-confirmed 7-day reminder notice after one selected due row is snoozed; the other due rule remains with its Allow decision.
- `CONFIRM_ALL_NOTICE.png` shows the server-confirmed result after confirming the remaining due rule, including the explicit statement that Allow and Deny were not changed and an empty review queue.
- `REVIEW_ALL_PENDING_FILTER.png` shows the `Pending review` filter selected after following Review all, with exactly the pending AI plugin row.
- The full suite under the sandbox PHP 8.3 runtime passed: `795 tests, 4256 assertions`.

The temporary review-due and pending-review fixtures, policy snapshots, and history were restored immediately after capture.
