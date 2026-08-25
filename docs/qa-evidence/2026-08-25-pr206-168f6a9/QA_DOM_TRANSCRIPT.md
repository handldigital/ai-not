# PR #206 QA DOM transcript

Deployed SHA: `168f6a9e7410930f4537a67140f4f91dfd980527` (`168f6a9`)

Fixture: authenticated isolated WordPress runtime at `127.0.0.1:8891`. The browser connection was unavailable, so this uses the team-approved authenticated-HTTP DOM-equivalence path for the markup-level A11Y-001–010 criteria. Temporary Rules, Activity, and Insights fixture data was used solely to render otherwise conditional states.

## Acceptance criteria evidence

| Criteria | Exercised rendered result |
| --- | --- |
| A11Y-001 | Insights rendered 10 weekly/daily SVGs with `role=img`, nonempty `aria-label`, and no `aria-hidden`. |
| A11Y-002 | Rules rendered one estimated-budget progressbar with both `aria-labelledby` and `aria-valuetext`. |
| A11Y-003 | The active WordPress runtime rendered the multisite-only pagination helper at page 2 of 3: one `Previous page` and one `Next page` screen-reader name. |
| A11Y-004 | Rules rendered all three stable labels and selects: Default policy, Unknown AI operations, and Calls with no detected plugin (3/3 each). |
| A11Y-005 | A real authenticated Rules save returned its `Saved.` notice and the page included the notices target (`role=status`, `aria-live=polite`) plus focus script `n.focus()`. |
| A11Y-006 | Rules rendered the seeded long note preview with its full `aria-label` (not only a `title`). |
| A11Y-007 | A rendered Policy checks row exposed its Actions column as `th scope=col` with screen-reader text. |
| A11Y-008 | Rules matrix select-all header rendered as `th id=cb scope=col`. |
| A11Y-009 | Rendered data-table headers were fully scoped: Insights 9/9; Activity 5/5, 3/3, 2/2, 13/13; Dashboard 3/3 and 4/4; plugin profile 3/3 across four tables; Rules matrix 13/13. |
| A11Y-010 | Seeded Insights leader rendered `aria-label="Highest value in this view"` with the star glyph itself `aria-hidden=true`. |

## Regression and scope checks

- Full PHPUnit: **532 tests, 2491 assertions**, run with the runner at the deployed SHA above.
- `readme.txt` diff against `origin/main...168f6a9`: empty.
- PR #206 was `CLEAN` before certification.

