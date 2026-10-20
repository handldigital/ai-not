# HandL WP QA evidence: PR1362 and PR1363

Captured 2026-10-20 from exact pull-request heads using Chromium against locally built production assets.

| PR | Issue | Exact head | Page capture | Directory capture | Acceptance criteria covered |
| --- | --- | --- | --- | --- | --- |
| [PR1362](https://github.com/handldigital/handlwp.com-frontend/pull/1362) | [#1344](https://github.com/handldigital/handlwp.com-frontend/issues/1344) | `562be52ccb8379d17a98b34acb8dca3e6bb1f1f3` | `handlwp-pr1362-page-562be52.png` | `handlwp-pr1362-industries-562be52.png` | Float-spa page renders a three-row plugin snapshot table; related booking/forms/ads links and canonical metadata resolve; industry directory includes Float spa after Events. |
| [PR1363](https://github.com/handldigital/handlwp.com-frontend/pull/1363) | [#1345](https://github.com/handldigital/handlwp.com-frontend/issues/1345) | `0c5345fda335694d653809b47f2e83adb9122511` | `handlwp-pr1363-page-0c5345f.png` | `handlwp-pr1363-industries-0c5345f.png` | Resume-writing page renders a three-row plugin snapshot table; related forms/file-upload/email links and canonical metadata resolve; industry directory includes Resume writing between Restaurant ordering and RSVP. |

Both heads passed the full production build and 470-route prerender with isolated local ports. Chromium assertions found no page or console errors.
