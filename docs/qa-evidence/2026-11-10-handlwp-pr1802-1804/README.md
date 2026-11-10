# HandL WP PR 1802–1804 QA evidence

Sanctioned headless-browser captures of exact local production bundles, 1440 px wide. Every capture contains its `qa <short-SHA>` bundle stamp at bottom right.

| Pull request | Exact head | Route | Captures | Covered acceptance criteria |
| --- | --- | --- | --- | --- |
| [PR 1802](https://github.com/handldigital/handlwp.com-frontend/pull/1802) | `3e278d1c5f0acce50591f2867d15262b4e298855` | `/wp-haunted-house-attraction-plugin-privacy` | top, table, methodology | Storage-path H1, CTA and caveat, comparison copy, three-row table with seven visible sources, methodology, and four related links. |
| [PR 1803](https://github.com/handldigital/handlwp.com-frontend/pull/1803) | `9a7367ee827c20321b229b1da4b3b0bc65f3ec29` | `/wp-drive-in-theater-plugin-privacy` | top, table, methodology | Storage-path H1, CTA and caveat, comparison copy, three-row table with seven visible sources, methodology, and four related links. |
| [PR 1804](https://github.com/handldigital/handlwp.com-frontend/pull/1804) | `b461047d0f03355c5037e6e2752f1359530227f2` | `/wp-storm-chaser-tours-plugin-privacy` | top, table, methodology | Storage-path H1, CTA and caveat, comparison copy, three-row table with seven visible sources, methodology, and four related links. |

The exact-head routes and four related links each returned HTTP 200. Each page rendered two comparison panels, exactly three table rows, a scan CTA plus its scope caveat, and four related links. All seven cited public sources loaded in the browser for each page.
