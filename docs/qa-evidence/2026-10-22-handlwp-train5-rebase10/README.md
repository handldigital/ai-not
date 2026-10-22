# HandL WP Train #5 — Database rebase-10 QA evidence

Captured 2026-10-22 against each PR's exact rebased head using headless Chrome and a Vite server created from that head's source archive.

Every route capture verifies the industry lander renders without a runtime error and has its three required data rows. Every companion `industry` capture verifies the industry directory contains the new entry and links to its route.

| PR | Exact head | Route | Route capture | Directory capture |
| --- | --- | --- | --- | --- |
| [#1176](https://github.com/handldigital/handlwp.com-frontend/pull/1176) | `384ff1b` | `/wp-tailor-plugin-privacy` | `pr1176-wp-tailor-plugin-privacy-384ff1b.png` | `pr1176-industry-384ff1b.png` |
| [#1177](https://github.com/handldigital/handlwp.com-frontend/pull/1177) | `be0375f` | `/wp-rv-rental-plugin-privacy` | `pr1177-wp-rv-rental-plugin-privacy-be0375f.png` | `pr1177-industry-be0375f.png` |
| [#1235](https://github.com/handldigital/handlwp.com-frontend/pull/1235) | `606327a` | `/wp-gunsmith-plugin-privacy` | `pr1235-wp-gunsmith-plugin-privacy-606327a.png` | `pr1235-industry-606327a.png` |
| [#1236](https://github.com/handldigital/handlwp.com-frontend/pull/1236) | `64d0241` | `/wp-taxidermy-plugin-privacy` | `pr1236-wp-taxidermy-plugin-privacy-64d0241.png` | `pr1236-industry-64d0241.png` |
| [#1240](https://github.com/handldigital/handlwp.com-frontend/pull/1240) | `419d08d` | `/wp-gutter-cleaning-plugin-privacy` | `pr1240-wp-gutter-cleaning-plugin-privacy-419d08d.png` | `pr1240-industry-419d08d.png` |
| [#1249](https://github.com/handldigital/handlwp.com-frontend/pull/1249) | `d929376` | `/wp-generator-installation-plugin-privacy` | `pr1249-wp-generator-installation-plugin-privacy-d929376.png` | `pr1249-industry-d929376.png` |
| [#1250](https://github.com/handldigital/handlwp.com-frontend/pull/1250) | `71bdf53` | `/wp-safe-installation-plugin-privacy` | `pr1250-wp-safe-installation-plugin-privacy-71bdf53.png` | `pr1250-industry-71bdf53.png` |
| [#1264](https://github.com/handldigital/handlwp.com-frontend/pull/1264) | `307b43c` | `/wp-tree-service-plugin-privacy` | `pr1264-wp-tree-service-plugin-privacy-307b43c.png` | `pr1264-industry-307b43c.png` |
| [#1269](https://github.com/handldigital/handlwp.com-frontend/pull/1269) | `22be748` | `/wp-radon-testing-plugin-privacy` | `pr1269-wp-radon-testing-plugin-privacy-22be748.png` | `pr1269-industry-22be748.png` |
| [#1276](https://github.com/handldigital/handlwp.com-frontend/pull/1276) | `c510fd2` | `/wp-ghostwriting-plugin-privacy` | `pr1276-wp-ghostwriting-plugin-privacy-c510fd2.png` | `pr1276-industry-c510fd2.png` |

At certification time all ten PRs were OPEN, CLEAN, and their `size-guard` check had succeeded.
