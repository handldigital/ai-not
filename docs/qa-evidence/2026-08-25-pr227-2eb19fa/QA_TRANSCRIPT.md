# PR #227 QA lifecycle transcript

Deployed SHA: `2eb19fa9123519b1bdb5e2a4cb76e91db33a59d8` (`2eb19fa`)

Fixture: isolated local WordPress runtime. PR state immediately before certification: `CLEAN`, with its PHPUnit CI check successful.

## Acceptance criteria evidence

| Criterion | Exercised result |
| --- | --- |
| Reactivation from a real deactivation | `wp plugin deactivate` succeeded, then `wp plugin activate` succeeded and the plugin was active. No fatal or missing-required-plugin error occurred. |
| Resumed enforcement records and closes the gap | The deactivation stamps were cleared; persisted tamper events contained `enforcement_stopped,enforcement_resumed`; the closed enforcement-gap notice rendered in wp-admin. [Screenshot](reactivation-gap-notice.png) |
| Plain activation from inactive | A second deactivate → activate regression returned inactive when expected, then active after activation. Stamps cleared again; the retained tamper count was two stopped / two resumed events. |

The screenshot is a direct capture of the authenticated wp-admin response and shows the rendered, dismissible closed-gap notice.

## Regression

- Full PHPUnit: **649 tests, 3526 assertions**, run at the SHA above.
- The fresh PR head was mergeable-clean and CI-green before QA.

