# HandL WP fe#576 / PR590 live QA

- Pull request: https://github.com/handldigital/handlwp.com-frontend/pull/590
- Issue: https://github.com/handldigital/handlwp.com-frontend/issues/576
- Deployed main commit: `dcacd0cb33f69421010f6d44ff1772c2fed80864`
- Squashed PR head: `7a982da7fca1a7a00eacbd63d6377c1cb0f5a60c`
- Tested route: https://handlwp.com/wp-webinar-plugin-privacy
- Capture method: real Chromium load of the live route, 1440×900 viewport, DPR 2.

| File | Acceptance criteria visibly covered |
| --- | --- |
| `fe576-hero-caveat-dcacd0c.png` | Hero claim and first-button browser-scan limitation. |
| `fe576-table-local-vendor-dcacd0c.png` | Local-first WebinarPress, then vendor rows; `Receiving domains not verified` where applicable. |
| `fe576-table-unverified-dcacd0c.png` | WebinarJam and WP GoToWebinar are unverified browser hosts, while the Zoom registration row preserves `zoom.us`. |
| `fe576-related-links-dcacd0c.png` | Related events, video, chat, and email pages. |
| `fe576-pr590-live-dcacd0c.png` | Full deployed page context. |
