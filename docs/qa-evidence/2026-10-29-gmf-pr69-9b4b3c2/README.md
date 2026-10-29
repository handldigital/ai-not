# ios#51 / PR 69 widget QA screenshots (public rehost)

Exact copies of the signed-simulator captures from `goals-made-fun-ios` branch `qa-evidence-pr69-9b4b3c2`.
Product SHA: `9b4b3c2dbe322c198375be2de17bd5aace01981b` (PR head unchanged).

Captured 2026-10-29 on signed iPhone 17 Pro simulator, iOS 26.5, UDID `C9CDF77C-9096-404E-8725-19AE77F86537`.
App Group `group.handldigital.Goals-Made-Fun`. Real Home Screen WidgetKit (not a composed SwiftUI render).

| File | Acceptance | sha256 | bytes |
| --- | --- | --- | --- |
| 01-small-medium-items-left-streak.png | Small: items-left + streak. Medium: today's titles + checked state | b12bf64e80a55e2e619b74445b58b2c558094472c718fd001c04965534fe7296 | 1802046 |
| 02-large-titles-checked.png | Large: today's titles + checked state | da027f69b9b8779faa50a469c88d6dfea1dfba53050aef630e09373ec657ba50 | 1378536 |
| 03-missing-cache-open-the-app.png | Missing cache reads "Open the app", never "0 left" | 7138260467c4a79eb6a2d2cd5a2b7fde7338895a7c1041c61e9eb32e05c120db | 1758888 |
| 04a-tap-home-widget.png | Before tap | c1b7b9441f2d84a3f1b3cad621f5bbe1c8e97055be92544606ab3c00faec74e2 | 1191239 |
| 04b-tap-opens-app.png | XCUITest tap opens Goals Made Fun (sim signed out → Sign In; widgetURL `goalsmadefun://today`) | ce19939f04dceead291073b4a7f2362169e8c8cae3bd788d9ad6a9422423a636 | 1355689 |
