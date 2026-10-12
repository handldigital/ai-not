# PR341 / #328 exact-SHA live evidence

- Product SHA: `cec0c3b07985c46efbde37680ef94797c2595dc0` (`feature/aicac-328-exit-interview`)
- Modal captures: Playwright + Chrome against fixture that inlines `assets/exit-interview.js|css` from that SHA and the verbatim localized strings from `Exit_Interview::enqueue`.
- States: default modal; Other selected (details field visible); Other filled.
- Email proof: temporary live-plugin checkout of `cec0c3b`, then `wp eval-file` store + `email_submission`; `wp_mail` filter captured site admin + `support@handldigital.com`. Live plugin restored to prior SHA after capture.
- SHA banner on every modal screenshot.
