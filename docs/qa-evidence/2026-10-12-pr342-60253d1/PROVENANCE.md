# PR342 / #337 LLMS-TXT evidence @ 60253d1

- Product SHA: `60253d12623c9d0c2fd7e0688ec21478df706075`
- Live handl-sandbox admin captures (host-map 127.0.0.1), SHA banner on each panel.
- Panels: Protections toggle OFF (404) → toggle ON with preview → public GET /llms.txt HTTP 200 text/plain.
- Seed uses Protections form POST markers so `Llms_Txt::merge_on_policy_save` persists the option.
