# Rules form ownership check

Run on any PR that touches `Admin::render_page()` or adds a section inside the Rules form:

```bash
php tests/bin/check-rules-form-ownership.php \
  --url 'https://handl-sandbox/wp-admin/options-general.php?page=handl-ai-connector-access-control&handl_aicac_tab=rules' \
  --cookie 'wordpress_logged_in_…=…'
```

Or against saved HTML:

```bash
php tests/bin/check-rules-form-ownership.php --html-file /tmp/rules.html
```

The check parses the HTML with `DOMDocument`. It fails unless Save, `#handl-aicac-action`, and the Rules save nonce all have form owner `handl-aicac-rules-save`. Failure output names the element and its actual owner.
