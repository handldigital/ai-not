# PR #228 uninstall QA — `d533e54`

Environment: disposable WordPress fixture `/Users/handl/Sites/localhost/handl-sandbox-163` at `d533e54ad992152cc2bf680f4958c4145064610d`.

## Keep is the default

```text
$ wp handl-aicac uninstall get
keep
Success: Uninstall will keep plugin data.

$ wp option update handl_aicac_policy '{"default":"deny"}' --format=json
Success: Updated 'handl_aicac_policy' option.

$ wp eval '... handl_aicac_run_uninstall();'
$ wp option get handl_aicac_policy --format=json
{"default":"deny"}
```

## Purge is opt-in and scoped

```text
$ wp handl-aicac uninstall set purge
Success: Uninstall will remove all plugin data.

$ wp eval '... handl_aicac_run_uninstall();'
$ wp db query "SELECT option_name FROM wp_options WHERE option_name LIKE 'handl_aicac_%'"
(no rows)

$ wp option get aicac_qa_unrelated_keep
retained
```

Full PHPUnit: `638/638`; targeted `UninstallPolicyTest`: `8/8`, 34 assertions.
