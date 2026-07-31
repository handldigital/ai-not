# PR #15 live QA evidence

Tested PR head: `c7afb0337eba8b069da538eaaaaf60d983796395`

Base: `bb03a7ba4a63f9976db1d83c94ade7bbede9475e`

The live sandbox verified the redesigned Exceptions control in both kill-switch states:

- With the kill switch off, the list is muted, the state note is visible, and both mouse clicks and keyboard `Tab` + `Space` can change selections.
- Turning the kill switch on hides the state note immediately and restores the active visual treatment without a save.
- Three selections made while the switch was off survived save and reload.
- Saving with no selected exceptions cleared `kill_switch_exceptions` to an empty array.

The sandbox was restored after testing. The complete `handl_aicac_*` option snapshot returned to SHA-256 `84286e77276b1106067a8981d67fc419a7f017d66a1058ad19c7b75dd7196ee7`, with 142 original log entries and no exceptions. The plugin checkout returned to `main` at `bb03a7b`.

A short Cap recording is still pending because macOS was locked when the recording step started. These screenshots are the verified static evidence, not a substitute recording.
