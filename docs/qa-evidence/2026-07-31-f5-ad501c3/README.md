# F5 Dashboard UI live QA evidence

- PR: #13
- Issue: #12
- Tested tip: `ad501c33eaeed64ee546a6334cedf51596db4fbe`
- Base: `285d13011f7513b3c96e609a54ab8bd16aaaf0dd`
- Version: `1.0.12`
- Environment: `https://handl-sandbox/`

## Evidence

- `dashboard-with-force-rules.jpg`: four-tile force-rules layout. Safety and Spend have aligned bottom edges; Pins and Block retain the 2x2 layout.
- `dashboard-owner-default-no-pins.jpg`: owner/default seven-key policy with no force rules. Block spans the full grid width.
- `dashboard-blocked.jpg`: one-click Block changed AI from explicit Allow to Deny.
- `dashboard-undone.jpg`: Undo restored the AI plugin rule to explicit Allow.
- `rules-restored.jpg`: Rules page confirms AI is explicitly Allow after Undo.
- `activity-outside-ai-client.jpg`: one retained direct-HTTP entry is labelled as one matching entry and separately reports 315 calls.
- `insights-entry-call-units.jpg`: retention is labelled in entries; 315 direct calls remain separate from the governed total of 199.

The owner explicitly waived the Cap recording for this task after the static workflow and dual-fixture visual gate passed. Screenshots were captured from the live sandbox at the exact tip above.

After capture, the sandbox option namespace was restored to SHA-256 `84286e77276b1106067a8981d67fc419a7f017d66a1058ad19c7b75dd7196ee7`: 142 original log entries, zero fixture rows, and the plugin checkout returned to `main` at the base commit. The only remaining untracked file was the pre-existing `deploy.sh`.
