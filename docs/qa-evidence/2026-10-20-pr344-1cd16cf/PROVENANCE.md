# PR344 evidence @ 1cd16cf

- Exact SHA: `1cd16cf84f860a51b4d0ff59f78b8f95d99f4413`
- Capture: Chrome headless browser against the immutable GitHub blob URL.
- Artifact: `01-blueprint-exact-sha.png` visibly shows the exact-SHA selector, the blueprint path, the login, plugin install/activation, landing page, PHP 8.2 / WP latest, and `runPHP` seed step.
- Validation: `jq empty` passed; full PHPUnit suite passed at this SHA: 1,163 tests / 7,308 assertions.
- Scope: WordPress.org Test Preview is intentionally deferred until the separate SVN asset deployment; this evidence certifies the committed blueprint artifact, not a deployed Preview instance.
