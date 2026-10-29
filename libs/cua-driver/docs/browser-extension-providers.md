# Browser extension providers

Maka's browser extension transport exposes provider selectors `maka` and
`chatgpt`, displayed as Maka and ChatGPT. The default provider is `maka`.

## Explicit setup

An embedding executable that calls `browser::extension_process::bootstrap_installed`
accepts these setup commands before entering its normal application runtime:

```text
<embedding-executable> browser extension --output <absolute-empty-directory>
<embedding-executable> browser install --extension-id <actual-maka-extension-id>
<embedding-executable> browser install --provider maka --extension-id <actual-maka-extension-id>
<embedding-executable> browser install --provider chatgpt --extension-id <actual-chatgpt-extension-id>
<embedding-executable> browser uninstall --provider maka
<embedding-executable> browser uninstall --provider chatgpt
```

The extension export contains Maka's source. Install or enable it through
Chrome's extension UI, then register its actual ID. ChatGPT setup registers an
explicitly selected, already available extension; it does not export, download,
modify, or install OpenAI application or extension code. Installation is scoped
to the current OS user and the selected Chrome extension ID.

## Protocol boundaries

The ChatGPT adapter keeps actual third-party response JSON intact, including
`nativeEffectUnknown`. Diagnostic metadata created by this implementation uses
`remoteCode`, `remoteMessage`, `remoteData`, `remoteMethod`, and
`remoteAcknowledged`; effect and budget tags use `extension_cdp_effect` and
`extension_message_budget`. Accepted effects retain their matched reply custody
through cancellation and cleanup. Unknown operations must not be replayed.

Stock OpenCLI integration is best-effort through its supported public surface.
Unsupported operations require another configured provider; fallback is allowed
only before dispatch. Use the Maka extension for managed browser sessions.
