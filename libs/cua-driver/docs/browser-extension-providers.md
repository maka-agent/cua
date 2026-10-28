# Browser extension providers

Maka's browser extension transport exposes provider selectors `maka` and
`chatgpt`, displayed as Maka and ChatGPT. The default provider is `maka`.
Browser APIs, IPC descriptors, connector types, and source modules use
`Extension` or `Browser` names. OS window identity, native desktop coordinates,
and native accessibility remain separate platform concepts.

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
modify, or install OpenAI application or extension code. The legacy
`--adapter original` spelling is rejected. Setup validates the same private
installation, origin, executable, ownership, and ACL/mode boundaries as before.
A rejected or ambiguous installed selection remains an error.

`ExtensionAdapterMode::from_host_name` recognizes only the two actual host names:
`org.apache.maka.browser_connector` maps to Maka and
`com.openai.codexextension` maps to ChatGPT. `selector()` and `display_name()`
provide the shared public names; display names and short selectors are not host
identity proofs. A disconnected provider is not an available connection.

## Protocol boundaries

Chrome's `runtime.connectNative`, `nativeMessaging` permission, and
`NativeMessagingHosts` registration paths retain their official names and exact
host values. Renaming our Rust modules does not change Chrome's framing,
registration, origin checks, or byte limits. The retained Maka UI source and its
`nativeControl` bridge field are unchanged.

The ChatGPT adapter keeps actual third-party response JSON intact, including
`nativeEffectUnknown`. Diagnostic metadata created by this implementation uses
`remoteCode`, `remoteMessage`, `remoteData`, `remoteMethod`, and
`remoteAcknowledged`; our effect and budget tags use `extension_cdp_effect` and
`extension_message_budget`. Accepted effects, unknown outcomes, matched reply
custody, cancellation, cleanup, and the prohibition on replay retain their
existing behavior.

Stock OpenCLI integration is best-effort through its supported public surface.
There is no custom OpenCLI browser host, provider enum branch, private raw
forwarding route, or modified vendored extension. This naming change does not
claim stock OpenCLI feature parity or new live browser/platform verification.
