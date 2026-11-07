# native/ios — the `auth.*` host channel for iOS

`AuthHostModule.swift` implements the host-channel functions the `nsh-auth`
TypeScript package calls through `host.call`, and `AuthKeychain.swift` is its
secure storage. The iOS host app in `examples/host-ios` registers the module on
an `NshAppView` before loading the bundle.

API ground truth: the `NativeShell` 0.4.0 swiftinterface in
`$(brew --prefix nsh)/libexec/embed/ios/NativeShell.xcframework` and
`examples/embed-ios` in the 0.4.0 source. Nothing here is guessed.

## Contract with packages/nsh-auth

The app must declare the names in its `nsh.json`: `"capabilities": { "host":
["auth.*"] }`. The host grants exactly that. Payload shapes:

| Method | Request | Reply | Errors |
|---|---|---|---|
| `auth.authorize` | `{url, scheme}` | `{callbackUrl}` | rejected with `"cancelled"` when the user dismisses the session, otherwise the failure message |
| `auth.store.save` | `{key, value}` | `{ok: true}` | non-empty-key validation, keychain OSStatus failures |
| `auth.store.load` | `{key}` | `{value: string \| null}` | — |
| `auth.store.clear` | `{key}` or `{}` | `{ok: true}` | missing `key` clears the whole service |
| `auth.config` | `{mockBaseUrl?, autoStart?}` | `{mockBaseUrl, autoStart, provider}` | — |

- `url` must be http/https; `scheme` is the custom callback scheme
  (`nsh.auth.sandbox` in this repo). The host validates `scheme` against the
  app's own registered `CFBundleURLSchemes` and rejects anything else, so the
  session cannot capture redirects meant for foreign schemes (RFC 8252).
- `auth.authorize` opens `ASWebAuthenticationSession` with
  `prefersEphemeralWebBrowserSession = false` (provider cookies persist).
  Rejection messages are plain strings — the 0.4.0 `NshHostReply.reject(_:)`
  takes a message — so the TSX side matches the literal `"cancelled"`.
- `auth.config`: `provider`/`autoStart` come only from the host process's own
  launch arguments (`--provider google` or `--provider=google`, as passed by
  `simctl launch`); the app's request values are not merged in. `mockBaseUrl`
  is echoed back unchanged. The app auto-starts `provider` when `autoStart` is
  `true`.
- `value` may be a string or a JSON object/array; non-strings are stored as
  JSON text. Values land as UTF-8 strings in the Keychain.

## Keychain

Generic-password items, service `nsh-auth.sandbox`, one item per key
(`kSecAttrAccount`),
`kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly` — readable after the first
unlock, but never migrated to another device through backups. The simulator
needs no entitlement. A test can prove tokens never reach plain `Storage` by
searching for the service name and checking the app's storage directory.

## Launch arguments

`simctl launch <udid> dev.nshauth.sandbox --provider google` passes
`--provider google` to the process; `ProcessInfo.processInfo.arguments` is read
once when the module is created. Arguments are read at registration time, so a
relaunch is needed to change the provider:

```sh
xcrun simctl terminate <udid> dev.nshauth.sandbox
xcrun simctl launch <udid> dev.nshauth.sandbox --provider google
```
