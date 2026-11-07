# native/ios — the `auth.*` host channel for iOS

`AuthHostModule.swift` implements the host-channel functions the `nsh-auth`
TypeScript package calls through `host.call` (web-session authorize and
secure storage), `NativeSignInModule.swift` adds the native SDK sign-ins
(`auth.nativeSignIn`), and `AuthKeychain.swift` is the secure storage. The
iOS host app in `examples/host-ios` registers both modules on an `NshAppView`
before loading the bundle.

API ground truth: the `NativeShell` 0.4.0 swiftinterface in
`$(brew --prefix nsh)/libexec/embed/ios/NativeShell.xcframework` and
`examples/embed-ios` in the 0.4.0 source. Nothing here is guessed.

## Contract with packages/nsh-auth

The app must declare the names in its `nsh.json`: `"capabilities": { "host":
["auth.*"] }`. The host grants exactly that. Payload shapes:

| Method | Request | Reply | Errors |
|---|---|---|---|
| `auth.authorize` | `{url, scheme}` | `{callbackUrl}` | rejected with `"cancelled"` when the user dismisses the session, otherwise the failure message; rejected up front when guided access is on (the session cannot return from it) |
| `auth.nativeSignIn` | `{provider: "google"\|"apple"\|"facebook", nonce?: string}` | google: `{provider: "google", serverAuthCode}`; apple: `{provider: "apple", identityToken, authorizationCode, nonce}`; facebook: `{provider: "facebook", accessToken, expiresAt?}` | user cancel rejects with exactly `"cancelled"`; SDK failure rejects with the SDK's message |
| `auth.store.save` | `{key, value}` | `{ok: true}` | non-empty-key validation, keychain OSStatus failures |
| `auth.store.load` | `{key}` | `{value: string \| null}` | keychain failures reject with the OSStatus text; only `errSecItemNotFound` yields `{value: null}` |
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

## `auth.nativeSignIn` — the native SDK adapters

`NativeSignInModule.swift` dispatches on `provider` and presents the provider's
own sign-in surface from the host's view controller. SDK coordinates and the
per-provider rules below are verified against the exact versions pinned in
`examples/host-ios`'s `Package.resolved` (GoogleSignIn-iOS 10.1.0,
facebook-ios-sdk v19.0.1); details in `docs/research/native-sdks.md`.

- **google** — `GIDSignIn` with `GIDClientID` /
  `GIDServerClientID` from the app's Info.plist
  (`nsh-auth-sandbox.apps.googleusercontent.com` /
  `nsh-auth-sandbox-web.apps.googleusercontent.com`). `serverAuthCode` comes
  from `GIDSignInResult.serverAuthCode`, which exists only because a server
  client id is configured; exchanging it is confidential-client work and
  belongs to the token broker, never this app. The request nonce, if any, is
  not forwarded (the Google SDK surface used here has no nonce parameter).
  With the unregistered sandbox id the expected on-device outcome is Google's
  own "Error 401: invalid_client" page on `accounts.google.com` — that is the
  trigger-proof pass, not a bug.
- **apple** — `ASAuthorizationController` +
  `ASAuthorizationAppleIDRequest` with `requestedScopes [.fullName, .email]`.
  The core sends the RAW `nonce`; the request carries SHA-256-hex(raw)
  (CryptoKit) and the reply echoes the raw nonce — the opposite of Google's
  verbatim rule, per Apple's documented pattern. `identityToken` /
  `authorizationCode` are the `ASAuthorizationAppleIDCredential` fields;
  exchanging the code needs an Apple client secret, so that leg is
  broker-only and the session stands on the JWKS-verified id token. Requires
  `com.apple.developer.applesignin` in the host app's entitlements
  (`examples/host-ios/NshAuthSandbox.entitlements`).
- **facebook** — `LoginManager` with
  `LoginConfiguration(permissions: ["public_profile", "email"],
  tracking: .enabled, appSwitch: .disabled)` from `import FacebookLogin` (the
  product re-exports the FBSDKLoginKit binary framework). Classic tracking
  yields the opaque Graph API `AccessToken`; the SDK generates its own PKCE
  verifier and nonce internally, so the core must not double-apply its own
  PKCE on this leg. `expiresAt` is epoch milliseconds from
  `AccessToken.expirationDate`, included only when present.
- User cancel maps to exactly `"cancelled"` on all three (Google
  `GIDSignInError.Code.canceled`, Apple `ASAuthorizationError.canceled`,
  Facebook `LoginResult.cancelled`); any other failure rejects with the SDK's
  own message text.
- A second `auth.nativeSignIn` while one is in flight rejects the pending
  reply with `"cancelled: superseded by a new nativeSignIn call"` (the core
  classifies that prefix as cancel) — same settled-supersede as the Android
  module; a late callback of the superseded flow cannot settle twice or
  release its replacement.
- `expiresAt` is epoch MILLISECONDS from `AccessToken.expirationDate`,
  included only when present — same unit as the Android module
  (`Date.getTime()`) and `Session.expiresAt`.

On-device behavior of the Apple sheet under this ad-hoc, no-team simulator
build is undocumented by Apple (research section 3) — capture what actually
presents during a live run instead of assuming.

## Keychain

Generic-password items, service `nsh-auth.sandbox`, one item per key
(`kSecAttrAccount`),
`kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly` — readable after the first
unlock, but never migrated to another device through backups. The simulator
needs no entitlement. A test can prove tokens never reach plain `Storage` by
searching for the service name and checking the app's storage directory.

Reads propagate keychain failures instead of reporting them as absence: only
`errSecItemNotFound` yields `null` (the TS core's "no session"); any other
OSStatus rejects `auth.store.load` with a human-readable message, so
`errSecAuthFailed` or `errSecInteractionNotAllowed` surface as a `store_error`
rather than silently forcing re-auth. The OSStatus-to-text mapping is adapted
from expo-secure-store's `SecureStoreExceptions.swift` (MIT, © 650 Industries)
with a `SecCopyErrorMessageString` fallback for unknown codes.

## Launch arguments

`simctl launch <udid> dev.nshauth.sandbox --provider google` passes
`--provider google` to the process; `ProcessInfo.processInfo.arguments` is read
once when the module is created. Arguments are read at registration time, so a
relaunch is needed to change the provider:

```sh
xcrun simctl terminate <udid> dev.nshauth.sandbox
xcrun simctl launch <udid> dev.nshauth.sandbox --provider google
```
