# native/android

Kotlin sources of the nsh-auth Android host module. This directory is not a
Gradle module of its own: `examples/host-android` compiles it into the app via
`kotlin.directories += "../../../native/android"` in `app/build.gradle.kts`
(AGP 9's built-in Kotlin). Keep the package path `dev/nshauth/sandbox/auth/`
under this directory.

- `AuthHostModule.kt` - Custom Tabs authorize, launch configuration
  (`provider` / `mockBaseUrl` launcher extras, loopback rewritten to `10.0.2.2`
  on the emulator), and the cancelled/resume bookkeeping.
- `SecureStore.kt` - AES-256/GCM with one AndroidKeyStore key (alias
  `nsh-auth-session`), a fresh random IV per seal, and only
  `{key -> iv, ciphertext}` persisted to the app-private
  `nsh-auth-store.json`. No plaintext token touches disk. A stored entry is
  dropped only when its tag fails (`AEADBadTagException`, tamper or a replaced
  Keymaster key after device restore) or the key is permanently invalidated;
  any other Keystore error propagates instead of wiping persisted auth.

Host channel contract (wired by `MainActivity.kt` onto `NshView.handle`, names
also granted in the host's `setGrantedCapabilities` and declared by the demo's
`nsh.json`):

| Name | Args | Reply | Reject message |
|---|---|---|---|
| `auth.authorize` | `{url, scheme}` - `scheme` must be `nsh.auth.sandbox`, the scheme the host manifest routes | `{callbackUrl}` | `cancelled`, `cancelled: superseded by a new authorize call`, `cancelled: host destroyed`, a not-registered-scheme error, or an argument error |
| `auth.store.save` | `{key, value}` | `{}` | storage error message |
| `auth.store.load` | `{key}` | `{value: string \| null}` | storage error message |
| `auth.store.clear` | `{key?}` (no key wipes all) | `{}` | storage error message |
| `auth.config` | `{}` | `{mockBaseUrl?, autoStart?}` | - |

Launch params (`host.params`, set with `NshView.setParams` before the bundle
loads; the host is the source of truth):

```json
{ "auth": { "redirectUri": "nsh.auth.sandbox://callback", "mockBaseUrl": "http://10.0.2.2:8787", "autoStart": "google" } }
```

`mockBaseUrl` and `autoStart` are present only when the corresponding launcher
extra was set. Redirect mechanism: the provider returns to
`nsh.auth.sandbox://callback` (query included); the VIEW/BROWSABLE intent
filter on the single-task `MainActivity` in
`examples/host-android/app/src/main/AndroidManifest.xml` delivers
`onNewIntent`, and the module completes the pending `auth.authorize` only when
the URI's scheme matches the pending one and its host and path are exactly the
registered `callback` (empty or `/`) - any other URI routed by the filter is
ignored, so a forged intent cannot finish the call. The launcher extras are
read only from the intent that creates the activity (`onCreate`); a warm
instance's `onNewIntent` never reconfigures sign-in.
`NshView` APIs follow the 0.4.0 embed example
(`.refs/nsh-v0.4.0/examples/embed-android` and
`crates/nsh-platform-android/java/com/longbridge/nsh/NshView.java`).
