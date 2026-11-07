# native/android

Kotlin sources of the nsh-auth Android host module. This directory is not a
Gradle module of its own: `examples/host-android` compiles it into the app via
`kotlin.directories += "../../../native/android"` in `app/build.gradle.kts`
(AGP 9's built-in Kotlin). Keep the package path `dev/nshauth/sandbox/auth/`
under this directory.

- `AuthHostModule.kt` - browser selection, Custom Tabs authorize, launch
  configuration (`provider` / `mockBaseUrl` launcher extras, loopback rewritten
  to `10.0.2.2` on the emulator), the cancelled/resume bookkeeping, and the
  persisted pending-authorize record (below).
- `BrowserSelector.kt` + `BrowserDescriptor.kt` - translated from
  AppAuth-Android (`openid/AppAuth-Android` at `e5f5184`,
  `library/java/net/openid/appauth/browser/{BrowserSelector,BrowserDescriptor}.java`,
  Apache-2.0; file headers carry the verbatim upstream notice plus the
  modification note). Enumeration keeps the full-browser hygiene check: a
  candidate must handle ACTION_VIEW + BROWSABLE for **both** http and https
  with no authority restriction, so a malicious app registered only for the
  specific authorize URI we query cannot pose as the browser (a
  man-in-the-middle vector upstream's javadoc names). `select` prefers
  custom-tab-capable browsers and puts the user's default browser first.
- `CustomTabManager.kt` - translated from AppAuth-Android's
  `browser/CustomTabManager.java` (Apache-2.0, same provenance): binds the
  browser's `CustomTabsService`, calls `warmup(0)` once connected, creates a
  session and asks for `mayLaunchUrl` prefetch of the authorize URL, waits up
  to 1 s for the connection, and falls back to a session-less tab (or a plain
  ACTION_VIEW for browsers without custom tabs) instead of failing.
- `SecureStore.kt` - AES-256/GCM with one AndroidKeyStore key (alias
  `nsh-auth-session`), a fresh random IV per seal, and only
  `{key -> iv, ciphertext}` persisted to the app-private
  `nsh-auth-store.json`. No plaintext token touches disk. Fresh keys ask for
  StrongBox when the device advertises `FEATURE_STRONGBOX_KEYSTORE` (falling
  back to the TEE on generation failure - never failing on unsupported
  hardware) and set `setUnlockedDeviceRequired(true)`, so the key is unusable
  while the device is locked (that use failure is transient and propagates;
  the store is not wiped). Keys already on the device keep their original
  settings - regenerating one would orphan every sealed entry. These two flags
  are ported from flutter_secure_storage's `KeyCipherImplementationAES23.java`
  (BSD-3-Clause, Copyright 2017 German Saprykin); a stored entry is dropped
  only when its tag fails (`AEADBadTagException`, tamper or a replaced
  Keymaster key after device restore) or the key is permanently invalidated;
  any other Keystore error propagates instead of wiping persisted auth.

Host channel contract (wired by `MainActivity.kt` onto `NshView.handle`, names
also granted in the host's `setGrantedCapabilities` and declared by the demo's
`nsh.json` - its `auth.*` wildcard covers all of them):

| Name | Args | Reply | Reject message |
|---|---|---|---|
| `auth.authorize` | `{url, scheme, verifier?, state?, provider?}` - `scheme` must be `nsh.auth.sandbox`, the scheme the host manifest routes; the last three are optional resumption metadata for the pending record | `{callbackUrl}` | `cancelled`, `cancelled: superseded by a new authorize call`, `cancelled: host destroyed`, `auth.authorize: no browser is installed on this device; the authorize URL cannot be opened`, a not-registered-scheme error, or an argument error |
| `auth.pendingAuthorize` | `{}` to report, `{clear: true}` to consume | `{scheme, url, state?, provider?, verifier?, callbackUrl?}` or `{}` when nothing is parked | - |
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
extra was set.

Redirect mechanism: the provider returns to `nsh.auth.sandbox://callback`
(query included); the VIEW/BROWSABLE intent filter on the single-task
`MainActivity` in `examples/host-android/app/src/main/AndroidManifest.xml`
delivers `onNewIntent`, and the module completes the pending `auth.authorize`
only when the URI's scheme matches the pending one and its host and path are
exactly the registered `callback` (empty or `/`) - any other URI routed by the
filter is ignored, so a forged intent cannot finish the call. The launcher
extras are read only from the intent that creates the activity (`onCreate`); a
warm instance's `onNewIntent` never reconfigures sign-in.
`NshView` APIs follow the 0.4.0 embed example
(`.refs/nsh-v0.4.0/examples/embed-android` and
`crates/nsh-platform-android/java/com/longbridge/nsh/NshView.java`).

## Process-death resilience

`auth.authorize` persists a record under the non-session key
`nsh-auth.pending-authorize` in the same sealed store before the browser
leaves the app: the scheme, the authorize URL, `state` (also read from the
URL's query when the caller does not pass it), and the optional
`verifier`/`provider` the caller supplies. The record holds no token. The
verifier is stored deliberately: in the RFC 7636 threat model (section 4.6)
the verifier without its matching authorization code redeems nothing, it only
ever travels to the token endpoint over TLS, and the app's own storage was
already readable by exactly the parties who could read this record - sealing
it adds no new exposure. (Full resumption - completing the exchange in the
core - additionally needs the core to pass `verifier`/`state`/`provider` and
to read them back; the record is in place for that, the core side is a
follow-up.)

A cold-start redirect (the authorize promise died with the old process)
resolves the record instead of being dropped: the callback URL is written into
it and `auth.pendingAuthorize` reports the interrupted flow - `{url, state,
verifier?, provider?, callbackUrl}` - until the app consumes it with
`{clear: true}` or the next `auth.authorize` supersedes it. Completion and the
resume-cancel clear the record; host destroy keeps it, because the browser may
still be out there. On Android 11+ the manifest's `<queries>` block (VIEW +
BROWSABLE for http and https, plus the `CustomTabsService` action) is what
makes the enumeration see any browsers at all.
