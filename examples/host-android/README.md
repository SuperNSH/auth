# nsh-auth Android host

An Android embedding host (`applicationId dev.nshauth.sandbox`) that runs the
nsh-auth demo app (`examples/demo`) inside a `com.longbridge.nsh.NshView` and
answers its `host` channel:

- `auth.authorize` picks a browser (AppAuth-style enumeration behind the
  manifest's `<queries>` block), opens it as a Custom Tab with warm-up and
  `mayLaunchUrl` prefetch (`androidx.browser`), parks the flow in the sealed
  store so it survives a process kill, and completes with the custom-scheme
  redirect, which returns through the `nsh.auth.sandbox://callback` intent
  filter in `app/src/main/AndroidManifest.xml`. With no browser installed it
  rejects up front instead of launching into nothing.
- `auth.nativeSignIn` runs the native SDK flows: Google through Credential
  Manager (a bottom sheet owned by Play services; our sandbox web client id
  makes Google itself reject inside that sheet, which surfaces as the reject
  message) and Facebook through `facebook-login` (its own login dialog; the
  result returns through `onActivityResult`, not the redirect scheme). The
  manifest needs the two `com.facebook.sdk.*` meta-data entries and the
  `nsh.auth.server-client-id` Google web client id (fake sandbox values
  below). Facebook silently fails to initialize without its entries; Google
  sign-in rejects with a configuration error without its key - no sandbox
  fallback, because the returned id_token's `aud` carries that id and a real
  Google config could never pass the core's `aud` check against a hard-coded
  sandbox value. A native flow killed mid-dialog leaves nothing pending - the
  SDKs own their state; call again.
- `auth.pendingAuthorize` reports (or with `{clear: true}` consumes) an
  authorize flow parked by a process death, including the callback when its
  redirect arrived after a cold start.
- `auth.store.save|load|clear` seal tokens with an AndroidKeyStore AES-256/GCM
  key (StrongBox where the hardware offers it, unusable while the device is
  locked); ciphertext lands in the app-private file `nsh-auth-store.json`.
- `auth.config` reports the launch configuration: `mockBaseUrl` and `autoStart`
  (the `provider` launch intent extra).

The native module itself lives in `native/android/` and is compiled into this
app via a `kotlin.srcDir` entry in `app/build.gradle.kts` (AGP 9's built-in
Kotlin compiles it; there is no separate `kotlin-android` plugin application,
and AGP 9 refuses one - see the build note below for why the built-in
compiler's version is forced upward).

## Prerequisites

- `nsh` 0.5.0 from the upstream installer (`~/.nsh/bin`; the gate puts it
  ahead of Homebrew, whose formula is still 0.4.0, and checks the version).
- The 0.5.0 embed AARs: `tools/fetch-nsh-embed.sh android` (the gate runs it)
  downloads `nsh-embed-android.zip` from the v0.5.0 release once, checks it
  against a pinned sha256 and unpacks it into the git-ignored
  `.nsh-embed/0.5.0/android` at the repository root. NSH 0.5.0 no longer
  puts the AARs in its install. Set `NSH_EMBED_ANDROID=<dir>` to use other
  copies.
- Android SDK at `$HOME/Library/Android/sdk`.
- Android Studio's JDK (this machine has no usable `/usr/bin/java`).
- An emulator or device with API 28+. On this shared machine, only use the
  AVD named `nsh-auth` and always pass `-s <serial>` to adb.

## Build (one command)

From this directory (`examples/host-android`):

```bash
./build-gate.sh
```

The gate is idempotent and fails on any error. It runs, in order:

1. Builds the demo bundle with the demo's own documented command: the fenced
   `nsh build` line naming `host-android` in `examples/demo/README.md` (the
   demo documents the iOS and Android embeds side by side), else the first
   `nsh build` line, else `nsh build --release` inside `examples/demo`.
2. Copies that bundle output into `app/src/main/assets/nsh` (what
   `NshView.loadAssetBundle("nsh")` loads).
3. Copies `nsh.aar` and `nsh-dev.aar` from `.nsh-embed/0.5.0/android`
   (fetched as above) into `app/libs/`, writes
   `local.properties`, and runs `./gradlew assembleDebug` with
   `JAVA_HOME="/Applications/Android Studio.app/Contents/jbr/Contents/Home"`
   and `ANDROID_HOME=$HOME/Library/Android/sdk`.

Two network-dependent build facts, both deliberate:

- **Maven resolution.** The `auth.nativeSignIn` dependencies
  (`androidx.credentials:credentials` + `credentials-play-services-auth`
  1.6.0 and `com.google.android.libraries.identity.googleid:googleid` 1.2.1
  from `dl.google.com`, `com.facebook.android:facebook-login` 19.0.1 from
  `repo1.maven.org`) resolve on the first Gradle run; versions are pinned
  exactly in `app/build.gradle.kts` (no ranges, no dynamic `+`). Later runs
  resolve against the local Gradle cache.
- **The Kotlin compiler engine.** AGP 9's built-in Kotlin is the
  `org.jetbrains.kotlin:kotlin-gradle-plugin` artifact, pinned to 2.2.10 by
  every AGP stable line up to 9.5.1 - a compiler that reads Kotlin metadata
  only up to 2.3.0. `googleid` 1.2.1 ships 2.4.0 metadata, so
  `build.gradle.kts` forces `kotlin-gradle-plugin` to 2.4.10 on the
  buildscript classpath (Gradle conflict resolution picks the higher). AGP 9
  hard-rejects applying `org.jetbrains.kotlin.android` as a plugin ("no
  longer required since AGP 9.0"), so this classpath force is the only way
  to consume googleid while keeping the pinned artifact versions.

The APK lands at `app/build/outputs/apk/debug/app-debug.apk`. Debug builds link
`nsh-dev.aar`; release builds link `nsh.aar` (see `app/build.gradle.kts`).

## Build without the gate

Same steps, spelled out, from `examples/host-android`:

```bash
export JAVA_HOME="/Applications/Android Studio.app/Contents/jbr/Contents/Home"
export ANDROID_HOME="$HOME/Library/Android/sdk"
mkdir -p app/libs
embed="$(../../tools/fetch-nsh-embed.sh android)"
cp "$embed/nsh.aar" "$embed/nsh-dev.aar" app/libs/
./gradlew assembleDebug
```

`./gradlew` needs `nsh` 0.5.0 first on `PATH` (its `preBuild` task rebuilds the demo bundle
into `app/src/main/assets/nsh`).

## Install and launch

From `examples/host-android`:

```bash
adb devices
adb -s <serial> install -r app/build/outputs/apk/debug/app-debug.apk
adb -s <serial> shell am start -n dev.nshauth.sandbox/.MainActivity --es provider google
```

`<serial>` is the `adb devices` line of our emulator; with exactly one device
attached the short forms also work:

```bash
adb install -r app/build/outputs/apk/debug/app-debug.apk
adb shell am start -n dev.nshauth.sandbox/.MainActivity --es provider google
```

`--es provider google` starts the Google flow immediately. Other values follow
the demo's provider ids (`facebook`, `discord`, `github`, `mock`).

Launch extras apply only on a cold start; re-launching a running app with new
extras changes nothing. Force-stop our app first when re-launching with
different extras (never kill anything else on this shared machine):

```bash
adb -s <serial> shell am force-stop dev.nshauth.sandbox
```

## The mock loop (full sign-in against tools/mock-oauth)

Run `tools/mock-oauth` on this Mac and note the port it prints (below: 8755).
The launch extras only apply on a cold start, and a `singleTask` instance left
running from an earlier proof ignores them, so force-stop first - every time
the extras change:

```bash
adb -s <serial> shell am force-stop dev.nshauth.sandbox
adb -s <serial> shell am start -n dev.nshauth.sandbox/.MainActivity --es provider mock --es mockBaseUrl http://127.0.0.1:8755
```

The host turns `localhost` / `127.0.0.1` into `10.0.2.2` when it detects an
emulator (the emulator cannot reach this Mac's loopback; `10.0.2.2` is its
alias for the host), so `host.params.auth.mockBaseUrl` and `auth.config` both
report `http://10.0.2.2:8755`. Use the same port on every
`tools/mock-oauth` call. On a physical device, keep `127.0.0.1` and first run
`adb -s <serial> reverse tcp:8755 tcp:8755`.

## Trigger proof and screenshots

After `am start --es provider <id>`, the system sign-in surface opens on the
provider's own domain. An unknown-client error page shown on the provider's own
domain is the pass - stop there; never type a credential. Capture from the
repository root:

```bash
adb -s <serial> exec-out screencap -p > docs/evidence/<provider>/android.png
```

Look at every PNG saved (an unread screenshot proves nothing).

## Contract with the demo app

The demo's `nsh.json` must declare every name it calls, or the calls reject
with `ERR_ACCESS_DENIED`:

```json
{ "capabilities": { "host": ["auth.authorize", "auth.store.save", "auth.store.load", "auth.store.clear", "auth.config"] } }
```

The host grants a ceiling of its own (`setGrantedCapabilities` in
`MainActivity.kt`): a call must be both declared by the bundle and allowed by
the host, so the host grant mirrors the demo's names (`auth.*` covers all of
the below; `auth.nativeSignIn` is named explicitly) and adds the mock network
hosts its token exchange fetches need:

```json
{ "host": ["auth.authorize", "auth.pendingAuthorize", "auth.store.save", "auth.store.load", "auth.store.clear", "auth.config", "auth.nativeSignIn"], "network": { "hosts": ["127.0.0.1", "localhost", "10.0.2.2"] } }
```

Keep the two lists in sync; a host that grants less than the bundle declares
denies the call with `not granted` even though the app declared it.

| Channel call | Args | Reply | Failure |
|---|---|---|---|
| `auth.authorize` | `{url, scheme, verifier?, state?, provider?}` - `scheme` must be `nsh.auth.sandbox`, the scheme the host manifest routes; the optional fields are parked in the process-death record | `{callbackUrl}` | reject `cancelled` (user backed out), `cancelled: superseded by a new authorize call`, `cancelled: host destroyed`, `auth.authorize: no browser is installed on this device; the authorize URL cannot be opened`, a not-registered-scheme error, or an argument error |
| `auth.pendingAuthorize` | `{}` to report, `{clear: true}` to consume | `{scheme, url, state?, provider?, verifier?, callbackUrl?}` - `{}` when nothing is parked | - |
| `auth.store.save` | `{key, value}` (strings) | `{}` | reject with the storage error |
| `auth.store.load` | `{key}` | `{value: string \| null}` | reject with the storage error |
| `auth.store.clear` | `{key?}` - no key wipes everything | `{}` | reject with the storage error |
| `auth.config` | `{}` | `{mockBaseUrl?, autoStart?}` - keys absent when unset | - |
| `auth.nativeSignIn` | `{provider: "google" \| "facebook", nonce?}` - `nonce` is the RAW nonce from the core | `{provider: "google", idToken, nonce?}` or `{provider: "facebook", accessToken, expiresAt?}` | reject `cancelled` (user cancelled), `cancelled: superseded by a new nativeSignIn call`, `cancelled: host destroyed`, or the SDK's own error message (Google's `GetCredentialException` message - with the sandbox client id that is Google's own rejection from inside its sheet; Facebook's `FacebookException` message); google without the `nsh.auth.server-client-id` manifest meta-data rejects with a configuration error (no sandbox fallback); unknown provider name rejects with an argument error |

Manifest additions for Facebook (fake sandbox values; without them
facebook-login 19.0.1 does not crash - its `FacebookInitProvider` catches and
logs the init failure at INFO - but every SDK call then fails at use time):

```xml
<meta-data android:name="com.facebook.sdk.ApplicationId" android:value="1234567890123456" />
<meta-data android:name="com.facebook.sdk.ClientToken" android:value="nsh-auth-sandbox-client-token" />
```

And for Google (the web client id the returned id_token's `aud` carries;
host-owned key - neither credentials 1.6.0 nor googleid 1.2.1 defines one;
`NativeSignInModule` rejects `auth.nativeSignIn google` when it is absent,
so a real app must put its own registered web client id here):

```xml
<meta-data android:name="nsh.auth.server-client-id" android:value="nsh-auth-sandbox-web.apps.googleusercontent.com" />
```

(sandbox value; fake on purpose).

The SDK's own manifest brings `FacebookActivity`, `CustomTabMainActivity`,
`CustomTabActivity` and `FacebookInitProvider`; no `fb<APP_ID>` intent filter
is needed for login on Android. Credential Manager itself takes only the
string at call time - the meta-data above is this host module's config
surface, read by `MainActivity` and passed to the module.

Launch params (`host.params`, set by the host before the bundle loads; the
host is the source of truth for the redirect URI):

```json
{ "auth": { "redirectUri": "nsh.auth.sandbox://callback", "mockBaseUrl": "http://10.0.2.2:8755", "autoStart": "google" } }
```

`mockBaseUrl` and `autoStart` are present only when the matching launcher extra
was set. The authorize URL must carry `redirect_uri` on
`nsh.auth.sandbox://callback` (the manifest's intent filter) and `scheme` must
be `nsh.auth.sandbox`. A redirect completes the pending authorize only when its
scheme matches and its host and path are exactly the registered `callback` -
other URIs on that scheme reach the filter but are ignored, so a forged intent
cannot finish the call; `state` and `code` are the demo core's job to check.
If the process died mid-flow, a matching cold-start redirect is parked in the
sealed store with the record and surfaces through `auth.pendingAuthorize`
instead of being dropped.

The manifest's `<queries>` block (VIEW + BROWSABLE with https and http data
schemes, plus the `android.support.customtabs.action.CustomTabsService`
action) exists for Android 11+ package visibility: without it, browser
enumeration returns nothing and the Custom Tabs service cannot be resolved or
bound.

## Files

- `app/src/main/kotlin/dev/nshauth/sandbox/MainActivity.kt` - NshView wiring
  and the host channel handlers.
- `native/android/` (outside this directory, compiled in via
  `kotlin.directories`) - `AuthHostModule.kt`, `NativeSignInModule.kt`, `BrowserSelector.kt`, `BrowserDescriptor.kt`, `CustomTabManager.kt`, `SecureStore.kt`.
- `build-gate.sh` - the build described above.
- `gradle/wrapper/` + `gradlew` - Gradle 9.3.1, matching AGP 9.1.0.
