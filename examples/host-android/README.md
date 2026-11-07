# nsh-auth Android host

An Android embedding host (`applicationId dev.nshauth.sandbox`) that runs the
nsh-auth demo app (`examples/demo`) inside a `com.longbridge.nsh.NshView` and
answers its `host` channel:

- `auth.authorize` opens Custom Tabs (`androidx.browser`) and completes with the
  custom-scheme redirect, which returns through the
  `nsh.auth.sandbox://callback` intent filter in
  `app/src/main/AndroidManifest.xml`.
- `auth.store.save|load|clear` seal tokens with an AndroidKeyStore AES-256/GCM
  key; ciphertext lands in the app-private file `nsh-auth-store.json`.
- `auth.config` reports the launch configuration: `mockBaseUrl` and `autoStart`
  (the `provider` launch intent extra).

The native module itself lives in `native/android/` and is compiled into this
app via a `kotlin.directories` entry in `app/build.gradle.kts` (AGP 9's
built-in Kotlin; the module has no `kotlin-android` plugin).

## Prerequisites

- `nsh` 0.4.0 from Homebrew (`brew --prefix nsh`/libexec has the embed AARs).
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
3. Copies `nsh.aar` and `nsh-dev.aar` from
   `$(brew --prefix nsh)/libexec/embed/android` into `app/libs/`, writes
   `local.properties`, and runs `./gradlew assembleDebug` with
   `JAVA_HOME="/Applications/Android Studio.app/Contents/jbr/Contents/Home"`
   and `ANDROID_HOME=$HOME/Library/Android/sdk`.

The APK lands at `app/build/outputs/apk/debug/app-debug.apk`. Debug builds link
`nsh-dev.aar`; release builds link `nsh.aar` (see `app/build.gradle.kts`).

## Build without the gate

Same steps, spelled out, from `examples/host-android`:

```bash
export JAVA_HOME="/Applications/Android Studio.app/Contents/jbr/Contents/Home"
export ANDROID_HOME="$HOME/Library/Android/sdk"
mkdir -p app/libs
cp "$(brew --prefix nsh)/libexec/embed/android/nsh.aar" "$(brew --prefix nsh)/libexec/embed/android/nsh-dev.aar" app/libs/
./gradlew assembleDebug
```

`./gradlew` needs `nsh` on `PATH` (its `preBuild` task rebuilds the demo bundle
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
Then launch the app with the mock provider and its base URL:

```bash
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

| Channel call | Args | Reply | Failure |
|---|---|---|---|
| `auth.authorize` | `{url, scheme}` - `scheme` must be `nsh.auth.sandbox`, the scheme the host manifest routes | `{callbackUrl}` | reject `cancelled` (user backed out), `cancelled: superseded by a new authorize call`, a not-registered-scheme error, or an argument error |
| `auth.store.save` | `{key, value}` (strings) | `{}` | reject with the storage error |
| `auth.store.load` | `{key}` | `{value: string \| null}` | reject with the storage error |
| `auth.store.clear` | `{key?}` - no key wipes everything | `{}` | reject with the storage error |
| `auth.config` | `{}` | `{mockBaseUrl?, autoStart?}` - keys absent when unset | - |

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

## Files

- `app/src/main/kotlin/dev/nshauth/sandbox/MainActivity.kt` - NshView wiring
  and the host channel handlers.
- `native/android/` (outside this directory, compiled in via
  `kotlin.directories`) - `AuthHostModule.kt`, `SecureStore.kt`.
- `build-gate.sh` - the build described above.
- `gradle/wrapper/` + `gradlew` - Gradle 9.3.1, matching AGP 9.1.0.
