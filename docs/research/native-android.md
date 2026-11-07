# Phase 2 research — the Android embedding host: what proven library code to adopt

Question: for `native/android/` (Kotlin `AuthHostModule` with a hand-rolled
Custom Tabs launch + `SecureStore.kt` doing AES-256/GCM over AndroidKeyStore,
alias `nsh-auth-session`, fresh IV per seal, ciphertext in the app-private
`nsh-auth-store.json`, `AEADBadTagException` drops the entry) — which proven
library code should we vendor or adapt, behind the unchanged `auth.*` host
channel?

Method: real code read in the local clones (paths cited inline, clone heads
noted), plus two live fetches on 2026-11-07 (Maven Central metadata, upstream
repo README). No provider page was signed in to, no credential typed, no
network call from the app; this is a docs-and-source study only.

---

## Our host today (the baseline being judged)

| Piece | File | What it does |
|---|---|---|
| Launch | `native/android/dev/nshauth/sandbox/auth/AuthHostModule.kt` (`authorize`, line 95) | Builds a bare `CustomTabsIntent.Builder().setShowTitle(true).build()` and calls `launchUrl`. No browser enumeration, no `setPackage`, no `CustomTabsService` binding, no warm-up, no `mayLaunchUrl`. |
| Callback | same file (`completeRedirect`, line 74) | Single-task `MainActivity` receives the redirect via the VIEW/BROWSABLE intent filter (`examples/host-android/app/src/main/AndroidManifest.xml`, scheme `nsh.auth.sandbox`, host `callback`), then validates **exact scheme + host + path** before completing the pending promise; anything else is ignored (and logged without the query). |
| Storage | `native/android/dev/nshauth/sandbox/auth/SecureStore.kt` | One Keystore AES-256-GCM key (`nsh-auth-session`), Keystore-generated random IV per seal, `{key -> iv, ct}` base64 in one JSON file (atomic rename). `AEADBadTagException` / `KeyPermanentlyInvalidatedException` drop the entry; other Keystore errors propagate. |
| Wiring | `examples/host-android/app/src/main/kotlin/dev/nshauth/sandbox/MainActivity.kt` | `nsh.handle("auth.authorize" | "auth.store.save" | "auth.store.load" | "auth.store.clear" | "auth.config")` onto `NshView`; capability grant caps the names. |

Known gaps in the launch path (each mapped to a candidate below):

1. **No process-death resilience.** `pending` lives only in memory. If the
   system kills the host process while the Custom Tab is foregrounded, the
   cold-start redirect finds `pending == null` (`completeRedirect`) and the
   `auth.authorize` promise is gone. The PKCE verifier is likewise memory-only,
   so the redirect cannot be redeemed even if it arrives.
2. **No browser selection or warm-up.** The default handler resolves at launch
   time; there is no up-front "no browser" detection, no `warmup(0)`, no
   `mayLaunchUrl` prefetch, no explicit `setPackage` (first open pays full
   browser cold-start; a hostile default handler is also undetected).
3. **No `<queries>` element.** Not needed for the current bare launch (a plain
   VIEW intent resolves fine), but it *is* required for any
   `queryIntentActivities`-based browser enumeration on API 30+ — so any
   adoption of AppAuth's matcher (candidate 1) must add it to our manifest.

The storage path is already close to the platform best practice; research.md
Part 3 records that EncryptedSharedPreferences/Jetpack Security is deprecated
in favour of direct Keystore — which is exactly what `SecureStore.kt` does.

---

## Candidate 1 — AppAuth-Android (`openid/AppAuth-Android`)

Local clone `/Users/hmziq/fo/.refs/AppAuth-Android`, head `e5f5184`
(2026-03-22). Library paths below are relative to `library/java/net/openid/appauth/`.

**(a) License + attribution.** Apache License 2.0 (`LICENSE` at clone root;
"Copyright 2015 The AppAuth for Android Authors"). Vendoring translated
Kotlin requires keeping the license notice and attribution in each file
header; using it as a Maven artifact requires shipping its NOTICE-equivalent
attribution. Apache 2.0 is compatible with everything in this repo.

**(b) Copy / adapt / skip, per class.**

*Adapt (translate to Kotlin, keep behavior) — the launcher mechanics:*
- `browser/BrowserSelector.java` — the piece we lack entirely.
  `getAllBrowsers` (line 77) queries `ACTION_VIEW`+`CATEGORY_BROWSABLE` with
  `http:` data, `MATCH_ALL` + `GET_RESOLVED_FILTER`; `isFullBrowser` (line 182)
  rejects intent filters that don't support **both** http and https with no
  authority restriction — its javadoc says the point is to "mitigate
  man-in-the-middle attacks by malicious apps pretending to be browsers for
  the specific URI we query". `hasWarmupService` (line 175) probes
  `CustomTabsService.ACTION_CUSTOM_TABS_CONNECTION` per package;
  `select` (line 152) returns the first custom-tab-capable match, preferring
  the user's default browser (separately resolved via `resolveActivity` and
  re-ordered to the head of the list — the comment explains package-manager
  ordering alone does not guarantee that).
- `browser/CustomTabManager.java` — the piece our launch misses. `bind`
  (line 68) calls `CustomTabsClient.bindCustomTabsService` and, on
  `onCustomTabsServiceConnected`, `customTabsClient.warmup(0)`;
  `createSession` (line 139) builds a session and `mayLaunchUrl` for the
  authorize URL so the browser prefetches; `getClient` waits up to
  `CLIENT_WAIT_TIME = 1L` second on a `CountDownLatch` before falling back to
  a non-custom-tab launch; `dispose` unbinds.
- `browser/BrowserDescriptor.java` — trivial data class (package, signature
  set, version, `useCustomTab`).

*Adapt only if we want an allow-list* (skip is fine — `AnyBrowserMatcher`
returns `true` unconditionally and is what most embedders use):
- `browser/Browsers.java` + `browser/VersionedBrowserMatcher.java` +
  `browser/VersionRange.java` + `browser/DelimitedVersion.java` — the
  known-good browser catalogue (Chrome ≥ 45 for custom tabs, Firefox ≥ 57,
  Samsung Internet ≥ 4.0, with signature SHA-512 pins).

*Skip — would change our cut line (see the cut-line section):*
- `AuthorizationService.java` as a whole. Its `performAuthorizationRequest`
  (line 223) wraps the launch in `AuthorizationManagementActivity` and hands
  results back through caller-supplied `PendingIntent`s; its
  `performTokenRequest` (line 485) does the token exchange in native
  `HttpURLConnection` — we exchange in the TS core. Two details inside it are
  worth stealing as knowledge, not code: the `Accept: application/json`
  header on token requests ("GitHub will only return a spec-compliant response
  if JSON is explicitly defined", line 725-735) — our core's fetch should pin
  that header; and `prepareAuthorizationRequestIntent` (line 549) throws
  `ActivityNotFoundException` **before** leaving the app when
  `BrowserSelector.select` returned null, instead of crashing at `startActivity`.
- `AuthorizationManagementActivity.java` + `RedirectUriReceiverActivity.java`
  — the trampoline pair. `AuthorizationManagementActivity` (manifest:
  `library/AndroidManifest.xml`, translucent, `singleTask`, `exported=false`)
  records the auth intent + PendingIntents, survives process death through
  `onSaveInstanceState` (line 262), distinguishes cancel (resume with no data,
  line 247) from complete, clears the browser from the back stack via
  `RedirectUriReceiverActivity` + `FLAG_ACTIVITY_CLEAR_TOP | SINGLE_TOP`
  (line 195), and validates **state** in `extractResponseData` (line 342:
  `STATE_MISMATCH` discards the response). High-quality code — but
  AppCompatActivity-based, and adopting it means adopting its manifest shape
  (below).
- `AuthState.java` (line 41) — token expiry tracking +
  `performActionWithFreshTokens` single-flight refresh. Our TS/Rust cores
  already implement this (single-flight refresh is tested in both); adopting
  it would fork session logic into Kotlin. Skip.
- `AuthorizationServiceConfiguration.java`, `TokenResponse.java`,
  `CodeVerifierUtil.java` — request/response modelling and PKCE generation
  live in the cores already. Note `CodeVerifierUtil.deriveCodeVerifierChallenge`
  (line 137) **falls back to `plain`** when SHA-256 is unavailable — a
  downgrade RFC 7636 §4.2 forbids and our cores never make. Do not copy.
- `connectivity/DefaultConnectionBuilder.java` — only relevant for the native
  exchange we are not adopting.

**(c) Integration cost in our Gradle project.**

*As a dependency:* `implementation("net.openid:appauth:0.11.1")` in
`examples/host-android/app/build.gradle.kts` next to the existing
`androidx.browser:browser:1.8.0` line. Facts that decide it:

- **The artifact is frozen.** Maven Central metadata (fetched 2026-11-07,
  <https://repo1.maven.org/maven2/net/openid/appauth/maven-metadata.xml>):
  latest = **0.11.1**, last updated 2021-12-22. The GitHub HEAD carries five
  years of merged fixes that were never released. flutter_appauth pins the
  same 0.11.1 (`flutter_appauth/android/build.gradle.kts`), so it is what
  production wrappers ship — but "works" and "maintained" differ.
- Its POM pulls `androidx.appcompat:appcompat:1.3.0` (for the two activities),
  `androidx.annotation:annotation:1.2.0`, `androidx.browser:browser:1.3.0`
  (Gradle resolves up to our 1.8.0). Our host app extends plain
  `android.app.Activity`; the appcompat pull is dead weight plus a theme
  requirement for the translucent trampoline.
- **Manifest shape conflict.** The library's `RedirectUriReceiverActivity` is
  `exported=true` with a scheme-only filter (`android:scheme="${appAuthRedirectScheme}"`,
  `library/AndroidManifest.xml` line 31). Our manifest already routes the same
  scheme with a **more specific** filter (scheme+host). Android intent
  resolution picks the more specific filter for our URIs — so their receiver
  would silently never fire, or, if we delete ours in favour of theirs, we
  lose exact-match manifest routing (their filter matches *any* host on the
  scheme). Either way the dependency forces us to restructure the redirect
  path that the security review already signed off.
- *As vendored code:* three files translated to Kotlin
  (`BrowserSelector`, `CustomTabManager`, `BrowserDescriptor`), roughly 350
  lines, Apache 2.0 headers kept, no new Gradle dependency, no appcompat, no
  manifest activities. We add one thing ourselves that the dependency would
  otherwise merge for us: the `<queries>` block (below). This is the cheaper
  integration on every axis except "not written by us".

**(d) What it does better than ours.** Warm-up + session + `mayLaunchUrl`
(latency and prefetch), default-browser-aware selection with custom-tab
preference, full-browser hygiene check (http+https, no authority), up-front
no-browser detection, and the trampoline/PendingIntent pattern that survives
process death and removes the browser tab from the back stack. Our exact
scheme+host+path validation is *stricter* than AppAuth's redirect handling
(their trampoline checks `state` only; the manifest filter is scheme-only) —
the two designs split the same guarantees differently.

**(e) What we keep.** The `auth.*` channel contract unchanged
(`AuthHostModule.kt` handlers; names also granted in `MainActivity.kt`
`HOST_GRANT`); our exact scheme/host/path callback validation (a security
feature, per `docs/security-review.md`); exchange in the TS core.

---

## Candidate 2 — flutter_appauth (`MaikuB/flutter_appauth`)

Local clone `/Users/hmziq/fo/.refs/flutter_appauth`, tag `flutter_appauth-v13.0.0`
(pub.dev: 13.0.0, published 2026-10, fetched 2026-11-07).

**(a) License + attribution.** BSD 3-Clause ("Copyright (c) 2019, Michael Bui",
`flutter_appauth/LICENSE`).

**(b) Copy / adapt / skip.** **Skip — nothing to take.** The Android side is
one file (`flutter_appauth/android/src/main/java/io/crossingthestreams/flutterappauth/FlutterAppauthPlugin.java`)
that adapts AppAuth-Android to a Flutter MethodChannel, plus
`InsecureConnectionBuilder.java` (cleartext HTTP for tests). It pins
`net.openid:appauth:0.11.1` (`flutter_appauth/android/build.gradle.kts`). What
it adds over raw AppAuth:

- Two long-lived `AuthorizationService` instances created at engine attach and
  disposed at detach (line 136-155) — a lifecycle pattern we already mirror
  with `AuthHostModule` + `onHostDestroyed`.
- `authorizeAndExchangeCode` / `token` / `endSession` plumbing, native
  discovery fetch, `clientSecret` passthrough, `ui_locales`/`claims`
  extraction (line 448-470). Every one of those is a thing our design
  deliberately keeps out of the host: discovery and exchange live in the TS
  core; secrets never traverse the host channel (broker seam instead).
- Launch via `getAuthorizationRequestIntent` + `startActivityForResult`
  (line 468-469) — the *non*-PendingIntent path of AppAuth, i.e. weaker than
  the demo's own PendingIntent flow.

Its Dart side (`flutter_appauth/lib/src/flutter_appauth.dart`) is a
platform-channel mapper. Our equivalent adapter (`MainActivity.kt` +
`AuthHostModule.kt`) already exists and satisfies the NSH host contract. The
plugin is useful only as evidence that AppAuth 0.11.1 remains the working
baseline for wrappers.

**(c) Integration cost.** None — it is a Flutter plugin, not consumable from
our Gradle app without dragging the Flutter toolchain in. Non-starter.

**(d)/(e).** Nothing better than ours; we keep the channel contract and
validation as in candidate 1.

---

## Candidate 3 — flutter_secure_storage, Android engine (`juliansteenbakker/flutter_secure_storage`, ex `mogol`)

Local clone `/Users/hmziq/fo/.refs/flutter_secure_storage` (origin
`https://github.com/juliansteenbakker/flutter_secure_storage.git`, the
canonical repo since maintainership moved from mogol — confirmed live on
2026-11-07: <https://github.com/mogol/flutter_secure_storage> resolves to the
same project under the current maintainer, BSD-3-Clause). Tags:
`v10.3.4` stable, `v11.0.0-beta.1` next; the clone head is past both
(commit `1012697`). Paths below are relative to
`flutter_secure_storage/android/src/main/java/com/it_nomads/fluttersecurestorage/`.

**(a) License + attribution.** BSD 3-Clause ("Copyright 2017 German Saprykin",
`LICENSE` at clone root). Vendoring requires keeping the copyright notice and
the three-clause conditions; attribution file sufficient.

**(b) Current architecture (recorded, because the task asks for it).**

The EncryptedSharedPreferences deprecation response is **removal, not
migration**: v10 dropped the Jetpack Security backend entirely and v11 cannot
read it — `UpgradeInspector.java` (line 44-49, 98-105) detects the leftover
Tink keysets (`__androidx_security_crypto_encrypted_prefs_*_keyset__`) and
reports `STATE_LEGACY_DATA_UNREADABLE` with the message "Data is in the
EncryptedSharedPreferences (Tink) store, whose backend v11 removed", so the
official path was "upgrade to v10 first". The declared
`com.google.crypto.tink:tink-android:1.23.0` in
`flutter_secure_storage/android/build.gradle` has **no remaining import** in
main source — a vestige of the v9/v10 backend.

The current stack is a two-layer cipher:

- **Key layer** (`ciphers/KeyCipherImplementationRSAOAEP.java`, the default
  `KeyCipherAlgorithm.RSA_ECB_OAEPwithSHA_256andMGF1Padding` per
  `ciphers/StorageCipherFactory.java` line 16): a Keystore RSA key (OAEP
  SHA-256/MGF1-SHA1, 25-year cert, `KeyGenParameterSpec` at line 138-147)
  **wraps a random software AES-128 data key** (`keySize = 16` bytes,
  `ciphers/StorageCipherImplementationGCM.java` line 18) which is stored
  base64 in a separate "key prefs" file under the constant name
  `AESVGhpcyBpcyB0aGUga2V5IGZvciBhIHNlY3VyZSBzdG9yYWdlIEFFUyBLZXkK`.
- **Storage layer** (`ciphers/StorageCipherImplementationGCM.java`): per
  entry, a fresh random **12-byte IV** from `SecureRandom`, AES-GCM, 128-bit
  tag, IV prepended to the ciphertext (lines 67-98). Values land in
  **SharedPreferences** (`MODE_PRIVATE` XML files), keys prefixed
  (`FlutterSecureStorage.addPrefixToKey`, line 50), with algorithm markers
  (`FlutterSecureSAlgorithmKey`/`Storage`) persisted so the factory can detect
  a change and re-encrypt.
- **Single key, not key-per-entry:** one data key for all entries; per-entry
  protection comes from the fresh IV — the same shape as our store, one
  hardware step weaker (their data key is software AES-128 wrapped by RSA;
  ours is a hardware-resident AES-256). Adopting their key hierarchy would be
  a **downgrade** for us; their direct-Keystore biometric variant
  (`ciphers/KeyCipherImplementationAES23.java`: Keystore AES-256-GCM, alias
  `<pkg>.FlutterSecureStoragePluginKey`, `setUserAuthenticationRequired`,
  `setInvalidatedByBiometricEnrollment`, `setUnlockedDeviceRequired(true)`
  line 188, **StrongBox with fallback** lines 187-237) is the strong one — and
  even it seals the app key with a *fixed* IV stored in prefs
  (`KeyStoreIV1`, line 102/113), because a Keystore AES key can't wrap, only
  encrypt — a wrinkle our per-entry design doesn't have.
- **Recovery machinery** (`FlutterSecureStorage.java`): on cipher/key errors,
  `handleKeyMismatch` (line 1019) offers `migrateOnAlgorithmChange`
  (full re-encryption, crash-safe with per-key `_MIGRATED` markers, line
  561-599) or `resetOnError` (wipe + reinit, line 1084); per-operation
  `handleStorageError` (line ~1230) deletes the corrupted entry and retries
  once. Namespace migration and biometric key relocation round it out.
- Storage file layout: `shared_prefs/<data-ns>.xml` (encrypted values) +
  `shared_prefs/<key-ns>.xml` (wrapped key + IV) + algorithm markers. Ours is
  one JSON file — functionally equivalent, app-private either way, and easier
  to grep-proof (the STATUS.md storage proof exploits exactly that).

**(c) Integration cost.** The engine is not published as an Android artifact
(it is a Flutter plugin module); only vendoring is possible. Its code is
plain Java with no AndroidX crypto dependency, so files *can* be lifted, but
the main handler (`FlutterSecureStorage.java`, ~1900 lines) is welded to the
Flutter MethodChannel lifecycle and config surface. Realistic adoption is
selective feature-port into `SecureStore.kt`, not file copy.

**(d) What it does better than ours — and what we keep.**

Better:
1. **StrongBox** (`PackageManager.FEATURE_STRONGBOX_KEYSTORE` check +
   `setIsStrongBoxBacked(true)` + retry-without-StrongBox on generation
   failure, `KeyCipherImplementationAES23.java` lines 126-237). Our
   `SecureStore.key()` has no StrongBox path.
2. **`setUnlockedDeviceRequired(true)`** (line 188) — the key is unusable
   while the device is locked; available on our minSdk 28 floor. Ours omits it.
3. Wrong-type alias guard: a non-`SecretKey` entry at the alias is replaced
   with a fresh key instead of producing a confusing provider error
   (`ensureSymmetricKeyAtAlias`, lines 52-64). Ours already behaves
   equivalently (`existing is SecretKey` check + regenerate), so no change.
4. Key-generation/algorithm-change migration machinery — not needed by us
   while `SecureStore.kt` has exactly one algorithm and one alias; noted as
   the pattern to copy if we ever rotate.

Not better (keep ours):
- Their software AES-128 data key wrapped by RSA vs our hardware-resident
  AES-256-GCM (their own strong path matches ours).
- SharedPreferences XML vs our single JSON file (equivalent privacy; ours is
  simpler to audit and to prove clean).
- Their fixed-IV app-key seal in the biometric path — an artifact of wrapping;
  ours seals fresh per entry.
- Their biometric/auth-bound keys — deliberately skip for *session* tokens:
  an auth-bound key cannot decrypt in background refresh, which is a core
  nsh-auth feature.

**(e) Keep:** `auth.store.save|load|clear` contract and reply shapes, single
Keystore key alias `nsh-auth-session`, fresh-IV-per-seal, `AEADBadTagException`
drop semantics.

---

## The cut line: launcher + callback routing (AppAuth) vs core-owned exchange

Our design: the host launches the browser and routes the redirect back to the
TS core, which owns the entire OAuth protocol (authorize URL, PKCE, state,
exchange via fetch, refresh, id-token verification). AppAuth-Android instead
models requests/responses as native objects and performs the token exchange
in `AuthorizationService.TokenRequestTask`. The honest evaluation:

**What moving the exchange into Kotlin would buy:** nothing we lack. The
native exchange adds `Accept: application/json` (a one-line header our core
can and should add itself — see takeaways), id-token parse+validate in
`IdToken.java` (our cores do RS256-vs-JWKS with nonce/iss/exp checks, which
the native `IdToken.validate` does not fully replicate — it does no signature
check), and HttpURLConnection connection reuse (irrelevant at our request
rate). It would cost: forking provider rules, PKCE/state/nonce handling,
broker routing and error taxonomy across two languages, and re-proving the
mock suite (success/denial/wrong-state/wrong-nonce/expired/refresh/
single-flight/revoked/sign-out) in a second place. The exchange stays in the
core. This also matches every wrapper studied: flutter_appauth and
react-native-app-auth do perform native exchanges, but they *own* their
session model; our cores do.

**What the launcher side genuinely lacks** (candidate 1's section d): warm-up
binding, browser enumeration/selection, up-front no-browser detection, and
process-death resilience. The first three are small, self-contained, and
license-clean to vendor. The last is the only *behavioral* gap: after a
process kill during the browser round trip, our `auth.authorize` promise dies
and the cold-start redirect is dropped (`completeRedirect` finds no pending).
AppAuth's PendingIntent trampoline solves the *native* half (the result
survives), but not the promise half — a JS/Dart promise dies with the process
too; its demo re-enters via the completion activity's fresh launch. The
complete fix for us is host-side: persist the pending PKCE verifier + state
(in `SecureStore`, before launching) so a cold-start redirect can be matched
and delivered as `auth.authorize`'s completion or an `auth.callback` host
event (NSH keeps early host events, up to 256 — research.md Part 4, exp 2).
That persistence is our code; AppAuth offers the shape, not the implementation.

**Adopt the launcher mechanics as vendored Kotlin, not as the Maven
dependency:** the dependency drags a frozen 2021 artifact, appcompat, and a
scheme-only redirect filter that collides with our more-specific
scheme+host+path filter (intent resolution would silently bypass AppAuth's
receiver or force us to relax our manifest). Vendoring
`BrowserSelector` + `CustomTabManager` + `BrowserDescriptor` (~350 lines)
keeps our routing, our validation, our manifest, and buys warm-up + selection
+ prefetch. The trampoline/PendingIntent flow is *not* vendored; the pending
verifier persistence (above) is the cheaper, contract-compatible answer to
the same problem.

---

## ADOPTION VERDICT

| Item | Verdict | What exactly | Why |
|---|---|---|---|
| AppAuth-Android `BrowserSelector`, `CustomTabManager`, `BrowserDescriptor` | **adapt (vendor + translate to Kotlin)** | ~350 lines into `native/android/`, Apache 2.0 headers kept; wire into `AuthHostModule.authorize`: select browser once, bind+warmup, `mayLaunchUrl(authorizeUrl)`, launch with `intent.setPackage(...)`; unbind in `onHostDestroyed` | Buys warm-up latency, default-browser-aware custom-tab selection, fake-browser hygiene, up-front no-browser error. Dependency rejected: Maven-frozen 0.11.1 (Dec 2021), pulls appcompat 1.3.0 into a plain-Activity host, and its scheme-only `RedirectUriReceiverActivity` filter conflicts with our exact scheme+host+path filter. |
| AppAuth-Android `<queries>` block | **adapt (manifest)** | Add to `examples/host-android/app/src/main/AndroidManifest.xml`: `<queries><intent><action android:name="android.intent.action.VIEW"/><category android:name="android.intent.category.BROWSABLE"/><data android:scheme="https"/></intent></queries>` (copied from `library/AndroidManifest.xml`) | Required for `queryIntentActivities` browser enumeration on API 30+; the Maven artifact would merge it, vendored code cannot. |
| AppAuth-Android `Accept: application/json` on token POSTs | **adapt (knowledge → core)** | One header in the TS/Rust exchange fetch | The library's `TokenRequestTask` carries it specifically for GitHub's non-spec JSON default; costs nothing, prevents a GitHub refresh/exchange parsing failure. |
| AppAuth-Android `AuthorizationService` exchange, `AuthState`, discovery, PKCE utils | **kept (ours) / skip** | — | Forks OAuth logic out of the cores; `CodeVerifierUtil` even downgrades to `plain`; core owns exchange + single-flight refresh + JWKS. |
| AppAuth trampoline (`AuthorizationManagementActivity`, `RedirectUriReceiverActivity`) + PendingIntents | **kept (ours) + follow-up** | Keep exact-match routing; separately consider persisting the pending PKCE verifier/state in `SecureStore` before launch so a cold-start redirect completes (or emits) the flow | The trampoline fixes process-death for the native half but not the promise half; appcompat-dependent; conflicts with our manifest routing. Pending persistence is contract-compatible and host-only. |
| flutter_appauth | **skip** | Nothing | Thin MethodChannel adapter; adds only what our design keeps out of the host (native discovery/exchange, secret passthrough); not consumable from Gradle. |
| flutter_secure_storage — StrongBox + retry-without fallback, `setUnlockedDeviceRequired(true)` | **adapt (feature-port into `SecureStore.kt`)** | In `SecureStore.key()`: `hasSystemFeature(FEATURE_STRONGBOX_KEYSTORE)` + `setIsStrongBoxBacked(true)` (API 28+; our minSdk is exactly 28) with generation-failure retry without StrongBox; add `setUnlockedDeviceRequired(true)` | Real hardening our key generation lacks, with an explicit degradation path; BSD-3 attribution note required. |
| flutter_secure_storage — everything else (RSA-wrap of a software AES-128 key, SharedPreferences, algorithm markers/migrations, biometric auth-bound keys, fixed-IV app-key seal) | **kept (ours) / skip** | Keep `SecureStore.kt` as is | Their default key hierarchy is weaker than our hardware-resident AES-256; SharedPreferences XML vs our single JSON file is a wash; migrations unneeded for a single-algorithm store; auth-bound keys would break background refresh. Their v10/v11 handling confirms the deprecation response: Jetpack Security removed outright, leftover Tink stores reported unreadable. |

Licenses to honor: Apache-2.0 (AppAuth-Android, vendored Kotlin headers),
BSD-3-Clause (flutter_secure_storage, if feature-port comments reference its
source), BSD-3-Clause (flutter_appauth — only if its error-code mapping is
consulted; skip verdict means likely none).

Blockers: none for the verdicts above. All changes are inside
`native/android/`, `examples/host-android/app/src/main/AndroidManifest.xml`,
and the cores' exchange fetch header — none touch the `auth.*` channel
contract, the demo's `nsh.json` capability declarations, or the redirect
validation.

---

## Result contract

```json
{
  "done": true,
  "summary": "Android host phase-2 study: AppAuth-Android's launcher mechanics (BrowserSelector + CustomTabManager + BrowserDescriptor, ~350 lines, Apache-2.0) should be vendored+translated into AuthHostModule for warm-up/binding, default-browser-aware custom-tab selection and up-front no-browser detection, with the <queries> block added to our manifest; its native exchange/AuthState/trampoline stay skipped because our TS core owns the protocol and our exact scheme+host+path redirect validation is stricter than AppAuth's scheme-only filter (dependency on frozen net.openid:appauth:0.11.1 rejected for the same manifest conflict plus appcompat drag). flutter_appauth adds nothing over AppAuth for us — skip. flutter_secure_storage's current Android engine (BSD-3) abandoned EncryptedSharedPreferences/Tink outright: RSA-OAEP-wrapped software AES-128 data key + per-entry AES-GCM in SharedPreferences, with a StrongBox/auth-bound biometric variant and crash-safe algorithm migration; we port only StrongBox-with-fallback and setUnlockedDeviceRequired(true) into SecureStore.kt and keep our hardware-resident AES-256-GCM single-file store. Process-death resilience is the one real gap; the fix is host-side pending-verifier persistence, not AppAuth's appcompat trampoline.",
  "verdict": {
    "vendored": [],
    "adapted": [
      "AppAuth-Android: BrowserSelector + CustomTabManager + BrowserDescriptor (Apache-2.0) translated to Kotlin behind auth.authorize",
      "AppAuth-Android: <queries> VIEW/BROWSABLE/https block added to examples/host-android/app/src/main/AndroidManifest.xml",
      "AppAuth-Android: Accept: application/json header on token POSTs adopted into the cores' exchange fetch",
      "flutter_secure_storage (BSD-3): StrongBox with generation-failure fallback + setUnlockedDeviceRequired(true) ported into SecureStore.kt key generation"
    ],
    "kept": [
      "auth.* host channel contract and MainActivity wiring unchanged",
      "exact scheme+host+path callback validation in AuthHostModule.completeRedirect",
      "TS-core-owned token exchange, refresh, discovery and id-token verification",
      "SecureStore.kt design: one hardware-resident AES-256-GCM Keystore key (nsh-auth-session), fresh IV per seal, single app-private JSON store, AEADBadTagException drop",
      "our manifest's exact scheme+host VIEW/BROWSABLE intent filter (stronger than AppAuth's scheme-only placeholder filter)"
    ]
  },
  "licenses": [
    "AppAuth-Android: Apache-2.0 (openid/AppAuth-Android, LICENSE)",
    "flutter_appauth: BSD-3-Clause (MaikuB/flutter_appauth, flutter_appauth/LICENSE, Copyright (c) 2019 Michael Bui)",
    "flutter_secure_storage: BSD-3-Clause (juliansteenbakker/flutter_secure_storage, LICENSE, Copyright 2017 German Saprykin)"
  ]
}
```
