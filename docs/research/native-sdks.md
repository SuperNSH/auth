# Native SDK adapters — exact coordinates, config, failure surfaces, licenses

Phase-3 research question: for the optional native SDK adapters behind the existing
`auth.*` host contract (`native/ios/Sources/AuthHostModule.swift`,
`native/android` modules, hand-built hosts under `examples/host-ios` and
`examples/host-android`), what are the current SDK coordinates, the exact config
each SDK needs with our FAKE sandbox ids, what happens at runtime with an
unregistered client id, what token shape reaches the core, and what the SPM /
Maven resolution does to our hermetic gates.

Verification date: 2026-11-07. Versions were read from GitHub releases pages and
Maven metadata XML (not from memory); licenses from LICENSE files, the GitHub
license API, and Maven POMs. Sandbox rules hold: fake ids only, no provider page
opened interactively, nothing signed in to. Everything below is docs/source
research; no code was written for this.

Local files this research maps onto (read, not modified):
`examples/host-ios/build-gate.sh`, `examples/host-ios/NshAuthHostIOS.xcodeproj/project.pbxproj`
(294 lines, hand-written, fixed IDs, no SPM sections today),
`examples/host-android/build-gate.sh`, `examples/host-android/app/build.gradle.kts`,
`examples/host-android/app/src/main/AndroidManifest.xml`,
`crates/nsh-auth/src/token.rs` (`exchange_code` :38, `jwks` :108, `revoke` :120),
`crates/nsh-auth/src/jwt.rs` (`IdTokenChecks`, `claims` :28),
`docs/providers.md` (Google JWKS :24, Facebook JWKS :104, Apple JWKS :318),
`docs/research/native-licensing.md` (notices rules), `docs/research/native-ios.md`
(cut lines: host contract must not change; nothing vendored).

---

## 1. Google Sign-In iOS

### Coordinates (current)

- SPM repo: `https://github.com/google/GoogleSignIn-iOS`. Current release
  **10.1.0** (2026-10-23); 10.1.0's release notes state it is **the last release
  published to CocoaPods** — SPM is the supported path from here. The "classic"
  GoogleSignIn (5.x, `GoogleSignIn` pod) is dead; do not touch it.
- Package products: `GoogleSignIn`, `GoogleSignInSwift` (SwiftUI
  `SignInWithGoogleButton`).
- `Package.swift` (main, read 2026-11-07): swift-tools **6.0**, platforms
  **iOS 15+ / macOS 12+**, **no binaryTargets** — all source targets. Source
  dependencies resolved over the network from github.com: AppAuth-iOS
  `from: "3.0.0"`, app-check `"11.0.0" ..< "13.0.0"`, GTMAppAuth `from: "6.0.0"`,
  gtm-session-fetcher `"3.3.0" ..< "6.0.0"`, GoogleUtilities `from: "8.0.0"`
  (plus an OCMock fork pinned to a revision, test-only).

### What it needs

Info.plist (Google docs "Sign-In for iOS — Start integrating",
https://developers.google.com/identity/sign-in/ios/start-integrating):

- `GIDClientID` — the iOS OAuth client ID. Our sandbox value
  `nsh-auth-sandbox.apps.googleusercontent.com` is syntactically valid (it is a
  normal `*.apps.googleusercontent.com` string); nothing validates it locally.
- `CFBundleURLSchemes` must contain the **reversed client id**
  (`com.googleusercontent.apps.nsh-auth-sandbox`) — the SDK checks for it at
  sign-in time (`GIDSignIn.m` builds `GIDSignInCallbackSchemes` from
  `configuration.clientID` and the bundle and raises on unsupported schemes).
- Optional `GIDServerClientID` — the backend's **web-application** client id
  ("not the ID for your iOS or macOS app"), `GIDHostedDomain`, `GIDOpenIDRealm`.
  Key constant verified in source: `GoogleSignIn/Sources/GIDSignIn.m:162`
  (`kConfigClientIDKey = @"GIDClientID"`).

API surface (headers at `GoogleSignIn/Sources/Public/GoogleSignIn/`, main
branch):

- `GIDSignIn.sharedInstance.configuration = GIDConfiguration(clientID:serverClientID:)`
  or plist-driven + `configure(completion:)` (`GIDSignIn.h:74,103`).
- `signIn(withPresenting:presentingViewController:)` → `GIDSignInResult`
  (`GIDSignIn.h:174+`).
- **serverAuthCode**: `GIDSignInResult.serverAuthCode` (`GIDSignInResult.h:30`,
  "An OAuth2 authorization code for the home server") — it is issued only when
  a server client id is configured (`GIDConfiguration(serverClientID:)` /
  `GIDServerClientID`). It moved here from `GIDGoogleUser` in the 7.x rewrite;
  `GIDGoogleUser` on main has no `serverAuthCode` (verified by grep over
  `GIDGoogleUser.h`).
- `GIDGoogleUser`: `userID`, `accessToken` (`GIDToken`), `idToken` (`GIDToken`,
  nullable), `profile` (`GIDProfileData`). `GIDConfiguration.h:27-30`: the
  server client id "will be returned as the `audience` property of the OpenID
  Connect ID token" — with `GIDServerClientID` set, the id_token's `aud` is the
  **web** client id, which our core's `aud` check must accept.

### Runtime with our fake client id

Two distinct layers:

1. **Developer errors (before any network):** `GIDSignIn.m` raises
   `NSInvalidArgumentException` when `GIDClientID` is absent ("No active
   configuration. Make sure GIDClientID is set in Info.plist.", ~line 780),
   when the reversed-client-id URL scheme is not registered ("Your app is
   missing support for the following URL schemes: …"), and when the client id
   is empty ("You must specify |clientID| in |GIDConfiguration|"). With our
   fake-but-well-formed id and scheme registered, none of these fire — the
   exception path is a *setup* check, not a validity check.
2. **Google's server:** the flow opens Google's authorization surface (Safari /
   SFSafariViewController / Google app switch, per SDK logic) at
   `accounts.google.com`, which responds with its own error page:
   "Access blocked: Authorization Error — Error 401: invalid_client — The OAuth
   client was not found" (message as reported by users of unregistered clients:
   https://support.google.com/accounts/thread/203097977,
   https://support.google.com/accounts/thread/152153282). No redirect fires, so
   the SDK callback ends in an error/cancel instead of a `GIDSignInResult`.
   Per `docs/PROMPT.md`, that error page on `accounts.google.com` **is** the
   pass surface for the trigger proof.

### Hand-built pbxproj integration (no Xcode GUI)

Exact sections to add to
`examples/host-ios/NshAuthHostIOS.xcodeproj/project.pbxproj` (section names
cross-checked against the XcodeProj library's parser,
https://github.com/badoo/xcodeproj/blob/master/Sources/XcodeProj/Objects/SwiftPackage/XCRemoteSwiftPackageReference.swift,
and the FOSSA pbxproj write-up):

1. `XCRemoteSwiftPackageReference` object:
   ```
   A3000...S1 /* XCRemoteSwiftPackageReference "GoogleSignIn-iOS" */ = {
     isa = XCRemoteSwiftPackageReference;
     repositoryURL = "https://github.com/google/GoogleSignIn-iOS";
     requirement = { kind = upToNextMajorVersion; minimumVersion = 10.1.0; };
   };
   ```
   (`kind` ∈ `exactVersion` | `upToNextMajorVersion` | `upToNextMinorVersion` |
   `range` | `branch` | `revision`; use `exactVersion` or `upToNextMajorVersion`
   + committed `Package.resolved` for reproducibility.)
2. `XCSwiftPackageProductDependency` object per product:
   ```
   A3000...P1 /* GoogleSignIn */ = {
     isa = XCSwiftPackageProductDependency;
     package = A3000...S1 /* XCRemoteSwiftPackageReference ... */;
     productName = GoogleSignIn;
   };
   ```
3. `PBXBuildFile` linking the product into the target:
   `A3000...B1 /* GoogleSignIn in Frameworks */ = { isa = PBXBuildFile; productRef = A3000...P1 /* GoogleSignIn */; };`
   plus a child in the existing `PBXFrameworksBuildPhase` files list.
4. `PBXNativeTarget.packageProductDependencies = ( A3000...P1, ... );` —
   **this is the one people forget**; without it the product is not linkable.
5. `PBXProject.packageReferences = ( A3000...S1 );` on the existing
   `PBXProject` object.

Gotcha: the `.git` suffix on `repositoryURL` flip-flops between Xcode writes
(https://stackoverflow.com/questions/72372402) — pick one form and keep it
stable in hand-written files.

**Network at build time: yes.** First `xcodebuild` run resolves all six package
repos over github.com; subsequent runs re-resolve against the committed
`Package.resolved`. Acceptable per the user's go-ahead; the gate must document
and pin it (section 7).

---

## 2. Facebook Login iOS

### Coordinates (current)

- SPM repo: `https://github.com/facebook/facebook-ios-sdk` (Meta's docs and
  `Package.swift` also use the `meta` org form, `https://github.com/meta/facebook-ios-sdk`;
  same repository). Current release **v19.0.1** (2026-11-02).
- `Package.swift` (main, read 2026-11-07): swift-tools **5.3**, platform
  **iOS 15+**. All SDK modules are **binaryTargets** — dynamic XCFrameworks
  downloaded from
  `https://github.com/meta/facebook-ios-sdk/releases/download/v19.0.1/<name>-Dynamic_XCFramework.zip`
  with SHA-256 checksums hard-pinned in `Package.swift` (e.g. login:
  `c38f78c4…b793`); an env flag `USE_LOCAL_FB_BINARIES` switches to local
  `build/XCFrameworks/Dynamic/<name>.xcframework`.
- SPM **product** to add: `FacebookLogin` (the login product bundles target
  `FacebookLogin` + binary target `FBSDKLoginKit`, which itself depends on the
  core/basics binaries — `Package.swift` String extension: `login =
  "FacebookLogin"`, `Prefixed.login = "FBSDKLoginKit"`). Import in Swift is
  `import FacebookLogin`. Meta's getting-started doc still names the legacy
  table entries (`FBSDKCoreKit`, `FBSDKLoginKit`, …) — those are the *modules*;
  the product list Xcode shows is the unprefixed names above.

### What it needs

Info.plist keys (verified where the SDK reads them:
`FBSDKCoreKit/FBSDKCoreKit/Settings.swift:304-374` — "The default value will be
read from the application's plist (FacebookAppID)" etc.; snippet from Meta's
getting-started doc, https://developers.facebook.com/docs/ios/getting-started):

- `FacebookAppID` — our fake numeric id `1234567890123456`.
- `FacebookClientToken` — required config (App Dashboard → Settings → Advanced
  → Client Token); a fake `nsh-auth-sandbox-client-token` is syntactically fine.
- `FacebookDisplayName` — e.g. `NSH Auth Sandbox`.
- `CFBundleURLTypes` / `CFBundleURLSchemes` — `fb1234567890123456`.
- `LSApplicationQueriesSchemes`: `fbapi`, `fb-messenger-share-api` (needed only
  for dialogs that switch into the Facebook/Messenger apps; harmless to include).
- App entry points: `ApplicationDelegate.shared.application(...)` in
  `didFinishLaunchingWithOptions` and the SceneDelegate `openURLContexts`
  forward — only needed for *inbound* URL delivery, which our host does not
  use (the SDK's login completes in its own presented surface and callback).

### LoginManager: default vs web-only

- Entry: `LoginManager.logIn(viewController:configuration:completion:)`
  (`FBSDKLoginKit/FBSDKLoginKit/LoginManager.swift`, main). `LoginConfiguration`
  (`FBSDKLoginKit/FBSDKLoginKit/LoginConfiguration.swift`) carries
  `tracking: LoginTracking` (`.enabled` classic / `.limited`), `appSwitch:
  AppSwitch` (`.enabled` default / `.disabled`), `nonce: String`,
  `codeVerifier: CodeVerifier` — **PKCE and nonce are built into the SDK**
  (`LoginManager.swift` Keys: `expected_challenge`, `expected_login_nonce`,
  `expected_login_code_verifier`; a verifier is generated if not provided).
- Surface selection is automatic (no `LoginBehavior` enum on iOS anymore; the
  logger distinguishes `native_app_switch_auth` / `sfvc_auth` / `browser_auth`
  in `LoginManager.swift`). **Web-only = `AppSwitch.disabled`** in the
  configuration — then the flow uses SFSafariViewController/Safari instead of
  switching to the Facebook app. That is the right default for our sandbox host
  (no Facebook app on the simulator anyway).
- Token shape is chosen by `tracking`: `.enabled` → `AccessToken` (opaque Graph
  API token, `result.token.tokenString`); `.limited` → `AuthenticationToken`
  (JWT verified against Facebook's JWKS, `docs/providers.md:104`).

### Runtime with our fake app id

The SDK does not pre-validate the app id against Meta's servers; it builds the
dialog URL and opens the surface. With `FacebookAppID = 1234567890123456` the
OAuth dialog at `facebook.com` renders Facebook's own error page ("Sorry,
something went wrong" is the observed shape for unknown client ids —
https://stackoverflow.com/questions/33822789,
https://developers.facebook.com/community/threads/536420708641817), and the
completion handler receives an error instead of a result. `facebook.com` error
page = pass surface per `docs/PROMPT.md`. What happens when the plist key is
missing entirely was not traced line-by-line in this pass (the SDK logs a
developer error and login fails; the exact code path is unverified) — phase 3
should capture it rather than assume.

---

## 3. Sign in with Apple iOS

No SDK — this is the OS framework `AuthenticationServices`; nothing to add to
the pbxproj beyond the entitlement and our own adapter code.

### Request and response

- `ASAuthorizationAppleIDProvider().createRequest()` →
  `ASAuthorizationAppleIDRequest` (subclass of `ASAuthorizationOpenIDRequest`).
  `requestedScopes = [.fullName, .email]`.
  `nonce` doc text ("A string value to pass to the identity provider. You can
  verify this value with the identity token provided as part of a successful
  ASAuthorization response"):
  https://developer.apple.com/documentation/authenticationservices/asauthorizationopenidrequest/nonce.
- Presentation: `ASAuthorizationController` with
  `presentationContextProvider` + delegate
  (`didCompleteWithAuthorization` / `didCompleteWithError`), `performRequests()`.
  https://developer.apple.com/documentation/authenticationservices/asauthorizationcontroller.
- Response: `ASAuthorizationAppleIDCredential` — `user`, `email`, `fullName`,
  `identityToken: Data` (RS256 JWT), `authorizationCode: Data`,
  `realUserStatus`, `authorizedScopes`.
  https://developer.apple.com/documentation/authenticationservices/asauthorizationappleidcredential.

### Nonce (anti-replay) — the Apple rule differs from Google's

Standard pattern (Apple/Firebase guidance, see also
https://stackoverflow.com/questions/59011314 for the raw-vs-hash pitfall): the
**core generates a raw nonce**, the adapter puts the **SHA-256 hash** of it in
`request.nonce`, the raw nonce is kept for the core, and verification compares
`sha256(rawNonce) == id_token.nonce`. This is the opposite of Google/Credential
Manager, where the request nonce is compared **verbatim** (section 4). Our
core's nonce machinery must apply the per-provider rule; this is exactly the
kind of quirk `docs/providers.md` already models.

### Entitlement

- `com.apple.developer.applesignin` with value array `["Default"]` in the app's
  `.entitlements` file
  (https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.developer.applesignin;
  setup: https://developer.apple.com/documentation/xcode/configuring-sign-in-with-apple-support).
  In a hand-built pbxproj this is `CODE_SIGN_ENTITLEMENTS = path/to/app.entitlements;`
  on the build configuration + the entitlements file itself — no capability
  GUI needed.
- **Free provisioning cannot sign it.** Personal (free) teams do not support
  the Sign in with Apple capability — the symptom is "Provisioning profile
  doesn't support the Sign In with Apple capability"
  (https://stackoverflow.com/questions/61965154; Apple Developer Forums).
  Our host app is ad-hoc signed with no team and no entitlements
  (`build-gate.sh`: "Ad-hoc signing only: simulator, no team, no entitlements"),
  so a device run of SIWA is out of reach for this repo regardless; a paid-team
  owner registers the capability at setup time (`docs/setup.md` concern).
- **Simulator:** Apple does not document runtime entitlement enforcement on the
  simulator; the consistent community picture is that simulator builds skip
  provisioning validation and the sheet presents without the entitlement, while
  on device a missing/broken capability surfaces as
  `ASAuthorizationError.unknown` (code 1000)
  (https://stackoverflow.com/questions/70734015). The other 1000 trigger is no
  Apple ID signed into the simulator (Settings → Sign in). **Unverified for our
  exact build** (ad-hoc, no entitlements, iOS 27 runtime): the phase-3 run must
  capture what actually presents, not assume either branch.

### Verification

The `identityToken` JWT is verified against Apple's JWKS at
`https://appleid.apple.com/auth/keys` (RS256), checks: `iss ==
https://appleid.apple.com`, `aud == bundle id`, `exp`, `nonce == sha256(raw)`
(`docs/providers.md:318`; Apple's "Verify the identity token":
https://developer.apple.com/documentation/sign_in_with_apple/sign_in_with_apple_rest_api/verifying_the_identity_token).
`authorizationCode` is single-use and exchanging it for tokens needs an Apple
**client secret** — confidential, so that leg belongs to the token broker seam,
never the app. The session itself can be established from the verified id_token.

---

## 4. Google Android (Credential Manager is current; legacy GoogleSignIn)

### Coordinates (current)

- **Current recommended SDK: Credential Manager.** Artifacts (Google Maven
  metadata read 2026-11-07):
  - `androidx.credentials:credentials` — latest stable **1.6.0**
    (1.7.0-alpha03 is the newest; the implementation guide's snippet shows the
    alpha, stable is the right pin for us).
  - `androidx.credentials:credentials-play-services-auth` — same versions.
  - `com.google.android.libraries.identity.googleid:googleid` — latest
    **1.2.1** (2026-09-16). Note the group is
    `com.google.android.libraries.identity.googleid`, not
    `…libraries.credentials` as the phase-3 task guess had it.
  - Licenses (POMs fetched 2026-11-07): `androidx.credentials` POM = Apache-2.0;
    `googleid` POM = **"Android Software Development Kit License"** (Google's
    SDK terms, not Apache); `play-services-auth` POM = same Android SDK License.
- **Legacy** `com.google.android.gms:play-services-auth` — latest **22.0.0**
  (lastUpdated 20260825174304). Its `GoogleSignIn` API is what
  `developer.android.com/identity/legacy/gsi/offline-access` (redirect target of
  the old offline-access doc) now labels: "The Google Sign-In for Android API is
  outdated and no longer supported. … migrate your Sign in with Google
  implementation to Credential Manager." Keep it only as the documented escape
  hatch for `serverAuthCode` (below).

### Config and API (implementation guide,
https://developer.android.com/identity/sign-in/credential-manager-siwg-implementation,
fetched 2026-11-07)

- Only a **web client id** string is needed: our fake
  `nsh-auth-sandbox.apps.googleusercontent.com` passed to
  `setServerClientId(...)`. No manifest entries, no plist equivalent.
- Bottom-sheet flow:
  ```kotlin
  val option = GetGoogleIdOption.Builder()
      .setFilterByAuthorizedAccounts(true)   // then false on NoCredentialException
      .setServerClientId(WEB_CLIENT_ID)
      .setAutoSelectEnabled(true)
      .setNonce(nonce)
      .build()
  val request = GetCredentialRequest.Builder().addCredentialOption(option).build()
  val result = CredentialManager.create(context).getCredential(context, request)
  ```
- Button flow: `GetSignInWithGoogleOption.Builder(serverClientId = WEB_CLIENT_ID)
  .setNonce(nonce).build()`.
- Result: `credential` is a `CustomCredential` of type
  `GoogleIdTokenCredential.TYPE_GOOGLE_ID_TOKEN_CREDENTIAL`; convert with
  `GoogleIdTokenCredential.createFrom(credential.data)`; fields
  `getIdToken()`, `getId()`, `getDisplayName()`, `getFamilyName()`,
  `getGivenName()`, `getProfilePictureUri()`.
- Sign-out: `clearCredentialState(ClearCredentialStateRequest)` — maps onto our
  core's sign-out + revoke, not a replacement for it.
- **Nonce rule: verbatim.** The guide: "Ensure that your server-side code
  validates that the request and response nonces are identical." No hashing —
  unlike Apple. Core adapter must not reuse Apple's sha256 step here.
- Emulator note: `credentials-play-services-auth` needs Google Play services in
  the AVD image; our `indopak-audit`/`nsh-auth` AVD must be a Google-Play image
  for any live capture (the mock loop on `10.0.2.2` is unaffected).

### serverAuthCode on Android: not available in Credential Manager

`GetGoogleIdOption`'s full property list (reference page fetched 2026-11-07)
contains no offline-access/server-auth-code option — closest is
`idTokenDepositionScopes` ("Oauth scopes that Google will need to deposit a
Google ID token to your application's backend server"), which is not an auth
code. The only `serverAuthCode` path is the deprecated legacy API:
`GoogleSignInOptions.Builder(GoogleSignInOptions.DEFAULT_SIGN_IN)
.requestServerAuthCode(serverClientId)` → `GoogleSignInAccount.getServerAuthCode()`
→ server exchanges the code at `https://oauth2.googleapis.com/token`
(https://developer.android.com/identity/legacy/gsi/offline-access, fetched
2026-11-07). Recommendation for phase 3: **id-token-only** via Credential
Manager; document the legacy path (and its "no longer supported" warning) as
the opt-in for owners who need offline access, routed through the broker if
used at all.

### Runtime with our fake web client id

Not separately documented by Google, so state only what is documented: the
bottom sheet / button surface is Google's own UI; an unknown client id makes
Google's server reject inside that surface and `getCredential` throws
`GetCredentialException`. Documented exception types worth handling
(troubleshooting guide,
https://developer.android.com/identity/sign-in/credential-manager-troubleshooting-guide):
`NoCredentialException` (no authorized accounts / filter true),
`GetCredentialUnsupportedException` (device/library too old),
`GetCredentialProviderConfigurationException` (play-services-auth artifact
missing — the one our gate would hit first), `GetCredentialCancellationException`.
The exact subtype Google returns for an unregistered client id must be captured
in the phase-3 emulator run — do not invent one.

---

## 5. Facebook Android

### Coordinates (current)

- `com.facebook.android:facebook-login` — latest **19.0.1** on Maven Central
  (metadata `lastUpdated` 20261104003838; matches GitHub tag
  `sdk-version-19.0.1`, 2026-11-04). Resolves from `repo1.maven.org`.
- SDK floor: minSdk 15 / compileSdk 34 (`gradle/libs.versions.toml`, main) —
  compatible with our host (minSdk 28 / compileSdk 36).
- POM license: **"Facebook Platform License"** (url points at the repo's
  LICENSE.txt).

### Minimal manifest config (exact, fake values)

The one non-negotiable app-side piece (constants verified in
`facebook-core/src/main/java/com/facebook/FacebookSdk.kt:101,113` —
`APPLICATION_ID_PROPERTY = "com.facebook.sdk.ApplicationId"`,
`CLIENT_TOKEN_PROPERTY = "com.facebook.sdk.ClientToken"`):

```xml
<meta-data android:name="com.facebook.sdk.ApplicationId"
    android:value="1234567890123456" />
<meta-data android:name="com.facebook.sdk.ClientToken"
    android:value="nsh-auth-sandbox-client-token" />
```

Everything else login needs is **merged from the SDK's own manifest**
(`facebook-common/src/main/AndroidManifest.xml`, read 2026-11-07):
`FacebookActivity`, `CustomTabMainActivity`, and `CustomTabActivity` with
intent-filter scheme `fbconnect` + host `cct.${applicationId}` (the
applicationId placeholder resolves to `dev.nshauth.sandbox`). **No `fb<APP_ID>`
intent filter is needed for login on Android** — that requirement is an iOS
plist thing. INTERNET permission is already in our manifest.

### The "ContentProvider crashes on start" claim — false for 19.0.1

`facebook-core/src/main/java/com/facebook/internal/FacebookInitProvider.kt`
(auto-merged ContentProvider, runs before `Application.onCreate`):

```kotlin
override fun onCreate(): Boolean {
  try {
    FacebookSdk.sdkInitialize(context)
  } catch (ex: Exception) {
    Log.i(TAG, "Failed to auto initialize the Facebook SDK", ex)
  }
  return false
}
```

The exceptions exist — `FacebookSdk.kt` (`sdkInitialize`, ~lines 482-495):
"A valid Facebook app id must be set in the AndroidManifest.xml or set by
calling FacebookSdk.setApplicationId before initializing the sdk." and the
matching client-token text — but the provider **catches and logs them at INFO**,
so there is no startup crash in 19.0.1. The real failure mode with missing
meta-data is worse for us: `sdkInitialized` stays false and every later SDK
call fails at use time. With fake-but-present values the SDK initializes
normally and the failure moves to the dialog (next paragraph). Document the
catch-and-log in the phase-3 adapter so "it didn't crash" is never mistaken
for "it initialized".

### LoginManager: default vs web-only, and the fake app id

- `LoginManager.getInstance()`; `loginBehavior` default
  `LoginBehavior.NATIVE_WITH_FALLBACK` (`facebook-common/.../LoginManager.kt:66`).
  Enum values (`facebook-common/.../LoginBehavior.kt`):
  `NATIVE_WITH_FALLBACK`, `NATIVE_ONLY`, `KATANA_ONLY`, `WEB_ONLY`,
  `DIALOG_ONLY`, `DEVICE_AUTH`. **Web-only = `setLoginBehavior(LoginBehavior.WEB_ONLY)`**
  (Custom Tab dialog only, no Facebook-app switch) — matches our existing
  Custom Tabs host. `logIn(activity, permissions)` /
  `logInWithConfiguration(fragment, LoginConfiguration)` + `CallbackManager`
  `registerCallback` with `FacebookCallback{onSuccess,onError,onCancel}`
  (the deprecated no-CallbackManager overloads are the old style; use the
  CallbackManager-parameterized ones).
- `LoginConfiguration` mirrors iOS: `LoginTracking.enabled/.limited`,
  nonce, PKCE code verifier auto-generated when absent.
- With `ApplicationId = 1234567890123456` the OAuth dialog URL
  (`https://www.facebook.com/<ver>/dialog/oauth?client_id=…`) opens in the
  Custom Tab and Facebook renders its own error page on `facebook.com` ("Sorry,
  something went wrong" shape — https://stackoverflow.com/questions/33822789);
  the callback surfaces `FacebookException` via `onError`. `facebook.com`
  error page = pass surface per `docs/PROMPT.md`.

---

## 6. Licenses and THIRD_PARTY_NOTICES implications

| SDK / artifact | License (verified where) | Family check vs `docs/research/native-licensing.md` |
|---|---|---|
| GoogleSignIn-iOS 10.1.0 | Apache-2.0 (GitHub license API: `spdx_id: apache-2.0`; repo LICENSE) | In family. Transitive source deps (AppAuth-iOS 3.x, GTMAppAuth, gtm-session-fetcher, GoogleUtilities, AppCheckCore) are Google Apache-2.0 projects per their repos; re-read each LICENSE at add time before the notices entry is written. |
| FBSDK iOS 19.0.1 (`facebook-login` equivalent: `FacebookLogin` product) | **Facebook Platform License** — "Copyright (c) Meta Platforms, Inc. and affiliates." + restriction: use "for use in connection with the web services and APIs provided by Facebook" and subject to the Facebook Platform Policy (LICENSE, main). GitHub classifies it `NOASSERTION`. | **Out of family** (MIT-derived but restricted). The licensing doc's rule: anything outside MIT/BSD/Apache-2.0 needs an explicit recorded decision before it enters the tree. Since phase 3 consumes a binary, not a vendored copy, the decision to record is "dependency, used only with Facebook's services" — satisfiable, but it must be written down in the licensing doc and the notices entry. Both FB SDKs ship NOTICE files (iOS: Mixpanel Apache-2.0 attribution, …; Android: NOTICE.txt with Apache-2.0 texts) — reference them from the notices entry. |
| FBSDK Android 19.0.1 (`facebook-login`) | Facebook Platform License (POM `<license><name>Facebook Platform License</name>` + LICENSE.txt, same text as iOS) | Same as above. |
| androidx.credentials 1.6.0 | Apache-2.0 (POM licenses section) | In family; same treatment as the existing androidx.browser entry. |
| googleid 1.2.1, play-services-auth 22.0.0 | "Android Software Development Kit License" (POMs) | **Out of family** (Google's SDK terms, not an OSI license). Record as dependency entries pointing at the terms URL; distribution inside the example APKs is governed by those terms. |
| Sign in with Apple (AuthenticationServices) | OS framework, not distributed by us | No entry, nothing to carry. |

**Dependencies vs adapted.** All four are consumed as *dependencies* (SPM
source packages + binary XCFrameworks; Maven AARs). Zero code is vendored or
adapted — consistent with phase 2's verdict for AppAuth, and unlike phase 2 no
Apache §4(b) change-notice obligations arise. What does arise: per the
licensing doc's rule ("one entry per dependency whose artifact is distributed
inside an app we build — androidx.browser today"), phase 3 adds notices entries
for every SDK artifact that lands in `NshAuthSandbox.app` / `app-debug.apk`,
including the transitive GoogleSignIn source deps and the FB NOTICE references.
The entries land in the same commit as the build.gradle.kts / pbxproj changes.

---

## 7. Hermetic gate impact and pinning

**iOS (`examples/host-ios/build-gate.sh`).** The gate is hermetic today
(comment and structure: no SPM, no `Package.resolved`). Adding either SDK
package breaks that property: the first `xcodebuild` run resolves packages over
the network — github.com for GoogleSignIn + its five transitive repos, and
github.com release downloads for the FB XCFramework zips. Accepted per the
user's go-ahead; required consequences:

1. README + gate script must state the new network step and which hosts it
   touches (github.com for both SDK paths; no dl.google.com on iOS since
   GoogleSignIn-iOS has no binary targets).
2. Pin: commit
   `NshAuthHostIOS.xcodeproj/project.xcworkspace/xcshareddata/swiftpm/Package.resolved`
   after the first resolution (generated automatically; Apple documents the
   location for reproducible CI builds,
   https://developer.apple.com/documentation/xcode/making-dependencies-available-to-xcode-cloud).
3. Gate hardening flags — names and descriptions verified against the local
   `xcodebuild -help` on this machine:
   `-resolvePackageDependencies` (explicit resolution step),
   `-onlyUsePackageVersionsFromResolvedFile` /
   `-disableAutomaticPackageResolution` (both: "prevents packages from
   automatically being resolved to versions other than those recorded in the
   `Package.resolved` file"), `-skipPackageUpdates`. Use
   `-resolvePackageDependencies` + `-onlyUsePackageVersionsFromResolvedFile`
   in the gate so a range-drift cannot silently change the build.
4. Extra supply-chain pin for FB: the XCFramework SHA-256 checksums are already
   inside upstream `Package.swift` — SPM verifies them; note this in the README
   rather than re-pinning anything.
5. Package clones land under the gate's own `-derivedDataPath` (`build/derived`
   → `SourcePackages/`), machine-local, gitignored — no repo-tree pollution.

**Android (`examples/host-android/build-gate.sh`).** Gradle resolves
`facebook-login` from `repo1.maven.org` and the Google artifacts from
`dl.google.com` (androidx.credentials, googleid, play-services-auth if used).
Accepted; consequences:

1. README + gate script state the new network step and the two hosts.
2. Pin exact versions in `app/build.gradle.kts` (no ranges, no dynamic `+`).
   Gradle has no committed-by-default lockfile; for reproducibility use either
   dependency verification (commit `gradle/verification-metadata.xml`, one-time
   `./gradlew --write-verification-metadata sha256` —
   https://docs.gradle.org/current/userguide/dependency_verification.html) or
   dependency locking (https://docs.gradle.org/current/userguide/dependency_locking.html);
   verification-metadata is the stronger of the two and matches the
   Package.resolved intent.
3. The gate's existing checks are unaffected and must stay: `client_secret`
   grep over the APK, libs verification, AAR copies.

**Trigger-proof note for both gates:** with fake ids, all four providers still
open their *own* surface (accounts.google.com error page, facebook.com error
page, Apple's system sheet) — exactly the pass surface `docs/PROMPT.md`
defines. The failure case proves the request reached the provider; stop there.

---

## 8. Token shapes reaching the core, and the adapter mapping

| Provider / platform | What the adapter hands the core | Core machinery that consumes it (`crates/nsh-auth/src/`, mirrored in `packages/nsh-auth/src/`) |
|---|---|---|
| Google iOS | `GIDSignInResult.serverAuthCode` (when `GIDServerClientID`/`serverClientID` configured) **and/or** `GIDGoogleUser.idToken` (JWT; `aud` = web client id when serverClientID is set, else iOS client id) | Auth-code leg: confidential web client → exchange needs the web client's secret → **token broker seam**, then `token.rs:38 exchange_code` server-side. Id-token leg (sandbox default): `jwt.rs:28 claims` + `IdTokenChecks` (iss `accounts.google.com`, aud, exp, nonce verbatim) against Google JWKS (`token.rs:108 jwks`, `docs/providers.md:24`). No refresh_token from the SDK legs — session lives on the id token; revoke/sign-out via `token.rs:120`. |
| Google Android | `GoogleIdTokenCredential.getIdToken()` (JWT, `aud` = web client id). **No serverAuthCode exists in Credential Manager** (verified from the 1.2.1 API surface). | Same id-token leg as above; nonce compared **verbatim** (guide's rule). The legacy `requestServerAuthCode` path (play-services-auth 22.0.0) is the only auth-code source and is deprecated — broker-only if ever wired. |
| Apple iOS | `ASAuthorizationAppleIDCredential.identityToken` (RS256 JWT) + `authorizationCode` (single-use) | `jwt.rs` + Apple JWKS (`token.rs:108`, `docs/providers.md:318`); checks iss/aud(bundle id)/exp/**nonce == sha256(raw)** — Apple hashes, so the core must not reuse Google's verbatim rule. `authorizationCode` exchange requires an Apple client secret → broker seam only; the session stands on the verified id token. |
| Facebook iOS | Classic (`LoginTracking.enabled`): `AccessToken.tokenString` — opaque Graph API token, no id_token, no JWKS. Limited (`.limited`): `AuthenticationToken` JWT → Facebook JWKS (`docs/providers.md:104`). | Session wrap directly from the access token (profile via Graph `/me`, `token.rs:94 userinfo`); limited login verifies via JWKS like Apple/Google but with Facebook's issuer. SDK-internal PKCE/nonce means the core's PKCE state is bypassed for SDK legs — the adapter must not double-apply it. |
| Facebook Android | Same split via `LoginBehavior` + `LoginConfiguration`: classic → `AccessToken` (direct), limited → `AuthenticationToken` JWT. | Same as Facebook iOS. |

Adapter mapping summary (all behind the existing `auth.*` host contract, which
`docs/research/native-ios.md` fixed as unchangeable): each SDK adapter is a new
`host.call` name pair (`auth.nativeSignIn {provider}` → resolves the provider
artifact string; result flows into the same `complete()`/session-wrap path),
the provider rules table in `docs/providers.md` gains a column marking which
verification rule applies (Google verbatim nonce / Apple sha256 nonce / Facebook
direct token), and the broker seam owns every leg that needs a client secret
(Google serverAuthCode exchange, Apple authorizationCode exchange).

---

## Open items phase 3 must capture (not assume)

1. The exact `GetCredentialException` subtype Android returns for our fake web
   client id (emulator run, Google-Play AVD image).
2. Whether the Apple sheet actually presents on the iOS 27 simulator with our
   ad-hoc, entitlement-less build, and what error appears with no Apple ID
   signed in.
3. The Facebook iOS SDK's exact behavior with the plist key absent entirely
   (vs present-but-fake, which is documented above).
4. License re-read of the five GoogleSignIn transitive repos at add time, so
   the notices entries cite the exact commits.

## Sources

- https://github.com/google/GoogleSignIn-iOS (+ releases, Package.swift, GIDSignIn.h, GIDConfiguration.h, GIDGoogleUser.h, GIDSignInResult.h, GIDSignIn.m, `xcodebuild -help` on this machine)
- https://developers.google.com/identity/sign-in/ios/start-integrating
- https://github.com/facebook/facebook-ios-sdk (+ releases, Package.swift, Settings.swift, LoginManager.swift, LoginConfiguration.swift, LICENSE, NOTICE)
- https://developers.facebook.com/docs/ios/getting-started
- https://developer.apple.com/documentation/authenticationservices/asauthorizationopenidrequest/nonce (+ asauthorizationappleidrequest, asauthorizationcontroller, asauthorizationappleidcredential, bundleresources/entitlements/com.apple.developer.applesignin, xcode/configuring-sign-in-with-apple-support, sign_in_with_apple…/verifying_the_identity_token, xcode/making-dependencies-available-to-xcode-cloud)
- https://stackoverflow.com/questions/59011314 (Apple raw-vs-hash nonce), https://stackoverflow.com/questions/70734015 (error 1000), https://stackoverflow.com/questions/61965154 (free-team capability)
- https://developer.android.com/identity/sign-in/credential-manager-siwg-implementation (+ credential-manager-troubleshooting-guide, identity/legacy/gsi/offline-access)
- https://developers.google.com/identity/android-credential-manager/android/reference/kotlin/com/google/android/libraries/identity/googleid/GetGoogleIdOption
- Google Maven metadata: dl.google.com/android/maven2/... for androidx.credentials, credentials-play-services-auth, com.google.android.libraries.identity.googleid:googleid, com.google.android.gms:play-services-auth; POM license sections fetched directly
- https://github.com/facebook/facebook-android-sdk (+ releases, FacebookSdk.kt, FacebookInitProvider.kt, Validate.kt, LoginManager.kt, LoginBehavior.kt, LoginClient.kt, facebook-common AndroidManifest.xml, libs.versions.toml, LICENSE.txt, NOTICE.txt)
- Maven Central metadata + POM: repo1.maven.org/maven2/com/facebook/android/facebook-login/
- https://docs.gradle.org/current/userguide/dependency_verification.html, https://docs.gradle.org/current/userguide/dependency_locking.html
- pbxproj SPM sections: https://github.com/badoo/xcodeproj/blob/master/Sources/XcodeProj/Objects/SwiftPackage/XCRemoteSwiftPackageReference.swift, https://docs.fossa.com/docs/project-setup/supported-languages/ios/swift, https://stackoverflow.com/questions/72372402
- Google fake-client error surfaces: https://support.google.com/accounts/thread/203097977, https://support.google.com/accounts/thread/152153282; Facebook error surfaces: https://stackoverflow.com/questions/33822789, https://developers.facebook.com/community/threads/536420708641817

---

## RESULT CONTRACT

```json
{
  "done": true,
  "summary": "Current coordinates verified 2026-11-07: iOS GoogleSignIn SPM 10.1.0 (google/GoogleSignIn-iOS, products GoogleSignIn/GoogleSignInSwift, GIDClientID+GIDServerClientID+reversed scheme, serverAuthCode on GIDSignInResult); iOS FacebookLogin product of facebook-ios-sdk v19.0.1 (binary XCFrameworks, FacebookAppID/ClientToken/DisplayName + fb-scheme, AppSwitch.disabled for web-only); Apple = AuthenticationServices + com.apple.developer.applesignin=['Default'] (free teams cannot provision it; simulator enforcement undocumented - capture in run); Android Google = Credential Manager (androidx.credentials 1.6.0 + googleid 1.2.1, GetGoogleIdOption/GetSignInWithGoogleOption, NO serverAuthCode - legacy play-services-auth 22.0.0 only); Android facebook-login 19.0.1 (meta-data ApplicationId+ClientToken minimal config; FacebookInitProvider catch-and-log, no startup crash; LoginBehavior.WEB_ONLY for web-only). Licenses: GoogleSignIn Apache-2.0, both FB SDKs Facebook Platform License (out-of-family, needs recorded decision + notices entries), googleid/play-services-auth Android SDK License, androidx Apache-2.0. Hermetic gates gain network steps (github.com / maven hosts) - pin with Package.resolved + -onlyUsePackageVersionsFromResolvedFile, and exact versions + gradle verification-metadata.",
  "sdkCoordinates": {
    "ios": {
      "google": {
        "spmRepo": "https://github.com/google/GoogleSignIn-iOS",
        "version": "10.1.0 (2026-10-23; last CocoaPods release, SPM is the path)",
        "products": ["GoogleSignIn", "GoogleSignInSwift"],
        "infoPlist": ["GIDClientID=nsh-auth-sandbox.apps.googleusercontent.com", "GIDServerClientID (optional, web client id)", "CFBundleURLSchemes: com.googleusercontent.apps.nsh-auth-sandbox (reversed)"],
        "api": "GIDSignIn.sharedInstance.configuration = GIDConfiguration(clientID:serverClientID:); signIn(withPresenting:) -> GIDSignInResult(user, serverAuthCode)",
        "pbxprojSections": ["XCRemoteSwiftPackageReference", "XCSwiftPackageProductDependency", "PBXBuildFile(productRef)", "PBXNativeTarget.packageProductDependencies", "PBXProject.packageReferences"],
        "fakeClientRuntime": "NSException only for setup errors; Google shows 'Error 401: invalid_client' page on accounts.google.com"
      },
      "facebook": {
        "spmRepo": "https://github.com/facebook/facebook-ios-sdk (meta org form also used upstream)",
        "version": "v19.0.1 (2026-11-02)",
        "product": "FacebookLogin (module FBSDKLoginKit + core/basics binaries)",
        "infoPlist": ["FacebookAppID=1234567890123456", "FacebookClientToken", "FacebookDisplayName", "CFBundleURLSchemes: fb1234567890123456", "LSApplicationQueriesSchemes fbapi, fb-messenger-share-api"],
        "api": "LoginManager.logIn(viewController:configuration:completion:); LoginConfiguration(permissions:tracking:nonce:appSwitch:); web-only = AppSwitch.disabled; PKCE+nonce built in",
        "fakeAppIdRuntime": "Facebook's own error page inside SafariVC/Safari on facebook.com; completion gets error"
      },
      "apple": {
        "sdk": "AuthenticationServices (system framework, nothing to install)",
        "request": "ASAuthorizationAppleIDRequest, scopes [.fullName,.email], nonce = sha256(rawNonce)",
        "response": "ASAuthorizationAppleIDCredential: identityToken (RS256 JWT), authorizationCode (single-use), email, fullName, user",
        "entitlement": "com.apple.developer.applesignin = [Default] via CODE_SIGN_ENTITLEMENTS; free personal teams CANNOT provision it; simulator enforcement undocumented - expected present-but-capture (error 1000 if capability broken or no Apple ID signed in)",
        "verification": "Apple JWKS https://appleid.apple.com/auth/keys, iss appleid.apple.com, aud = bundle id, nonce claim == sha256(raw)"
      }
    },
    "android": {
      "google": {
        "artifacts": ["androidx.credentials:credentials:1.6.0", "androidx.credentials:credentials-play-services-auth:1.6.0", "com.google.android.libraries.identity.googleid:googleid:1.2.1"],
        "api": "GetGoogleIdOption.Builder().setServerClientId(webClientId).setFilterByAuthorizedAccounts(...).setAutoSelectEnabled(...).setNonce(nonce) or GetSignInWithGoogleOption.Builder(serverClientId=...); getCredential -> GoogleIdTokenCredential.createFrom(...).getIdToken()",
        "serverAuthCode": "NOT available in Credential Manager; legacy path = play-services-auth 22.0.0 GoogleSignInOptions.requestServerAuthCode + GoogleSignInAccount.getServerAuthCode (deprecated, 'no longer supported')",
        "fakeClientRuntime": "Google surface errors, getCredential throws GetCredentialException (documented types: NoCredentialException, GetCredentialUnsupportedException, GetCredentialProviderConfigurationException); exact subtype for unknown client id to capture in run",
        "config": "web client id string only; no manifest entries",
        "nonceRule": "verbatim comparison (unlike Apple's sha256)"
      },
      "facebook": {
        "artifact": "com.facebook.android:facebook-login:19.0.1 (Maven Central, lastUpdated 2026-11-04)",
        "manifestMinimal": {"meta-data:com.facebook.sdk.ApplicationId": "1234567890123456", "meta-data:com.facebook.sdk.ClientToken": "nsh-auth-sandbox-client-token", "note": "FacebookActivity + CustomTab activities (scheme fbconnect, host cct.${applicationId}) merge from the SDK manifest; no fb-scheme intent filter needed for login"},
        "api": "LoginManager.getInstance().setLoginBehavior(LoginBehavior.WEB_ONLY); logIn(activity, permissions) + CallbackManager.registerCallback(FacebookCallback)",
        "initBehavior": "FacebookInitProvider catches sdkInitialize failures and logs at INFO - no startup crash in 19.0.1; missing meta-data = silent init failure, failures at use time",
        "fakeAppIdRuntime": "Facebook error page in the Custom Tab on facebook.com; onError(FacebookException)"
      }
    }
  },
  "tokenShapes": {
    "google": "iOS: GIDSignInResult.serverAuthCode (requires GIDServerClientID; exchange is confidential -> broker) and/or GIDGoogleUser.idToken (aud = web client id when serverClientID set). Android: GoogleIdTokenCredential.getIdToken() only. Core: id-token leg via jwt.rs IdTokenChecks + token.rs jwks() (Google JWKS, nonce verbatim); auth-code leg via broker then exchange_code.",
    "apple": "identityToken (RS256 JWT, aud = bundle id, nonce claim = sha256(raw)) + single-use authorizationCode (exchange needs client secret -> broker-only). Session stands on the verified id token via Apple JWKS.",
    "facebook": "accessToken direct (classic LoginTracking.enabled; opaque Graph API token, no exchange, no JWKS) or AuthenticationToken JWT (limited login, Facebook JWKS). SDK-internal PKCE/nonce; core must not double-apply PKCE."
  },
  "hermeticGateImpact": "iOS gate loses its hermetic property: SPM resolution at xcodebuild time hits github.com (GoogleSignIn + 5 transitive source repos; FB XCFramework zips from github.com releases). Pin with committed Package.resolved (project.xcworkspace/xcshareddata/swiftpm/) and run xcodebuild -resolvePackageDependencies then -onlyUsePackageVersionsFromResolvedFile (flag names verified against local xcodebuild -help); FB checksums already pinned in upstream Package.swift. Android gate: Gradle resolution hits repo1.maven.org (facebook-login) and dl.google.com (androidx.credentials, googleid, play-services-auth); pin exact versions + optional gradle/verification-metadata.xml (--write-verification-metadata sha256) or dependency locking. Both READMEs and gate scripts must document the network step; accepted per user go-ahead; client_secret grep and other gate checks unchanged.",
  "licenses": {
    "GoogleSignIn-iOS": "Apache-2.0 (GitHub license API + repo LICENSE); transitive source deps AppAuth-iOS/GTMAppAuth/gtm-session-fetcher/GoogleUtilities/AppCheckCore are Google Apache-2.0 projects - re-read each LICENSE at add time",
    "FBSDK iOS + Android": "Facebook Platform License (LICENSE / LICENSE.txt / POM; GitHub NOASSERTION) - MIT-derived but restricted to use with Facebook's services and subject to Platform Policy; out of the MIT/BSD/Apache family so the licensing doc needs an explicit recorded dependency decision; both SDKs ship NOTICE files to reference",
    "androidx.credentials": "Apache-2.0 (POM)",
    "googleid + play-services-auth": "Android Software Development Kit License (POMs) - Google SDK terms, not OSI; record as notices pointers",
    "SignInWithApple": "system framework, no entry",
    "noticesPolicy": "all four are dependencies (zero adapted code); THIRD_PARTY_NOTICES.md gains one entry per artifact distributed inside the example apps, in the same commit as the dependency changes"
  },
  "blockers": []
}
```
