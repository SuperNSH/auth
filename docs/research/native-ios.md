# Native iOS — adopt proven library code or keep ours?

Phase-2 research question: for `native/ios/` (Swift `AuthHostModule` with an
`ASWebAuthenticationSession` launcher + hand-rolled `AuthKeychain.swift` over
`kSecClassGenericPassword`, service `nsh-auth.sandbox`, ThisDeviceOnly), what
proven library code should we vendor or adapt, and what do we keep?

Sources read (read-only clones under `/Users/hmziq/fo/.refs/`; file paths below
are inside them):

- **AppAuth-iOS** at commit `dfbb0e0` (v3.0.0, Nov 2026), ObjC, Apache-2.0.
- **react-native-app-auth** (`packages/react-native-app-auth/ios/RNAppAuth.m`,
  843 lines), ObjC over AppAuth, MIT.
- **expo-auth-session / expo-web-browser** sparse clone (MIT). The clone does
  not contain expo-secure-store, so its iOS sources were fetched from the expo
  monorepo `main` branch (`packages/expo-secure-store/ios/`, MIT) into
  `/tmp/nsh-auth-research/expo-secure-store-ios/` — citations below name those
  five files; upstream path is `expo/expo` → `packages/expo-secure-store/ios/`.
- Our side: `native/ios/Sources/AuthHostModule.swift` (174 lines),
  `native/ios/Sources/AuthKeychain.swift` (63 lines), contract in
  `native/ios/README.md`, host app `examples/host-ios/`.

## 0. What we have today, precisely

- `AuthHostModule.swift` registers `auth.authorize`, `auth.store.save`,
  `auth.store.load`, `auth.store.clear`, `auth.config` on `NshAppView.handle`.
  The launcher validates `url` is http/https, validates `scheme` against the
  app's own `CFBundleURLSchemes` (RFC 8252), cancels any prior session, sets
  `prefersEphemeralWebBrowserSession = false`, and replies with
  `{callbackUrl}` (or rejects the literal `"cancelled"`).
- `AuthKeychain.swift` is 63 lines: generic-password items keyed by
  `kSecAttrAccount` under one service, delete-then-add on save,
  `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`, `load` returns `nil` for
  *every* failure, `clear(nil)` wipes the service.
- The TS core owns the state machine: it stores the whole session as one JSON
  blob through `auth.store.*` (`packages/nsh-auth/src/host.ts:37`), builds
  authorize URLs, validates callbacks, and runs single-flight refresh
  (`crates/nsh-auth/src/flight.rs`, `crates/nsh-auth/src/lib.rs:313-416`).
- The host app compiles `../../native/ios/Sources/*.swift` straight into the
  target via a hand-written pbxproj
  (`examples/host-ios/NshAuthHostIOS.xcodeproj/project.pbxproj`, group path at
  line 70). No CocoaPods, no SPM packages, no Package.resolved.

The host channel contract `auth.authorize` / `auth.store.*` / `auth.config`
must not change. Everything below is judged against that constraint.

---

## 1. AppAuth-iOS (launcher and flow machinery)

**License.** Apache-2.0 (`/Users/hmziq/fo/.refs/AppAuth-iOS/LICENSE`), not MIT
as sometimes assumed. Vendoring any file obligates us to keep its per-file
header (each `.h/.m` carries the copyright + Apache-2.0 pointer), state
changes made, and add the license text to our distribution's notices. There is
no NOTICE file in the repo; `AUTHORS`/`CONTRIBUTORS` exist. Attribution cost is
real but small; *copying* cost is what dominates (see (c)).

### (b) What to copy / adapt / skip

**Adapt into `AuthHostModule.swift` (three behaviors, no ObjC):**

1. **Session-retention after completion (FB12132525).**
   `Sources/AppAuth/iOS/OIDExternalUserAgentIOS.m:46-69`:
   deallocating `ASWebAuthenticationSession` before its dismiss transition
   finishes crashes the app, so AppAuth keeps the finished session alive for
   2s on the main queue (`OIDRetainSessionBriefly`). Our module already holds
   `session` in a property and never nils it on completion
   (`AuthHostModule.swift:26,111-125`), so we are immune today — but the
   invariant is undocumented. Adaptation: a comment stating the invariant
   (never release the session while the dismiss transition may run) plus, if
   we ever add cleanup, the 2s delayed-release pattern — never a synchronous
   `session = nil` in the completion handler.

2. **Guided-access pre-check.**
   `OIDExternalUserAgentIOS.m:150-152`: `ASWebAuthenticationSession` does not
   work under guided access (rdar://40809553) and AppAuth refuses to start one
   (`if (!UIAccessibilityIsGuidedAccessEnabled())`). We launch unconditionally;
   under guided access `start()` misbehaves with no diagnosis. Adaptation: one
   guard line that rejects `auth.authorize` with a clear message.

3. **iOS 17.4 HTTPS callback support (record, do not implement yet).**
   `OIDExternalUserAgentIOS.m:115-137` (`HTTPSCallbackForRequest`) and expo's
   `expo-web-browser/ios/WebAuthSession.swift:35-50`: since iOS 17.4 an
   `ASWebAuthenticationSessionCallback` with host+path allows https redirect
   URIs; a redirect URL with no path is normalized to `/`; without this API an
   https redirect silently never fires (the custom-scheme initializer rejects
   https). Our `auth.authorize` contract carries `{url, scheme}` only, and our
   providers use custom-scheme redirects on iOS — so this is a contract
   extension (`callback: {scheme} | {httpsHost, httpsPath}`) to record in the
   backlog, not to slip into the current payload.

**Skip:** the `SFSafariViewController` path, `OIDExternalUserAgentIOSCustomBrowser`
(Chrome/Opera fallbacks), Mac Catalyst branches, the `OIDExternalUserAgent`
abstraction itself — we have one user agent, one surface, and the OS hands us
the callback directly through the session's completion handler, which is a
stronger seam than AppAuth's `resumeExternalUserAgentFlowWithURL:` indirection.

**Skip (behavior difference, deliberate):** AppAuth refuses a second flow
while one is in progress (`OIDExternalUserAgentIOS.m:141-144`); we cancel the
old session and start the new one (`AuthHostModule.swift:110`). Our core owns
single-flow state (`flight.rs`), and the TS side serializes `authorize` calls,
so cancel-and-replace is the correct host behavior. Keep ours.

### (c) Integration cost

- **As vendored ObjC sources:** 39 `.m` files across `Sources/AppAuthCore`,
  `Sources/AppAuth/iOS|macOS|tvOS`, plus `PrivacyInfo.xcprivacy` per product.
  In our hand-built pbxproj this means a bridging header
  (`SWIFT_OBJC_BRIDGING_HEADER`), every `.m` added to the target, and
  `#if TARGET_OS_*` scaffolding compiling dead code on iOS. Heavy.
- **As an SPM dependency:** `Package.swift` exists (swift-tools 5.7; iOS 15,
  macOS 12 — `AppAuth.podspec` agrees at v3.0.0). Hand-editing our pbxproj
  needs `XCRemoteSwiftPackageReference` + `XCSwiftPackageProductDependency`
  sections, `packageProductDependencies` on the target, and a committed
  `Package.resolved`; builds then require network resolution where the gate
  (`examples/host-ios/build-gate.sh`) is hermetic today, and pinning a tag
  still widens the supply-chain surface for a library of which we would use
  the launcher's error handling and nothing else.
- **Verdict:** neither. Adapt the three behaviors above into our own Swift.

### (d) What it does better than ours

- **Error taxonomy.** `Sources/AppAuthCore/OIDError.h:96-162` splits library
  errors (user-canceled, network, server, token-refresh, URL-mismatch,
  id-token parse/validation) from RFC 6749 §5.2 OAuth errors in three domains
  (authorization/token/registration), and `OIDErrorUtilities` maps raw `error`
  JSON into those domains. Our host maps exactly one case —
  `ASWebAuthenticationSessionError.canceledLogin` → `"cancelled"`
  (`AuthHostModule.swift:115-117`) — and the core maps provider error strings
  itself (`crates/nsh-auth/src/token.rs:190-192`). Nothing to adopt in Swift;
  the taxonomy is already mirrored where state lives.
- **Callback-match strictness.** The completion-handler comment at
  `OIDExternalUserAgentIOS.m:163-170`: the session matches callbacks loosely
  (custom scheme = scheme alone; https callback ignores case and port), so the
  flow re-validates the redirect. Our host passes the raw `callbackUrl` to the
  core, which validates `state`/nonce/redirect — the strict validation lives
  in the right place. Keep as is.

### (e) What we keep

The whole host-channel contract; core-owned validation; launch-argument
auto-start; the `NshHostReply` Sendable handling for the unspecified
completion thread (`AuthHostModule.swift:112-114`).

---

## 2. OIDAuthState (token storage + refresh) vs our core-owned state machine

This is the honest evaluation the question asks for, and the answer is:
**do not adopt OIDAuthState in the host.** It conflicts with the core-owned
state machine, and every behavior it embodies that we lack is a few lines in
the core.

**What OIDAuthState does** (`Sources/AppAuthCore/OIDAuthState.m`):

- Holds access/refresh tokens, scope, expiry in memory; archives itself via
  `NSSecureCoding` (`OIDAuthState.m:269-286`).
- Persisting is the app's job, signaled by
  `OIDAuthStateChangeDelegate.didChangeState:` — "you should update the
  storage when the state changes" (`OIDAuthStateChangeDelegate.h:25-33`).
  **AppAuth ships no keychain class**: `grep SecItem` across `Sources/`
  returns nothing but test/example comments, and its own samples store the
  archive in **plain UserDefaults**
  (`Examples/Example-iOS_Swift-SPM/Example/AuthManager.swift:389-402`) — the
  macOS example even says "for production usage consider using the OS Keychain
  instead" (`Examples/Example-macOS/Source/AppAuthExampleViewController.m:95`).
  So "AppAuth's keychain pattern" is a delegate contract, not code to vendor.
- Single-flight refresh: `performActionWithFreshTokens` queues pending actions
  under `@synchronized(_pendingActions)` while one refresh runs
  (`OIDAuthState.m:534-543,568-578`); expiry checked with a 60-second
  tolerance (`OIDAuthState.m:60,599`).
- Refresh-token rotation: a refresh response without `refresh_token` keeps the
  old token — "the spec says these may be changed by the server" RFC 6749 §5.1/§6
  (`OIDAuthState.m:393-402`).
- Hard vs transient errors (`OIDAuthStateErrorDelegate.h:30-58`): an OAuth
  error (HTTP 400 with a valid OAuth error body) during refresh calls
  `updateWithAuthorizationError` → `authorizationError` set → `isAuthorized`
  false → the app must treat the user as unauthorized and drop cached
  resources; invalid_grant is recoverable only by re-auth. Transient (network)
  errors leave the state valid and call `didEncounterTransientError` for a
  backoff retry. `OIDAuthState.m:557-565` routes token-endpoint errors by
  domain.

**What our core already does, at least as well:**

- Single-flight refresh where the flight carries the refresh token it started
  for — "a caller may only join a flight of its own token, so a stale flight
  can never answer for a newer session" (`crates/nsh-auth/src/flight.rs:19-21`).
  AppAuth's pending queue has no such guard; a queued action binds to whichever
  state exists when the refresh lands.
- `invalid_grant` mapped by grant kind — revoked refresh token vs expired code
  (`crates/nsh-auth/src/token.rs:190-192`), feeding session-signaling states
  (`crates/nsh-auth/src/session.rs:127-130`).
- Storage is core-canonical JSON through `auth.store.*`, the exact blob the
  core restores on restart (`packages/nsh-auth/src/host.ts:19-47`).

**Where OIDAuthState is genuinely ahead of our core (two real gaps found):**

1. **Rotation keep-if-absent.** Our refresh replaces `refresh_token` with
   whatever the response carries — `crates/nsh-auth/src/lib.rs:403`
   (`refresh_token: tokens.refresh_token`), so a provider that rotates only
   sometimes leaves us with `None` and a session that can never refresh again.
   Adapt in core (Rust `lib.rs:399-410` and the TS mirror in
   `packages/nsh-auth/src/tokens.ts:124-129` + its caller): keep the previous
   refresh token when the response omits one, with a mock test where the
   refresh endpoint returns no `refresh_token`.
2. **Expiry tolerance.** Our `expired()` is exact: `now_ms >= expires_at`
   (`crates/nsh-auth/src/session.rs:38-39`). AppAuth treats tokens as stale 60s
   early (`OIDAuthState.m:60`) so a refresh isn't sent with a token that
   expires mid-flight. Adapt in core: a constant (60s) subtracted in the
   "needs refresh" decision, both languages, mock-clock tested.

The hard-vs-transient split: our core already returns distinct error kinds
(`error.rs`, `InvalidGrant` vs transport errors); what to port is the *policy*
— a transient refresh failure must leave the session intact and retryable,
while `InvalidGrant` clears it — which matches `OIDAuthState.m:557-565`.
Add an explicit test pair if not present; no code shape to import.

**The conflict if we adopted it:** two refresh engines (Swift and core) racing
on the same provider; two session truths (an `NSKeyedArchiver` blob opaque to
the core, plus the core's JSON through `auth.store.*`); sign-out authority
split between core revocation and `OIDAuthState.update(withAuthorizationError:)`;
and the host would need a mirroring layer between the two representations. It
would also put a second persistence schema on iOS that migrations must carry
forever. The cut line: **vendor nothing from OIDAuthState; port the two
behaviors above into the core (Rust + TS parity) and the launcher's three
behaviors into `AuthHostModule.swift`.**

---

## 3. react-native-app-auth (the thin RN layer)

`packages/react-native-app-auth/ios/RNAppAuth.m` (MIT, `LICENSE`: "Copyright
(c) 2017 Formidable Labs") adds, beyond AppAuth-iOS itself: discovery vs
explicit service configuration, PKCE/state generation via AppAuth utilities
(`RNAppAuth.m:43-49,273-281`), the code exchange, revoke, a URLSession
timeout/header configuration, a string error-code mapping for JS
(`getErrorCode`, `RNAppAuth.m:697-741`), and `RNAppAuthAuthorizationFlowManager`
— a protocol the **host app's AppDelegate must implement** so RN can forward
the resume URL into AppAuth's session (`RNAppAuth.m:18-33`).

- Nothing here is vendorable for us: the file imports React Native headers and
  AppAuth; its features are either already in our core (URL building, PKCE,
  error strings), in the OS (the resume seam — `ASWebAuthenticationSession`
  delivers the callback without a forwarding protocol), or unwanted
  (`clientSecret` pass-through, which our broker seam replaces).
- The one documented insight matches our design: the JS wrapper cannot own the
  resume, so the host does. Ours does it one level lower (the OS calls the
  completion handler directly), which is why our `auth.authorize` needs no
  protocol at all.
- Its one-session-consumes-one-redirect cleanup (`RNAppAuth.m:28-31`, needed
  because AppAuth < 2.1.0 throws on re-resume) is free for us: an
  `ASWebAuthenticationSession` completes exactly once.

**Skip entirely.**

---

## 4. expo (WebAuthSession + SecureStore)

Both MIT ("Copyright (c) 2015-present 650 Industries" / 650 Industries; also
`packages/expo-auth-session/package.json:18`).

### expo-web-browser — `packages/expo-web-browser/ios/WebAuthSession.swift`

83 lines doing what our launcher does: `ASWebAuthenticationSession`, promise
resolve/reject, the iOS 17.4 `.https(host:path:)` branch behind an explicit
`preferUniversalLinks` opt-in (lines 38-50), `dismiss()` → `cancel()` +
`"dismiss"` result. No capability we lack. One cautionary contrast: `finish()`
sets `authSession = nil` **inside the completion handler** (lines 78-82) — the
exact release timing AppAuth's FB12132525 workaround exists to avoid; whether
expo has crash reports from it is unverified from source. Do not copy the
immediate-nil pattern. **Skip** (except the recorded https-callback note above).

### expo-secure-store — `packages/expo-secure-store/ios/` (fetched from main)

Five Swift files; the podspec (`ExpoSecureStore.podspec`) targets iOS 16.4 /
tvOS 16.4 and **depends on ExpoModulesCore**, and `SecureStoreModule.swift:7`
does `import ExpoModulesCore` — vendoring the files standalone is a
non-starter; only patterns are adaptable.

**(b)/(d) what it does better than our 63-line `AuthKeychain.swift` — and the verdicts:**

1. **Read-path error propagation — adapt.** `searchKeyChain` throws on any
   OSStatus that is not `errSecSuccess`/`errSecItemNotFound`
   (`SecureStoreModule.swift:170-183`). Our `load` collapses *every* failure
   into `nil` (`AuthKeychain.swift:45-47`) — `errSecInteractionNotAllowed` or
   `errSecAuthFailed` would masquerade as "no session stored", silently
   triggering a re-auth loop instead of a visible error. This is the single
   most important finding of this research. Adaptation: `load` throws
   `AuthHostError` on unexpected statuses; only `errSecItemNotFound` yields
   `nil`; the `auth.store.load` handler maps it to `{value: null}` (contract
   unchanged — the success shape is identical, failures currently can't happen
   and would now reject, which is the honest behavior).
2. **OSStatus → message mapping — adapt.** `SecureStoreExceptions.swift:21-69`
   maps the common security-error codes to human text with a
   `SecCopyErrorMessageString` fallback. Our messages carry only the number
   (`AuthKeychain.swift:36,59`). Adapt ~15 lines so host-channel rejections are
   diagnosable without a lookup table.
3. **`errSecDuplicateItem` → `SecItemUpdate` — keep ours.**
   `SecureStoreModule.swift:115-158` adds, then updates on duplicate, and must
   re-pass accessibility attributes because "Keychain updates keep the existing
   access settings by default" (comment at lines 137-139). Our delete-then-add
   (`AuthKeychain.swift:33-34`) reaches the same result and always re-applies
   the accessibility constant. Keep the simpler one.
4. **Accessibility option surface — keep ours.** Expo exposes all seven
   `kSecAttrAccessible` values (`SecureStoreAccessible.swift`), default
   `whenUnlocked`. We hard-code
   `AfterFirstUnlockThisDeviceOnly` — the right choice for auth tokens (readable
   for background refresh after first unlock, never leaves the device via
   backups), and the contract has no field to carry an option anyway.
5. **Biometric access control — skip.** `kSecAttrAccessControl` with
   `.biometryCurrentSet` + an `NSFaceIDUsageDescription` check
   (`SecureStoreModule.swift:97-128,227-239`) prompts on every read; session
   tokens are read automatically by the core, so this would break refresh
   outright. Wrong tool for this data class.
6. **Alias scheme — skip.** Expo writes items under service names suffixed
   `:auth`/`:no-auth` and reads all three aliases, deleting them together
   (`SecureStoreModule.swift:44-59,186-206`) purely to migrate their own older
   schema (an item's accessibility can't switch between attribute and
   access-control in place). We have one schema from day one and no migration.
7. **`kSecAttrGeneric` mirror and `accessGroup` — skip.** The generic
   attribute duplicates the account key for legacy reads
   (`SecureStoreModule.swift:194-199`); `accessGroup` matters only for app
   groups/extensions (lines 201-203), which we don't have.

**The "AppAuth keychain helper" myth, stated plainly for the record:** the
proven, production-grade iOS keychain code among the studied projects is
expo-secure-store's — AppAuth ships none, and react-native-app-auth points its
users at third-party stores (`docs/docs/token-storage.md` in the
react-native-app-auth repo, lines 29-33, recommends
react-native-keychain or expo-secure-store). Our wrapper already implements
the common core of what expo's does; the deltas that matter are items 1 and 2.

---

## 5. Integration cost summary (vendoring vs SPM in this repo)

- **Vendoring Swift files** into `native/ios/Sources/` costs three small
  pbxproj stanzas per file (PBXBuildFile, PBXFileReference, group child +
  Sources entry) in a project file that is already hand-written with fixed
  IDs. No network, no resolution step, gate stays hermetic. If a future
  adaptation grows beyond ~100 lines of copy, this is the route.
- **Adding any SPM package** (AppAuth or anything else) to the hand-built
  pbxproj: `XCRemoteSwiftPackageReference` + `XCSwiftPackageProductDependency`
  + `packageProductDependencies` on the target + a committed
  `Package.resolved`, and build-time network resolution. Justifiable only for
  a dependency we lean on broadly — which, per section 2, AppAuth would not be.
- **expo files** cannot be vendored standalone (`import ExpoModulesCore`);
  flutter-secure-storage-style wrappers were not examined (out of scope).

---

## ADOPTION VERDICT

| Component | Decision | Reason |
|---|---|---|
| `AuthHostModule.swift` launcher (`auth.authorize`) | **kept** | Correct against RFC 8252 and the OS API; core owns flow state; contract must not change |
| Host channel contract `auth.*` | **kept** | Fixed by `native/ios/README.md` + `packages/nsh-auth/src/host.ts`; nothing learned justifies a break |
| Guided-access pre-check (AppAuth, `OIDExternalUserAgentIOS.m:150-152`) | **adapted** | One guard line; prevents an undiagnosable `start()` failure under guided access |
| Session-retention invariant (AppAuth FB12132525, `OIDExternalUserAgentIOS.m:46-69`) | **adapted** | Document the invariant in `AuthHostModule.swift`; never nil the session inside the completion handler |
| iOS 17.4 HTTPS callback (`HTTPSCallbackForRequest`; expo `WebAuthSession.swift:38-50`) | **kept-skip** | Real future need, but requires an `auth.authorize` contract extension; recorded as backlog, not implemented |
| OIDAuthState engine (storage, auto-refresh, delegation) | **skipped** | Second refresh engine + second session truth; conflicts with core-owned state machine; AppAuth itself ships no storage and its sample uses plain UserDefaults |
| OIDAuthState semantics: keep old refresh token when response omits one (`OIDAuthState.m:400-402`) | **adapted** | Real bug-shaped gap in our core (`crates/nsh-auth/src/lib.rs:403`, TS mirror); fix in Rust + TS with mock tests |
| OIDAuthState semantics: 60s expiry tolerance (`OIDAuthState.m:60`) | **adapted** | Our `expired()` is exact (`session.rs:38-39`); avoid refreshing with a token that dies mid-request |
| OIDAuthState semantics: hard-vs-transient error policy (`OIDAuthStateErrorDelegate.h:30-58`) | **adapted** | Policy spec + test pair in core; error kinds already exist (`token.rs:190-192`) |
| OIDError taxonomy (`OIDError.h:96-162`) | **kept-skip** | Core already maps RFC 6749 error strings; host already maps `canceledLogin` |
| react-native-app-auth (`RNAppAuth.m`) | **skipped** | React-Native-coupled; everything it adds is either in our core, in the OS, or unwanted (client-secret pass-through) |
| expo-web-browser `WebAuthSession.swift` | **skipped** | No capability delta; its completion-handler nil is the crash pattern AppAuth guards against |
| expo-secure-store read-path error propagation (`SecureStoreModule.swift:170-183`) | **adapted** | Our `load` swallowing every OSStatus as `nil` can turn an auth failure into a silent re-auth loop — the top finding |
| expo-secure-store OSStatus message map (`SecureStoreExceptions.swift:21-69`) | **adapted** | ~15 lines; makes keychain rejections diagnosable in host-channel errors |
| expo-secure-store `SecItemUpdate` path (`SecureStoreModule.swift:115-158`) | **kept-skip** | Delete-then-add is equivalent and always re-applies accessibility |
| expo-secure-store biometric / aliases / accessGroup / accessibility options | **skipped** | Prompts break background refresh; alias scheme is expo's migration baggage; accessGroup needs targets we don't have; options can't cross the fixed contract |
| `AuthKeychain.swift` (63-line wrapper) | **kept** | Covers the common proven core (generic password, one service, ThisDeviceOnly, service-wide clear); receives the two error-handling adaptations above in place |

Net: **nothing vendored**; four adaptations into our own files
(`AuthHostModule.swift` ×2, core Rust+TS ×2 policies, `AuthKeychain.swift`
+ error text ×2), everything else kept or skipped with the reasons above. No
license obligations are created (Apache-2.0/MIT code is adapted as behavior
with citations, not copied as files; if any file copy ever happens, reproduce
the Apache-2.0 header and note it in the distribution's notices).
