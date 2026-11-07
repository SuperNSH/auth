# Native gap analysis: our hand-rolled implementations vs the mature libraries

Read-only comparison, 2026-11-07, of what this repository hand-rolled in phase 1
against what the mature auth/storage libraries do on the same surfaces. It answers
one question per row: keep (ours is audited and adequate), adopt (the library is
clearly better — take the code or mechanism), or adapt (take the idea, not the code).

Honesty note up front: the phase-1 security audits converged on our implementations
(`docs/security-review.md`), so most rows below end in **keep**. That is the finding,
not inertia: where a library genuinely does better, this doc says so with the exact
mechanism and the source it was read from.

## What was read

Ours (read-only):

- `native/ios/Sources/AuthKeychain.swift`, `native/ios/Sources/AuthHostModule.swift`
- `native/android/dev/nshauth/sandbox/auth/SecureStore.kt`, `.../AuthHostModule.kt`
- `examples/host-desktop/src/loopback.rs`, `browser.rs`, `session_store.rs`
- `crates/nsh-auth/src/{store,error,flight,token,callback,session,lib}.rs`
- `examples/host-android/app/build.gradle.kts`, `app/src/main/AndroidManifest.xml`

Library side (`~/fo/.refs` clones, HEADs at read time; upstream repos where no local
clone exists):

- AppAuth-Android `e5f5184` (2026-03-22) — `library/java/net/openid/appauth/`
- AppAuth-iOS `dfbb0e0` (2026-11-02) — `Sources/AppAuthCore/`, `Sources/AppAuth/iOS/`
- flutter_secure_storage `1012697` (2026-11-01) — `flutter_secure_storage/android/.../ciphers/`, `flutter_secure_storage_darwin/.../Sources/flutter_secure_storage_darwin/`
- flutter_appauth `3a0e0e6` (2026-10-31) — wrapper; delegates to AppAuth on both platforms
- react-native-app-auth `ed4a3fa` (2026-10-19) — `packages/react-native-app-auth/ios/RNAppAuth.m`, `android/src/main/java/com/rnappauth/RNAppAuthModule.java`
- expo-auth-session `03ed6a8` (2026-11-06) — `packages/expo-auth-session/src/`
- expo-secure-store v58.0.2 (web) — `packages/expo-secure-store/{android,ios}`
- keyring v4.2.0 (web) — https://github.com/open-source-cooperative/keyring-rs, facade over `keyring-core` + per-platform store crates
- tauri-plugin-oauth (web) — https://github.com/FabianLars/tauri-plugin-oauth, `src/lib.rs`

Context: `docs/STATUS.md` (device-proof history), `docs/security-review.md` (audit
convergence).

## Gap table

| # | Row | Ours today | What the mature library does | Verdict |
|---|-----|-----------|------------------------------|---------|
| 1 | Key generation | Android: one AES-256 key inside AndroidKeyStore, created on first use, recreated only when the entry is gone or unusable (`SecureStore.kt:104-127`). iOS/desktop: no app-managed keys — the Keychain encrypts items itself (`AuthKeychain.swift:19-34`); desktop is plain files, by design (`store.rs:54-56`). | flutter_secure_storage (default): app-space random AES-128 storage key wrapped by an AndroidKeyStore RSA-2048/OAEP keypair, wrapped key parked in SharedPreferences (`ciphers/KeyCipherImplementationRSAOAEP.java:128-155`, `ciphers/StorageCipherImplementationGCM.java:47-54`, defaults at `ciphers/StorageCipherFactory.java:16-17`); optional Keystore-AES-256 variant (`KeyCipherImplementationAES23.java:33-35`). expo-secure-store: Keystore RSA keypair wrapping per-item AES keys (`HybridAESEncryptor.kt`, header comment lines 27-31). keyring: none — the OS store manages keys. | **keep** |
| 2 | Cipher / AEAD | AES/GCM/NoPadding, 128-bit tag, one seal per entry (`SecureStore.kt:131-135`). Desktop: plaintext JSON, explicitly documented as a baseline (`store.rs:54-56`). | Same AEAD family: fss AES/GCM/NoPadding with 128-bit tag (`StorageCipherImplementationGCM.java:19,64,105`), data key is 128-bit by default (`keySize = 16`, line 18). expo: AES with a 128-bit tag via its encryptors; its hybrid path uses `RSA/None/PKCS1Padding` wrapping (`HybridAESEncryptor.kt:112`). | **keep** |
| 3 | IV / nonce handling | Every seal gets a fresh IV generated inside the Keystore (`cipher.init(ENCRYPT_MODE, key())` with no IV spec, `SecureStore.kt:91-95`); the IV is stored next to the ciphertext per entry (`SecureStore.kt:69-71,80`). | fss: `SecureRandom` 12-byte IV per encryption, prepended to the ciphertext (`StorageCipherImplementationGCM.java:67-83`). expo: per-item IV stored inside the item record (`HybridAESEncryptor.kt:31`). Equivalent mechanism, different storage location. | **keep** |
| 4 | Key rotation | None proactive. Recovery is failure-driven: `AEADBadTagException` / `KeyPermanentlyInvalidatedException` drop the entry and the load returns null (`SecureStore.kt:32-46`); a missing/unusable Keystore key is recreated on next use (`SecureStore.kt:112-127`). | fss ships a whole migration story: algorithm markers in prefs (`StorageCipherFactory.java:27-56`), `requiresReEncryption()` (`:59-61`), a migrate-with-backup flow plus `MigrationBackup.java`, and explicit `deleteKey()` for reset (`StorageCipherImplementationGCM.java:58-61`). Their rotation exists mainly because users can change cipher options across versions. | **adapt** (scoped, low priority) |
| 5 | Error taxonomy (transient vs fatal) | Crate: one flat `AuthError` with semantic OAuth variants (`error.rs:7-28`); `invalid_grant` is distinguished by grant kind (`token.rs:190-194`) and a revoked refresh signs out (`lib.rs:359`). Android store already splits fatal-integrity errors (drop entry, return null) from transient Keystore errors (propagate) (`SecureStore.kt:32-46`). No explicit retryability marker, and user cancellation is a string on the TS/host side ("cancelled") rather than a variant. | AppAuth-Android: typed `AuthorizationException` families — GeneralErrors 0-999 (`NETWORK_ERROR`, `USER_CANCELED_AUTH_FLOW`, `SERVER_ERROR`, JSON/ID-token errors — `AuthorizationException.java:161-225`), OAuth authorization errors 1000-1999 and token errors 2000-2999 mapped from the RFC error strings (same file, below line 230). AppAuth-iOS mirrors it (`OIDError.h:99-166` general codes, `:173-221` OAuth codes). react-native-app-auth just maps these to JS rejects (e.g. `"token_refresh_failed"`, `RNAppAuthModule.java:412`). | **adapt** |
| 6 | Backup / migration policy | iOS: `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly` (`AuthKeychain.swift:32`) — items do not migrate device-to-device via backup restore. Android: `android:allowBackup="false"` on the host (`AndroidManifest.xml:10`), and even if the file were restored elsewhere, Keystore keys never export, so `AEADBadTagException` → entry dropped (row 4). Tokens effectively die on restore, which is the property we want. | fss documents the same property and makes accessibility configurable on darwin, including `ThisDeviceOnly` variants (`FlutterSecureStorage.swift:92-96`); expo iOS defaults to `AfterFirstUnlock` with a `ThisDeviceOnly` option plus optional `accessGroup` sharing (`SecureStoreModule.swift:196-213`). Their configurability exists because they are generic key-value plugins; we serve one use case. | **keep** |
| 7 | Multi-entry support | Android: single JSON map of `{key -> iv, ct}` with atomic tmp-then-rename writes (`SecureStore.kt:63-89`). iOS: one generic-password item per key under one service (`AuthKeychain.swift:19-25,52-61`). Crate: per-provider files or a memory map behind the `SessionStore` trait (`store.rs:13-17,70-74`). | fss: many prefixed SharedPreferences entries (`FlutterSecureStorage.java:51,116-123`); expo: one Keychain/Keystore item per (service, key) pair (`SecureStoreModule.swift:196-198`); keyring: one credential per (service, user) in the OS store. Same shape everywhere. | **keep** |
| 8 | Browser / service binding (Android CustomTabsService) | A bare `CustomTabsIntent.Builder().setShowTitle(true).build().launchUrl(...)` (`AuthHostModule.kt:117`) — no `CustomTabsService` connection, no warmup, no `mayLaunchUrl`, browser chosen by Android defaults. | AppAuth-Android `browser/CustomTabManager.java`: binds the browser's `CustomTabsService`, calls `warmup(0)` on connect (`:68-103`), builds a session per flow and calls `mayLaunchUrl` on the authorize URL (`:137-159`); a `BrowserSelector` + matcher set picks an explicit browser (the `browser/` package: `BrowserAllowList`, `VersionedBrowserMatcher`, …). This is why AppAuth tabs open faster and reuse the browser process. | **adopt** |
| 9 | Redirect validation | Android: pending authorize completes only on the exact registered scheme + host, path empty or `/`; forged URIs routed by the manifest filter are ignored without logging their query; the scheme is validated against the manifest at authorize time (`AuthHostModule.kt:74-93,101-114`). iOS: callback scheme must appear in `CFBundleURLTypes`, authorize URL must be http(s), and `ASWebAuthenticationSession` enforces the scheme binding (`AuthHostModule.swift:98-109,111-131`). Desktop loopback: GET-only, exact `/callback` path, `Host` header must equal this listener's `127.0.0.1:<port>` (DNS-rebinding probe refused), single-use registration, 5 s read timeout, 8 KiB cap (`loopback.rs:75-124,12`). Crate: `state` and `nonce` checks with dedicated errors (`callback.rs:16-35`, `error.rs:9-15`). | AppAuth-Android binds redirect to request by completing through `PendingIntent`s created for the exact flow (`AuthorizationManagementActivity.java:150-166`, steps documented at `:89-94`), so a cold-start redirect cannot complete a different flow. AppAuth-iOS uses `ASWebAuthenticationSession` internally (`OIDExternalUserAgentIOS.m`) — the same primitive we call directly. tauri-plugin-oauth's own docs warn that its localhost server is unprotected and "you _must_ verify the URL in the handler function" (`src/lib.rs:15-17,61-63`) — validation is the caller's job there; ours is built in. | **keep** |
| 10 | Token refresh location | In the shared core, not per host: `exchange_refresh` (`token.rs:55-62`), single-flight sharing with token-bound flights and driver-takeover on cancel (`flight.rs:22-27,152-167`), epoch guard so a stale flight cannot overwrite a newer session (`lib.rs:325-338`), revocation via broker or provider (`token.rs:123-160`). Refresh is caller-driven; `Session::expired` is exact-at-time with no tolerance (`session.rs:38-41`). | AppAuth puts refresh inside the state object: `AuthState.performActionWithFreshTokens` (Android `AuthState.java:474-528`) / `OIDAuthState` (iOS `OIDAuthState.m:493-511`), refreshing proactively within a 60 s expiry tolerance (`AuthState.java:49` `EXPIRY_TIME_TOLERANCE_MS = 60000`; `OIDAuthState.m:60`). react-native-app-auth and flutter_appauth wrap exactly these; expo-auth-session does the refresh grant in TS (`TokenRequest.ts:66,369`). | **adapt** (small: proactive tolerance; the location itself is right) |

## Row notes — where ours is already equivalent

These are the rows where "adopt" would be churn, and the evidence for saying so:

- **Key generation (1).** Our Android key is a direct hardware-bound AES-256 key; the
  RSA-wrap designs in flutter_secure_storage and expo-secure-store exist to keep the
  data key across processes and to offer opt-in biometric variants, at the cost of
  unwrapping a symmetric key into app memory at startup and (in expo's hybrid path)
  PKCS1 padding. We need neither: one process seals, one key, no biometric gate on
  tokens. iOS and desktop are not comparable at all — every library defers to the
  Keychain / OS store there.
- **Cipher and IV (2, 3).** Same AEAD (AES-GCM, 128-bit tag) and same discipline
  (fresh random IV per write) on both sides. Our data key is 256-bit where fss's
  default is 128-bit. Nothing to take.
- **Backup / migration (6).** The property "a restored backup yields no readable
  tokens" holds on all three of our mobile paths (ThisDeviceOnly keychain items,
  `allowBackup="false"` plus non-exportable Keystore keys). The libraries reach the
  same property with configurability we do not need for a single-purpose token
  store.
- **Multi-entry (7).** Identical shape: keyed entries, one seal (or item) per key,
  atomic rewrite. Our Android tmp-then-rename write (`SecureStore.kt:77-89`) is the
  mechanism fss relies on SharedPreferences for.
- **Redirect validation (9).** Our binding is at least as tight as AppAuth's
  PendingIntent completion: the manifest intent filter is the only route in, the
  exact scheme+host+path must match the one pending flow, and `state`/`nonce` bind
  the callback to the authorize request in the crate. The desktop loopback's
  `Host`-header pinning exceeds what tauri-plugin-oauth requires callers to do
  themselves, and AppAuth-iOS's launcher is the same `ASWebAuthenticationSession`
  call we make. Nothing to adopt.

## Recommended phase-2 actions, ranked

1. **Adopt CustomTabs service binding (row 8).** Port the mechanism of
   `browser/CustomTabManager.java`: bind the CustomTabsService of the selected
   browser, `warmup(0)`, create a session, `mayLaunchUrl(authorizeUrl)`, and launch
   with that session. Optionally reuse AppAuth's browser-matcher idea to prefer an
   explicit Chrome-family package. Roughly 100 lines; if copied verbatim it is
   Apache-2.0 and follows the attribution plan in `native-licensing.md`; the
   mechanism itself can also be re-derived — the plan documents either path.
2. **Adapt the error taxonomy (row 5).** Add `UserCancelled` (or a `Cancelled`
   variant) to `AuthError` so host cancellation stops being a string contract, and
   an `is_retryable()` helper marking `Network`/`BrokerError` transient versus the
   fatal OAuth variants. Do not import AppAuth's numeric-code families; our semantic
   variants are better and only these two additions are missing.
3. **Adapt refresh tolerance (row 10).** Add a tolerance parameter to the
   expiry/helper surface (the `now_ms + margin >= expires_at` shape AppAuth uses
   with 60 s) so hosts can refresh proactively instead of after expiry. The
   single-flight machinery stays untouched.
4. **Adapt a scoped rotation story (row 4).** Not fss's re-encryption machinery — we
   ship no cipher options. What is worth adding: an explicit "invalidate store"
   host call (delete Keystore key + clear file / keychain service) and a documented
   rule that any future change to cipher parameters bumps the store-file format and
   drops unreadable entries, which the `AEADBadTagException` path already does
   today.

Everything else stays as built. The remaining library code (AppAuth's request
builders, fss's biometric variants, keyring's Linux/Windows stores) maps to needs we
do not have in phase 1's surfaces, and the crate's `SessionStore` seam already
defines where a keyring-backed desktop store would go if a host ever wants OS-level
secret storage on desktop — that would be an addition behind the seam, not a
replacement.
