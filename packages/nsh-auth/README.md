# nsh-auth (TypeScript)

Social and OAuth 2.0 / OIDC sign-in for Native Shell TSX apps. One call gives the
app signals for the session, the user, the status and the last error:

```tsx
import { createAuth } from "nsh-auth";

const auth = createAuth({
  clientId: "your-client-id.apps.googleusercontent.com",
  redirectUri: "com.example.app://callback",
});

auth.session(); // Session | null
auth.status();  // "idle" | "authorizing" | "exchanging" | "authenticated" | "refreshing" | "error"

The config also takes an optional `onAuthorizeUrl(url)` callback, invoked with
each authorize URL a `signIn` builds — useful for logs and test harnesses.

<button onPress={() => auth.signIn("google")}>Sign in with Google</button>
```

Providers: `google`, `facebook`, `discord`, `github`, `apple`, `microsoft`, `x`,
`oidc` and `mock` (the local mock, see `tools/mock-oauth`). The core does PKCE
S256, `state` and `nonce` (crypto random), the authorize URL, callback parsing
and validation, token exchange, refresh with single-flight (parallel `refresh()`
calls share one request), id-token claims with JWKS RS256 verification
(WebCrypto), revocation at sign-out, and a session store. GitHub and Apple,
whose token endpoints need a client secret, exchange only through `brokerUrl`;
no secret ever travels in a request from the app.

## Launchers, and what each cannot do

`signIn` picks its launcher in this order:

0. **The provider's native SDK** (`google`, `apple`, `facebook`, only when a
   host embeds the app). It calls `auth.nativeSignIn` — Google's Credential
   Manager or GoogleSignIn, Apple's system sheet, Facebook's dialog. Details,
   the per-provider nonce rules and the fallback rules are in the next
   section. If the host has no such channel, `signIn` continues below.
1. **A host embeds the app** (`host.available()`). It calls
   `host.call("auth.authorize", { url, scheme })` and the host answers with
   `{ callbackUrl }` — an `ASWebAuthenticationSession` on iOS/macOS or Custom
   Tabs on Android caught the redirect. The whole loop finishes by itself, and
   tokens live in the host's secure store through `auth.store.save` /
   `auth.store.load` / `auth.store.clear` (Keychain, Keystore, DPAPI or Secret
   Service behind it); the session crosses as a JSON string, which `load`
   parses. Names must be listed under `capabilities.host`.
2. **The web** (`platform.os === "web"`). `openUrl` opens the authorize page in
   a new tab. **The redirect cannot come back by itself in nsh 0.4.0**: the web
   runtime has no `window`, no `location`, no inbound-URL channel. The page
   hosting the app must bridge the redirect — a small script on the
   `redirect_uri` page reads `location.search` and hands the URL to the app,
   which then calls `auth.handleRedirect(url)`.
3. **No host, not the web (bare TSX, desktops)** — the honest fallback.
   `openUrl()` opens the authorize URL (headless tests record it in
   `app.openedUrls()`), and then it waits. **This fallback cannot receive the
   redirect automatically**: there is no listener, no URL scheme, no loopback
   socket in TSX on 0.4.0. `signIn` stays `authorizing` until the app calls
   `auth.handleRedirect(url)` with a callback URL pasted back by hand (or
   bridged by the code around the app). If `openUrl` itself fails or nothing
   handles the URL, `signIn` rejects with `no_launcher`.

`handleRedirect` and the host path are the same machinery: parse the callback,
check `state`, exchange the code, verify the id token's signature and `nonce`,
load the user, store the session.

## Native SDK legs (`auth.nativeSignIn`)

On iOS and Android the provider's own SDK is the better surface: Google blocks
embedded web views, Apple's sheet is the system's, Facebook's dialog runs its
own PKCE. When a host embeds the app, `signIn` for `google`, `apple` and
`facebook` tries the native channel first, and only a **missing channel** falls
back to the browser loop:

- The core generates a raw nonce (CSPRNG, the same family as `state` and the
  browser nonce) and calls `host.call("auth.nativeSignIn", { provider, nonce })`.
- **Channel absent** — no host, the name not granted, or an embedder built
  before the channel existed (the engine answers "handles no ..."): the call
  counts as absent and the browser launcher runs, exactly as before. Web and
  hostless builds never attempt the call. Absence can also be per provider: a
  host whose native module does not serve this provider — Android implements
  google and facebook only — rejects with `auth.nativeSignIn: unknown
  provider ...`, which counts as absent for that provider alone, so `apple`
  on Android signs in through the browser instead of hard-erroring.
- **Cancelled** — the host rejects with a `cancelled` message when the user
  dismisses the sheet. The `signIn` promise rejects with `access_denied` and
  the signals return to what they were: no error report, no session change.
- **SDK or provider failure** — any other rejection. It lands on `error`
  (code `unknown`, the host's message kept) with status `error`. No silent
  browser retry after a real failure, and no double flow: a failure and a
  cancel never launch the browser.

`auth.signInNative(provider)` is the same flow without the fallback: a missing
channel rejects with `no_launcher` instead of opening a browser, and it takes
an optional `{ audience }` override for the one call.

### What each leg returns, and how the core verifies it

| Leg | The host answers with | What the core does |
| --- | --- | --- |
| google on iOS | `{provider, serverAuthCode}` | Redeems the code with the existing `exchangeCode` machinery — through `brokerUrl` when configured (a server code is the SERVER client's grant; its secret never lives in the app), or direct to Google's token endpoint otherwise. Then the browser path's tail: userinfo, store save, signals. |
| google on Android | `{provider, idToken, nonce?}` | `verifyIdToken` against Google's JWKS: `iss https://accounts.google.com`, `aud` = `nativeAudiences.google`, nonce claim == the raw nonce **verbatim**. The session stands on the id token: its `exp` is the session's expiry and the token is the only bearer credential (it fills both `idToken` and `accessToken`). |
| apple on iOS | `{provider, identityToken, authorizationCode, nonce}` | `verifyIdToken` against Apple's JWKS (`https://appleid.apple.com/auth/keys`): `iss https://appleid.apple.com`, `aud` = `nativeAudiences.apple`, nonce claim == **SHA-256 hex of the raw nonce** — the opposite of Google's rule, because Apple's request already carried the hash. The session keeps `authorizationCode` on the record: single-use, and exchanging it needs an Apple client secret, so the broker owns that leg; the session itself stands on the verified identity token. |
| facebook (both) | `{provider, accessToken, expiresAt?}` | Session wrap — no exchange, no JWKS, the classic SDK token is opaque — plus Graph `/me` for the user signal. `expiresAt` is the host's epoch ms when it has one, otherwise 0 (never expires locally). |

Every result answers with `provider` and echoes the raw `nonce` (apple always,
google when the request carried one); an echo that is not the nonce the core
sent is a `nonce_mismatch` before anything is fetched.

The nonce rules, side by side:

| Provider | The request carried | The token's `nonce` claim | The core compares |
| --- | --- | --- | --- |
| google, native | raw nonce | raw nonce | verbatim |
| apple, native | `sha256(raw)` | `sha256(raw)` | `sha256Hex(rawNonce)` |
| browser flows | raw nonce (authorize URL) | raw nonce | verbatim |

### Configuring the native audiences

```ts
const auth = createAuth({
  clientId: "your-ios-client-id.apps.googleusercontent.com",
  redirectUri: "com.example.app://callback",
  nativeAudiences: {
    // The id tokens of the native legs are issued for these, not for clientId:
    google: "your-web-client-id.apps.googleusercontent.com", // Credential Manager's serverClientId
    apple: "com.example.app", // the app's bundle id
  },
});
```

A missing audience fails the leg with a clear config error before any fetch —
fail loud rather than silently falling back to the browser. Hosts implement the
channel to this contract; apps declare `auth.nativeSignIn` under
`capabilities.host`.

## Surviving process death (hosts)

`signIn`'s host call carries `verifier`, `state` and `provider` next to
`url` and `scheme`, so the host can seal a parked record (no tokens in it) and
the sign-in can outlive the process that started it. At boot, on a host, the
core asks `auth.pendingAuthorize`:

- With a `callbackUrl` (the redirect arrived while the app was dead), the core
  rebuilds the flow from the record — `state` and `nonce` from it and the
  authorize URL, PKCE verifier included — completes the exchange, saves the
  session, and sends `{ clear: true }` to consume the record.
- Without one, the browser was opened but never returned. The core reports
  `interrupted` on `error` and does **not** re-launch anything: a browser only
  ever opens on a user action. The record stays parked — its redirect may
  still arrive on a later boot, and a new `signIn` supersedes it host-side.
- A record that cannot answer a callback is cleared and reported as
  `interrupted` — fail closed: missing `url`, `state` or `provider`; a sealed
  URL whose `state` disagrees with the record's; a wants-nonce provider whose
  sealed URL carries no `nonce` (never exchange without nonce binding); a PKCE
  provider with no `verifier` (never burn a single-use code on a doomed
  exchange).

Hostless and web builds never call the channel; a host that predates it just
fails the call, which the core reads as "nothing parked".

## Errors

`auth.error()` holds an `AuthError` with a `code`: `access_denied`,
`state_mismatch`, `nonce_mismatch`, `expired_code`, `invalid_grant`, `network`,
`server_error`, `broker_error`, `store_error`, `no_launcher`, `interrupted`,
`unknown`. The rejected `signIn`, `handleRedirect`, `refresh` or `signOut`
promise carries the same error. A refresh the server rejects as `invalid_grant`
(revoked, expired) drops the local session.

`error.isRetryable()` says whether the same request can succeed later: the
transient failures are `network` and `server_error` (any 5xx from a token
endpoint or the broker); everything else — the OAuth protocol errors, state and
nonce mismatches, store and broker failures — is final. A transient refresh
failure reports on `error` and leaves the session in place for a retry.

A refresh response that omits `refresh_token` keeps the session's previous one
(RFC 6749 §6: the server may rotate the token or leave it unchanged).

A restored session comes back only while it outlives a 60-second proactive
margin (`EXPIRY_TOLERANCE_MS`): one expiring sooner counts as expired and is
cleared at startup, so no request goes out on a token that dies mid-flight.
`user` is filled by the sign-in flow, not by restore.

## The mock and the broker

`mockBaseUrl` (default `http://127.0.0.1:8755`) is the base for the `mock` and
`oidc` providers, each its own realm of the sandbox server
(`tools/mock-oauth`): `GET/POST {base}/mock/authorize`, `POST {base}/mock/token`,
`GET {base}/mock/userinfo`, `POST {base}/mock/revoke`,
`GET {base}/mock/.well-known/jwks.json`, with issuer `{base}/mock` — and the
same shape under `{base}/oidc/…` with issuer `{base}/oidc`. Each realm also
serves a discovery document (`{base}/mock/.well-known/openid-configuration`).
Android emulators reach a host Mac at `10.0.2.2`.

The broker contract (`brokerUrl`): `POST {brokerUrl}/token` with JSON
`{ provider, code, codeVerifier, redirectUri }` or
`{ provider, refreshToken }`, answering `{ accessToken, refreshToken?,
idToken?, expiresIn?, scope? }`; `POST {brokerUrl}/revoke` with
`{ provider, token }`. A reference broker lives in `tools/`. Every token
request sends `Accept: application/json` — AppAuth-Android added the same
header because GitHub answers form-encoded without it.

## Tests

Run from this directory (`packages/nsh-auth`); all four gates exit 0:

```sh
nsh check && nsh build && nsh test && bun test
```

- `nsh check`, `nsh build` (no warnings), `nsh test` — the full loop through the
  UI of the harness `App.tsx`, headless, on a manual clock with a fake
  transport: authorize URLs asserted exactly for every provider, success,
  denial, wrong state, a callback with no state, wrong nonce, expired code,
  single-flight refresh under 8 parallel calls, revoked refresh, a refresh
  response without rotation keeping the previous token, transient (network,
  5xx) refresh failures leaving the session for retry, sign-out, the host
  launcher with its secure store, the GitHub broker path with its Accept
  header, restore including the 60-second expiry margin, the parked-flow
  boot resume (completes with its callback, reports `interrupted` without one,
  and works unchanged on a host that lacks the channel), and the native SDK
  legs over a fake `auth.nativeSignIn` host: each shape's happy path (google
  serverAuthCode direct and through the broker, google id token with the
  verbatim nonce, apple identity token with the sha256 nonce and the kept
  authorization code, facebook wrap with Graph `/me`), the nonce and echo
  mismatches, the missing-audience refusal, cancel restoring the prior state,
  SDK failure reporting without a browser fallback, the browser fallback on a
  channel-absent embedder, and `signInNative` reporting `no_launcher`.
- `bun test` (plain) — the pure protocol units in `tests/protocol.spec.ts`
  against a loopback `Bun.serve` mock on 127.0.0.1 with a fake clock: base64url
  and PKCE vectors, the SHA-256 hex vectors Apple's native nonce rule leans
  on, byte-exact authorize URLs, callback parsing, token exchange
  and error mapping, retryability classification, expiry tolerance, the broker,
  JWKS RS256 verification, user mapping.
  `bunfig.toml` scopes bun to that file with
  `pathIgnorePatterns = ["tests/auth.test.tsx"]`, because `tests/auth.test.tsx`
  imports `nsh/test`, which only `nsh test` provides. `bun test
  tests/protocol.spec.ts` runs the same file explicitly. The spec is also
  excluded from `nsh check`'s tsconfig for the same reason.
- `nsh test --target macos` runs the non-host tests on a real surface and
  saves each state as a PNG under `docs/evidence/ts-core/`; a headless run
  draws nothing, and `host.handlers` exists only headless in 0.4.0, so the
  three host tests stay headless.
