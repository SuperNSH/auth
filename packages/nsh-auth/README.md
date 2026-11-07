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

1. **A host embeds the app** (`host.available()`). It calls
   `host.call("auth.authorize", { url, scheme })` and the host answers with
   `{ callbackUrl }` — an `ASWebAuthenticationSession` on iOS/macOS or Custom
   Tabs on Android caught the redirect. The whole loop finishes by itself, and
   tokens live in the host's secure store through `auth.store.save` /
   `auth.store.load` / `auth.store.clear` (Keychain, Keystore, DPAPI or Secret
   Service behind it). Names must be listed under `capabilities.host`.
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

## Errors

`auth.error()` holds an `AuthError` with a `code`: `access_denied`,
`state_mismatch`, `nonce_mismatch`, `expired_code`, `invalid_grant`, `network`,
`broker_error`, `store_error`, `no_launcher`, `unknown`. The rejected `signIn`,
`handleRedirect`, `refresh` or `signOut` promise carries the same error. A
refresh the server rejects as `invalid_grant` (revoked, expired) drops the
local session.

A restored session comes back only while unexpired; an expired one is cleared
at startup. `user` is filled by the sign-in flow, not by restore.

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
`{ provider, token }`. A reference broker lives in `tools/`.

## Tests

Run from this directory (`packages/nsh-auth`); all four gates exit 0:

```sh
nsh check && nsh build && nsh test && bun test
```

- `nsh check`, `nsh build` (no warnings), `nsh test` — the full loop through the
  UI of the harness `App.tsx`, headless, on a manual clock with a fake
  transport: authorize URLs asserted exactly for every provider, success,
  denial, wrong state, a callback with no state, wrong nonce, expired code,
  single-flight refresh under 8 parallel calls, revoked refresh, sign-out, the
  host launcher with its secure store, the GitHub broker path, and restore.
- `bun test` (plain) — the pure protocol units in `tests/protocol.spec.ts`
  against a loopback `Bun.serve` mock on 127.0.0.1 with a fake clock: base64url
  and PKCE vectors, byte-exact authorize URLs, callback parsing, token exchange
  and error mapping, the broker, JWKS RS256 verification, user mapping.
  `bunfig.toml` scopes bun to that file with
  `pathIgnorePatterns = ["tests/auth.test.tsx"]`, because `tests/auth.test.tsx`
  imports `nsh/test`, which only `nsh test` provides. `bun test
  tests/protocol.spec.ts` runs the same file explicitly. The spec is also
  excluded from `nsh check`'s tsconfig for the same reason.
- `nsh test --target macos` runs the non-host tests on a real surface and
  saves each state as a PNG under `docs/evidence/ts-core/`; a headless run
  draws nothing, and `host.handlers` exists only headless in 0.4.0, so the
  three host tests stay headless.
