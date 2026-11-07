# tools/mock-oauth — nsh-auth sandbox OAuth provider mock

A local OAuth provider mock for the nsh-auth sandbox. It imitates Google,
Facebook, Discord, GitHub, Apple, Microsoft, X, a generic OIDC provider and a
plain mock provider — each in that provider's real response shape, with its
quirks. It is **not** any of those services: it binds to `127.0.0.1` only,
issues only sandbox-prefixed fake tokens, and never contacts the network.

## Run

```sh
node tools/mock-oauth/main.mjs --port 0   # ephemeral port (CI-safe)
node tools/mock-oauth/main.mjs            # default port 8755
bun tools/mock-oauth/main.mjs --port 8755 # bun works too
```

From inside `tools/mock-oauth`, the package scripts work too: `bun run dev` or
`bun run start` (aliases of `node main.mjs`; `--port` goes after `--`, e.g.
`bun run dev -- --port 0`).

On boot it prints the address to use:

```
MOCK_URL=http://127.0.0.1:63071
```

From the **Android emulator** the same server is reachable as
`http://10.0.2.2:<port>` (10.0.2.2 is the emulator's alias for the host's
loopback). From an iOS simulator or macOS app use the `MOCK_URL` as printed;
the server binds `127.0.0.1` only, so a physical device cannot reach it.

**The issuer follows the host you used.** The id_token `iss`, the discovery
document's `issuer`, the Microsoft callback `iss` and the picture URLs are
derived from each request's `Host` header, not from the startup URL. A client
that reaches the mock as `http://10.0.2.2:<port>` gets
`iss = http://10.0.2.2:<port>/<realm>`; a client using `http://127.0.0.1:<port>`
gets the loopback issuer from the same server. Why: a client validates
`iss` against its own configured base URL, and clients behind host aliases —
emulators, tunnels — would otherwise fail ID-token verification against an
issuer they never used. Requests without a `Host` header (HTTP/1.0) fall back
to the loopback base.

Tests: `cd tools/mock-oauth && bun test`.

## CORS

Every response — all providers, discovery, JWKS, userinfo, control endpoints,
errors, and OPTIONS preflights (204 on any path) — carries
`Access-Control-Allow-Origin: *` plus `Allow-Methods`/`Allow-Headers` covering
the token exchange. Why `*` is right here: the mock binds `127.0.0.1` only,
holds no real credentials, and a web demo served on a different loopback port
(e.g. `127.0.0.1:8790`) cannot complete the token exchange or fetch the JWKS
from a browser without it. `tools/broker` deliberately does **not** send CORS
headers — it serves an app owner who holds a client secret, not browser code.

## Provider route table

| Provider | Authorize | Token | Userinfo / me | Revoke | JWKS | Discovery |
| --- | --- | --- | --- | --- | --- | --- |
| Google | `/google/o/oauth2/v2/auth` | `/google/token` | `/google/userinfo` | `/google/revoke` | `/google/.well-known/jwks.json` | `/google/.well-known/openid-configuration` |
| Facebook | `/facebook/v21.0/dialog/oauth` | `/facebook/v21.0/oauth/access_token` (GET or POST, query-string params) | `/facebook/me?access_token=…` | `/facebook/permissions` (DELETE → `{success:true}`) | `/facebook/.well-known/jwks.json` (openid mode) | — |
| Discord | `/discord/oauth2/authorize` | `/discord/oauth2/token` (form-urlencoded only; JSON body rejected) | `/discord/api/users/@me` | `/discord/oauth2/token/revoke` (204) | — | — |
| GitHub | `/github/login/oauth/authorize` | `/github/login/oauth/access_token` (form-encoded by default, JSON with `Accept: application/json`; token errors come back **in-band with HTTP 200**) | `/github/api/user` | `/github/revoke` (204) | — | — |
| Apple | `/apple/auth/authorize` (form_post callback with `code`, `state`, `user`) | `/apple/auth/token` (requires non-empty `client_secret`) | — (profile arrives in the callback `user` field) | `/apple/auth/revoke` | `/apple/auth/keys` | — |
| Microsoft | `/microsoft/{tenant}/oauth2/v2.0/authorize` (query/fragment/form_post) | `/microsoft/{tenant}/oauth2/v2.0/token` | `/microsoft/common/oidc/userinfo` | — | `/microsoft/common/discovery/v2.0/keys` | `/microsoft/{tenant}/v2.0/.well-known/openid-configuration` |
| X | `/x/i/oauth2/authorize` (state required) | `/x/2/oauth2/token` | `/x/2/users/me` (`data` wrapper) | `/x/2/oauth2/revoke` | — | — |
| Generic OIDC | `/oidc/authorize` | `/oidc/token` | `/oidc/userinfo` | `/oidc/revoke` | `/oidc/.well-known/jwks.json` | `/oidc/.well-known/openid-configuration` |
| Mock | `/mock/authorize` | `/mock/token` | `/mock/userinfo` | `/mock/revoke` | `/mock/.well-known/jwks.json` | `/mock/.well-known/openid-configuration` |

`{tenant}` accepts `common`, `organizations`, `consumers` or any short
identifier; each tenant scopes its own discovery document and `tid` claim.

`GET /__routes` returns this table as JSON. `GET /` serves a sandbox-branded
HTML index. `GET /avatar.png` serves the picture the profile claims reference.

## Scripted user and behavior

- **Approve by default**: authorize immediately redirects the callback with
  `code` and the `state` you sent, echoed verbatim. The mock never validates
  `state` — the client must, so client bugs stay observable. (X and Apple
  reject an authorize request with *no* `state` parameter at all, like the
  real services.)
- **Deny**: add `prompt=deny` to the authorize URL, or globally flip the
  scripted user with the control endpoint. The callback then carries
  `error=access_denied` (+ `state` echo).
- **Codes** are single-use and expire after 120 seconds. An expired code
  exchanges to the provider's real error envelope — `invalid_grant` with an
  expired-saying description for Google/Discord/X/Apple/OIDC/Mock,
  `invalid_grant` + `error_codes:[70008]` (AADSTS70008) for Microsoft,
  in-band HTTP 200 `bad_verification_code` for GitHub, and a nested Graph
  `OAuthException` for Facebook. No provider ever returns a bare
  `expired_code` error code; that string exists only as the
  `(sandbox_reason: expired_code | code_already_used | …)` suffix in the
  description/message. Replaying a used code also revokes the tokens it
  issued (Google-style).
- **Refresh tokens** rotate on every use and are single-use: reusing a spent
  refresh token revokes the whole token family, and a revoked token (via the
  provider's revoke endpoint) fails refresh with the provider's revoked
  shape.
- **id_tokens** are real RS256 JWTs signed with an RSA keypair generated at
  boot; the matching JWKS is served per provider. They carry `iss`, `aud`,
  `sub`, `email`, `exp`/`iat`, provider claims, and `nonce` when the authorize
  request had one. Providers without OIDC id_tokens in reality (Discord,
  GitHub, X) don't issue one.
- **PKCE**: `S256` verified on exchange for every provider; `plain` is also
  accepted where the real provider allows it (X). Missing/wrong verifiers
  fail with `pkce_missing`/`pkce_mismatch` reasons.
- **client_secret** is accepted as any non-empty value (Apple requires one to
  be present); GitHub's broker flow never needs a secret through this mock —
  that is what `tools/broker` is for.

## Control endpoints

`POST /__control` with a JSON body:

| Field | Effect |
| --- | --- |
| `{"deny":true}` / `{"deny":false}` | scripted user denies (or approves) all authorize requests |
| `{"expireCodes":true}` | force-expire every outstanding authorization code (testing `expired_code` without waiting 120 s) |
| `{"reset":true}` | clear all codes, tokens, families and the deny flag |

`GET /__control` reports the current state: `{"sandbox":"nsh-auth
sandbox","deny":false,"codes":N,…}`.

## Errors carry a sandbox reason

Every token-error body keeps the provider's real error envelope — the wire
`error` code is always the provider's own (`invalid_grant`,
`bad_verification_code`, `invalid_client`, `unsupported_grant_type`, …) — and
appends `(sandbox_reason: <reason>)` to the description/message. Reasons
include `unknown_code`, `expired_code`, `code_already_used`, `client_mismatch`,
`redirect_mismatch`, `pkce_missing`, `pkce_mismatch`, `unknown_refresh`,
`revoked_refresh`, `refresh_reused`, `invalid_client`, `wrong_content_type`,
`unsupported_grant`; they are diagnostic strings, never wire error codes.
GitHub keeps its HTTP-200 in-band quirk; Facebook nests its reasons in the
Graph error `message`; Microsoft uses real AADSTS codes (`70008` expired,
`54005` redeemed, `50173` PKCE) in `error_codes`.

## Sandbox guarantees

- Binds `127.0.0.1` only; no outbound connections anywhere.
- All tokens, codes and ids are fake and prefixed `nsh-sandbox-` (GitHub-style
  `gho_nshsandbox…`/`ghr_nshsandbox…`, Facebook-style `EAAGnshsandbox…`).
- Every response carries an `X-Nsh-Auth-Sandbox` header; issuer strings are
  always the mock's own URL as addressed by the caller (loopback by default,
  per-request `Host`-derived — see above); user email is
  `sandbox.user@nsh-auth.invalid`.
