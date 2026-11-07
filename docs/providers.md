# Provider reference

Per-provider facts for the eight providers nsh-auth ships plus a generic OIDC template. This is the reference the core, mock, demo, and setup docs point at. Every endpoint URL was read from the provider's own documentation or its live, public discovery/metadata document in November 2026; the source page is cited under each table. If a provider doc contradicts an assumption made elsewhere in this repo, it is listed in [Discrepancies to relay](#discrepancies-to-relay) and flagged inline.

Conventions used everywhere unless the provider section says otherwise:

- Authorization code flow only. PKCE with `code_challenge_method=S256`. Random `state` (validated on return) and random `nonce` (validated inside the ID token when the provider issues one).
- Client ids and secrets in this file and in `fixtures/provider-catalog.json` are fake sandbox values (for example `nsh-auth-sandbox.apps.googleusercontent.com`). Nothing here was registered, and no credential was ever typed into a provider console.
- Surfaces: **ios/android** = system browser session (ASWebAuthenticationSession / Android Custom Tabs) with a custom-scheme callback; **desktop** = system browser with a `127.0.0.1:{random port}` loopback listener; **web** = `https` redirect or popup on the web host.

---

## Google

### (a) Endpoints

| Endpoint | URL |
| --- | --- |
| Discovery | `https://accounts.google.com/.well-known/openid-configuration` |
| Authorization | `https://accounts.google.com/o/oauth2/v2/auth` |
| Token | `https://oauth2.googleapis.com/token` |
| Userinfo | `https://openidconnect.googleapis.com/v1/userinfo` |
| Revocation | `https://oauth2.googleapis.com/revoke` |
| JWKS | `https://www.googleapis.com/oauth2/v3/certs` |

Revoke takes `POST` with `token=<access-or-refresh-token>` and returns an empty 200 for either token type. ID tokens are signed RS256; `iss` is `https://accounts.google.com` (or `accounts.google.com`); use `sub` as the user key, never `email`. The `tokeninfo` endpoint is debug-only, not part of the flow.

Sources: [OpenID Connect](https://developers.google.com/identity/protocols/oauth2/openid-connect) (discovery URL and all endpoint URLs, ID token claims), [OAuth 2.0 for mobile & desktop apps](https://developers.google.com/identity/protocols/oauth2/native-app) (revoke, PKCE, client_secret optionality).

### (b) Scopes (sign-in minimum)

| Scope | Returns |
| --- | --- |
| `openid` | ID token; required |
| `profile` | name, picture, locale claims when present |
| `email` | `email` + `email_verified` claims |

Add `access_type=offline&prompt=consent` on the authorize request or there is no refresh token at all, and only on the first consent.

Source: [OpenID Connect](https://developers.google.com/identity/protocols/oauth2/openid-connect).

### (c) Redirect rules per surface

| Surface | Rule |
| --- | --- |
| iOS | Custom scheme: `com.googleusercontent.apps.<client-id-prefix>:/oauth2redirect` (the client ID reversed) or your own reverse-domain scheme; scheme must contain a period. The loopback redirect is blocked for iOS client types (see quirks). |
| Android | No custom-scheme or loopback redirect: Google blocks both for Android client types. Register the Android client by package name + SHA-1 signing cert and use the native SDK path; from the web-view-free flow the SDK hands back a server auth code. For a hand-built flow there is no redirect to intercept. |
| Desktop | `http://127.0.0.1:{port}` (or `[::1]`) with a random free port chosen at runtime; register as `http://127.0.0.1` in the console. `localhost` works but Google warns about firewall issues. Loopback stays supported for desktop client types. |
| Web | Registered `https` redirect URI, exact match (`redirect_uri_mismatch` otherwise). |

Sources: [mobile & desktop apps](https://developers.google.com/identity/protocols/oauth2/native-app) (scheme format, loopback format, port rule), [Loopback IP address flow Migration Guide](https://developers.google.com/identity/protocols/oauth2/resources/loopback-migration) (mobile/Chrome blocking dates), demo host rules.

### (d) Quirks

- **Embedded webviews are blocked.** Google's authorization endpoint returns the `disallowed_useragent` error when shown in an embedded user-agent (WKWebView and friends). Use the system browser; `SFSafariViewController` is a supported option. Never load Google sign-in in an in-app web view.
- **PKCE is required in practice** ("always use PKCE"), `S256` recommended; `plain` is accepted but nsh-auth always sends S256.
- **`client_secret` is optional** for installed/desktop clients. Never embed one; the token exchange works with client_id + PKCE.
- **Refresh token only on first consent**, only with `access_type=offline`; Google caps refresh tokens per client/user and silently invalidates the oldest when the cap is hit. Store it on first sign-in.
- **Loopback blocked on mobile client types** since 2022 (new iOS/Android/Chrome clients 2022-03-14; all existing 2022-10-21). Desktop keeps loopback.
- Revocation kills the grant for that token; revoke the refresh token at sign-out.

Sources: [mobile & desktop apps](https://developers.google.com/identity/protocols/oauth2/native-app), [OpenID Connect](https://developers.google.com/identity/protocols/oauth2/openid-connect), [loopback migration guide](https://developers.google.com/identity/protocols/oauth2/resources/loopback-migration).

### (e) What the owner registers

1. Google Cloud console ([console.cloud.google.com](https://console.cloud.google.com)) -> **APIs & Services -> OAuth consent screen**: fill app name, support email, scopes in use (`openid`, `.../auth/userinfo.profile`, `.../auth/userinfo.email`).
2. **Credentials -> Create credentials -> OAuth client ID**, one client per surface:
   - *Web application*: Authorized redirect URI `https://demo.example.com/callback` (example, fake).
   - *Desktop app*: `http://127.0.0.1` (loopback port is supplied at runtime).
   - *iOS*: bundle ID; Google derives the `com.googleusercontent.apps.*` scheme.
   - *Android*: package name + SHA-1 of the signing cert.
3. Copy the client ID, e.g. fake `nsh-auth-sandbox.apps.googleusercontent.com`. Desktop/iOS clients have no client secret; web clients do, and a web secret belongs on a server (broker seam), never in an app.

### (f) Brand / UX for the hand-built button

| Attribute | Rule |
| --- | --- |
| Label | `Sign in with Google` / `Sign up with Google` / `Continue with Google`, exactly this capitalization; never "Google" alone as the action |
| Themes | Light: fill `#FFFFFF`, 1px inside stroke `#747775`, text `#1F1F1F`. Dark: fill `#131314`, stroke `#8E918F`, text `#E3E3E3`. Neutral: fill `#F2F2F2`, no stroke, text `#1F1F1F`. |
| Type | Google Sans Medium, 14/20 |
| Shape | Rectangular or pill; preserve aspect ratio when scaling |
| Logo | Standard multicolor "G" only, never recolored or redrawn, white G on dark theme; padding 12px before the logo, 10px after logo, 12px after text (iOS variants: 16/12/16) |
| Placement | At least as prominent as other third-party sign-in buttons |
| Assets | [signin-assets.zip](https://developers.google.com/static/identity/images/signin-assets.zip) |

Source: [Sign-In Branding Guidelines](https://developers.google.com/identity/branding-guidelines). Note the current spec is white/dark/neutral fills — the old solid-blue Google button is no longer the spec.

---

## Facebook

### (a) Endpoints

Facebook URLs are versioned; the docs sampled here show `v27.0`. Pin one version per release.

| Endpoint | URL |
| --- | --- |
| Discovery (OIDC metadata) | `https://www.facebook.com/.well-known/openid-configuration/` |
| Authorization | `https://www.facebook.com/{version}/dialog/oauth` |
| Token | `https://graph.facebook.com/{version}/oauth/access_token` |
| Userinfo (Graph) | `https://graph.facebook.com/me?fields=id,name,email,picture` (Bearer token) |
| Token debug | `https://graph.facebook.com/debug_token?input_token=<token>&access_token=<app access token>` |
| Permission revocation (equivalent) | `DELETE https://graph.facebook.com/{version}/me/permissions` |
| JWKS | `https://www.facebook.com/.well-known/oauth/openid/jwks/` |

The live discovery document declares issuer `https://www.facebook.com`, RS256 signing, `at_hash`/`nonce` claims, and no `token_endpoint` (its declared `response_types_supported` are `id_token` and `token id_token`, i.e. implicit only). The code-flow token endpoint is the Graph one above. Facebook access tokens are opaque strings, not JWTs; the ID token (JWT, RS256) only exists in the OIDC/PKCE variant.

Sources: [Manually Build a Login Flow](https://developers.facebook.com/documentation/facebook-login/guides/advanced/manual-flow), [OIDC Code Flow with PKCE for Manually Built Facebook Login](https://developers.facebook.com/documentation/facebook-login/guides/advanced/oidc-token), [Login Security](https://developers.facebook.com/documentation/facebook-login/security), and the live `https://www.facebook.com/.well-known/openid-configuration/` document.

### (b) Scopes (sign-in minimum)

| Scope | Returns |
| --- | --- |
| `public_profile` | id, name, picture (default granted) |
| `email` | email on Graph `/me` and in the ID token; only when granted, can be empty |
| `openid` | ID token; required for the OIDC code flow |

`state` is a required dialog parameter. Source: [manual flow](https://developers.facebook.com/documentation/facebook-login/guides/advanced/manual-flow), [OIDC code flow](https://developers.facebook.com/documentation/facebook-login/guides/advanced/oidc-token), discovery `claims_supported`.

### (c) Redirect rules per surface

| Surface | Rule |
| --- | --- |
| Web | `https` redirect URI, registered under **Facebook Login -> Settings -> Valid OAuth Redirect URIs**. **Enforce HTTPS** is on and required for OAuth redirects; **Strict Mode** (required for all apps) demands exact string match, no path substitution, no extra query params (`state` is the only ignored extra). |
| Desktop | `redirect_uri=https://www.facebook.com/connect/login_success.html` with `response_type=token` — the implicit, desktop-webview shape. No refresh token, no ID token in this shape. |
| iOS / Android | The manual-flow docs describe **no custom-scheme redirect** for mobile. The sanctioned native path is the Facebook SDK, which round-trips through its own `fb{app-id}://` scheme and returns the session to the app. A hand-built flow has no documented redirect to catch on mobile; treat mobile as SDK-or-HTTPS-relay (see quirks). Legacy: `ms-app://{package-security-identifier}` for Windows 8 style brokers. |

Sources: [manual flow](https://developers.facebook.com/documentation/facebook-login/guides/advanced/manual-flow), [Login Security](https://developers.facebook.com/documentation/facebook-login/security), [Enforce HTTPS announcement](https://developers.facebook.com/blog/post/2018/06/08/enforce-https-facebook-login).

### (d) Quirks

- **Two documented flow shapes, different auth:** the classic manual flow requires `client_secret` on the token exchange (server-to-server, hence the broker seam); the OIDC code flow makes `client_secret` optional **only when `code_verifier` is sent**. nsh-auth implements the OIDC+PKCE shape for public clients and keeps the classic shape behind the broker.
- **PKCE:** `code_challenge` required in the OIDC flow; `code_challenge_method` defaults to `plain` when omitted — always send `S256` explicitly. `nonce` is required in the authorization request.
- **No RFC 7009 revocation endpoint.** Sign-out server-side means `DELETE /{version}/me/permissions`; apps can also register a deauthorize callback URL in the dashboard.
- **HTTPS + Strict Mode** for every redirect (see above). Development mode only allows unregistered localhost redirects — a dashboard behavior, not in the docs; do not rely on it in production.
- **Versioned URLs.** Every dialog/Graph call carries `{version}`; versions rotate and old ones retire, so the version is provider config, not a constant.
- **App secret proof.** With "Require App Secret" enabled, Graph calls need `appsecret_proof` (HMAC-SHA256 of the access token using the app secret) — one more reason the secret lives in the broker.
- The `user` name/email delivery of Apple does not exist here; email arrives via Graph `/me` with the `email` permission granted.

Sources: [manual flow](https://developers.facebook.com/documentation/facebook-login/guides/advanced/manual-flow), [OIDC code flow](https://developers.facebook.com/documentation/facebook-login/guides/advanced/oidc-token), [Login Security](https://developers.facebook.com/documentation/facebook-login/security).

### (e) What the owner registers

1. [developers.facebook.com](https://developers.facebook.com) -> **My Apps -> Create App** (Authentication use case).
2. Add the **Facebook Login** product. In **Facebook Login -> Settings**: enable Client OAuth Login, set **Valid OAuth Redirect URIs** (e.g. fake `https://demo.example.com/callback/facebook`), keep **Enforce HTTPS** and Strict Mode on.
3. **App Settings -> Basic**: copy the App ID (fake example `1234567890123456`) and App Secret (fake `nsh-sandbox-app-secret-not-real`). The secret goes to the broker only; with the OIDC+PKCE shape the public client path needs no secret.
4. Add the demo domain under **Settings -> Basic -> App Domains**, and keep the app in Development mode while testing.

### (f) Brand / UX for the hand-built button

| Attribute | Rule |
| --- | --- |
| Label | `Continue with Facebook` or `Log in with Facebook` (context-dependent), copy inside the button |
| Color | Button blue per the UX page: `#5890FF` ("Button colors are white and Facebook blue: 5890FF") fill with white logo + text; the same page's color-values list gives the official Facebook blue as `#1877F2` (RGB 24, 119, 242) — the page carries both values; approved alternate is the white button; fall back to black/white if neither fits |
| Logo | Approved "f" logo from the Brand Resource Center, placed before the call to action, never recolored, scaled, or altered |
| Type / size | Font choice is free but must stay legible; no pixel minimums are published — keep the button large, rectangular, and thumb-reachable |
| Placement | Offer Facebook Login prominently with the other providers |

Source: [Facebook Login User Experience Design](https://developers.facebook.com/documentation/facebook-login/userexperience).

---

## Discord

### (a) Endpoints

| Endpoint | URL |
| --- | --- |
| Discovery (OIDC) | `https://discord.com/.well-known/openid-configuration` |
| Metadata (RFC 8414) | `https://discord.com/.well-known/oauth-authorization-server` |
| Authorization | `https://discord.com/oauth2/authorize` (metadata also serves `https://discord.com/api/oauth2/authorize`) |
| Token | `https://discord.com/api/oauth2/token` |
| Userinfo (REST) | `https://discord.com/api/users/@me` |
| Userinfo (OIDC) | `https://discord.com/api/oauth2/userinfo` |
| Revocation | `https://discord.com/api/oauth2/token/revoke` |
| JWKS | `https://discord.com/api/oauth2/keys` |

The token endpoint accepts `application/x-www-form-urlencoded` **only** (JSON is rejected) and authenticates with HTTP Basic `client_id:client_secret` or `client_id`/`client_secret` form fields; the RFC 8414 metadata additionally lists `none`, i.e. PKCE public clients. Token response: `access_token`, `token_type: "Bearer"`, `expires_in: 604800` (7 days), `refresh_token`, `scope`. Metadata declares issuer `https://discord.com`, `code_challenge_methods_supported: ["S256"]`, `authorization_response_iss_parameter_supported: true`.

Sources: [OAuth2](https://docs.discord.com/developers/topics/oauth2), and the live metadata documents `https://discord.com/.well-known/oauth-authorization-server` and `https://discord.com/.well-known/openid-configuration`.

### (b) Scopes (sign-in minimum)

| Scope | Returns |
| --- | --- |
| `identify` | `/users/@me` without email: id, username, global_name, discriminator, avatar, public_flags |
| `email` | adds `email` (+ `verified` flag) to `/users/@me` |
| `openid` | ID token (RS256) in the token response |

Every authorization redirect carries `iss=https://discord.com` (RFC 9207); validate it before exchanging the code.

Source: [OAuth2](https://docs.discord.com/developers/topics/oauth2) (scopes table, iss note), discovery metadata.

### (c) Redirect rules per surface

| Surface | Rule |
| --- | --- |
| All | Redirect URIs are registered in the Developer Portal (**OAuth2 -> Redirects**) and sent URL-encoded as `redirect_uri`. The docs impose no scheme restriction and no documented loopback or custom-scheme rules either way. |
| Web | `https` redirect URI. |
| Desktop / iOS / Android | Native clients register custom-scheme redirect URIs in the portal; the docs do not forbid or bless them, so confirm in the portal at registration time. If a provider rejects the scheme, fall back to the loopback listener on desktop. |

Source: [OAuth2](https://docs.discord.com/developers/topics/oauth2).

### (d) Quirks

- **`iss` on every redirect** (RFC 9207). A flow that ignores it fails Discord's mix-up guidance; nsh-auth validates `iss=https://discord.com`.
- **Revocation revokes the whole authorization**: `token/revoke` kills the access token *and* all refresh tokens for that grant regardless of `token_type_hint`.
- **Form-encoded only** at the token endpoint; refresh via `grant_type=refresh_token` + `refresh_token`.
- **Refresh token presence varies by grant**: authorization_code returns one; implicit and client_credentials do not.
- **PKCE + `openid` are under-documented.** S256 PKCE and the OIDC `userinfo`/`keys` endpoints exist in the server metadata but not in the prose docs (see [Discrepancies](#discrepancies-to-relay)). nsh-auth sends PKCE S256 regardless and reads identity from `/users/@me` first, ID token second.
- Implicit-grant responses come back in URL fragments, not query strings.

Source: [OAuth2](https://docs.discord.com/developers/topics/oauth2), live metadata documents.

### (e) What the owner registers

1. [discord.com/developers/applications](https://discord.com/developers/applications) -> **New Application**.
2. **OAuth2**: copy the Client ID (fake example `1122334455667788990`); **Reset Secret** to get a Client Secret (fake `nsh-sandbox-discord-secret`) — shown once.
3. **OAuth2 -> Redirects**: add one per surface (e.g. fake `https://demo.example.com/callback/discord`, `com.nshauth.sandbox:/oauth2redirect`).
4. Public-client sign-in needs only the Client ID; the secret is for the broker/confidential use.

### (f) Brand / UX for the hand-built button

| Attribute | Rule |
| --- | --- |
| Label | Discord publishes no mandated button label; `Continue with Discord` is the conventional wording |
| Color | Blurple `#5865F2` (companion palette: Light Blurple `#E0E3FF`, black `#000000`) fill with white mark + text |
| Logo | Official Discord mark, "do not edit, change, distort, recolor, or reconfigure"; use color/black/white variants only; standalone symbol only where the brand is already established |
| Rules | Digital use only; do not imply Discord sponsors or endorses the app |

Source: [Discord Brand Guidelines](https://discord.com/branding).

---

## GitHub

### (a) Endpoints

GitHub OAuth Apps are OAuth 2.0, not OIDC: no discovery document, no JWKS, no ID token.

| Endpoint | URL |
| --- | --- |
| Discovery | none |
| Authorization | `https://github.com/login/oauth/authorize` |
| Token (+ refresh) | `https://github.com/login/oauth/access_token` |
| Userinfo | `https://api.github.com/user` (Bearer token) |
| User emails | `https://api.github.com/user/emails` (Bearer token) |
| Token check | `POST https://api.github.com/applications/{client_id}/token` — body `{"access_token": "..."}` (Basic auth `client_id:client_secret`) |
| Token reset | `PATCH https://api.github.com/applications/{client_id}/token` — body `{"access_token": "..."}` (Basic auth) |
| Revocation | `DELETE https://api.github.com/applications/{client_id}/token` with body `{"access_token": "..."}` (Basic auth) |

The authorize request takes `client_id`, `redirect_uri`, `scope` (space-delimited), `state`, `code_challenge`/`code_challenge_method` (S256 only — `plain` is not supported), `allow_signup`, `prompt=select_account`. The issued `code` expires after 10 minutes. The token endpoint returns form-encoded output by default; send `Accept: application/json` for JSON. Refresh: `grant_type=refresh_token` + `refresh_token` (+ `client_secret` unless the token came from the device flow).

Sources: [Authorizing OAuth Apps](https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/authorizing-oauth-apps), [OAuth apps REST API](https://docs.github.com/en/rest/apps/oauth-applications), [Scopes for OAuth Apps](https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/scopes-for-oauth-apps).

### (b) Scopes (sign-in minimum)

| Scope | Returns |
| --- | --- |
| *(none)* | read-only public profile via `/user` — enough if you only need a login + avatar |
| `read:user` | full profile data |
| `user:email` | private emails via `/user/emails` |
| `offline_access` | expiring tokens: refresh token issued (scope never shows in the consent prompt) |

Never ask for `repo` for sign-in. Source: [Scopes for OAuth Apps](https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/scopes-for-oauth-apps), [Authorizing OAuth Apps](https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/authorizing-oauth-apps).

### (c) Redirect rules per surface

| Surface | Rule |
| --- | --- |
| Web | `https` callback URL registered on the OAuth app (up to 10; host and port must match exactly, path may be a subdirectory, optional per-URL wildcard subdomain matching). |
| Desktop | **Loopback is explicitly supported**: `redirect_uri` on `http://127.0.0.1:{any port}` or `[::1]` does not need to match the registered port; use `127.0.0.1`/`::1`, not `localhost`. |
| iOS / Android | **No documented custom-scheme callback.** A non-HTTP redirect does not complete a documented flow. Mobile nsh-auth goes through the broker (https callback owned by the owner's server, which bounces to the app) or the device flow (`https://github.com/login/device`), which has no redirect at all. |

Sources: [Authorizing OAuth Apps](https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/authorizing-oauth-apps) (loopback port exemption, wildcard rules), callback-count behavior per the OAuth app registration docs.

### (d) Quirks

- **`client_secret` is required on the code exchange** for the web application flow (only the device flow omits it). PKCE does not remove this requirement. A client secret can never ship inside an app, so every in-app GitHub sign-in goes through the token broker seam — the nsh-auth reference broker exists exactly for this.
- **Rotating refresh tokens**: with expiring tokens enabled (or `offline_access` requested), access tokens last 8 hours, refresh tokens 6 months of disuse, and a used refresh token is invalidated and replaced. Refreshing cannot widen scopes.
- **Token check/reset/revoke need Basic auth with the client secret** — server-side operations, so they belong in the broker, not in the app.
- No OIDC: profile identity comes from the REST `/user` call; `id` is the stable user key.
- GitHub itself recommends fine-grained GitHub Apps over OAuth Apps for new integrations; nsh-auth still implements the OAuth App flow because it is the one that fits user sign-in.

Source: [Authorizing OAuth Apps](https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/authorizing-oauth-apps), [REST API](https://docs.github.com/en/rest/apps/oauth-applications).

### (e) What the owner registers

1. GitHub -> **Settings -> Developer settings -> OAuth Apps -> New OAuth App**.
2. Fill Application name, Homepage URL, and the **Authorization callback URL** (one per surface; up to 10 total), e.g. fake `http://127.0.0.1:0/callback` conceptually, `https://broker.example.com/callback/github` for the broker path.
3. Copy the Client ID (fake example `Ov23linshsandbox0000000`) and generate the Client Secret (fake `nsh-sandbox-gh-secret`) — shown once. The secret goes into the broker config, never into an app bundle.
4. Optional: enable **Expire user authorization tokens** to get the refresh-token behavior.

### (f) Brand / UX for the hand-built button

| Attribute | Rule |
| --- | --- |
| Label | `Sign in with GitHub` (GitHub publishes no mandated label; this is the conventional form) |
| Color | No official button-color spec. Use a dark neutral fill (GitHub's own UI dark `#24292F` is the conventional choice — a convention, not a published spec) with white logo + text, or white fill with the black mark |
| Logo | The Invertocat mark, "should only appear in white, black, or in few cases grey or green"; never compress, distort, skew, stretch, or alter; keep contrast |
| Rules | Do not use the logo as your app's icon or in a way that suggests GitHub endorses your app; use it only to indicate GitHub sign-in/integration |

Source: [GitHub brand site](https://brand.github.com/foundations/logo).

---

## Apple (Sign in with Apple)

### (a) Endpoints

| Endpoint | URL |
| --- | --- |
| Discovery | `https://appleid.apple.com/.well-known/openid-configuration` |
| Authorization | `https://appleid.apple.com/auth/authorize` |
| Token | `https://appleid.apple.com/auth/token` |
| Userinfo | none — claims ride in the ID token (name/email also arrive as a `user` field on the first authorization POST) |
| Revocation | `https://appleid.apple.com/auth/revoke` |
| JWKS | `https://appleid.apple.com/auth/keys` |

Live discovery: issuer `https://appleid.apple.com`, scopes `openid`, `email`, `name`, `response_modes` `query|fragment|form_post`, `token_endpoint_auth_methods_supported: ["client_secret_post"]`, RS256. The token endpoint takes `grant_type=authorization_code` or `grant_type=refresh_token` plus `client_id`, `client_secret`, and `code`/`refresh_token`; the issued `code` is single-use and valid for five minutes.

Sources: live `https://appleid.apple.com/.well-known/openid-configuration`, [Request an authorization to the Sign in with Apple server](https://developer.apple.com/documentation/signinwithapplerestapi/request-an-authorization-to-the-sign-in-with-apple-server), [Incorporating Sign in with Apple into other platforms](https://developer.apple.com/documentation/signinwithapple/incorporating-sign-in-with-apple-into-other-platforms), [Generate and validate tokens](https://developer.apple.com/documentation/signinwithapplerestapi/generate-and-validate-tokens).

### (b) Scopes (sign-in minimum)

| Scope | Returns |
| --- | --- |
| `openid` | required; enables the ID token |
| `name` | `user` field (`name.firstName`/`name.lastName`) on the **first** authorization only |
| `email` | `email`, `email_verified`, `is_private_email` claims in the ID token |

Source: discovery document; [incorporating guide](https://developer.apple.com/documentation/signinwithapple/incorporating-sign-in-with-apple-into-other-platforms).

### (c) Redirect rules per surface

| Surface | Rule |
| --- | --- |
| iOS / macOS native | Use `ASAuthorizationController` (the system flow — no HTTP redirect involved) reached through the host. The web-based `ASWebAuthenticationSession` path still needs an https redirect (next row). |
| All web-based (incl. desktop, Android) | `redirect_uri` is **https only**: "must include a domain name and can't be an IP address or `localhost`, and must not contain a fragment identifier", registered per Services ID as Return URLs. Apple does **not** accept custom-scheme redirects — the Return URL is a page on your server, and "it's your server's responsibility to persist the data and return control to the app" (e.g. by redirecting to your app's custom scheme afterwards). |
| Response mode | `response_mode=form_post` is mandatory whenever scopes are requested: the result (`code`, `id_token`, `state`, first-time `user`) arrives as an `application/x-www-form-urlencoded` HTTP POST **body** at the redirect URI, not as query parameters. |

Source: [incorporating guide](https://developer.apple.com/documentation/signinwithapple/incorporating-sign-in-with-apple-into-other-platforms) (quotes), [configuring your environment](https://developer.apple.com/documentation/signinwithapple/configuring-your-environment-for-sign-in-with-apple).

### (d) Quirks

- **`client_secret` is a JWT you make yourself**: header `{alg: ES256, kid: <Key ID>}`, payload `{iss: <10-char Team ID>, iat, exp <= iat+15777000 (six months), aud: "https://appleid.apple.com", sub: <client_id>}`, signed with the `.p8` private key downloaded from the developer account. That key is a credential: it lives in the broker, never in an app. This is the canonical token-broker provider on Apple's side.
- **form_post + POST-body identity** (see above). Loopback and custom schemes cannot receive the POST; only a real https endpoint can. On iOS the app therefore either uses `ASAuthorizationController` or needs a relay page.
- **First-authorization-only name/email.** Later authorizations return no `user` field. Persist it at first sign-in.
- **`user_cancelled_authorize`** is the only error Apple may POST back — treat it as a cancel, not a failure.
- Revocation (`/auth/revoke` with `token`, `client_id`, `client_secret`, `token_type_hint`) is required by App Store rules when deleting an account.
- Refresh tokens have no fixed expiry but can be invalidated out-of-band (password change, email change); handle `invalid_grant` on refresh by re-running the flow.
- ID token: RS256, `iss=https://appleid.apple.com`, `aud`=client_id, `sub`=stable per-developer user id.

Source: [Creating a client secret](https://developer.apple.com/documentation/accountorganizationaldatasharing/creating-a-client-secret) (JWT claims, quoted example, 15777000s cap), [incorporating guide](https://developer.apple.com/documentation/signinwithapple/incorporating-sign-in-with-apple-into-other-platforms), discovery document.

### (e) What the owner registers

1. Apple Developer account -> **Certificates, Identifiers & Profiles -> Identifiers**: register an App ID with the **Sign In with Apple** capability (native app flow).
2. Register a **Services ID** (e.g. fake `com.nshauth.sandbox`) — this is the `client_id` for web-based flows. Configure it: enable Sign In with Apple, set the primary domain and **Return URLs** (e.g. fake `https://demo.example.com/callback/apple`).
3. **Keys -> Create a Key** with Sign In with Apple enabled, download the `.p8`, note the 10-char **Key ID**; note your **Team ID** (fake `NSHSANDBX01`). All four (Services ID, Team ID, Key ID, `.p8`) are the broker's inputs for minting `client_secret` JWTs.

Sources: [Register a Services ID](https://developer.apple.com/help/account/configure-app-capabilities/services-ids/register-a-services-id), [Configure Sign in with Apple for the web](https://developer.apple.com/help/account/capabilities/configure-sign-in-with-apple-for-the-web), [Creating a client secret](https://developer.apple.com/documentation/accountorganizationaldatasharing/creating-a-client-secret).

### (f) Brand / UX for the hand-built button

| Attribute | Rule |
| --- | --- |
| Styles | Black (light backgrounds), White (dark backgrounds), White-with-outline (low-contrast light backgrounds). Black/white only — "don't use custom colors" for logo or text |
| Minimums | Width >= 140pt, height >= 30pt; margin around the button >= 1/10 of its height |
| Logo / type | `apple.logo` SF Symbol, logo height = button height; title font size = 43% of button height (e.g. 44pt button -> 19pt font); prefer the system font |
| Label | `Sign in with Apple`, `Sign up with Apple`, or `Continue with Apple`, capitalization preserved (first word + "Apple" capitalized) |
| Shape | Corner radius adjustable (rounded default, square, capsule) to match the app's other buttons |
| Logo-only | 1:1 aspect ratio, no crop, no added padding; PNG only at exactly 44pt height |
| Rules | No smaller than other sign-in buttons, no scrolling to reach it; custom buttons get App Review scrutiny; artwork only from [design resources](https://developer.apple.com/design/resources/) |

Source: [Apple HIG: Sign in with Apple](https://developer.apple.com/design/human-interface-guidelines/sign-in-with-apple).

---

## Microsoft

### (a) Endpoints

Tenant-scoped: `{tenant}` is `common` (work/school + personal), `organizations` (work/school), `consumers` (personal), or a tenant GUID/domain.

| Endpoint | URL |
| --- | --- |
| Discovery | `https://login.microsoftonline.com/{tenant}/v2.0/.well-known/openid-configuration` |
| Authorization | `https://login.microsoftonline.com/{tenant}/oauth2/v2.0/authorize` |
| Token | `https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token` |
| Userinfo | `https://graph.microsoft.com/oidc/userinfo` |
| Revocation | none (no RFC 7009 endpoint) |
| JWKS | `https://login.microsoftonline.com/{tenant}/discovery/v2.0/keys` |
| End session (logout) | `https://login.microsoftonline.com/{tenant}/oauth2/v2.0/logout` |

Sign-out is the OIDC end-session request with `post_logout_redirect_uri` (must be a registered redirect URI); there is no token-revocation endpoint, so "sign out" = local token destruction + optional end-session.

Source: [OpenID Connect on the Microsoft identity platform](https://learn.microsoft.com/en-us/entra/identity-platform/v2-protocols-oidc) (endpoint table, tenant table, logout section), [auth code flow](https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-auth-code-flow).

### (b) Scopes (sign-in minimum)

| Scope | Returns |
| --- | --- |
| `openid` | ID token; required |
| `profile` | display name, job title and similar claims |
| `email` | email claim (only meaningful together with `openid`) |
| `offline_access` | refresh token — **only provided if requested** |
| `User.Read` | Graph access token for the signed-in user's profile |

Access tokens last ~1 hour (`expires_in: 3599`). Source: [v2-protocols-oidc](https://learn.microsoft.com/en-us/entra/identity-platform/v2-protocols-oidc), [auth code flow](https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-auth-code-flow) ("`refresh_token` ... **Note:** Only provided if `offline_access` scope was requested").

### (c) Redirect rules per surface

| Surface | Rule |
| --- | --- |
| iOS / Android | Register under the **iOS/macOS / Android** platform types or "Mobile and desktop applications"; custom schemes are supported (MSAL generates `msal{client-id}://auth` for the mobile platform). AppAuth-style native clients use the "Mobile and desktop applications" platform. |
| Desktop | Loopback supported per RFC 8252: `http://localhost:{any port}` — the port is **ignored** when matching localhost redirect URIs, and Microsoft recommends `127.0.0.1` over `localhost`. Caveats: the portal's redirect-URI text box rejects `http://127.0.0.1`, so it must be added via the manifest `replyUrlsWithType`; `[::1]` is not supported. |
| Web | `https` URI; SPA code+PKCE needs the URI registered as type **SPA** (a `web`-type URI fails CORS token redemption from the browser). |
| Any | Default fallback for embedded-webview desktop apps: `https://login.microsoftonline.com/common/oauth2/nativeclient`. URIs are case-sensitive, max 256 chars, 256 URIs total (100 when personal accounts are in the audience), no fragments, no IDN, `! $ ' ( ) , ;` disallowed. `response_mode=form_post` is recommended with `http://localhost`. |

Source: [Redirect URI (reply URL) best practices and limitations](https://learn.microsoft.com/en-us/entra/identity-platform/reply-url) (all quotes), [auth code flow](https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-auth-code-flow) (nativeclient values, form_post note).

### (d) Quirks

- **Tenant scoping is in the URL path.** `common` vs `organizations` vs `consumers` changes who can sign in and which issuer signs the token; guest cross-tenant sign-in must use the target tenant ID. nsh-auth treats `{tenant}` as provider config with `common` as default.
- **`offline_access` must be requested explicitly** or no refresh token exists; requesting it shows a separate consent prompt. Refresh tokens are not revoked on use (rotate-and-discard), and `spa`-registered redirect URIs get 24-hour refresh tokens.
- **No revocation endpoint**: sign-out = drop local tokens + OIDC logout request.
- **ID-token issuance must be enabled** in the app registration for `response_type` containing `id_token` (implicit/hybrid); the plain code flow returns the ID token from the token endpoint when `openid` was requested.
- **Graph access tokens are not parseable JWTs** (opaque/encrypted, especially for personal accounts) — never validate or decode tokens for an API you don't own; use the ID token for identity.
- Scopes are resource-prefixed (`User.Read` = Graph); mixed-resource scope lists on the token request collapse to the first resource.
- `response_mode`: `query` for code-only, `fragment`/`form_post` when ID tokens ride along; `form_post` recommended for reliability and localhost.

Source: [v2-protocols-oidc](https://learn.microsoft.com/en-us/entra/identity-platform/v2-protocols-oidc), [auth code flow](https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-auth-code-flow), [reply-url](https://learn.microsoft.com/en-us/entra/identity-platform/reply-url).

### (e) What the owner registers

1. Microsoft Entra admin center ([entra.microsoft.com](https://entra.microsoft.com)) -> **Microsoft Entra ID -> App registrations -> New registration**. Pick the account audience (e.g. "Accounts in any organizational directory and personal Microsoft accounts").
2. Copy the **Application (client) ID** (fake example `11111111-2222-3333-4444-555555555555`).
3. **Authentication -> Add a platform**, one per surface: Web (`https://demo.example.com/callback/microsoft`, fake), Single-page application (same URI, type SPA), Mobile and desktop applications (`msal{client-id}://auth` is offered; add the loopback URI via the manifest for `http://127.0.0.1`).
4. **Authentication -> Advanced settings -> Enable "Allow public client flows" = Yes** for the no-secret native flow.
5. Confidential/broker deployments add a credential under **Certificates & secrets** (or a certificate for `private_key_jwt`).

### (f) Brand / UX for the hand-built button

| Attribute | Rule |
| --- | --- |
| Label | `Sign in with Microsoft` (short form `Sign in` is allowed when space is tight); pair it with "work or school account" copy where useful |
| Schemes | Light and dark button themes; use the official downloadable button images/SVGs as the reference for both |
| Logo | Microsoft logo (the four-square symbol) exactly as published — "DON'T alter the Microsoft logo"; association of the logo with the "Sign in with Microsoft" wording is what represents the platform |
| Rules | Never say "Azure AD", "Microsoft 365 ID", "enterprise account", or "corporate account" in UI copy; expose a sign-out/switch-account path |

Source: [Sign in with Microsoft branding guidelines](https://learn.microsoft.com/en-us/entra/identity-platform/howto-add-branding-in-apps). The page ships assets and redlines rather than hex values, so the hand-built button should embed the official SVG symbol and follow the redlines; it publishes no numeric pixel minimums.

---

## X (Twitter)

### (a) Endpoints

X OAuth 2.0 is **not** OIDC: no discovery, no JWKS, no ID token.

| Endpoint | URL |
| --- | --- |
| Discovery | none |
| Authorization | `https://x.com/i/oauth2/authorize` |
| Token (+ refresh) | `https://api.x.com/2/oauth2/token` |
| Userinfo | `GET https://api.x.com/2/users/me` (Bearer token) |
| Revocation | `https://api.x.com/2/oauth2/revoke` |
| JWKS | none |

Authorize parameters: `response_type=code`, `client_id`, `redirect_uri` (exact-match validated), `scope` (space/percent-encoded), `state` (<= 500 chars), `code_challenge`, `code_challenge_method` (`S256` or `plain`). Token requests are form-encoded; public clients send `client_id` in the body, confidential clients use a Basic header (`client_id:client_secret`) and may omit body `client_id`. The authorization code expires after **30 seconds**; access tokens live **2 hours** without `offline.access`.

Sources: [User access token (Authorization Code Flow with PKCE)](https://docs.x.com/fundamentals/authentication/oauth-2-0/user-access-token), [Authorization Code guide](https://docs.x.com/resources/fundamentals/authentication/oauth-2-0/authorization-code), [Developer apps](https://docs.x.com/fundamentals/developer-apps).

### (b) Scopes (sign-in minimum)

| Scope | Returns |
| --- | --- |
| `users.read` | `/2/users/me` profile |
| `tweet.read` | required alongside `users.read` for user-context calls |
| `offline.access` | refresh token — "If this scope is not passed, we will not generate a refresh token" |
| `users.email` | email (added scope; availability gated by app access level) |

Source: [Authorization Code guide](https://docs.x.com/resources/fundamentals/authentication/oauth-2-0/authorization-code), [User access token](https://docs.x.com/fundamentals/authentication/oauth-2-0/user-access-token).

### (c) Redirect rules per surface

| Surface | Rule |
| --- | --- |
| All | Callback URLs are allowlisted per app in the developer console; "URLs must match exactly (including trailing slashes)"; up to **10 callback URLs per app**; "Use `https://` in production"; local development should use `http://127.0.0.1` rather than `localhost`; schemes like `javascript:`, `data:`, `file:`, `ftp:`, `mailto:`, `telnet:` are disallowed. |
| Web | `https` callback URI. |
| Desktop | `http://127.0.0.1:{port}` callback registered as an allowlisted URL. |
| iOS / Android | Native App is a public client type; custom-scheme callbacks are not called out in the docs either way — register the scheme and verify in the console, or route mobile through the https relay. |

Source: [Developer apps](https://docs.x.com/fundamentals/developer-apps) (quotes).

### (d) Quirks

- **PKCE-only for public clients** ("Public clients use PKCE only") and PKCE on every example; the flow is literally named "Authorization Code Flow with PKCE". nsh-auth always sends S256.
- **No OIDC**: identity is the REST `/2/users/me` call; there is no ID token to verify, so the signed-in identity claim rests on the token exchange over TLS.
- **Refresh token gated by `offline.access`**; rotate on refresh at the same token endpoint (`grant_type=refresh_token`).
- **30-second code lifetime** — the app must exchange immediately, no queueing.
- **Public vs confidential is chosen in the console** by app type (Native App / Single Page App = public, no secret issued; Web App / Automated App = confidential with secret).
- Revoke takes `token` (+ `client_id` or Basic header).

Source: [User access token](https://docs.x.com/fundamentals/authentication/oauth-2-0/user-access-token), [Developer apps](https://docs.x.com/fundamentals/developer-apps).

### (e) What the owner registers

1. [console.x.com](https://console.x.com) (developer portal) -> create a Project and an App.
2. **Settings -> User authentication settings -> Set up**: enable **OAuth 2.0**, choose app type **Native App** (public) or **Web App** (confidential), set Read or Read-and-write, and enter the Callback URI(s) (fake `http://127.0.0.1:0/` desktop placeholder in dev, `https://demo.example.com/callback/x` in prod) plus a Website URL.
3. Copy the **OAuth 2.0 Client ID** (fake example `bnNoLXNhbmRib3gtbm90LXJlYWwwMDAwMDAwMDoxOmNp`, which decodes to `nsh-sandbox-not-real00000000:1:ci`) and, for confidential apps, the **Client Secret** — "Save credentials immediately — they're only shown once".

Source: [Developer apps](https://docs.x.com/fundamentals/developer-apps).

### (f) Brand / UX for the hand-built button

| Attribute | Rule |
| --- | --- |
| Label | X publishes no mandated button label; `Continue with X` is the conventional form |
| Color | Black `#000000` fill with the white X mark (or white fill with black mark) — X's brand kit constrains the logo to black/white treatments |
| Logo | The X logo may not be altered; "our >x< logo is our most valuable asset — that's why we protect it"; full rules live in the linked trademark/brand guidelines of the toolkit page |
| Rules | Use the mark only to indicate X sign-in; do not imply endorsement |

Source: [X brand toolkit](https://about.x.com/en/who-we-are/brand-toolkit). The toolkit page defers specifics to its downloadable guidelines; no numeric button minimums are published.

---

## Generic OIDC (template)

Used for "any generic OAuth 2.0 or OIDC provider". All URLs are read at runtime from discovery; nothing is hard-coded.

### (a) Endpoints (all discovered)

| Endpoint | Source key |
| --- | --- |
| Discovery | `https://{issuer-host}/.well-known/openid-configuration` (OIDC) or `/.well-known/oauth-authorization-server` (OAuth 2.0 AS, RFC 8414) |
| Authorization | `authorization_endpoint` |
| Token | `token_endpoint` |
| Userinfo | `userinfo_endpoint` (optional) |
| Revocation | `revocation_endpoint` (optional) |
| JWKS | `jwks_uri` |
| End session | `end_session_endpoint` (optional, OIDC session management) |

Sources: [OpenID Connect Discovery 1.0](https://openid.net/specs/openid-connect-discovery-1_0.html), [RFC 8414](https://datatracker.ietf.org/doc/html/rfc8414). Server behavior is read from the metadata: `code_challenge_methods_supported`, `token_endpoint_auth_methods_supported` (a `"none"` entry means public clients work), `id_token_signing_alg_values_supported`, `scopes_supported`, `authorization_response_iss_parameter_supported`.

### (b) Scopes (sign-in minimum)

`openid profile email`, plus `offline_access` when the provider grants refresh tokens only on request (the OIDC standard behavior). Confirm against `scopes_supported` from discovery.

### (c) Redirect rules per surface (template, RFC 8252)

| Surface | Rule |
| --- | --- |
| iOS / Android | Custom scheme in reverse-domain form (`com.example.app:/oauth2redirect`), declared to the host so the OS routes it back. Some providers require the scheme to contain a period. |
| Desktop | `http://127.0.0.1:{random free port}` loopback listener (RFC 8252 sec. 7.3); some providers ignore the port, most require exact registration. |
| Web | `https` redirect URI registered with the provider. |

What the console accepts is provider-specific — this template ships the mechanism, and the owner consults the provider's registration docs for the accepted forms.

### (d) Quirks (template)

- Do everything the metadata says: only send `code_challenge_method` values in `code_challenge_methods_supported`; use `client_secret_basic`/`client_secret_post`/`none` per `token_endpoint_auth_methods_supported`; verify `iss` on responses when `authorization_response_iss_parameter_supported` is true.
- Validate the ID token against `jwks_uri` with `id_token_signing_alg_values_supported`; check `iss` equals the discovery `issuer`, `aud` equals client_id, `exp`/`iat`, and `nonce` equals the sent nonce.
- A provider with no `userinfo_endpoint` and no `openid` scope is plain OAuth 2.0: identity claims must come from an `/me`-style REST call the owner configures.

### (e) What the owner registers

Whatever the provider's console calls it: create an OAuth client, register one redirect URI per surface (fake examples `https://demo.example.com/callback/oidc`, `com.nshauth.sandbox:/oauth2redirect`), obtain `client_id` (+ `client_secret` only for confidential deployments), and paste the issuer URL into nsh-auth config. nsh-auth fetches discovery at runtime.

### (f) Brand / UX

No brand rules exist for a generic provider. The demo renders a neutral secondary button labeled `Sign in with {provider name}` using the host app's own palette.

---

## Discrepancies to relay

1. **Discord `openid` scope is real but absent from the prose docs.** The scopes table in the OAuth2 docs has no `openid`, yet Discord serves an OIDC discovery document with `userinfo_endpoint` (`/api/oauth2/userinfo`), `jwks_uri` (`/api/oauth2/keys`), and RS256. The mock and core must support sign-in with `identify`+`email` only (documented path) and not depend on the ID token. Integrators should confirm `openid` behavior with a live client id.
2. **Discord PKCE is in the metadata, not the docs.** RFC 8414 metadata lists `code_challenge_methods_supported: ["S256"]` and token auth method `none`, but the OAuth2 page documents no `code_challenge` parameter. Sending PKCE is safe per metadata; a provider that starts rejecting it needs a code path without it.
3. **GitHub still requires `client_secret` on the code exchange even with PKCE S256** (only the device flow omits it). The brief's open question — "is a client secret still needed?" — is answered **yes**: the broker seam is mandatory for in-app GitHub sign-in. (Docs have moved since older writeups: GitHub now supports PKCE S256 and rotating refresh tokens, which older notes say it lacks.)
4. **Facebook has two competing manual-flow shapes**: the classic manual flow (client_secret required, server-to-server) and the OIDC code flow (client_secret optional when `code_verifier` is sent, `code_challenge` required, `plain` default). The OIDC discovery document declares only implicit response types and no token endpoint — the code exchange is documented on the Graph endpoint, not in discovery. Implementers must not derive Facebook's flow from discovery alone.
5. **Apple cannot loop back or custom-scheme the redirect.** Return URLs must be https domains, `response_mode=form_post` delivers tokens in a POST body, and Apple's docs put the burden of returning control to the app on your server. A pure `ASWebAuthenticationSession` flow against Apple needs a relay page; on iOS the sanctioned no-server path is `ASAuthorizationController`.
6. **Google loopback is desktop-only now.** Loopback redirects are blocked for iOS/Android/Chrome client types (fully blocked since 2022-10-21); mobile uses custom schemes (iOS) or the package/SHA-1-registered SDK path (Android). Any doc that tells mobile apps to listen on 127.0.0.1 for Google is stale.
7. **Google's button spec changed**: current branding is white/dark/neutral fills with the multicolor G; the legacy solid blue button is no longer the published spec. The demo must not ship the old blue.
8. **X has no OIDC artifacts at all** (no id_token, JWKS, or discovery). Anything modeling X as an OIDC provider is wrong; model it as OAuth 2.0 + REST profile.
9. **Microsoft has no token-revocation endpoint**; sign-out is local token destruction plus the OIDC end-session request. Any mock that exposes a Microsoft-style revocation endpoint is inventing one.
10. **Microsoft's portal rejects `http://127.0.0.1` in the redirect URI text box** (must go in via the manifest `replyUrlsWithType`), and `[::1]` is unsupported — worth calling out in setup docs since RFC 8252 recommends the IP literal.

---

## Machine-readable catalog

The same facts live in [`fixtures/provider-catalog.json`](../fixtures/provider-catalog.json) (`{ providers: { google: { endpoints, scopes, redirect: {ios, android, desktop, web}, quirks, registration, brand, sources } ... } }`). Tests, the mock server, and the demo read that file; this document remains the citation of record.
