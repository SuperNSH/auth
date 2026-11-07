# nsh-auth research

The study this build stands on: how each provider's sign-in works for a native
public client, how established libraries launch browsers and keep tokens, what
the standards require, and what NSH 0.4.0 actually gives us (measured, not
assumed). Everything ends in the design decisions in the last section.

Method: provider behavior is taken from the official doc pages fetched on
2026-11-07 (each claim carries the URL). Library behavior comes from clones
under `/Users/hmziq/fo/.refs/` (paths cited). NSH facts were run against the
installed `nsh` 0.4.0 (e626a8d), with logs under `docs/evidence/research/` and
the scratch app in `.zflow/scratch/research-app/`. No provider page was signed
in to and no credential was typed anywhere; client ids in this repo are fake.

---

## Part 1 — Providers

Summary matrix (details and citations below):

| Provider | PKCE | Client secret at token step | Redirect for a native app | id_token |
| --- | --- | --- | --- | --- |
| Google | S256 | optional | loopback (desktop) / reversed-client-id custom scheme (iOS) / SDK on Android | yes, RS256 |
| Facebook | **not supported** in the classic manual flow | **required** (server-to-server) | https URL in "Valid OAuth Redirect URIs"; `login_success.html` for a desktop webview; `ms-app:` for UWP | no (Limited Login has an OIDC token, iOS only) |
| Discord | S256 only (`none` auth allowed) | not needed with PKCE | https or custom scheme registered in the portal | optional (no OIDC by default) |
| GitHub | S256 only, strongly recommended | **required** — broker needed | callback URL: https; loopback allowed with any port | no |
| Apple | no PKCE; `state`+`nonce` | **required** — it is a JWT the developer signs | `response_mode=form_post` to a registered https return URL | yes, RS256, `code id_token` |
| Microsoft | S256 (plain accepted) | not needed for public clients | `http://localhost` port-ignored, custom scheme, `nativeclient` | yes |
| X | S256 or plain, required | not needed for public clients | callback URL, exact match | no |
| Generic OIDC | per discovery doc | per provider | per provider | per provider |

The practical rule the table forces: **anything with a required secret
(GitHub, Facebook, Apple) goes through the token broker; the rest work as
public clients.** Google is public-client capable but its Android path wants
the Credential Manager SDK.

### Google

- Flow (installed apps): system browser opens
  `https://accounts.google.com/o/oauth2/v2/auth` with `client_id`,
  `redirect_uri` (exact match or `redirect_uri_mismatch`), `response_type=code`,
  `scope`, `state`, and `code_challenge`/`code_challenge_method`. "Always use
  PKCE … when requesting authorization codes"; S256:
  `code_challenge = BASE64URL-ENCODE(SHA256(ASCII(code_verifier)))`, verifier
  43-128 chars of `[A-Z]/[a-z]/[0-9]/-./_~`. Token exchange is a POST to
  `https://oauth2.googleapis.com/token` (`client_id`, `client_secret`
  *optional*, `code`, `code_verifier`, `grant_type=authorization_code`,
  `redirect_uri`); "refresh tokens are always returned for installed
  applications". Revocation: `https://oauth2.googleapis.com/revoke`.
  [https://developers.google.com/identity/protocols/oauth2/native-app]
- Redirect formats registered in Cloud Console (Clients page): loopback
  `http://127.0.0.1:port` ("Loopback IP address … recommended" for macOS/Linux/
  Windows desktop clients; the port may be anything at request time) and custom
  scheme `com.example.app:/oauth2redirect` or the reversed client id
  `com.googleusercontent.apps.<id>:/oauth2redirect` (scheme "must contain a
  period", path begins with a single slash) — but "Custom URI schemes are no
  longer supported on Android and Chrome apps", and the loopback type is
  deprecated for Android/iOS/Chrome client types. The out-of-band (OOB)
  copy/paste flow "has been deprecated and is no longer supported".
  [same page]
- Embedded web views are blocked: `disallowed_useragent` — "The authorization
  endpoint is displayed inside an embedded user-agent disallowed by Google's
  OAuth 2.0 Policies. iOS and macOS developers may encounter this error when
  opening authorization requests in WKWebView." SFSafariViewController and the
  system browser are the supported user agents. [same page]
- OIDC scopes and id_token: `scope` "must begin with the `openid` value and
  then include the `profile` value, the `email` value, or both". `email` adds
  `email`/`email_verified` claims; `profile` claims are "not guaranteed" in the
  token (fetch `https://openidconnect.googleapis.com/v1/userinfo` with the
  access token instead). id_token is a JWT, RS256 only (per discovery
  `id_token_signing_alg_values_supported`); validate `iss`
  (`https://accounts.google.com` or `accounts.google.com`), `aud`, `exp`,
  `nonce`; use `sub` as the user key — "Don't use the `email` field as a unique
  identifier for a user". `nonce` is required ("replay protection"), `state`
  "Optional, but strongly recommended" (~30 random chars). JWKS:
  `https://www.googleapis.com/oauth2/v3/certs`. Discovery:
  `https://accounts.google.com/.well-known/openid-configuration`.
  [https://developers.google.com/identity/openid-connect/openid-connect]
- Per surface: iOS/macOS/desktop register a Desktop-app or iOS client and use
  loopback (desktop) or the reversed-client-id scheme (iOS) via
  ASWebAuthenticationSession/AppAuth; Android uses the Google ID SDK
  (Credential Manager) — the native-app page defers Android to its Android
  authorization guides and says custom schemes are no longer supported there,
  while Google's OIDC page notes "Android apps should use the Credential
  Manager API", corroborated by google_sign_in (Part 2); web uses Google
  Identity Services. [native-app page and
  https://developers.google.com/identity/openid-connect/openid-connect]

### Facebook

- Classic manual flow ("Manually Build a Login Flow"): system or embedded
  browser opens `https://www.facebook.com/v{version}/dialog/oauth` with
  `client_id`, `redirect_uri`, `state` ("passed back to you, unchanged"),
  optional `response_type=code` (default). **No PKCE anywhere on the page**:
  the current doc has zero occurrences of `code_challenge`, `code_verifier` or
  "PKCE" (verified by grepping the fetched page HTML). Token exchange is
  `GET https://graph.facebook.com/v{version}/oauth/access_token` with
  `client_id`, `redirect_uri`, `code` and **`client_secret`** — "The call will
  need to be server-to-server, since it involves your app secret"; "Never
  include this app secret in client-side code". Permissions are a
  comma/space-separated `scope`; `public_profile` is always granted; declined
  scopes via `auth_type=rerequest` and `/me/permissions`. Denial returns
  `error_reason=user_denied&error=access_denied`.
  [https://developers.facebook.com/docs/facebook-login/guides/advanced/manual-flow/]
- Redirects: the owner registers **Valid OAuth redirect URIs** under
  Facebook Login → Settings (Client OAuth Settings), https enforced. For the
  documented desktop flow inside an app's webview the redirect must be
  `https://www.facebook.com/connect/login_success.html`; Windows UWP may use
  `ms-app://{package-security-identifier}`. No general custom-scheme support is
  documented. [same page]
- Limited Login (iOS/Unity only) is the OIDC-shaped flow: it "returns an
  `AuthenticationToken` that wraps an OpenID Connect token", takes a `nonce`,
  does not call Graph API and now lives under `limited.facebook.com`.
  [https://developers.facebook.com/docs/facebook-login/limited-login]
- Consequence for us: because the token step demands the app secret, **a
  browser-only Facebook flow requires the broker**; the alternative per surface
  is the native SDK adapter (Facebook Login SDK) on mobile, which owns the flow
  itself. The brief's assumption "manual flow with PKCE" did not survive the
  docs — see Design decisions.
- Per surface: iOS/Android = SDK adapter (or broker + https redirect); desktop
  = system browser to an https redirect through the broker (the doc's
  `login_success.html` path is a webview flow we reject — same credential
  exposure RFC 8252 warns about); web = JS SDK or manual flow with an https
  redirect through the broker.

### Discord

- Authorize `https://discord.com/oauth2/authorize` (canonical API path
  `https://discord.com/api/oauth2/authorize`) with `response_type=code`,
  `client_id`, `scope` (space-separated), `redirect_uri` ("whatever URL you
  registered when creating your application, url-encoded"), `state`, `prompt`
  (`consent` re-asks; `none` skips the screen), and `integration_type` for bot
  installs. Responses carry `code`, `state`, and `iss` (`https://discord.com`,
  RFC 9207). [https://docs.discord.com/developers/topics/oauth2]
- PKCE and client auth: the portal's docs recommend "the authorization code
  grant with PKCE" but don't enumerate parameters; the live metadata settles
  it. Measured from `https://discord.com/.well-known/openid-configuration` and
  `https://discord.com/.well-known/oauth-authorization-server` (both fetched):
  `code_challenge_methods_supported: ["S256"]`,
  `token_endpoint_auth_methods_supported: ["client_secret_basic",
  "client_secret_post", "none"]`, `revocation_endpoint` present, `iss` support
  flagged. So a public client works with S256 and no secret.
- Token endpoint `https://discord.com/api/oauth2/token` "will **only** accept a
  content type of `application/x-www-form-urlencoded`" (JSON errors out);
  response has `access_token`, `token_type: Bearer`, `expires_in` (~604800),
  `refresh_token`, `scope`. Revocation `https://discord.com/api/oauth2/token/revoke`
  with `token` + optional `token_type_hint` — and "revoking … any active access
  or refresh tokens associated with that authorization will be revoked,
  regardless of the `token` and `token_type_hint` values". Scopes: `identify`
  allows `GET /users/@me` without email; `email` "enables `/users/@me` to
  return an `email`"; user object also via `GET /oauth2/@me` (returns
  application, scopes, expires, user).
  [https://docs.discord.com/developers/topics/oauth2]
- Redirect formats: the docs don't enumerate allowed schemes beyond "registered
  … url-encoded"; the portal accepts https and custom schemes in practice, but
  our plan should not depend on an undocumented custom-scheme path — prefer the
  loopback listener on desktop and an https redirect on web, custom scheme only
  on mobile where the portal demonstrably accepts it.
- Per surface: iOS/Android = custom scheme redirect (registered in portal) via
  ASWebAuthenticationSession/Custom Tabs; desktop = loopback listener;
  web = https redirect or popup; public client, no broker.

### GitHub

- Web application flow: `GET https://github.com/login/oauth/authorize` with
  `client_id`, `redirect_uri` ("Strongly recommended"), `scope` (space
  delimited), `state` ("An unguessable random string"), `allow_signup`,
  optional `prompt=select_account`. PKCE **is supported now**:
  `code_challenge` "Must be a 43 character SHA-256 hash of a random string",
  `code_challenge_method` "Must be `S256` — the `plain` code challenge method
  is not supported", `code_verifier` at the token step "Required if a
  `code_challenge` was sent".
  [https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/authorizing-oauth-apps]
- Token step `POST https://github.com/login/oauth/access_token`: `client_id`,
  **`client_secret` (required)**, `code`, `redirect_uri`, `code_verifier`;
  send `Accept: application/json` to get JSON `{ access_token, scope,
  token_type: bearer }`; with `offline_access` the response adds an expiring
  token (8 h) plus `refresh_token` and `refresh_token_expires_in` — "The access
  token expires after eight hours, and the refresh token expires after six
  months without use." Refresh via
  `grant_type=refresh_token`; a bad refresh is `bad_refresh_token`. Because the
  secret is required even with PKCE, **GitHub always needs the broker** from an
  app. [same page]
- Callback registration: multiple callback URLs are allowed; wildcard matching
  can be enabled per URL (host and port exact, path must be a subdirectory;
  "Enabling wildcard matching can expose your app to security risks"). Loopback
  is supported for desktop: with callback `http://127.0.0.1/path`, a redirect
  to `http://127.0.0.1:1234/path` works — "The `redirect_uri` does not need to
  match the port specified in the callback URL"; the docs quote RFC 8252's
  advice to use `127.0.0.1`/`::1` rather than `localhost`. Non-HTTP schemes are
  acknowledged to exist ("if the application has a non-HTTP redirect URI") but
  are not documented — desktop should use loopback. Revocation is per-user at
  `https://github.com/settings/connections/applications/:client_id`; the API
  route an app uses is `DELETE /applications/{client_id}/token` with the app
  credentials (broker's job). [same page]
- Scopes: `read:user` and `user:email` cover identity; the page defers the list
  to the scopes document.
- Per surface: iOS/Android = custom scheme or app-link callback to the broker
  exchange; desktop = loopback listener, exchange through the broker; web =
  redirect to an https callback through the broker.

### Apple

- Non-iOS surfaces use the web endpoints. Measured live from
  `https://appleid.apple.com/.well-known/openid-configuration` (fetched):
  `authorization_endpoint: https://appleid.apple.com/auth/authorize`,
  `token_endpoint: https://appleid.apple.com/auth/token`,
  `revocation_endpoint: https://appleid.apple.com/auth/revoke`,
  `jwks_uri: https://appleid.apple.com/auth/keys`,
  `response_modes_supported: ["query","fragment","form_post"]`,
  `id_token_signing_alg_values_supported: ["RS256"]`,
  `scopes_supported: ["openid","email","name"]`,
  `token_endpoint_auth_methods_supported: ["client_secret_post"]`, claims
  include `email`, `email_verified`, `is_private_email`, `real_user_status`,
  `nonce`, `transfer_sub`, subject type `pairwise`.
- The web flow Apple documents uses `response_mode=form_post` and
  `response_type=code id_token`: the authorization response arrives as an HTTP
  **POST** to the registered return URL, not a query redirect — a loopback
  listener can receive it on desktop, but the web surface needs a real https
  endpoint (the broker). The `client_secret` at the token endpoint is not a
  shared string but a JWT the developer signs with the Sign in with Apple
  private key (Key ID, Team ID, `client_id` as issuer/subject, ES256) —
  Apple's REST API pages document this but are JS-rendered and could not be
  fetched by our tools; the requirement that *some* client secret be posted is
  proven by the discovery document above, and the JWT-secret shape is what
  implementations build (see better-auth's provider in Part 2, which takes the
  secret as configured server-side and validates `iss: https://appleid.apple.com`,
  RS256 against Apple's JWKS). Marked honestly: JWT-secret format is
  documented-by-Apple, corroborated by implementations, not quoted from Apple's
  page here.
- Button: the HIG requires the **system-provided button** ("When you use the
  system-provided APIs to create a Sign in with Apple button, you get … a
  button that's guaranteed to use an Apple-approved appearance … Automatic
  translation … Support for configuring the button's corner radius … a
  system-provided alternative text label that lets VoiceOver describe the
  button"), displayed "no smaller than other sign-in buttons", with white /
  white-outline / black styles; people may share a private relay address
  ("people can choose to share a private relay address that automatically
  forwards messages"), so `is_private_email` handling is required.
  [https://developer.apple.com/design/human-interface-guidelines/sign-in-with-apple]
- Registration: an App ID with the Sign in with Apple capability, a Services ID
  with return URLs for web/non-native surfaces, and a Sign in with Apple key
  (Key ID) under the Team ID. (Apple's help pages were unreachable to our
  fetchers; the endpoint/audience shape is corroborated by the discovery
  document and better-auth's provider configuration — `audience` defaults to
  the app bundle identifier or the Services ID.)
- Native Apple surfaces (iOS, macOS) should not use the web flow at all:
  `ASAuthorizationController` with the system button gives the id_token
  directly (and is what "the system button requires" — the native API, not a
  browser round trip).
- Per surface: iOS/macOS = native button via the SDK adapter; desktop (non-Apple
  UI) = browser + form_post to loopback via broker (Apple signs nothing client
  side; the broker holds the p8); web = form_post to an https return URL on the
  broker.

### Microsoft

- MSAL/public-client pattern: authorization code + PKCE against
  `https://login.microsoftonline.com/{tenant}/oauth2/v2.0/authorize`; tenant
  is `common`, `organizations`, `consumers`, or a tenant id. PKCE: `S256`
  "SHOULD", `plain` also supported ("The Microsoft identity platform supports
  both `plain` and `S256`"); "Public clients, which include native applications
  and single page apps, must not use secrets or certificates when redeeming an
  authorization code." OIDC needs `openid profile` (+ `email`); refresh tokens
  require `offline_access` ("Only provided if `offline_access` scope was
  requested"). `response_mode`: `query` (default), `fragment`, `form_post` —
  "We recommend apps use `form_post`, especially when using `http://localhost`
  as a redirect URI." Nonce is required for id_token flows (hybrid flow table).
  Token endpoint `…/v2.0/token`; refresh via `grant_type=refresh_token`.
  [https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-auth-code-flow]
- Redirect URIs for desktop/mobile: register under the "Mobile and desktop
  applications" platform. Rules: "Redirect URIs must begin with the scheme
  `https`, with exceptions for some localhost redirect URIs"; `http` "is
  supported *only* for *localhost* URIs"; localhost ports are ignored when
  matching ("all of these URIs are considered equivalent: `http://localhost/MyApp`,
  `http://localhost:1234/MyApp`, …"), so don't register multiple localhost URIs
  differing only by port; `[::1]` "isn't currently supported"; "Prefer
  127.0.0.1 over localhost" (firewalls/renamed interfaces), though adding an
  `http://127.0.0.1` URI currently requires editing the manifest's
  `replyUrlsWithType` because the portal rejects it. MSAL's defaults for native
  clients: `https://login.microsoftonline.com/common/oauth2/nativeclient`
  (embedded browser) or `http://localhost` (system browser). The "Mobile and
  desktop applications" platform also accepts "one or more Custom redirect
  URIs", and the iOS/macOS and Android platform tiles generate a redirect URI
  from the Bundle ID / package name + signature hash.
  [https://learn.microsoft.com/en-us/entra/identity-platform/how-to-add-redirect-uri]
  Wildcard URIs are unsupported for multi-tenant/personal audiences.
  [https://learn.microsoft.com/en-us/entra/identity-platform/reply-url]
- Per surface: iOS/Android = custom scheme (registered, "Mobile and desktop"
  platform) via ASWebAuthenticationSession/Custom Tabs; desktop = loopback
  `http://localhost` (port ignored) — host the listener in Rust; web = `spa`
  redirect type (CORS-enforced) with PKCE required. No broker needed; consumer
  + work accounts via `common`.

### X (Twitter)

- OAuth 2.0 user context = "Authorization Code Flow with PKCE". Authorize
  `https://x.com/i/oauth2/authorize` with `response_type=code`, `client_id`,
  `redirect_uri`, `state` (≤500 chars), `code_challenge`,
  `code_challenge_method` ("S256 OR plain"), scope space-separated.
  [https://docs.x.com/fundamentals/authentication/oauth-2-0/authorization-code]
- Client types: "Native App and Single page App are public clients … Public
  clients are unable to use your client secrets" and "include Client Id in the
  body" at the token endpoint. Token `https://api.x.com/2/oauth2/token`; refresh
  tokens only with `offline.access` ("If this scope is not passed, we will not
  generate a refresh token"); access tokens live "two hours unless you've used
  the `offline.access` scope"; the authorization code expires in **30 seconds**
  — exchange immediately. Callbacks must match a registered Callback URL with
  "exact match validation" (RFC 6749 §10.6); the portal takes the callback
  URLs (https for web; the developer portal also accepts custom schemes for
  native apps, though format details are portal-side, not in this page).
  Revoke: `POST https://api.x.com/2/oauth2/revoke` (OAuth API reference index).
  Identity: `users.read` (+ `tweet.read` typically), `users.email` for email;
  user info via `GET /2/users/me` with the user token.
  [authorization-code page + https://docs.x.com/fundamentals/authentication/api-reference]
- Per surface: public client everywhere, no broker. iOS/Android = custom scheme
  callback; desktop = loopback listener; web = exact-match https callback.

### Generic OIDC provider

- Discovery: "OpenID Providers supporting Discovery MUST make a JSON document
  available at the path formed by concatenating the string
  `/.well-known/openid-configuration` to the Issuer"; required metadata:
  `issuer` (must equal the discovery prefix and the id_token `iss`),
  `authorization_endpoint`, `token_endpoint`, `jwks_uri`,
  `subject_types_supported`, `response_types_supported`,
  `id_token_signing_alg_values_supported` (must include RS256); recommended:
  `userinfo_endpoint`, `scopes_supported`, `claims_supported`.
  [https://openid.net/specs/openid-connect-discovery-1_0.html]
- Flow: authorization code + PKCE (RFC 7636) with `nonce` in the request;
  validate the id_token's `iss`, `aud`, `exp`, `nonce`, and signature against
  `jwks_uri`; use `sub` as the user key (OIDC Core). Both Discord and Google
  publish discovery documents, and we measured both live — the generic client
  should drive everything off discovery when the provider has it, with
  hardcoded endpoints as fallback for providers without it.

---

## Part 2 — How others do it

Clones (read-only) under `/Users/hmziq/fo/.refs/`: `react-native-app-auth`,
`expo-auth-session` (sparse checkout of the expo monorepo), `flutter_appauth`,
`AppAuth-iOS`, `AppAuth-Android`, `better-auth`, `google_sign_in` (sparse
checkout of flutter/packages). File paths below are inside those clones.

**AppAuth-iOS** (`openid/AppAuth-iOS`)
- Launches `ASWebAuthenticationSession` — `Sources/AppAuth/iOS/OIDExternalUserAgentIOS.m`
  builds the session from the request with either a custom-scheme callback or
  an HTTPS callback (`HTTPSCallbackForRequest` → `ASWebAuthenticationSessionCallback`
  with host+path), presented through `ASWebAuthenticationPresentationContextProviding`.
- macOS mirror in `Sources/AppAuth/macOS/OIDExternalUserAgentMac.m`:
  `initWithURL:callbackURLScheme:` and `prefersEphemeralWebBrowserSession`
  (the ephemeral toggle we should expose as the same option).
- Tokens: `Sources/AppAuthCore/OIDAuthState` holds access/refresh tokens and
  performs authorized refresh through a delegate; the library itself does not
  persist — samples store the serialized state (the Android sample uses
  SharedPreferences; iOS samples use the Keychain), leaving the vault choice
  to the app. Secrets: none — public clients pass `clientSecret: nil`.

**AppAuth-Android** (`openid/AppAuth-Android`)
- Launches Chrome Custom Tabs: `library/java/net/openid/appauth/AuthorizationService.java`
  builds a `CustomTabsIntent` (`createCustomTabsIntentBuilder`) and hands the
  result back via a `PendingIntent` into `AuthorizationManagementActivity`, so
  the redirect returns to the app without a browser-history entry.
- The redirect itself is an app-claimed intent filter: the demo manifest
  registers `https://appauth.demo-app.io/oauth2redirect` (App Link) with
  BROWSABLE/DEFAULT categories — the pattern for our Android host.
- Public clients: `library/java/net/openid/appauth/NoClientAuthentication.java`
  (`NAME = "none"`) is the client-auth for PKCE public clients.
- Storage: the demo's `app/java/net/openid/appauthdemo/AuthStateManager.java`
  keeps the serialized `AuthState` in plain `SharedPreferences` — explicitly a
  demo shortcut; production code must go to the Keystore-backed vault.

**react-native-app-auth** (`FormidableLabs/react-native-app-auth`)
- JS wrapper over AppAuth on both platforms.
  `packages/react-native-app-auth/ios/RNAppAuth.m` builds an
  `OIDAuthorizationRequest` with `codeChallengeMethod:
  OIDOAuthorizationRequestCodeChallengeMethodS256`, a generated `state` and
  `nonce`, and requires the app's AppDelegate to conform to
  `RNAppAuthAuthorizationFlowManager` — i.e. the **host app carries the flow's
  resume**, which is exactly the shape NSH's embedding host forces on us.
- `packages/react-native-app-auth/android/src/main/java/com/rnappauth/RNAppAuthModule.java`
  drives AppAuth-Android's `AuthorizationService` + `CustomTabsIntent`
  (`setEphemeralBrowsingEnabled` surfaced as an option).
- Secrets: an optional `clientSecret` is passed through from JS — the docs warn
  against it; our broker seam replaces this path.
- Storage: none built in; `docs/docs/token-storage.md` tells apps to use
  react-native-keychain or expo-secure-store ("secure for iOS by using keychain
  services, secure for Android by using values in SharedPreferences encrypted
  with Android's Keystore system").

**expo-auth-session** (expo monorepo, `packages/expo-auth-session`)
- Pure-TS OAuth layer: `src/PKCE.ts` generates the verifier (charset-checked,
  43–128 chars) and derives the challenge with SHA-256 + URL-safe base64;
  `src/AuthRequest.ts` builds the URL, `src/TokenRequest.ts` exchanges the code.
- Browser: `promptAsync` (src/AuthRequestHooks.ts) goes through
  `expo-web-browser`'s `openAuthSessionAsync` — `packages/expo-web-browser/ios/WebAuthSession.swift`
  wraps `ASWebAuthenticationSession`; Android uses Custom Tabs; web uses a
  popup with `WebBrowser.maybeCompleteAuthSession()` to close it.
- Redirect: `src/SessionUrlProvider.ts` builds it from `Linking.createURL`
  (the app's registered scheme from app config), then the OS delivers it to the
  app and expo-linking surfaces it — the "system hands it to the app" path.
- Storage: the library returns tokens to JS and stores nothing; apps are
  pointed at expo-secure-store. Secrets: none expected client-side.

**flutter_appauth** (`MaikuB/flutter_appauth`)
- Dart API (`flutter_appauth/lib/src/flutter_appauth.dart`:
  `authorizeAndExchangeCode`, `token`, `endSession`) over platform channels to
  AppAuth on each platform: the iOS pod pins `AppAuth` 3.0.0
  (`ios/flutter_appauth.podspec`), Android pins `net.openid:appauth:0.11.1`
  (`android/build.gradle.kts`) and re-uses AppAuth's `RedirectUriReceiverActivity`
  (`android/src/main/AndroidManifest.xml`) — the app declares the redirect
  intent filter in its own manifest.
- Custom user agents: `ios/.../Sources/flutter_appauth/OIDExternalUserAgentIOSNoSSO.m`
  runs an **ephemeral** ASWebAuthenticationSession (no shared cookies); a
  SafariViewController variant exists too.
- Storage: nothing persisted by the plugin; secrets never embedded.

**better-auth** (`better-auth/better-auth`)
- Server-side framework client: providers live in
  `packages/core/src/social-providers/` (google.ts, github.ts, discord.ts,
  facebook.ts, apple.ts, microsoft-entra-id.ts, twitter.ts …), each declaring
  hardcoded endpoints + default scopes; `packages/better-auth/src/oauth2/state.ts`
  mints and verifies `state` server-side with the round-trip data.
- Secrets live server-side by construction (the server holds `clientSecret` and
  does the token exchange); `packages/better-auth/src/plugins/oauth-proxy`
  exists specifically to keep even SPA flows off the client.
- Apple (`apple.ts`): `authorizationEndpoint: "https://appleid.apple.com/auth/authorize"`,
  `responseMode: "form_post"`, `responseType: "code id_token"`, id_token
  validated with `issuer: "https://appleid.apple.com"`, `algorithms: ["RS256"]`,
  JWKS lookup by `kid`, audience defaulting to the bundle id, `nonceComparison:
  "exact-or-sha256"`, and the JWT client secret required in options.
- Its flow model (browser or popup on web, state in a server store, code
  verified against a server-held verifier) is the reference shape for our
  broker, not for the on-device core.

**google_sign_in** (flutter/packages, sparse checkout rooted at the clone root)
- Android (`packages/google_sign_in/google_sign_in_android/android/src/main/kotlin/io/flutter/plugins/googlesignin/GoogleSignInPlugin.kt`)
  is rewritten on **Credential Manager** (`androidx.credentials.CredentialManager`,
  `GetGoogleIdOption`, `GoogleIdTokenCredential`) and requires a
  `serverClientId` — the web client id — confirming Google's Android direction:
  the SDK, not a browser redirect.
- iOS/macOS (`packages/google_sign_in/google_sign_in_ios/darwin/google_sign_in_ios/Sources/google_sign_in_ios/GoogleSignInPlugin.swift`) wraps
  GoogleSignIn's `GIDSignIn`; token persistence is the SDK's job and errors are
  surfaced as `GIDSignInError.hasNoAuthInKeychain` → `.noAuthInKeychain` — i.e.
  **the official SDK stores auth state in the Keychain**.
- Web (`packages/google_sign_in/google_sign_in_web`) uses Google Identity
  Services (GIS). The platform interface
  (`packages/google_sign_in/google_sign_in_platform_interface/lib/google_sign_in_platform_interface.dart`)
  splits client vs server authorization tokens for scopes — the same seam our
  broker will expose.

---

## Part 3 — Standards

**RFC 8252 (OAuth 2.0 for Native Apps).**
- Loopback: "Native apps that are able to open a port on the loopback network
  interface without needing special permissions (typically, those on desktop
  operating systems) can use the loopback interface to receive the OAuth
  redirect"; URIs are `http://127.0.0.1:{port}/{path}` / `http://[::1]:{port}/{path}`
  with any port, and "The authorization server MUST allow any port … for
  loopback IP redirect URIs"; bind both IPv4 and IPv6 when available.
  [https://www.rfc-editor.org/rfc/rfc8252.txt §7.3]
- Custom schemes work but claimed https redirects are safer: "multiple apps can
  typically register the same scheme, which makes it indeterminate as to which
  app will receive the authorization code" — the code-interception motivation
  for PKCE; loopback can be intercepted by other local apps; app-claimed
  https is "less susceptible".
- PKCE is mandatory: "Public native app clients MUST implement the Proof Key
  for Code Exchange (PKCE [RFC7636]) … and authorization servers MUST support
  PKCE for such clients"; servers "SHOULD reject authorization requests from
  native apps that don't use PKCE".
- Embedded webviews: "it was common for native apps to use embedded
  user-agents … That approach has many drawbacks, including the host app being
  able to copy user credentials and cookies as well as the user needing to
  authenticate from scratch in each app" (§6, detail in §8.12); external
  user-agents get SSO from the browser's session.

**RFC 7636 (PKCE).**
- Verifier: "high-entropy cryptographic random STRING using the unreserved
  characters [A-Z] / [a-z] / [0-9] / "-" / "." / "_" / "~" …, with a minimum
  length of 43 characters and a maximum length of 128"; recommended: 32 random
  octets, base64url-encoded (256 bits of entropy, §7.1).
- Challenge: `plain` is `code_challenge = code_verifier`; `S256` is
  `BASE64URL-ENCODE(SHA256(ASCII(code_verifier)))`, and "If the client is
  capable of using "S256", it MUST use "S256", as "S256" is Mandatory To
  Implement (MTI) on the server"; "Clients MUST NOT downgrade to "plain" after
  trying the "S256" method" (§7.2). We will always send S256.
  [https://www.rfc-editor.org/rfc/rfc7636.txt]

**Token storage per platform (current best practice).**
- iOS/macOS: Keychain — "The keychain services API helps you solve this problem
  by giving your app a mechanism to store small bits of user data in an
  encrypted database called a keychain."
  [https://developer.apple.com/documentation/security/keychain-services]
- Android: **direct Android Keystore**. The androidx `security-crypto` library
  (EncryptedSharedPreferences/EncryptedFile) is deprecated: 1.1.0-beta01
  (2025-06-04) and alpha07 (2025-04-09) both say "Deprecated all APIs in favour
  of existing platform APIs and direct use of Android Keystore."
  [https://developer.android.com/jetpack/androidx/releases/security]
  So new code must not build on EncryptedSharedPreferences; encrypt token
  blobs with a Keystore key and store the ciphertext in app-private storage.
- Windows: DPAPI — `CryptProtectData` "Typically, only a user with the same
  logon credential as the user who encrypted the data can decrypt the data";
  per-user scope unless `CRYPTPROTECT_LOCAL_MACHINE`; optional entropy blob.
  [https://learn.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptprotectdata]
- Linux: Secret Service API (`org.freedesktop.secrets`), the D-Bus secret store
  implemented by gnome-keyring and KWallet; secrets live in collections/items,
  with a default collection alias; sessions encrypt secrets in transit.
  [https://specifications.freedesktop.org/secret-service/latest/]
- Web: never localStorage — OWASP: "Do not store session identifiers in local
  storage as the data is always accessible by JavaScript"; a single XSS "can be
  used to steal all the data in these objects".
  [https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html]
  Tokens belong server-side (HttpOnly cookie) or nowhere persistent.

---

## Part 4 — NSH 0.4.0 experiments

All five ran for real against `nsh` 0.4.0 (e626a8d). Logs:
`docs/evidence/research/exp1-openurl.log` … `exp5-webview.log`.
Scratch app: `.zflow/scratch/research-app/` (gitignored `.zflow/` area).
Scratch Rust probe: `.zflow/scratch/loopback/loopback.rs`.

**1. `openUrl` — verified.**
A TSX app declaring `"capabilities": { "openUrl": { "schemes": ["https"] } }`
calls `openUrl("https://example.com/")` from a button; the headless test
asserts `app.openedUrls()` equals `["https://example.com/"]`.
`nsh check` clean, `nsh build` clean, `nsh test`: 1 passed (222 ms). Nothing
opened; the URL was recorded. Exact generated types (`.nsh/types/nsh/index.d.ts`):

```ts
export interface OpenUrlResult { opened: boolean; }
export declare function openUrl(url: string): Promise<OpenUrlResult>;
```

`.nsh/types/nsh/test.d.ts`: `openedUrls(): (string)[];` — "recorded, never
opened, and reported opened to the app". Capability shape confirmed in the
installed crate (`nsh-core-0.4.0/src/access.rs`): `true` grants every scheme,
`{ "schemes": [...] }` a list. This is our headless trigger proof for every
provider: assert the full authorize URL from `openedUrls()`.

**2. Inbound URLs — none in 0.4.0; the embedding host must forward.**
Searched `~/fo/.refs/nsh-v0.4.0` and `~/fo/.refs/nsh-main` (log has the exact
queries). 0.4.0: no `Linking` module, no url-scheme `EventKind`, no `schemes`
key in `nsh.json`/`nsh package`. Main (unreleased) has the whole system:
`crates/nsh-core/src/url_scheme.rs` (root `EventKind::UrlScheme`, pending
buffer of 16, reserved schemes) and `crates/nsh-platform-windows/src/linking.rs`
(registry + named mutex + `WM_COPYDATA`), and `nsh package` writes iOS
`CFBundleURLTypes` from `nsh.json` `"schemes"`. Conclusion for 0.4.0: an
embedding host receives the redirect (AppDelegate/scene `openURL` on iOS,
`Activity.onNewIntent` on Android, its own scheme handling on desktop) and
sends it over the host channel — `app.send("auth.callback", {...})` on the
`NshAppView`/`NshView` handle, heard with `host.on("auth.callback", ...)`
(0.4.0 `.nsh/types`: `HostEvents.on`, `Host.on`, `Host.params`, `Host.call`;
host events sent before a listener are kept, up to 256). The `examples/embed-ios`
sample shows exactly this direction (`app.send` / `app.handle`).

**3. Loopback listener — Rust yes, TSX no.**
Rust: `std::net::TcpListener::bind("127.0.0.1:0")` works on macOS (no crates);
the probe served a GET with `code`/`state` and answered 200 (`exp3` log has
the transcript). `[::1]` also binds. One implementation lesson from the first
attempt: read to end-of-headers, not EOF — a browser keeps the socket open and
`read_to_string` blocks forever. Also `localhost` resolves to `[::1]` first on
this Mac, which is exactly why RFC 8252/Google/Microsoft say to use the
literal `127.0.0.1`. TSX: `.nsh/types/net.d.ts` exports only `connect(options)`
and `class Socket` (read/write/close, ≤32 sockets, `capabilities.network.sockets`
gated) — no `listen`, `bind` or `Server` anywhere in `.nsh/types`. So the
desktop loopback redirect must live in Rust code or the host, never in TSX.

**4. `Storage` is a plain store.**
Generated types: `StorageModule` is `getItem/setItem/removeItem/keys/clear`,
strings only, 5 MB quota, "kept on the device across launches" — no
encryption, no access control. Source: `nsh-core-0.4.0/src/storage.rs`
(in-memory entries over a `StorageBackend` trait) and `nsh-engine`'s
`FileStorage`: one JSON object at `<data_dir>/<app-id>/storage.json`, rewritten
atomically. `data_dir()` (nsh-engine/src/storage.rs): `~/Library/Application
Support` (macOS/iOS), `%APPDATA%` (Windows), `$XDG_DATA_HOME` else
`~/.local/share` (Linux); Android is platform-provided; **web backend is the
browser's `localStorage`** (`nsh-platform-web/src/storage.rs`), which OWASP
forbids for tokens. Conclusion: tokens never touch `Storage`; the session
store's secure half needs the platform vaults from Part 3, reached from the
Rust crate's native code or the embedding host. This is also the concrete
basis for the storage proof test: grep `storage.json` and logs, not vibes.

**5. Web view ban — confirmed from Google.**
Google's installed-apps page rejects embedded user agents outright
(`disallowed_useragent`, naming WKWebView on iOS/macOS; SFSafariViewController
and the system browser are the supported agents) and RFC 8252 gives the
credential reason ("the host app being able to copy user credentials and
cookies"). Log `exp5-webview.log` carries the exact quotes. nsh's `webview`
capability must therefore never be granted for provider authorization pages;
launchers use the system surfaces only.

---

## Part 5 — Design decisions

Places the evidence confirmed or changed the brief's "The shape it will likely
take", with the reason:

1. **Core in both languages, signals for session/user/status — confirmed.**
   Every provider above fits the same public-client shape (authorize URL →
   redirect → token/refresh → id_token/userinfo), and AppAuth's `AuthState`
   shows the session-object pattern (Part 2). Nothing in the evidence favors a
   different core shape.
2. **Token broker seam — confirmed, and widened.** The brief named GitHub; the
   docs add **Facebook** (secret required at token step; no PKCE to protect the
   code instead) and **Apple** (`client_secret_post` only, secret is a signed
   JWT) to the broker list. X, Discord, Microsoft and generic OIDC stay
   public-client. Google is public-client on desktop/iOS via loopback/custom
   scheme but Android's supported path is Credential Manager — the SDK adapter
   covers it.
3. **Facebook "manual flow with PKCE" — changed.** The current manual-flow
   doc has no PKCE at all (measured: zero matches on the page). Facebook in a
   browser flow is therefore always broker-exchanged (secret on the server),
   or goes through the native SDK adapter on mobile. Documented in providers.md
   as "secret required, PKCE not supported".
4. **Launchers per surface — confirmed in shape, pinned in detail.**
   ASWebAuthenticationSession on iOS and macOS (exclusive callback per calling
   app; ephemeral option exists — AppAuth-iOS exposes
   `prefersEphemeralWebBrowserSession`), Custom Tabs + PendingIntent on Android
   (AppAuth-Android's mechanism; app-claimed https App Link preferred over
   custom scheme), system browser + Rust loopback listener on desktop
   (experiment 3), redirect or popup on web. `ASWebAuthenticationSession`
   handles the iOS/macOS case for both TSX-packaged and embedded apps; a TSX
   app with no host and no Rust gets no inbound redirect — its fallback is the
   broker's redirect to a web origin, stated honestly in docs.
5. **Inbound redirects on 0.4.0 go through `host.on` — new decision.** There is
   no Linking module and no `schemes` manifest key on 0.4.0 (experiment 2), so
   `examples/host-ios` and `examples/host-android` forward the redirect with
   `app.send("auth.callback", …)` and the core hears it with `host.on`. When
   NSH ships main's `UrlScheme` event, the core can switch behind the same
   internal interface.
6. **Desktop loopback in Rust, never TSX — confirmed.** TSX `net` is
   dial-out-only (experiment 3); the listener plus a random port is Rust-side,
   which also matches RFC 8252's loopback section and Microsoft's
   "prefer 127.0.0.1" guidance.
7. **No provider page in a webview — confirmed.** Google rejects it
   (`disallowed_useragent`), RFC 8252 gives the credential-exposure reason, and
   Facebook's `login_success.html` webview path is legacy. The `webview`
   capability is not granted for provider flows at all; the audit checks it.
8. **Secure storage behind a trait — confirmed, with the Android detail
   changed.** `Storage` is plain (experiment 4). The session store keeps
   non-secret fields in `Storage` and secrets in the platform vault; the vault
   trait has iOS/macOS (Keychain), Android (**direct Keystore** —
   EncryptedSharedPreferences is deprecated, so the brief's "Keystore/
   EncryptedSharedPreferences status" resolves to Keystore-only), Windows
   (DPAPI), Linux (Secret Service with an encrypted-file fallback), web
   (no persistent tokens; HttpOnly cookie via the broker if the app needs a
   web session).
9. **PKCE always S256 — confirmed and strict.** RFC 7636 makes S256 MTI;
   GitHub and Discord accept S256 only; Google/Microsoft/X accept S256. We
   never emit `plain`. Verifier: 32 random bytes base64url (256 bits).
10. **`state` + `nonce` round-trip — confirmed.** Google requires `nonce`,
    Microsoft requires it for id_token flows, Apple validates it
    (`exact-or-sha256` in better-auth's implementation), GitHub/X/Discord
    require `state` for CSRF. The mock's wrong-state/wrong-nonce tests map
    directly onto these rules.
11. **Discovery-driven generic OIDC — confirmed.** OIDC Discovery's
    `/.well-known/openid-configuration` contract (and the live Discord/Google
    documents we fetched) let the generic client build itself from metadata;
    endpoints are hardcoded only where a provider publishes no discovery.
12. **Apple's native button on Apple surfaces — confirmed.** The HIG requires
    the system button; the native `ASAuthorizationController` path is the
    adapter on iOS/macOS, and the web form_post flow is for everywhere else —
    which also means Apple on web/desktop is broker-mediated by construction
    (the return URL must accept a POST and the broker holds the p8).
13. **Redirect-URI rules per provider drive registration docs.** Google:
    loopback (Desktop client) or reversed-client-id scheme (iOS); GitHub:
    https callback URL, loopback exempt from port matching; Microsoft:
    "Mobile and desktop applications" platform, localhost port-ignored,
    `[::1]` unsupported; Discord/X: portal-registered callback; Facebook:
    Valid OAuth Redirect URIs (https only); Apple: Services ID return URLs.
    These become the per-provider setup tables in docs (area 10) verbatim.

## Honest gaps

- Apple's "client secret is a signed JWT" and the exact registration pages are
  documented by Apple but their doc pages are JS-rendered and could not be
  fetched here; the fact set is corroborated by the live discovery document
  (secret required, form_post, RS256) and by better-auth's Apple provider.
- Discord's allowed redirect-URI schemes are not enumerated in its docs; the
  plan avoids depending on an undocumented custom-scheme path.
- X's callback-format rules live in the developer portal; the docs page only
  states exact-match validation.
- GitHub's revocation API route (`DELETE /applications/{client_id}/token`) is
  from the REST API docs family rather than the authorization page fetched
  here; treat the exact route shape as to-verify when the broker implements it.
