# Provider setup

What you, the app owner, register with each provider so nsh-auth can sign in against it. Per
provider: which console, which client type, the redirect URIs to enter per surface, and where the
client id goes in this repository's configuration. None of it requires changing library code — the
client id and redirect URIs are data your app passes when it builds its provider list.

Two rules that hold everywhere:

- **No client secret ever goes into an app.** The big four (Google, Facebook, Discord, GitHub) all
  issue client ids that work with PKCE as a public client, or in GitHub's case are routed through
  the token broker ([below](#github-and-the-token-broker)). If a console shows you a secret for a
  native client, leave it unused; the flow never sends it. Anything that needs a secret at the
  token exchange runs through `tools/broker` on your own server.
- **Sandbox values in this repo are fake.** Everything marked `nsh-auth-sandbox…` is a placeholder
  so the mock loop runs with no real account. When you register your own app, substitute your real
  ids from the console.

## Sandbox values this repository uses

These are the values the demo and hosts are configured with in sandbox mode. Where the value
depends on a file still being built by a parallel area, it is marked TO-VERIFY — confirm against
the named file before relying on it.

| Surface | Redirect URI (sandbox) | Mechanism |
|---|---|---|
| iOS (`examples/host-ios`) | `nsh-auth.demo://callback` | `ASWebAuthenticationSession` callback, scheme registered by the embedding host (`native/ios`) — TO-VERIFY: scheme string against the host manifest |
| macOS (`examples/host-ios`) | `nsh-auth.demo://callback` | Same as iOS — TO-VERIFY: the desktop area may instead use the loopback listener |
| Android (`examples/host-android`) | `nsh-auth.demo://callback` | Intent filter on the embedding host (`native/android`) — TO-VERIFY: scheme string against the host manifest |
| Windows / Linux desktop | `http://127.0.0.1:<port>/callback` | Loopback listener on a random port (`crates` core + desktop launcher). Register the bare `http://127.0.0.1/callback` form where the console allows a variable port; otherwise use the fixed port the demo prints at startup — TO-VERIFY |
| Web demo | `http://localhost:<port>/auth/callback` | Web redirect; `<port>` is whatever `nsh run --target web` prints — TO-VERIFY: callback path against `examples/demo` |

Mock endpoints, for the sandbox loop only: the base URL `tools/mock-oauth` prints on start
(expected `http://127.0.0.1:<port>`, command TO-VERIFY against `tools/mock-oauth/README.md`); on
the Android emulator that host is `http://10.0.2.2:<port>`.

---

## Google

**Console:** [Google Cloud Console](https://console.cloud.google.com) → *APIs & Services* →
*OAuth consent screen* (configure audience first), then *Credentials* → *Create credentials* →
*OAuth client ID*.

**What to register:** create one client per surface type — *Desktop app* for Windows/Linux/macOS
loopback, *iOS app* for the simulator and device, *Android app* for the emulator and device. Google
issues a client secret for desktop-type clients but an installed-app flow never uses it; treat it
as disposable.

**Redirect URIs to enter:**

| Surface | Enter |
|---|---|
| Desktop app client | `http://127.0.0.1/callback` (Google accepts any port at runtime on loopback) |
| iOS client | Google requires the reversed client-id scheme it generates, e.g. `com.googleusercontent.apps.<id>:/oauthredirect` — enter that, and register the resulting scheme in the iOS host. The demo's sandbox scheme does not apply to Google iOS. |
| Android client | No redirect URI: Google uses the package name plus SHA-1 fingerprint of the signing key |
| Web client | `http://localhost:<port>/auth/callback` (exact port of the demo's web target) |

Google blocks embedded web views (`disallowed_useragent`); this library always uses the system
browser, so this only bites if you bypass the launcher.

**Where the client id goes:** the provider definition in your app's provider list (in this repo,
the demo's provider config — TO-VERIFY: file name against `examples/demo`, which is being built).
Quirks and endpoint table: [docs/providers.md](docs/providers.md) (providers area).

## Facebook

**Console:** [developers.facebook.com](https://developers.facebook.com) → *My Apps* → *Create App*
(Authentication use case) → add the *Facebook Login* product → *Facebook Login → Settings*.

**What to register:** an app id (public) and the *App secret* — the secret never goes in the app.
nsh-auth uses Facebook's **OIDC code flow with PKCE** for public clients: the exchange sends
`code_verifier`, which makes `client_secret` optional, so the app path runs secretless. Facebook's
classic manual flow (secret required, no PKCE) also exists; if you use that shape, the secret
belongs only in your broker's environment. Pin the Graph API version — `{version}` in the URLs is
provider config, not a constant.

**Redirect URIs to enter:** Facebook enforces HTTPS and exact-string Strict Mode on *Valid OAuth
Redirect URIs* (under *Facebook Login → Settings*):

| Surface | Enter |
|---|---|
| Web / desktop | Your HTTPS callback, e.g. `https://your.app/callback/facebook` — exact string match |
| iOS / Android | No custom-scheme redirect is documented for a hand-built flow: use the optional native SDK adapter or an HTTPS relay through the broker — see [docs/providers.md](docs/providers.md) |

(The demo's `http://localhost` callback works only because Facebook tolerates unregistered
localhost in Development mode — a dashboard behavior, not part of the documented contract.)

**Where the client id goes:** the provider definition in your app's provider list; the Graph API
version sits alongside it. Endpoints, quirks and button rules:
[docs/providers.md](docs/providers.md).

## Discord

**Console:** [discord.com/developers/applications](https://discord.com/developers/applications) →
*New Application* → *OAuth2* → *Add Redirect*.

**What to register:** a client id; Discord supports PKCE for public clients, so no secret is used
in the app. The console shows a client secret — leave it alone unless you run a server-side
integration of your own.

**Redirect URIs to enter:**

| Surface | Enter |
|---|---|
| iOS / Android / macOS | `nsh-auth.demo://callback` |
| Windows / Linux | `http://127.0.0.1/callback` — Discord requires the exact registered string, so if the demo binds a random port, register the fixed sandbox port it prints instead — TO-VERIFY |
| Web | `http://localhost:<port>/auth/callback` |

**Where the client id goes:** the provider definition in your app's provider list.

## GitHub and the token broker

**Console:** GitHub → *Settings* → *Developer settings* → *OAuth Apps* → *New OAuth App*.

**What to register:** a client id and a callback URL. GitHub's authorization-code exchange requires
the client secret, so the app never talks to GitHub's token endpoint directly — it goes through
the broker, a small server you deploy (`tools/broker`, reference implementation in this repo).

**Callback URL to enter:** the broker's callback endpoint, e.g.
`https://broker.example.com/github/callback` — TO-VERIFY: exact path against
`tools/broker/README.md` when it lands.

**Deploying the broker:**

1. Register the GitHub OAuth app with the broker's callback URL (above).
2. Deploy `tools/broker` where your app's users can reach it, behind TLS. TO-VERIFY: runtime and
   build steps against `tools/broker/README.md` (broker area).
3. Give the broker the client secret through its environment variable only —
   expected `GITHUB_CLIENT_SECRET`, TO-VERIFY: exact name in `tools/broker/README.md`. Never in a
   file that ships, never in the app.
4. Point the app's GitHub provider definition at the broker base URL plus the client id. The app
   sends the authorization code (and its PKCE verifier) to the broker; the broker adds the secret,
   exchanges with GitHub, and returns the tokens over the app's existing authenticated channel.
5. Prove the secret is absent: the build gate includes a grep over app build output for secret
   material (brief criterion 7). Run it after adding any provider config.

The same seam serves any other provider that ends up requiring a confidential exchange.

## Apple

**Console:** [developer.apple.com](https://developer.apple.com) → *Certificates, Identifiers &
Profiles*.

**What to register:**

- iOS / macOS: create an *App ID* with *Sign in with Apple* enabled. The system flow
  (AuthenticationServices) does the work; there is no web round-trip to register, and this
  repository reaches it through the optional native adapter behind the same provider interface.
- Web / Android: create a *Services ID*, enable Sign in with Apple for it, and register the
  redirect URL(s) and the key (a private `.p8`, server-side only — it belongs wherever your
  server-side token handling runs, e.g. alongside the broker; it is never in the app).

**Redirect URIs to enter (web / Android only):** your HTTPS endpoint that can receive Apple's
`response_mode=form_post` — a POST body, not a query string, so a custom scheme cannot take it.
This is why Apple's non-native path involves your server. TO-VERIFY: whether the reference broker
gains an Apple endpoint; check `tools/broker/README.md`.

**Where the client id goes:** the Services ID (web/Android) or App ID (iOS/macOS) in the provider
definition; the key id and team id alongside it, server-side only.

## Microsoft

**Console:** [Azure portal](https://portal.azure.com) → *Microsoft Entra ID* → *App registrations*
→ *New registration*.

**What to register:** a public client — do not add a client secret. Choose the authority/tenant
model (single tenant vs `common`) and record the application (client) id and the authority URL the
demo should use.

**Redirect URIs to enter:** add the *Mobile and desktop applications* platform, which allows
loopback redirects with a variable port:

| Surface | Enter |
|---|---|
| iOS / Android / macOS | `nsh-auth.demo://callback` |
| Windows / Linux | `http://localhost` (Microsoft accepts any port at runtime) |
| Web | `http://localhost:<port>/auth/callback` |

Microsoft is OIDC: ID tokens carry a `nonce`, which this library validates on every sign-in.

**Where the client id goes:** the provider definition (client id + authority) in your app's
provider list.

## X

**Console:** [developer.x.com](https://developer.x.com) → your project → the app → *User
authentication settings* → *Set up*.

**What to register:** OAuth 2.0, app type *Native App* (public client, PKCE — a native app gets no
usable client secret), the callback URI(s), and the scopes you need (typically `users.read`,
`tweet.read`, `offline.access` for refresh).

**Redirect URIs to enter:**

| Surface | Enter |
|---|---|
| iOS / Android / macOS | `nsh-auth.demo://callback` |
| Windows / Linux / Web | An exact HTTPS or loopback string — X requires the exact registered URI; use the fixed port the demo prints if it binds one — TO-VERIFY |

**Where the client id goes:** the provider definition in your app's provider list.

## Generic OAuth 2.0 / OIDC

Any provider with an authorization endpoint and either a token endpoint (OAuth 2.0) or a discovery
document (OIDC: `<issuer>/.well-known/openid-configuration`) works through the generic provider
definition.

**What to register with the provider:** a native/public client with PKCE enabled, and the redirect
URIs for your surfaces — same shapes as the table at the top of this file.

**What your app passes:** issuer URL (OIDC) or explicit endpoints (OAuth 2.0), client id, scopes
(`openid profile email` at minimum for OIDC), and the per-surface redirect URIs. With OIDC, the
discovery document supplies authorize/token/JWKS endpoints and the library validates the ID
token's `nonce`; with plain OAuth 2.0 there is no ID token and no `nonce` check to do.

**Where it goes:** the generic provider definition in your app's provider list, next to the
built-in providers.

---

## Where the client id goes, precisely

- **In this repository (demo):** the demo's provider config — the file in `examples/demo` that
  lists providers with their sandbox ids. TO-VERIFY: exact file name when the demo area lands;
  `examples/demo/README.md` will name it.
- **In your own app:** wherever you construct the provider list. Both cores take the client id,
  redirect URIs, and (for generic providers) endpoints as plain configuration values. Nothing is
  compiled into the libraries; swapping a sandbox id for a real one is a config change, not a code
  change.
- **Secrets:** only in `tools/broker`'s environment, on your server. If you find yourself putting
  one anywhere else, stop — see [docs/threats.md](docs/threats.md).
