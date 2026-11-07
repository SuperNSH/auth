# nsh-auth

Social and OAuth sign-in for [Native Shell](https://nsh.dev) apps. One call from your app starts a
sign-in with Google, Facebook, Discord, GitHub, Apple, Microsoft, X or any generic OAuth 2.0 / OIDC
provider, and returns a signal holding the session: `session`, `user` and `status`, with refresh,
single-flight refresh, sign-out with token revocation, and secure token storage on every platform
NSH targets — iOS, Android, macOS, Windows, Linux and the web.

There are two versions with the same behavior, like its sibling libraries
`nsh-query` and `nsh-form` (separate repositories; both require NSH 0.4.0):

| Version | Path | For |
|---|---|---|
| Rust crate | `crates/nsh-auth` | Rust and Rust-with-TSX apps |
| TypeScript package | `packages/nsh-auth` | TSX apps, signed packages, anything with no Rust crate |

The flows follow [RFC 8252](https://www.rfc-editor.org/rfc/rfc8252) (OAuth for native apps): the
system browser always carries the provider's login — ASWebAuthenticationSession on iOS and macOS,
Custom Tabs on Android, the default browser on Windows and Linux — never an embedded web view, which
Google blocks and which would expose credentials to the app. Every request carries PKCE (`S256`),
a random `state`, and a `nonce` for providers that mint ID tokens. Providers that require a
confidential client, GitHub today, go through a small token broker you run yourself
(`tools/broker`); no client secret is ever embedded in an app, and a test greps the build output to
prove it. `tools/mock-oauth` imitates every provider locally, so the complete loop — authorize,
approve, redirect back, exchange, session — runs with no real account.

## Architecture

```
 your app (TSX, Rust, or Rust-with-TSX)
   │  one call  →  session / user / status signals
   │
   ├─ core (same behavior, two languages)
   │    packages/nsh-auth   TypeScript
   │    crates/nsh-auth     Rust
   │    provider definitions · PKCE + state + nonce · authorize-URL building
   │    callback parsing + validation · token exchange + refresh · ID-token claims
   │    session store trait · single-flight refresh · sign-out with revocation
   │
   ├─ surfaces (one launcher mechanism each)
   │    iOS / macOS    ASWebAuthenticationSession   native/ios
   │    Android        Custom Tabs + intent filter  native/android
   │    both reached from the embedding host via host.call("auth.authorize", ..)
   │    in examples/host-ios and examples/host-android
   │    Windows / Linux  system browser + 127.0.0.1 loopback listener, random port
   │    web            redirect or popup, via web.host
   │
   ├─ tools/mock-oauth   local fake of every provider's authorize, token, userinfo,
   │                     revoke and JWKS endpoints, with each provider's quirks
   ├─ tools/broker       reference token broker for confidential clients (GitHub);
   │                     you deploy it, the secret lives only in its environment
   │                     (directory produced by the broker area; may not exist yet)
   └─ examples/demo      per-provider buttons (brand rules) + a mock provider,
                         session screen; forms via nsh-form, profile via nsh-query
```

On the Android emulator the mock's host is `10.0.2.2`, not `127.0.0.1`.

## Quickstart: mock sign-in

Everything below is sandbox-only: fake client ids (`nsh-auth-sandbox…`), a local mock, no real
account, no credential typed anywhere.

Prerequisites: `nsh` 0.4.0 (Homebrew) and `bun`.

```sh
# 1. Clone
git clone <repository-url> nsh-auth
cd nsh-auth

# 2. Install mock dependencies and start the mock (terminal 1)
cd tools/mock-oauth
bun install
bun run dev
# The server prints its base URL, e.g. http://127.0.0.1:<port>. Keep it running.
# TO-VERIFY: exact command and default port live in tools/mock-oauth/README.md
# (being built by the mock area). The shape above is the intended one.

# 3. Run the demo (terminal 2)
cd examples/demo
nsh run --target macos    # or: web | ios | android, per examples/demo/README.md
# TO-VERIFY: examples/demo/README.md (demo area) is authoritative for its exact
# commands, including any node_modules links the demo sets up (nsh-auth,
# nsh-form, nsh-query) and how it is told the mock's base URL from step 2.
```

In the demo window, press **Mock provider**. The system browser (or ASWebAuthenticationSession on
iOS/macOS, Custom Tabs on Android) opens the mock's authorize page — `127.0.0.1`, or `10.0.2.2` on
the Android emulator; the scripted user approves; the redirect returns through the platform's real
mechanism — loopback listener, scheme callback, or web redirect — and the session screen shows the
mock user's claims. **Sign out** revokes the mock's tokens. On iOS and Android, restart the app and
the session is restored from secure storage.

To watch the same flow fail safely, the mock can deny approval, send a wrong `state`, a wrong
`nonce`, an expired code, or a revoked refresh token — see the mock suite (`nsh test` in
`tools/mock-oauth` and in the core directories).

Heads-up while the build is in progress: commands marked TO-VERIFY are being finalized by parallel
areas. When their files land, the named file wins over the shape shown here.

## Bring your own provider

Registering real client ids for each provider — which console, which client type, the exact
redirect URIs to enter per surface, and where the id goes in this repo's config — is documented per
provider in [docs/setup.md](docs/setup.md). It requires no change to library code: the client id
and redirect URIs are data your app passes when it builds its provider list.

During this repository's own sandbox build, do not register real ids at all; the demo runs against
the mock and obviously-fake ids. Registering real ids is for your own app, after the sandbox.

## The Firebase seam

`nsh-firebase` is a separate project. It signs in to Firebase with an ID token minted by this
library. This repo exposes the provider's `idToken` (and access token) cleanly on the session and
has no dependency on `nsh-firebase`, in either direction — you wire them together in your app by
handing the session's ID token to the Firebase credential API. Nothing to configure here.

## Honest limits

- A TSX app packaged with no embedding host can start a flow with `openUrl`, but on iOS and Android
  NSH 0.4.0 gives it no way to receive the redirect back — there is no inbound-URL module in that
  configuration. Native sign-in on those platforms needs the host (`examples/host-ios`,
  `examples/host-android`). On the web, redirect and popup flows work without a host.
- Desktop token storage is a `0600` file under the user's profile. It is not Keychain-grade:
  anyone with the user's file access can read it. The mobile paths use the Keychain and Android
  Keystore. See [docs/threats.md](docs/threats.md) for the full picture, including what the
  mitigations do not claim.

## Where to look

| Path | Contents |
|---|---|
| [docs/setup.md](docs/setup.md) | Per-provider registration, redirect URIs, broker deployment |
| [docs/threats.md](docs/threats.md) | Threat table: risk, surface, mitigation, code anchor |
| [docs/upstream-issues.md](docs/upstream-issues.md) | Bugs found in `nsh-query` / `nsh-form` |
| [docs/providers.md](docs/providers.md) | Per-provider endpoints, scopes, redirect rules, quirks — *produced by the providers area; may not exist yet* |
| [docs/research.md](docs/research.md) | Flow research with citations, NSH 0.4.0 experiments — *produced by the research area; may not exist yet* |
| [docs/security-review.md](docs/security-review.md) | Security audit report — *produced at the audit phase; may not exist yet* |
| [docs/STATUS.md](docs/STATUS.md) | Build progress and what was verified how |
| [docs/evidence/](docs/evidence/) | Screenshots and logs from the device proofs |
