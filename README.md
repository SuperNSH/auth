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
   │    iOS / Android  ASWebAuthenticationSession / Custom Tabs   native/ios, native/android
   │                   reached from the embedding host via host.call("auth.authorize", ..)
   │                   in examples/host-ios and examples/host-android
   │    desktop        examples/host-desktop  system browser + a 127.0.0.1 loopback
   │                   listener on an OS-assigned port (Rust host over the crate)
   │    web            the demo under nsh run --target web; a loop completes only with
   │                   a page-bridge host, so the hostless web demo ends at paste-back
   │
   ├─ tools/mock-oauth   local fake of every provider's authorize, token, userinfo,
   │                     revoke and JWKS endpoints, with each provider's quirks
   ├─ tools/broker       reference token broker for confidential clients (GitHub);
   │                     you deploy it, the secret lives only in its environment
   └─ examples/demo      per-provider buttons (brand rules) + a mock provider,
                         session screen; forms via nsh-form, profile via nsh-query
```

On the Android emulator the mock's host is `10.0.2.2`, not `127.0.0.1`.

## Quickstart: mock sign-in

Everything below is sandbox-only: fake client ids (`nsh-auth-sandbox…`), a local mock, no real
account, no credential typed anywhere.

Prerequisites: `nsh` 0.4.0 (Homebrew); Node or bun for the mock; a Rust toolchain for the desktop
host. Two loopback ports are involved: the mock's default **8755** — the demo's default expects it
free — and the web dev server (the demo README uses **8790**). If one is busy: the mock takes
`--port 0` / `--port <p>` plus an override (`--mock-url` on host-desktop; the demo's host params /
`auth.config` — see `examples/demo/README.md`), and `nsh run` takes `--port`.

```sh
# 1. Clone
git clone <repository-url> nsh-auth
cd nsh-auth

# 2. Start the mock (terminal 1; it has zero dependencies)
node tools/mock-oauth/main.mjs
# prints MOCK_URL=http://127.0.0.1:8755 — keep it running. Equivalent from
# tools/mock-oauth/: `bun run start` (a `dev` alias may also exist — the mock's
# README is the source of truth).
```

**Path A — the full automatic loop (recommended).** The desktop embedding host; no Xcode or
Android SDK needed.

```sh
# 3a. Run the desktop host (terminal 2)
cd examples/host-desktop
cargo run -p host-desktop -- --provider mock
# if the mock is not on 8755: --mock-url http://127.0.0.1:<port>
```

A window opens, the system browser opens the mock's authorize page, the scripted user approves,
the host's loopback listener catches the redirect, and the window shows the signed-in session.
**Sign out** revokes the mock's tokens. The iOS and Android hosts (`examples/host-ios`,
`examples/host-android`) run the same automatic loop through `ASWebAuthenticationSession` /
Custom Tabs — they need Xcode and the Android SDK respectively; see their READMEs. On iOS and
Android, restarting the app restores the session from secure storage.

**Path B — the hostless demo, and what it cannot do.** A bare TSX app on NSH 0.4.0 has no way to
receive a redirect.

```sh
# 3b. Run the demo standalone (its node_modules setup steps come first —
#     see examples/demo/README.md)
cd examples/demo
nsh run --target macos
```

Press **Sign in with Mock**: the browser opens the mock's authorize page and the scripted user
approves — and there it stops, because nothing catches the redirect. Copy the
`nsh.auth.sandbox://callback?...` URL from the browser's address bar into the demo's "Finish a
sign-in by hand" box and press **Finish sign-in**: the loop completes and the session screen
appears. On the web target (`nsh run --target web --port 8790 App.web.tsx`, per the demo README)
pressing the button cannot even open a browser — it reports `no_launcher`. A web loop completes
only through a page-bridge host, which the demo does not ship.

To watch the same flow fail safely, the mock can deny approval, send a wrong `state`, a wrong
`nonce`, an expired code, or a revoked refresh token. The suites: `bun test` in
`tools/mock-oauth`, `cargo test` in `crates/nsh-auth` (and in `examples/host-desktop`), `nsh
test` in `packages/nsh-auth` and `examples/demo`.

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
  configuration. On the web it cannot even launch the browser (the demo's mock button reports
  `no_launcher` there), and a loop completes only through a page-bridge host feeding the redirect
  to `handleRedirect` — which the demo does not ship. A full automatic loop therefore needs an
  embedding host: `examples/host-ios`, `examples/host-android`, `examples/host-desktop`.
- Desktop token storage is a `0600` file under the user's profile. It is not Keychain-grade:
  anyone with the user's file access can read it. The mobile paths use the Keychain and Android
  Keystore. See [docs/threats.md](docs/threats.md) for the full picture, including what the
  mitigations do not claim.

## Third-party code

Parts of the native layers build on proven library work: browser-selection and
custom-tab code translated from AppAuth-Android into this repository's Kotlin,
small behaviors adapted from AppAuth-iOS, flutter_secure_storage and
expo-secure-store into our own Swift/Kotlin, and the keyring crate family plus
androidx.browser consumed as dependencies. What was taken from each, with
copyright lines and license texts, is recorded in
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md). Provider logos and sign-in
button artwork are deliberately not stored here; the demo renders
brand-compliant buttons with assets the app owner supplies (see
[docs/providers.md](docs/providers.md)).

## Where to look

| Path | Contents |
|---|---|
| [docs/setup.md](docs/setup.md) | Per-provider registration, redirect URIs, broker deployment |
| [docs/threats.md](docs/threats.md) | Threat table: risk, surface, mitigation, code anchor |
| [docs/upstream-issues.md](docs/upstream-issues.md) | Bugs found in `nsh-query` / `nsh-form` |
| [docs/providers.md](docs/providers.md) | Per-provider endpoints, scopes, redirect rules, quirks |
| [docs/research.md](docs/research.md) | Flow research with citations, NSH 0.4.0 experiments |
| [docs/security-review.md](docs/security-review.md) | Security audit report |
| [docs/STATUS.md](docs/STATUS.md) | Build progress and what was verified how |
| [docs/evidence/](docs/evidence/) | Screenshots and logs from the device proofs |
