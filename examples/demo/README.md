# nsh-auth Demo

A TSX sign-in demo for the nsh-auth package: one button per provider (Google,
Facebook, Discord, GitHub, Apple, Microsoft, X, generic OIDC, and the local
mock), a contact-email form on `nsh-form`, a session screen with the userinfo
profile on `nsh-query`, the ID-token claims readout, and refresh / sign-out.

Everything stays in the sandbox: client ids are fake, the `mock` and `oidc`
providers talk only to the local mock (`tools/mock-oauth`), and no real
provider is ever signed in to. The other seven providers point at their real
domains with fake client ids, so a press proves the flow is triggered
correctly and stops there.

## Prerequisites

- The `nsh` CLI, 0.4.0 (never upgrade it).
- This repository cloned locally (the demo lives in `examples/demo`).
- The two sibling libraries the demo imports, cloned alongside it — `nsh-form`
  and `nsh-query` (the paths below assume `~/fo/nsh-form` and `~/fo/nsh-query`;
  adjust if your checkouts live elsewhere). They are external dependencies,
  not part of this repository.
- `bun`, only if you want to run the sibling libraries' own test suites; the
  demo's gates need just `nsh`.

## Setup (from a clean clone)

```sh
cd examples/demo
mkdir -p node_modules
ln -s ../../../packages/nsh-auth node_modules/nsh-auth
ln -s ~/fo/nsh-form/packages/nsh-form node_modules/nsh-form
ln -s ~/fo/nsh-query/packages/nsh-query node_modules/nsh-query
```

The `nsh-auth` link is relative and resolves inside any clone (three levels
up from `node_modules/` to this repository's root). The sibling-library links
assume the checkout location from Prerequisites. A link written as
`../../packages/nsh-auth` resolves from `node_modules/` and lands on
`examples/packages/`, which does not exist. `tsconfig.json` needs no `paths`
entries; the `.nsh` types break if you add them.

## Gates

```sh
nsh check        # the only type check
nsh build        # read every warn as a finding
nsh test         # headless, manual clock, stubbed network, played host
```

Screenshots on a real target (headless draws nothing; the look test skips
itself there):

```sh
nsh test look.test.tsx --target macos
```

## Run it

Start the mock first (its own README defines the exact command; default port
8755, use one port everywhere):

```sh
node tools/mock-oauth/main.mjs   # per tools/mock-oauth/README.md
```

Web, on this machine (the demo's default mock address
`http://127.0.0.1:8755` reaches it):

```sh
cd examples/demo
nsh run --target web --port 8790 App.web.tsx
```

`App.web.tsx` is required as the entry: the web runtime cannot load nsh-query
(the `lifecycle` import is web-fatal on nsh 0.4.0), so the web surface mounts
the query-free account screen variant. Running the bare command builds
`App.tsx`, whose account screen crashes after a completed sign-in.

`--port 0` asks the OS for a free port. A browser on another device cannot
reach `127.0.0.1`; embedded surfaces pass the override instead (below).

## Embedding build (what the native hosts run)

```sh
cd examples/demo
nsh build App.tsx --release --out ../host-ios/nsh                        # folder reference "nsh"
nsh build App.tsx --release --out ../host-android/app/src/main/assets/nsh # loadAssetBundle("nsh")
```

Bytecode loads only from inside the app bundle or APK, never from storage.

## The host contract

`nsh.json` declares `"host": ["auth.*"]`, `openUrl` (http/https) and
`network` (127.0.0.1, localhost, 10.0.2.2). The package makes the calls; the
demo wires the surfaces.

- **Config** — the demo reads, in order: defaults (`mockBaseUrl`
  `http://127.0.0.1:8755`, client id `nsh-auth-sandbox-client`, redirect
  `nsh.auth.sandbox://callback` — the scheme/path both hosts register), then
  `host.params.auth` (Android's mirror: `{redirectUri, mockBaseUrl?,
  autoStart?}`), then `host.call("auth.config", { mockBaseUrl? })` (both
  hosts implement it; iOS answers `{mockBaseUrl, autoStart, provider}` where
  `autoStart` is a boolean and `provider` names the provider). The config
  must be final before `createAuth` runs, so the demo builds its auth
  instance after the read and shows "Loading…" until then.
- **Launch** — the package calls `host.call("auth.authorize", { url, scheme })`
  and the host answers `{ callbackUrl }` (`ASWebAuthenticationSession` /
  Custom Tabs caught the redirect). The loop then finishes by itself: state
  and nonce checks, code exchange, JWKS RS256 verification, userinfo, and the
  session into the host's secure store through `auth.store.save` /
  `auth.store.load` / `auth.store.clear`.
- **No host** — `openUrl` opens the authorize URL, and the flow waits: a bare
  TSX build has no way to catch the redirect on 0.4.0. The sign-in screen
  shows a paste-in box (`CallbackPasteBack`) that hands a callback URL to
  `auth.handleRedirect`; a web host can feed the same path through the
  `auth.redirect` event (the page bridge calls it; the demo's listener does
  the rest).
- **Test-only** — `auth.test.refreshBurst` with `{ count }` fires that many
  concurrent refreshes; no real host sends it, and the single-flight test
  uses it to watch the package share one transport call.

GitHub and Apple exchange codes only through a broker (`brokerUrl` in the
package's `AuthConfig`). The demo passes none, so those two buttons report
`broker_error` until the owner configures one — by design; no client secret
ever belongs in an app.

## The nsh-auth API the demo consumes

`src/auth.ts` is the only file importing `nsh-auth`; a contract change lands
its type errors there alone.

```ts
createAuth({ clientId, redirectUri, mockBaseUrl }) // => Auth with Signal fields
auth.session(); // Signal<Session | null>: { provider, accessToken, refreshToken?, idToken?, expiresAt, scope }
auth.user();    // Signal<UserInfo | null>: { id, name?, email?, picture?, raw }
auth.status();  // Signal<"idle" | "authorizing" | "exchanging" | "authenticated" | "refreshing" | "error">
auth.error();   // Signal<AuthError | null>; code: access_denied, state_mismatch, nonce_mismatch,
                // expired_code, invalid_grant, network, broker_error, store_error, no_launcher, unknown
auth.signIn(provider);        // builds the authorize URL and launches it (see above)
auth.handleRedirect(url);     // the paste-back / web-bridge path
auth.refresh();               // single-flight: parallel calls share one request
auth.signOut();               // revokes, clears the store, resets the signals
```

`mock` and `oidc` each talk to their own realm under `mockBaseUrl`, matching
the `tools/mock-oauth` route table: `GET {base}/mock/authorize`,
`POST {base}/mock/token`, `GET {base}/mock/userinfo`,
`POST {base}/mock/revoke`, `GET {base}/mock/.well-known/jwks.json`, with
issuer `{base}/mock`; the `oidc` realm is the same shape under `{base}/oidc`
with issuer `{base}/oidc`. The other providers carry their real domains in
the package's `src/providers.ts`.

## Button marks and their limits

docs/providers.md section (f) requires each provider's approved mark before
the label. NSH has no SVG element, so the demo draws what hand-built views
can honestly render, hidden from screen readers (the button's accessible name
stays the plain wording):

- **Drawn faithfully** — Microsoft's four squares (pure geometry, official
  four colors as theme tokens).
- **Drawn as letterform approximations, pending the official assets** —
  Facebook's white `f` and the X mark as bold letterforms in the brand's
  black/white treatment. Providers forbid altering their marks; these two are
  the closest letterform renderings and should be replaced by the approved
  assets from the Brand Resource Center / X toolkit before shipping.
- **Not drawn, deliberately** — Google's multicolor G ("never recolored or
  redrawn"), Apple's Apple-logo glyph (the `apple.logo` SF Symbol; a private-use
  character renders only on Apple platforms), Discord's mark and GitHub's
  Invertocat (complex trademark artwork). Faking them would violate each
  provider's rules, so those four buttons are text-only.

Spacing follows the Button's shared 8pt icon gap; Google's 12/10/12px logo
padding applies only once its official logo asset is embedded. Apple's title
follows the 43%-of-height rule (`19px` on the 44pt button, an arbitrary size
justified by that brand rule); other providers keep the shared 14pt label.

## The contact email form

The email form saves a contact address shown on the account screen. It does
not reach the OAuth flow: `signIn(provider)` takes no options, so a
`login_hint` is not sent (see the upstream notes below).

## Web runtime notes

Three nsh 0.4.0 web-runtime gaps shape the web build, each reproduced by probe
in this directory:

1. `env()` inside arbitrary class math (`pt-[calc(env(safe-area-inset-top)+16px)]`)
   crashes the web runtime. The demo therefore uses fixed padding on every
   surface (`p-4` headers, `pb-6` content); native surfaces have no notch
   compensation in this demo.
2. `platform` crashes a web app on import — even unread, and try/catch around
   the read does not contain it. No runtime platform detection exists in this
   demo.
3. `lifecycle` is typed in `.nsh/types` but missing from the web runtime, and
   nsh-query's `createQuery` calls `untracked(lifecycle)` — so nsh-query can
   never load on web (upstream: nsh 0.4.0 + nsh-query). A dynamic `import()`
   of the module dies with the app too.

Because imports (not just uses) are fatal, the per-surface switch is the
entry file: `App.tsx` (native, nsh-query-backed account screen) and
`App.web.tsx` (web, account screen with a note in the profile card's place —
identity comes from the ID-token claims; refresh and sign-out work). The web
phase builds and bundles the web entry:

```sh
cd examples/demo
nsh build App.web.tsx --release --out .nsh/out-web
```

`preview.tsx` and `preview.test.tsx` statically import nsh-query, so they are
native/headless fixtures — run them without `--target web`.

## Tests

- `preview.test.tsx` — the demo's own UI (provider table, email form,
  userinfo query, claims readout, paste-back box). No `nsh-auth` needed.
- `App.test.tsx` — the full mock loop against the package: exact authorize
  URL (PKCE S256, state, nonce, scopes, redirect), token exchange with
  `code_verifier`, session screen from a host-caught redirect, the no-host
  paste-back loop, denial, wrong state, wrong nonce, expired code, refresh
  updating session and profile, single-flight refresh under 8 parallel calls,
  revoked refresh, sign-out with revocation, the contact email on the account
  screen, and host params + `auth.config` driving `mockBaseUrl` and
  `autoStart`. The id tokens in the stubs are really RS256-signed against a
  WebCrypto keypair whose public half the stub JWKS publishes — the package
  verifies signatures.
- `look.test.tsx` — screenshots in both appearances; evidence in
  `docs/evidence/demo/`, looked at by a person.

Tests never import the app's modules (a test file's imports are a separate
module instance from the running app's — verified by probe on 0.4.0); they
drive the UI and play the host (`open(..., { host })` answering
`auth.authorize` and `auth.store.*`, `app.host.send` for the redirect and
refresh-burst events), and stub the network with routes. Every test runs on a
manual clock (`clock: { time: 0 }`).

Every behavior test was seen failing once with a deliberate demo-code break:
a wrong `clientId` passed to `createAuth` (authorize-URL and loop tests red),
a sequential burst hook (single-flight test red, 8 transport calls), an error
banner that dropped the real code (denial / wrong-state / nonce / expired
tests red), and a `mockBaseUrl` merge that ignored both delivery channels
(host-params test red). All restored, all green after.
