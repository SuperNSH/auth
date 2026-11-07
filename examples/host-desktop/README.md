# host-desktop — the desktop launcher

An NSH Rust app that signs in through the system browser and receives the
redirect on a `127.0.0.1` loopback port (OS-assigned by default, pinnable
with `--redirect-port`). One window: a provider list, the crate's status,
and the session once the loop is complete.

Flow, in order: the app binds `127.0.0.1` and picks its store (the OS
credential store by default on macOS and Windows, 0600 JSON files
otherwise — the active store is named in the startup log) and its
transport (nsh-http over the platform fetch by default — also named in
the startup log), builds the crate's `Auth` with
`redirect_uri = http://127.0.0.1:<port>/callback`, calls
`authorize_request(provider)` (PKCE, `state`, `nonce` are the crate's
job), opens the browser at the authorize URL (`open` on macOS), serves
exactly one `/callback` request on the listener, and hands the callback
URL to `complete(provider, url)`. The window's status, session and user
read the crate's signals directly. Sign-out calls `sign_out()`.

## Prerequisites

- The repo's `crates/nsh-auth` and `crates/nsh-auth-keyring` (path
  dependencies, part of this repository).
- The sibling library the default transport runs on, cloned alongside it —
  `nsh-http` (the paths assume `~/fo/nsh-http`; adjust if your checkout
  lives elsewhere). It is an external dependency, not part of this
  repository, and stays read-only for this build:
  `examples/host-desktop/Cargo.toml` refers to
  `../../../nsh-http/crates/nsh-http`.

## Which transport

Token and userinfo calls run over the platform's own transport by default:
`NshHttpTransport` (`src/nsh_http_transport.rs`) adapts the crate's `Http`
seam onto the sibling `nsh-http` client, whose transport is
`nsh_core::prelude::fetch` — the engine's network stack, the only path that
runs under the app's capability checks and answers NSH's stubs and test
clocks (measured comparison: `~/fo/nsh-http/docs/decision.md`).

`--transport reqwest` switches to `crates/nsh-auth`'s `ReqwestHttp` (reqwest
+ rustls). It is the bypass-the-platform transport: it opens its own
sockets outside the engine's fetch path and needs its own tokio runtime.
It is kept as an escape hatch, not as the default — measured and observed
on 0.4.0, its futures stall inside engine-spawned tasks under headless
runs (docs/upstream-issues.md), which is exactly what the flow tests
watch for.

## Run it

From `examples/host-desktop/` (the package builds against the repo's
`crates/nsh-auth` through a path dependency):

```sh
# Full loop against the local mock (auto-approves):
cargo run -p host-desktop -- --provider mock

# Trigger proof against a real provider with the sandbox client id.
# Expected stop: the provider's own "unknown client" page. Do not sign in.
cargo run -p host-desktop -- --provider google
```

Flags:

| Flag | Meaning | Default |
|---|---|---|
| `--provider <id>` | `google`, `facebook`, `discord`, `github` or `mock`; starts the flow as the window opens | none |
| `--print-urls` | Print the authorize URL for the provider on stdout, one line, and exit | off |
| `--mock-url <url>` | Base URL of the local mock provider | `http://127.0.0.1:8755` |
| `--broker-url <url>` | Token broker for confidential clients (GitHub) | `http://127.0.0.1:8756` |
| `--store <json\|keyring>` | Where sessions live (see "Where sessions live" below) | `keyring` on macOS and Windows, `json` on Linux |
| `--transport <nsh\|reqwest>` | How token calls travel (see "Which transport" above) | `nsh` |
| `--redirect-port <port>` | Pin the loopback callback port instead of an OS-assigned one, for providers that require an exact registered port | OS-assigned (`:0`) |

An unknown `--store` value, an unknown `--transport` value, or an unusable
`--redirect-port` (not a TCP port between 1 and 65535) is a startup error,
not a silent default.

The mock provider talks to the server from `tools/mock-oauth` (see its
README for how to start it). GitHub exchanges tokens only through the broker
from the same area — no client secret exists in this app to remove.

## Where the proof lands

Proof logs go to **stderr** (they are on at `info` by default, no `RUST_LOG`
needed):

```sh
cargo run -p host-desktop -- --provider mock 2> /tmp/host-desktop.log
```

The lines, in order: `sessions: <store>` (which store backs this run — an
OS-keyring default that cannot be honored is downgraded to the JSON store
with a warn line saying why, never silently), `transport: <transport>`
(`nsh-http over the platform fetch` by default; the reqwest line names
itself as the bypass transport), `authorize Google ->
<authorize URL, state and nonce redacted>` (the endpoint, client id,
scopes, redirect URI and `code_challenge_method` — the trigger proof;
`state` and `nonce` are anti-CSRF secrets, so their values never reach the
log), `browser opened; waiting for the callback on
http://127.0.0.1:<port>/callback`, `callback received on ...`, and
`mock sign-in complete (scope: …)` (or `mock sign-in failed: <error>`).
Tokens are never logged or shown on screen.

`--print-urls` is where the *exact* authorize URL comes from: it prints one
unredacted URL on stdout and exits, which is how the gate asserts the
authorize URL without a browser:

```sh
cargo run -p host-desktop -- --print-urls --provider google
```

## Screenshots

Save captures the brief expects under `docs/evidence/<provider>/macos.png`
and look at every one before calling it evidence:

```sh
# App window (the session screen after the mock loop):
osascript -e 'tell app "System Events" to id of window 1 of (first process whose name is "host-desktop")'
screencapture -l<windowid> docs/evidence/mock/macos.png

# Browser window (the provider's own domain, or its unknown-client page):
screencapture -l<windowid> docs/evidence/google/macos.png
```

List candidate window ids non-intrusively with
`screencapture -l$(osascript -e '...')` or CGWindowList; capture only
windows this flow opened.

## Loopback security notes

- The listener binds `127.0.0.1` only, on a port the OS assigned (`:0`) by
  default. `--redirect-port <port>` pins an exact port for providers that
  require a pre-registered one — the fixed-port option of
  `tauri-plugin-oauth` (MIT OR Apache-2.0), whose other behaviors this
  server deliberately does not import. A pinned port that is already taken
  is a startup error naming the port.
- Requests must hit `/callback` with `Host: 127.0.0.1:<port>`; anything else
  gets a 403/404, which is the DNS-rebinding resistance. GET only; request
  heads are capped at 8 KiB with a 5 s read timeout.
- One registration per flow, consumed by one request; late or duplicate
  callbacks find nothing pending. `state` equality is enforced by the crate
  when the callback URL is completed.
- `cancel()` stops the listener: a flag goes up, a connection to the
  server's own port unblocks the blocked `accept` (the shutdown pattern of
  `tauri-plugin-oauth`'s `cancel(port)`), the loop exits and the port
  closes. Callbacks after `cancel()` are refused. The app itself lets
  process exit close the port; `--print-urls` cancels its listener before
  printing, and tests await `wait_closed()`.
- The browser is opened by a fixed program (`open` / `xdg-open` /
  `rundll32 url.dll,FileProtocolHandler`) with the URL as a single argument —
  no shell string.

## Where sessions live

By default the launcher persists sessions in the OS credential store
through the repo's `crates/nsh-auth-keyring` crate — one credential per
session field (`access_token`, `refresh_token`, `id_token`, non-secret
`meta`) under one service name, so no single entry approaches the Windows
Credential Manager's 2560-byte blob cap:

| OS | Default store | `--store keyring` uses |
|---|---|---|
| macOS | keyring | login Keychain |
| Windows | keyring | Credential Manager (DPAPI-protected) |
| Linux | `json` | freedesktop Secret Service |

Linux defaults to the JSON files because a Secret Service daemon is not
guaranteed there (headless sessions, minimal window managers). Whichever
store is active is named in the startup log, and a default that cannot be
honored falls back to JSON with a warn line — never silently. `--store
keyring` asks for the keyring explicitly; if the binary was built with
`--no-default-features` (no keyring compiled in), that is a startup error,
and on Linux an absent daemon surfaces as a store error at first use.

`--store json` selects the crate's `JsonFileStore`: one 0600 file per
provider at `~/.nsh-auth-desktop/<provider>.json` (the directory is created
0700). It is an ordinary-file baseline, not secure storage — any process
running as your user can read it, there is no per-item access control or
consent prompt, and backups include it.

Residuals the keyring stores do not remove: no biometric gate or per-use
consent (keyring exposes no such options), no iCloud sync, and on macOS the
Keychain ACL names the creating binary — an unsigned dev rebuild can raise
the "wants to access your confidential information" prompt, which no keyring
API can suppress.

## Web

The web surface is not this app: it is the demo served with
`nsh run --target web` — see `examples/demo/README.md`.

## Gates

```sh
cd examples/host-desktop
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo build
```

Headless UI tests run with `cargo test` (they render the screen and never
open a browser). Two of them run the complete mock loop — authorize,
redirect through the real loopback callback server, exchange, userinfo,
session — once through the platform transport and once through the
`--transport reqwest` escape hatch, both against an in-test loopback-only
mock provider; the reqwest one is the standing probe for the phase-2 stall
(docs/upstream-issues.md).
