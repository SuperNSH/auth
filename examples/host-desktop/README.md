# host-desktop — the desktop launcher

An NSH Rust app that signs in through the system browser and receives the
redirect on a `127.0.0.1` loopback port it binds with an OS-assigned port.
One window: a provider list, the crate's status, and the session once the
loop is complete.

Flow, in order: the app binds `127.0.0.1:0`, builds the crate's `Auth` with
`redirect_uri = http://127.0.0.1:<port>/callback`, calls
`authorize_request(provider)` (PKCE, `state`, `nonce` are the crate's job),
opens the browser at the authorize URL (`open` on macOS), serves exactly one
`/callback` request on the listener, and hands the callback URL to
`complete(provider, url)`. The window's status, session and user read the
crate's signals directly. Sign-out calls `sign_out()`.

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
| `--broker-url <url>` | Token broker for confidential clients (GitHub) | `http://127.0.0.1:8760` |

The mock provider talks to the server from `tools/mock-oauth` (see its
README for how to start it). GitHub exchanges tokens only through the broker
from the same area — no client secret exists in this app to remove.

## Where the proof lands

Proof logs go to **stderr** (they are on at `info` by default, no `RUST_LOG`
needed):

```sh
cargo run -p host-desktop -- --provider mock 2> /tmp/host-desktop.log
```

The lines, in order: `authorize Google -> <authorize URL, state and nonce
redacted>` (the endpoint, client id, scopes, redirect URI and
`code_challenge_method` — the trigger proof; `state` and `nonce` are
anti-CSRF secrets, so their values never reach the log), `browser opened;
waiting for the callback on http://127.0.0.1:<port>/callback`, `callback
received on ...`, and `mock sign-in complete (scope: …)` (or
`mock sign-in failed: <error>`). Tokens are never logged or shown on screen.

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

- The listener binds `127.0.0.1` only, on a port the OS assigned (`:0`).
- Requests must hit `/callback` with `Host: 127.0.0.1:<port>`; anything else
  gets a 403/404, which is the DNS-rebinding resistance.
- One registration per flow, consumed by one request; late or duplicate
  callbacks find nothing pending. `state` equality is enforced by the crate
  when the callback URL is completed.
- The browser is opened by a fixed program (`open` / `xdg-open` /
  `rundll32 url.dll,FileProtocolHandler`) with the URL as a single argument —
  no shell string.

## Storage on macOS, honestly

This launcher stores sessions in **JSON files with 0600 permissions** at
`~/.nsh-auth-desktop/<provider>.json` (for example `google.json`; the
directory is created 0700), via the crate's `JsonFileStore`. That is
documented here as a limitation, not a feature: it is **not** the Keychain.
What it cannot do:

- any process running as your user can read the tokens; there is no
  per-item access control, no user-consent prompt, and no biometric gate;
- the file is ordinary disk content — nothing ties it to device unlock or a
  secure enclave, and backup tools will include it;
- revocation of the file does not revoke Keychain items or sessions on
  other devices.

Keychain integration is future work; the crate's `SessionStore` trait is the
seam it will land behind.

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
open a browser).
