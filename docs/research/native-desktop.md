# Native desktop research — secure storage and the loopback callback (phase 2)

Phase-2 question set for the desktop host (`examples/host-desktop/`): can we
replace the hand-rolled 0600 JSON store with proven library code, and what does
the Tauri ecosystem's loopback plugin do better or worse than ours. Written
2026-11-07 against: `keyring` 3.6.3 (source read from the local cargo
registry) and the 4.x line (crates.io API), `tauri-plugin-oauth` 2.1.0 (source
read from GitHub), the local sibling `~/fo/nsh-secure-storage` (read-only),
`~/fo/nsh-starter` (read-only) and `/Users/hmziq/fo/.refs/nsh-v0.4.0` (read-only).
NSH stays 0.4.0 (e626a8d). Everything quoted from local source says so; web
claims carry their URL.

Starting points in this repo:

- The store seam: `crates/nsh-auth/src/store.rs` — `trait SessionStore` with
  `save/load/clear`, plus `MemoryStore` and `JsonFileStore` (0600 files,
  mode set at creation, no write-then-chmod window).
- The desktop store: `examples/host-desktop/src/session_store.rs` picks
  `~/.nsh-auth-desktop/` (0700 dir); `examples/host-desktop/README.md`
  ("Storage on macOS, honestly") documents the limitation.
- The loopback: `examples/host-desktop/src/loopback.rs` — 127.0.0.1, OS-assigned
  port, exact `/callback` path, GET only, exact `Host: 127.0.0.1:<port>` match,
  8 KiB request cap, 5 s read timeout, single-use `take()` registration.

---

## Question 1 — `keyring` for the desktop session store

### The crate, today

Two lines exist. v3.6.3 is the single-crate form (the copy in the local cargo
registry is fully readable; `license = "MIT OR Apache-2.0"`, MSRV 1.75). v4
is the current line: 4.2.0 released 2026-08-29; the API library split into
`keyring-core` 1.0.1 and one store crate per platform
(`apple-native-keyring-store` 1.0.2, `windows-native-keyring-store` 1.1.0,
`zbus-secret-service-keyring-store` 1.0.1 — all verified on crates.io,
all MIT OR Apache-2.0). The 4.x README tells app developers to depend on
`keyring-core` plus only the store crates they need, and warns off the
`keyring` crate's own `cli` feature. All versions: MIT OR Apache-2.0.

v3.6.3 features, from its `Cargo.toml`: `apple-native` (security-framework 3
on macOS, 2 on iOS), `windows-native` (`windows-sys` 0.60, feature
`Win32_Security_Credentials` — the `CredWriteW`/`CredReadW` generic-credential
family), `sync-secret-service` (`dbus-secret-service`, needs `libdbus`),
`async-secret-service` (`secret-service` + `zbus`), `linux-native`
(`linux-keyutils`), `vendored` (statically links dbus), plus a built-in
`mock` keystore. v3 has no default stores: an app names them explicitly.

### Per-platform behavior, from source

**Windows.** `src/windows.rs` enforces the Credential Manager limits and
returns `Error::TooLong(name, limit)`: the secret blob is capped at
`CRED_MAX_CREDENTIAL_BLOB_SIZE` — verified as literal `2560` in the local
`windows-sys-0.60.2` source (`Security/Credentials/mod.rs:378`) — for both
`set_secret` (`secret.len()`) and `set_password` (UTF-16 length × 2). The
README warns that Windows does not serialize concurrent calls to one
credential from different threads. Protection is DPAPI under the hood: the
OS encrypts the credential blob for the logged-in user, so the honest
"0600 file" limitation is fixed without us touching DPAPI.

That 2560-byte cap is the one real risk for us. Our `Session` JSON
(`crates/nsh-auth/src/session.rs`: provider, access_token, refresh_token,
id_token, expires_at, scope) is provider-dependent: Google-shaped sessions
are roughly 1.1–1.6 KB (an RS256 id_token alone is ~750–1,000 base64 chars),
but Microsoft-shaped sessions (multi-KB JWT access token plus id_token) can
plausibly cross 3 KB. Estimate, not a measurement — but the mitigation is
cheap either way: **one keyring entry per secret field** (access, refresh,
id_token) under a shared service name, each safely under 2560, rather than
one entry holding the whole serialized session. Non-secret fields
(provider, expiry, scope) can stay in the existing JSON file or be
reconstructed. Keychain and Secret Service have no comparable small cap.

**macOS.** `src/macos.rs` uses the legacy generic-password API
(`SecKeychain::set_generic_password`, `find_generic_password`) against the
login keychain. Quirks, from the module docs: service and account must be
non-empty (empty is a lookup wildcard); items appear in Keychain Access as
passwords. Because the API is the legacy keychain, there are no per-item
options — no accessibility level, no label, no operation prompt, no
synchronizable flag. The ACL prompt is real: an item's access list names the
binary that created it, so a read from a differently-signed binary (which
happens on every dev rebuild) can raise the "wants to access your
confidential information" dialog. Nothing in keyring's API controls that.
The macOS data-protection keychain, which has modern semantics, needs the
keychain-access-group entitlement — our sibling measured unsigned binaries
failing with `errSecMissingEntitlement` there (see below).

**Linux.** Three options in v3: Secret Service (D-Bus, `org.freedesktop.secrets`,
implemented by gnome-keyring/KWallet), kernel keyutils, and the combo. The
quirks are documented in the crate README and `src/keyutils.rs`:

- Every Secret Service call is an IPC round trip (tens to hundreds of ms);
  a write-through cache is recommended for hammering workloads.
- `sync-secret-service` needs `libdbus` on the machine (it is present on
  desktop installs that ship a secret service; the `vendored` feature
  statically links it, at the cost of rebuilds for libdbus updates).
  The v4 ecosystem crate `zbus-secret-service-keyring-store` uses `zbus`
  (pure-Rust D-Bus) instead — no C library at runtime.
- If no secret-service daemon runs (headless server, minimal WM session,
  CI), storage fails — a host must fall back (ours would fall back to
  `JsonFileStore` and say so).
- Kernel keyutils does **not** persist across reboots ("completely
  in-memory", `src/keyutils.rs` docs); `linux-native-sync-persistent`
  combines keyutils as a cache with Secret Service as the durable back end.

### Does it fix the honest limitation?

Yes, on all three desktops, with one caveat per platform. A keyring-backed
store gives us: per-item access control tied to the app (Keychain ACL),
DPAPI-grade per-user encryption (Windows Credential Manager), the standard
desktop secret service (Linux), tooling visibility (Keychain Access /
Credential Manager UI / seahorse), and no tokens on disk in our own files.
It does not give: a biometric gate or per-use consent (keyring exposes no
such options), iCloud sync, and on Linux it presumes a running secret
service. The README section "Storage on macOS, honestly" would be replaced
by a per-platform table with the Linux fallback stated.

### Mapping onto our seam, and where it lives

The trait already fits exactly: `save` → `set_secret(serialized)` (or three
field entries), `load` → `get_secret` + deserialize, `clear` →
`delete_credential`; `Entry::new("nsh-auth", provider_slug)`; keyring's
`Error` maps to `AuthError::StoreError`, `Error::NoEntry` to `Ok(None)`.
Threading: keyring is always synchronous, so the host's existing
`blocking(move |..| ..)` wrapper is the right call site.

Where the `KeyringStore` implementation goes — three options, and the
phase-2 note this task was asked to record:

1. **Feature-gated module in `crates/nsh-auth`** (e.g. `src/store_keyring.rs`
   behind a `keyring` cargo feature, off by default so iOS/Android/web
   builds never pull dbus or windows-sys). Cleanest for consumers, but it
   edits `crates/nsh-auth/Cargo.toml` and (honestly) the doc comment on the
   trait itself — `store.rs:10-12` says secure stores "live in the embedding
   hosts", which phase 2 would amend to "or this crate's feature-gated
   desktop store". Those files belong to the rust-core area historically;
   the change is small and should be coordinated with that area rather than
   driven through the desktop area's files.
2. **A new crate `crates/nsh-auth-keyring`** (dep on `nsh-auth` for the
   trait, keyring for the store; one new workspace member line in the root
   `Cargo.toml`). Keeps every existing file's ownership untouched; the
   recommended shape if the crate area does not take option 1.
3. **Inside `examples/host-desktop`** (next to `session_store.rs`). Smallest
   change, but demo-grade: other Rust hosts cannot reuse it.

### The sibling context, which changes the long-term answer

`~/fo/nsh-secure-storage` (sibling project, under construction; read-only)
already made this decision at source level on 2026-11-07
(`docs/decisions.md`): Apple gets its own backend on `security-framework`
3.7.0 because `apple-native-keyring-store` lacks per-item label, comment,
accessibility and prompt options; Windows and Linux build on `keyring-core`
with `windows-native-keyring-store` and `zbus-secret-service-keyring-store`;
Android gets its own JNI Keystore backend because the keyring ecosystem's
Android store uses SharedPreferences that Auto Backup includes. It also
solved the testing problems a Keychain store drags in (never touch the login
keychain in tests, never let a test open a system dialog, throwaway keychain
files, `errSecMissingEntitlement` as a mapped error).

So the concrete recommendation: **adopt now, thin.** Land a `KeyringStore`
behind the existing `SessionStore` trait (option 1 or 2 above) against the
keyring 4.x family (`keyring-core` + the three platform store crates; v3.6.3
with `apple-native`, `windows-native`, `sync-secret-service` is the
acceptable fallback if a single-crate dependency is preferred), with
per-field entries for the Windows blob cap and a `JsonFileStore` fallback
when the Linux daemon is absent — surfaced as a status, never silent. When
`nsh-secure-storage` ships, its back end replaces the KeyringStore's
internals behind the same trait; the trait is precisely the seam that makes
that swap a one-file change.

### Windows DPAPI direct vs keyring — one paragraph

Direct DPAPI via the `windows` crate is fully reachable:
`CryptProtectData`/`CryptUnprotectData` sit in
`windows::Win32::Security::Cryptography` (verified in the local
`windows-sys-0.59.0` source, `crypt32.dll` link), with optional extra
entropy, machine-vs-user scope, and prompt flags — and nothing else changes:
the ciphertext still lands in a file we own, with permissions we manage,
invisible to the tools users know, and needing our own honest-limitation
paragraph again. keyring's `windows-native` path instead stores generic
credentials through the Credential Manager (`CredWriteW`), where the OS
applies DPAPI for us, exposes the items in `credwiz`/Credential Manager,
and gives the same API on all three desktops — at the cost of the 2560-byte
blob and no entropy control (both irrelevant for per-field token entries).
Direct DPAPI is the right tool only if we ever need >2560-byte secrets or
local-machine scope; for per-provider session tokens, keyring wins.

---

## Question 2 — the Tauri ecosystem's loopback (`tauri-plugin-oauth`)

**Provenance.** The plugin the brief named is no longer in
`tauri-apps/plugins-workspace` (the `plugins/` directory lists no `oauth`;
the request for an official OAuth plugin, issue #265, was never fulfilled).
It lives on at [FabianLars/tauri-plugin-oauth](https://github.com/FabianLars/tauri-plugin-oauth)
(Fabian Lars is Tauri core team): `tauri-plugin-oauth` 2.1.0 on crates.io
(2026-07-07), MIT OR Apache-2.0, runtime deps `httparse`, `serde`, `log`,
`url`, `tauri`. The 281-line `src/lib.rs` is the whole server.

**Its design, from source.** `start(handler)` binds `127.0.0.1:0` (or a
configured fixed port list "only … if your oauth provider does not accept
wildcard localhost addresses"), spawns an accept thread, returns the port.
One connection, one response:

- A connection is a single 4,048-byte read (no loop, no read timeout).
- `GET /exit` or a magic 4-byte payload (`[1, 3, 3, 7]`) tells the loop to
  stop — `cancel(port)` self-connects and writes it, an explicit graceful
  shutdown without OS-handle gymnastics.
- Any path, any method: the plugin never checks them. The Host check is
  `header.value.starts_with("localhost")` — weaker than ours (any port
  matches, and a `127.0.0.1` Host does not even count; a rebinding host that
  keeps the `localhost` prefix would pass).
- To capture what the browser really did, the served page injects a script
  that `fetch`es `http://…/cb` with a `Full-Url: window.location.href`
  header — a second connection carries the true URL. That is how it accepts
  providers that redirect to arbitrary paths and how it would see fragments
  (which never reach a server). The handler then receives the full URL, and
  the plugin's own README says: "Because of the unprotected localhost port,
  you must verify the URL here."
- Options: static response HTML, a `redirect_uri` to 302 the browser
  elsewhere after capture, the fixed port list. Tauri command wrappers emit
  `oauth://url` / `oauth://invalid-url`.

**Against ours (`examples/host-desktop/src/loopback.rs`).**

| | theirs 2.1.0 | ours |
|---|---|---|
| bind | 127.0.0.1, `:0` or fixed list | 127.0.0.1, `:0` only |
| path | any | exact `/callback` (404 otherwise) |
| method | any | GET only (405 otherwise) |
| Host | `starts_with("localhost")` | exact `127.0.0.1:<port>` (403 — the DNS-rebinding guard) |
| read | one 4,048-byte read, no timeout | to end-of-headers or 8,192 bytes, 5 s timeout |
| capture | page JS posts the URL back | server-side, query passed through percent-encoded |
| lifetime | auto-stop after one handled connection, or `cancel()` | listener lives for the process; per-flow single-use `take()` |
| state | none — handler validates | `state`/`nonce` verified by the crate on `complete()` |

**Adopt from it:** (1) an explicit `cancel()` — their magic-bytes
self-connect is a clean way to stop the accept thread; ours deliberately
lives for the process, but a `shutdown()` would give tests and multi-window
hosts a clean teardown instead of thread-for-process-life; (2) an optional
fixed-port fallback in `Options` for any future provider that insists on a
pre-registered exact port (all current loopback providers in
`docs/providers.md` accept wildcard ports, so this is config, not core);
(3) nothing else. **Keep everything of ours:** the exact path, method and
Host checks, the byte cap and read timeout, single-use registration, and
server-side capture (no JS served from an unprotected local port — their
`Full-Url` dance also means the handler must validate URLs, which ours
never has to). Their weaknesses are documented upstream expectations, not
bugs to import. Tauri's other desktop path — the `deep-link` plugin with
custom schemes and auto-start — maps to what `~/fo/nsh-starter` does with
launch arguments (next section), and stays the mobile-first pattern for us.

---

## Question 3 — the GPUI starter and `embed-gpui`, read-only

**`~/fo/nsh-starter` exists** (shared machine; nothing written, nothing
built there). It is *not* a GPUI host: it is the NSH Rust-first starter
(`platform::run_app`, one crate at the root) that mirrors an external
desktop "gpui-starter" boilerplate feature-for-feature
(`docs/gpui-starter-parity.md` records the mapping).

**Auth status: a seam, no auth.** `src/services/auth.rs` is a mock
`AuthProvider` trait (`current_user` / `sign_in` / `sign_out`, object-safe
`AuthFut`) with an in-memory `MockAuthProvider` — any well-formed email and
a non-empty password signs in a fake user; nothing persists, nothing
networks. There is no OAuth, no loopback listener, no browser launch, no
secure storage anywhere in the tree: the parity doc states "secrets are
never persisted in this sandbox … the auth seam documents where the real
provider would store tokens", and the swap-in point is one file ("the real
provider swaps in from the nsh-auth project by replacing one file").

**What is worth adopting for the wrapper design:**

- The **deep-link seam**, `src/shell/deep_link.rs`: `SCHEME` constant,
  a `OnceLock<String>` `PENDING` filled from launch arguments before the
  engine runs (`main.rs` parses `argv` for `nsh-starter://…`), `open(url)`
  parsing into typed routes, `open_pending()` replayed once from the shell
  install. This is exactly the 0.4.0 shape a desktop OAuth custom-scheme
  redirect must take (the OS delivers a second launch, the host forwards the
  URL into the core) and the documented hook for an embedding host's
  delivery. A future GPUI host should keep this three-part shape: scheme
  const, launch-arg staging, one `open()` seam the host calls.
- The **service-seam style**: `Arc<dyn Trait>` behind a `LazyLock` singleton
  (`services/auth.rs:provider()`), one-file swap. The nsh-auth wrapper for a
  GPUI host should be the mirror image: one adapter file that builds the
  crate's `Auth` on the host's `SessionStore` choice and exposes the
  session/user/status signals to GPUI code, so swapping stores or launchers
  never touches call sites.

**`/Users/hmziq/fo/.refs/nsh-v0.4.0/examples/embed-gpui`** is the
host-embedding record for GPUI — a GPUI Kit trading app embedding NSH
surfaces. The shape a future GPUI auth host would follow:

- `nsh_platform_gpui::{App, AppOptions, AppView, AssetBase, Bundle}`
  (`src/main.rs:63`); each embedded surface is an `Entity<AppView>` built
  with `cx.new(|cx| AppView::new(options, window, cx))` (`src/main.rs:600`);
  dropping the view stops that surface's engine.
- Host functions are a Rust module registered as a UI set:
  `nsh_platform_gpui::set_ui_sets(vec![nsh_base::registry(),
  trading::registry()])` (`src/main.rs:639`), reached from the app as
  `nativeModule("host/trading")`. An auth host would register a
  `host/auth` set the same way (browser launch, loopback control, vault).
- Host widgets can enter the app as native components (`src/watchlist.rs`,
  `src/switch.rs`); host theme reaches surfaces on every change via
  `cx.observe_global::<Theme>` (`src/theme.rs`).
- `build.rs` bundles and compiles the TSX app (`app/`) with `nsh-bundler`,
  and the example is its own Cargo workspace so GPUI stays out of NSH's
  workspace builds — the same pattern to repeat for a GPUI auth demo.

**No auth-related pattern exists in embed-gpui** (no storage, no browser
launch, no loopback — it is a paper-trading demo with a `tokio::sync::watch`
desk). What it proves is the embedding shape, not the auth design; the auth
design stays ours (`browser.rs` argv launch, `loopback.rs`, the
`SessionStore` seam), delivered through a `host/auth` UI set.

---

## Adoption verdict

| Target | Verdict | Why |
|---|---|---|
| `keyring` 4.x family (`keyring-core` + `windows-native-keyring-store` + `zbus-secret-service-keyring-store` + `apple-native-keyring-store`) as a **`KeyringStore`** behind `SessionStore` | **adapted — adopt now** | Fixes the README's honest limitation on all three desktops; the trait already fits (`save/load/clear` ↔ `set_secret/get_secret/delete_credential`); per-field entries dodge the Windows 2560-byte blob; `JsonFileStore` stays as the Linux no-daemon fallback and the test store. Location: feature-gated module in `crates/nsh-auth` (coordinate with the rust-core area; the trait's doc comment changes) or a new `crates/nsh-auth-keyring` crate. The sibling `nsh-secure-storage` becomes the internals later — the trait makes that a one-file swap. |
| `keyring` 3.6.3 single-crate | **kept as fallback** | Acceptable (`apple-native` + `windows-native` + `sync-secret-service`), but it is the previous major line; prefer 4.x to stay on the maintained shape the sibling standardized on. |
| `tauri-plugin-oauth` 2.1.0 | **kept-skip** (adopt two ideas only) | Our `loopback.rs` is strictly harder: exact path, GET only, exact-Host rebinding guard, byte cap, read timeout, single-use registration, server-side capture without served JS. Adopt its explicit `cancel()` shutdown and, later, an optional fixed-port config for exact-port providers. Do not import its permissive model (any path/method, weak `localhost` Host check, no timeout, "verify the URL yourself"). |
| Direct DPAPI via the `windows` crate | **kept-skip** | keyring's Windows-native path gives DPAPI-backed protection through the Credential Manager with cross-platform API parity; direct DPAPI only pays off for >2560-byte secrets or machine scope, neither of which we have with per-field token entries. |
| `nsh-starter` deep-link + service seams | **adapted** | Its `deep_link.rs` (scheme const / launch-arg staging / one `open()` seam) and one-file service-swap style are the wrapper shape for a future GPUI host; it has no OAuth or storage to reuse as-is. |
| `embed-gpui` host shape | **adapted** | `AppView` per surface, `set_ui_sets` host functions (`host/auth`), native components, theme push, `build.rs` bundling, own workspace — the record to copy for a GPUI auth demo; it contains no auth code itself. |

**Licenses:** `keyring` and the whole 4.x family (`keyring-core`,
`apple-native-keyring-store`, `windows-native-keyring-store`,
`zbus-secret-service-keyring-store`) are MIT OR Apache-2.0 (crates.io API,
2026-11-07); `tauri-plugin-oauth` is MIT OR Apache-2.0. Compatible with this
repo's dual-license surface.

**Blockers:** none hard. Open items: the Windows 2560-byte cap makes the
whole-session-in-one-entry design wrong — the field-per-entry shape is part
of the adoption; macOS ACL prompts can appear for unsigned dev builds
(accepted residual, document it); Linux Secret Service absence must fall
back visibly, not silently; landing the store inside `crates/nsh-auth`
needs the rust-core area's coordination (or the separate-crate option).

**Sources:** [keyring on crates.io](https://crates.io/crates/keyring),
[keyring-rs (4.x, open-source-cooperative)](https://github.com/open-source-cooperative/keyring-rs),
keyring 3.6.3 source at `~/.cargo/registry/src/index.crates.io-*/keyring-3.6.3/`
(read locally), [tauri-plugin-oauth](https://github.com/FabianLars/tauri-plugin-oauth)
(source read via GitHub), [plugins-workspace issue #265](https://github.com/tauri-apps/plugins-workspace/issues/265),
[RFC 8252 §7.3](https://www.rfc-editor.org/rfc/rfc8252.txt),
`~/fo/nsh-secure-storage/docs/decisions.md` (read-only sibling).

```json
{
  "done": true,
  "summary": "Desktop phase-2 research: keyring 4.x family recommended behind the existing SessionStore trait (KeyringStore, field-per-entry for the Windows 2560-byte blob cap, JsonFileStore as the visible Linux fallback); tauri-plugin-oauth studied at source and skipped in favor of our hardened loopback (adopt only its cancel() and optional fixed-port config); nsh-starter has a mock auth seam and a deep-link/service-seam shape worth mirroring; embed-gpui records the GPUI host-embedding shape (AppView + set_ui_sets) for a future host/auth UI set; direct DPAPI skipped in favor of keyring's Credential Manager path.",
  "verdict": {
    "vendored": [],
    "adapted": [
      "keyring 4.x family as KeyringStore behind SessionStore (keyring-core 1.0.1 + apple-native-keyring-store 1.0.2 + windows-native-keyring-store 1.1.0 + zbus-secret-service-keyring-store 1.0.1)",
      "tauri-plugin-oauth ideas: explicit cancel() shutdown, optional fixed-port config",
      "nsh-starter deep-link seam and one-file service-swap style for the GPUI wrapper design",
      "embed-gpui host-embedding shape (Entity<AppView>, set_ui_sets, build.rs bundling, own workspace) for a future host/auth UI set"
    ],
    "kept": [
      "examples/host-desktop loopback.rs (exact path, GET, exact-Host rebinding guard, 8 KiB cap, 5 s timeout, single-use take)",
      "JsonFileStore as fallback/test store and MemoryStore for tests",
      "browser.rs argv browser launch (open/xdg-open/rundll32, single-argument URL)",
      "tauri-plugin-oauth library itself (skip: permissive model)",
      "direct DPAPI via windows crate (skip: no need beyond Credential Manager)"
    ]
  },
  "licenses": [
    "keyring: MIT OR Apache-2.0",
    "keyring-core: MIT OR Apache-2.0",
    "apple-native-keyring-store: MIT OR Apache-2.0",
    "windows-native-keyring-store: MIT OR Apache-2.0",
    "zbus-secret-service-keyring-store: MIT OR Apache-2.0",
    "tauri-plugin-oauth: MIT OR Apache-2.0"
  ],
  "blockers": [
    "Windows CRED_MAX_CREDENTIAL_BLOB_SIZE (2560 B, verified in windows-sys 0.60.2 source) forbids the whole-session-in-one-entry design; KeyringStore must use field-per-entry or vault-only refresh/id_token",
    "KeyringStore inside crates/nsh-auth edits the rust-core area's Cargo.toml and the trait doc comment in store.rs — coordinate, or land as crates/nsh-auth-keyring",
    "macOS ACL prompts may appear for unsigned dev rebuilds (keyring exposes no ACL control) — accepted residual to document",
    "Linux Secret Service absence (headless/minimal sessions) needs a visible JsonFileStore fallback, never silent",
    "Sibling nsh-secure-storage (under construction) will supersede keyring internals behind the same trait when it ships"
  ]
}
```
