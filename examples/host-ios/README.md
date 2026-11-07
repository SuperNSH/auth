# examples/host-ios — the iOS embedding host

A UIKit app (`dev.nshauth.sandbox`) that embeds the demo (`examples/demo`)
through `NshAppView` and serves its `auth.*` host calls:
`ASWebAuthenticationSession` for `auth.authorize`, Keychain for
`auth.store.*`. The URL scheme `nsh.auth.sandbox` is registered in
`Info.plist`; there are no entitlements, no signing team, simulator only.
The `auth.*` payload contract is documented in `native/ios/README.md`.

App target `NshAuthSandbox`; scheme `NshAuthSandbox`. A build phase runs
`scripts/demo-bundle.sh`, which builds the demo with the command documented in
`examples/demo/README.md` (falling back to `nsh build --release --out`, the
form used by nsh 0.4.0 `examples/embed-ios`) and copies the bundle into
`./nsh`, a folder reference — bytecode loads only from the app bundle. Debug
links `NativeShellDev.xcframework`, Release links `NativeShell.xcframework`
(both static, from `$(brew --prefix nsh)/libexec/embed/ios`, pinned by
`NSH_EMBED_DIR` in the project).

Requirements: `nsh` 0.4.0 (never upgrade), Xcode with the iOS 27 simulator
runtime, and the simulator named `nsh-auth`:

```sh
xcrun simctl list devices | grep 'nsh-auth ('
```

All commands run from the repository root.

## The gate

Runs the demo build, copies the bundle in, and xcodebuilds; fails on any
error, including a missing `bundle.nshc`, an unregistered URL scheme, or a
`client_secret` in the built app:

```sh
./examples/host-ios/build-gate.sh
```

## The demo build step the gate runs

`scripts/demo-bundle.sh --force` — extracts the first `nsh build` command from
`examples/demo/README.md` code fences and runs it verbatim (appending
`--out` when missing), copying its output to `examples/host-ios/nsh/`. Run it
alone with:

```sh
examples/host-ios/scripts/demo-bundle.sh --force
```

## Build only (what the gate's last step runs)

```sh
xcodebuild \
  -project examples/host-ios/NshAuthHostIOS.xcodeproj \
  -scheme NshAuthSandbox \
  -configuration Debug \
  -destination 'id=DEE48BA7-1919-47BC-A04A-887B6D2AB046' \
  -derivedDataPath examples/host-ios/build/derived \
  build
```

The destination is the shared simulator named `nsh-auth` (iPhone 18 Pro,
iOS 27). Touch that one only.

## Install and launch

```sh
xcrun simctl boot DEE48BA7-1919-47BC-A04A-887B6D2AB046 || true
xcrun simctl install DEE48BA7-1919-47BC-A04A-887B6D2AB046 \
  examples/host-ios/build/derived/Build/Products/Debug-iphonesimulator/NshAuthSandbox.app
xcrun simctl launch DEE48BA7-1919-47BC-A04A-887B6D2AB046 dev.nshauth.sandbox
```

Launch with a provider auto-started — simctl passes the trailing arguments to
the process, where `AuthHostModule` reads them via `ProcessInfo`. Launch
arguments only apply to a fresh launch, so terminate first:

```sh
xcrun simctl terminate DEE48BA7-1919-47BC-A04A-887B6D2AB046 dev.nshauth.sandbox
xcrun simctl launch DEE48BA7-1919-47BC-A04A-887B6D2AB046 dev.nshauth.sandbox --provider google
```

## Screenshots

```sh
xcrun simctl io DEE48BA7-1919-47BC-A04A-887B6D2AB046 screenshot docs/evidence/<provider>/ios-simulator.png
```

Look at every PNG after saving it. The proof is the system sign-in surface on
the provider's own domain; a provider error page for the fake client id also
passes. Stop there — never sign in, never type a credential.

## Full mock loop

Start `tools/mock-oauth` first (see its README), then install and launch as
above; the demo's mock provider round-trips through `ASWebAuthenticationSession`
and the `nsh.auth.sandbox` callback. The mock must run on loopback; the app's
ATS exception covers local networking only.

## Layout

- `Sources/AppDelegate.swift` — app entry. UIScene lifecycle (required on the
  iOS 26+ SDK): `SceneDelegate` owns the window and URL contexts,
  `HostViewController` wires `NshAppView` (grants and handlers before
  `loadBundle`).
- `../native/ios/Sources/` — `AuthHostModule` and `AuthKeychain`, referenced
  directly by the project.
- `scripts/demo-bundle.sh` — demo build + bundle copy (stamp-based, so the
  Xcode build phase is incremental).
- `build-gate.sh` — the gate. `nsh/` and `build/` are generated and ignored.
