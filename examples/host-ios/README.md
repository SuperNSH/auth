# examples/host-ios — the iOS embedding host

A UIKit app (`dev.nshauth.sandbox`) that embeds the demo (`examples/demo`)
through `NshAppView` and serves its `auth.*` host calls:
`ASWebAuthenticationSession` for `auth.authorize`, native SDK sign-ins for
`auth.nativeSignIn`, Keychain for `auth.store.*`. The URL schemes
`nsh.auth.sandbox`, the reversed Google client id
(`com.googleusercontent.apps.nsh-auth-sandbox`) and `fb1234567890123456` are
registered in `Info.plist`. Ad-hoc signing, no team, simulator only — but the
app carries `NshAuthSandbox.entitlements` with the Sign in with Apple
capability (`CODE_SIGN_ENTITLEMENTS` in the pbxproj). The `auth.*` payload
contract is documented in `native/ios/README.md`.

## SPM packages and the network at gate time

Phase 3 links two SwiftPM packages (hand-written pbxproj sections, exact
version pins):

- `GoogleSignIn` 10.1.0 — `https://github.com/google/GoogleSignIn-iOS`
- `FacebookLogin` 19.0.1 — `https://github.com/facebook/facebook-ios-sdk`
  (binary XCFrameworks; their SHA-256 checksums are pinned in upstream's
  `Package.swift`)

The gate therefore needs NETWORK access to `github.com` for package
resolution — it is no longer hermetic, accepted for phase 3. Versions are
pinned two ways: `exactVersion` requirements in the pbxproj and the committed
`NshAuthHostIOS.xcodeproj/project.xcworkspace/xcshareddata/swiftpm/Package.resolved`,
which the gate enforces with `-onlyUsePackageVersionsFromResolvedFile`.
Bootstrap on a clean clone (once):

```sh
xcodebuild -project examples/host-ios/NshAuthHostIOS.xcodeproj \
  -scheme NshAuthSandbox -resolvePackageDependencies \
  -derivedDataPath examples/host-ios/build/derived
```

which regenerates `Package.resolved` (commit it); delete the file to
re-bootstrap. Note that passing `-resolvePackageDependencies` together with a
`build` action makes xcodebuild resolve and exit without building, so the
gate runs resolution and the build as two invocations. Package clones land
under `build/derived/SourcePackages/`, gitignored.

App target `NshAuthSandbox`; scheme `NshAuthSandbox`. A build phase runs
`scripts/demo-bundle.sh`, which builds the demo with the command documented in
`examples/demo/README.md` (falling back to `nsh build --release --out`, the
form used by nsh's `examples/embed-ios`) and copies the bundle into
`./nsh`, a folder reference — bytecode loads only from the app bundle. Debug
links `NativeShellDev.xcframework`, Release links `NativeShell.xcframework`
(both static). `NSH_EMBED_DIR` in the project points at
`.nsh-embed/0.5.0/ios` at the repository root, which
`tools/fetch-nsh-embed.sh ios` fills from the v0.5.0 release's
`nsh-embed-ios.zip`, checked against a pinned sha256 (git-ignored; the gate
runs it, and a plain `xcodebuild` needs it run once). NSH 0.5.0 no longer
puts these frameworks in its install, and Homebrew's formula is still 0.4.0.
Pass `NSH_EMBED_DIR=<dir>` to the gate or to `xcodebuild` to use other copies.

Requirements: `nsh` 0.5.0 from the upstream installer (`~/.nsh/bin`, which
the build phase puts ahead of Homebrew's 0.4.0 and checks), network access to
github.com for the first fetch of the embedding frameworks, Xcode with the iOS 27 simulator
runtime, and the simulator named `nsh-auth`:

```sh
xcrun simctl list devices | grep 'nsh-auth ('
```

All commands run from the repository root.

## The gate

Runs the demo build, copies the bundle in, resolves the pinned SPM packages
(network, see above), and xcodebuilds; then fails on any error, including a
missing `bundle.nshc`, any unregistered URL scheme (`nsh.auth.sandbox`, the
reversed Google client id, `fb1234567890123456`), a missing
`com.apple.developer.applesignin` in the built executable's entitlements, or
an embedded `client_secret` value in the app. The bare OAuth parameter-name
constants inside the linked SDKs are allowed; the checks anchor on assigned
values in url/query, single- and double-quoted, and XML-plist (key and string
value on separate lines) forms, and self-test against planted files of each
form every run:

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
  -onlyUsePackageVersionsFromResolvedFile \
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
- `../native/ios/Sources/` — `AuthHostModule`, `NativeSignInModule`,
  `AuthSignInMath` and `AuthKeychain`, referenced directly by the project.
- `../native/ios/tests/` — swiftc-compiled unit asserts for the pure sign-in
  math (`auth-signin-math-test.sh`); run standalone or by the gate.
- `NshAuthSandbox.entitlements` — Sign in with Apple. On the iOS 27 SDK the
  simulator does not embed app entitlements in the code signature
  (`ENTITLEMENTS_ALLOWED=NO`); Xcode links them into the executable's
  `__TEXT,__entitlements` section instead, which is what the gate checks.
  Runtime enforcement of the capability on an ad-hoc simulator build is
  undocumented — see the open item in `docs/research/native-sdks.md` §3.
- `scripts/demo-bundle.sh` — demo build + bundle copy (stamp-based, so the
  Xcode build phase is incremental).
- `build-gate.sh` — the gate. `nsh/` and `build/` are generated and ignored.
