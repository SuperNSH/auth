# Build nsh-auth

## Goal

Make `nsh-auth`: social and OAuth sign-in for Native Shell apps, in Rust and TypeScript, on iOS, Android, macOS, Windows, Linux and the web. Support Google, Facebook, Discord and GitHub first, then Apple, Microsoft, X and any generic OAuth 2.0 or OIDC provider. Sessions, refresh, sign-out and secure token storage included. An app calls one function and gets a signal holding the session.

Success does not need a real account. It needs proof that a real sign-in flow is triggered correctly on each platform, and a complete loop against a local mock.

This repository holds only directories, `.agents/skills`, `.zcode` and this prompt. You build everything else.

## Study first

Write `docs/research.md`, citing current official docs and the source you read:

- How each provider's flow works for a native public client: Google (installed apps, PKCE, loopback or custom scheme, and the block on embedded web views, `disallowed_useragent`), Facebook (manual login flow and PKCE, app-link redirect, its native SDK), Discord (OAuth2 with PKCE, public clients), GitHub (web flow, PKCE support, and whether a client secret is still needed, in which case a token broker is required), Apple (Sign in with Apple, form-post redirect, what the system button requires), Microsoft (MSAL patterns).
- How others do it per platform: `react-native-app-auth`, `expo-auth-session`, `flutter_appauth`, `google_sign_in`, AppAuth-iOS, AppAuth-Android, `better-auth`, `firebase_auth`. Clone what you need into `~/fo/.refs/`. Firebase's references are already there.
- RFC 8252 (OAuth for native apps), RFC 7636 (PKCE), and the current best practice for storing tokens on each platform.

Then find out what NSH 0.4.0 gives you, by experiment, and record it:

- `openUrl` opens a URL outside the app. It takes `capabilities.openUrl`, and tests record it in `app.openedUrls()` without opening anything.
- Inbound URLs: there is no `Linking` module in `.nsh/types` on 0.4.0 that the docs name. Look in `~/fo/.refs/nsh-v0.4.0` and `nsh-main`, including `crates/nsh-platform-windows/src/linking.rs` on main. `nsh package` has no URL-scheme setting, and an embedding host does: `host.on` can carry the redirect back from `AppDelegate` or an `Activity`.
- A Rust crate's native code is not sandboxed, so a loopback listener with `std::net` on desktop is possible. TSX has `net` for outbound sockets, and has no listener that the docs show. Verify.
- `Storage` is a plain store. Secure storage needs the Keychain, Android Keystore, DPAPI or Secret Service, so find out what each path can reach.
- A web view must not carry a provider's login: Google blocks it, and it exposes credentials to the app.

## The shape it will likely take

Test this against what you find, and change it if the evidence says so. Write down why.

- **Core, in both languages:** provider definitions, PKCE and `state` and `nonce`, authorize-URL building, callback parsing and validation, token exchange and refresh, ID-token claim reading with signature checks where the flow needs them, a session store behind a trait, single-flight refresh, sign-out with revocation, and `session`, `user` and `status` as signals. Rust in `crates/nsh-auth`, TypeScript in `packages/nsh-auth`, with the same behavior and tests, following `~/fo/nsh-query`'s structure.
- **Launchers, one per surface:** `ASWebAuthenticationSession` on iOS and macOS and Custom Tabs on Android, in `native/ios` and `native/android`, reached through `host.call("auth.authorize", ..)` from `examples/host-ios` and `examples/host-android`. Desktop in a Rust app: the system browser plus a `127.0.0.1` loopback listener with a random port. Web: redirect or popup, with `web.host`. Name a fallback for a TSX app packaged with no host, and say honestly what it cannot do.
- **Native SDK adapters, optional:** Google Sign-In, Facebook Login and Sign in with Apple through the hosts, behind the same provider interface, where the provider's rules or UX call for it.
- **Token broker seam:** GitHub and any provider that needs a confidential client goes through a small server the app owner runs. Ship a reference broker in `tools/`, and never embed a client secret in an app. A test greps build output to prove it.
- **Firebase seam:** a separate project, `nsh-firebase`, signs in with an ID token. Expose the provider's ID token and access token cleanly, and show this in docs. Do not depend on it.
- **Form and state:** the demo's email forms use `nsh-form`, and profile loading uses `nsh-query`.
- Audit: a `z-security-auditor` pass over redirect validation, state and nonce checks, token storage, logging and URL handling is a named phase of the core and launcher areas.

## Areas

Disjoint files:

1. **research**: `docs/research.md` and the NSH experiments.
2. **rust core** and 3. **ts core**.
4. **providers**: Google, Facebook, Discord, GitHub, Apple, Microsoft, X, generic OIDC, each with a table of its endpoints, scopes, redirect rules and quirks in `docs/providers.md`.
5. **mock**: `tools/mock-oauth`.
6. **native-ios** and 7. **native-android**: launchers, secure storage, hosts.
8. **desktop and web launchers**.
9. **demo**: `examples/demo`, with buttons per provider that follow each provider's brand rules as well as a mock provider, and a session screen, using the `nsh-component-library` rules.
10. **docs**: `README.md` and per-provider setup steps with what the owner must register, security notes, and a threat table.

## Sandbox: no real account

This is how the work gets verified. Read it twice.

- **Never sign in to a real provider, never create an account, and never type a credential.** Client ids are fake and obviously so, such as `nsh-auth-sandbox.apps.googleusercontent.com`. Nothing here needs a real one.
- **Complete loop against a mock.** `tools/mock-oauth` is a local server that imitates each provider's authorize, token, userinfo, revoke and JWKS endpoints, in that provider's shape, including its quirks, errors and a scripted "user" who approves or denies. Tests cover success, denial, wrong `state`, wrong `nonce`, expired code, refresh, revoked refresh, and sign-out. On the Android emulator the host is `10.0.2.2`.
- **Trigger proof against the real provider.** For each of Google, Facebook, Discord and GitHub, on each surface you can reach, start the real flow with the fake client id and prove the right thing happened:
  1. In headless tests, `app.openedUrls()` shows the exact authorize URL, with `code_challenge`, `code_challenge_method=S256`, `state`, the right scopes and redirect URI.
  2. On the iOS simulator, the Android emulator and macOS, use computer-use, the ios-simulator and android-emulator plugins, `mobilecli` or `open-computer-use` to press the demo's button and capture what appears. The system sign-in surface opening on the provider's own domain is the pass. A provider's error page for an unknown client id, shown on its own domain, also counts as a pass, as it proves the request reached it. Stop there. Save the screenshot under `docs/evidence/<provider>/<surface>.png`, and look at it to confirm the domain.
  3. On the web, use `agent-browser` to do the same, and confirm the page reached the provider's domain.
- **Redirect loop proof.** On each surface, complete the return leg against the mock, so the app receives the redirect through the real mechanism: `ASWebAuthenticationSession` callback, Android intent filter, loopback listener, or web redirect. It then shows a signed-in session.
- **Storage proof.** After sign-in against the mock, restart the app and show the session restored from secure storage, on a real iOS simulator and Android emulator. Confirm the token is not in `Storage` or any plain file, and not in logs.

## Satisfaction criteria

All of these hold, each with evidence in `docs/STATUS.md`:

1. `docs/research.md` exists, with citations, and answers per provider and per surface what the flow is and what the app owner must register.
2. Gates pass for the crate, the package and the native modules. `xcodebuild` and Gradle builds of both hosts pass.
3. The mock suite passes in Rust and TypeScript: success, denial, wrong state, wrong nonce, expired code, refresh, single-flight refresh under parallel calls, revoked refresh, sign-out.
4. For each of Google, Facebook, Discord and GitHub, the authorize URL is asserted by tests, and a saved, looked-at screenshot shows the provider's own domain opened from the app on at least iOS simulator, Android emulator and macOS or web.
5. The full loop against the mock works through the real redirect mechanism on iOS simulator, Android emulator, macOS and web. Screenshots saved and looked at.
6. A session survives an app restart on iOS and Android, from secure storage. A test or log check shows no token in plain storage or logs.
7. No client secret appears in any app bundle. GitHub's path through the broker works against the mock.
8. A `z-security-auditor` pass reports no open high-severity finding, and its report is in `docs/security-review.md`.
9. A person can follow `README.md` from a clean clone to the mock sign-in running, and from there to registering their own real client ids, without changing library code.

## Environment, as measured on this Mac

- `nsh` 0.4.0 (e626a8d), from Homebrew. Do not upgrade it. Embedding frameworks: `$(brew --prefix nsh)/libexec/embed/ios/{NativeShell,NativeShellDev}.xcframework` and `$(brew --prefix nsh)/libexec/embed/android/{nsh,nsh-dev}.aar`.
- Rust stable with `aarch64-apple-ios`, `aarch64-apple-ios-sim`, `aarch64-linux-android`, `armv7-linux-androideabi`, `x86_64-linux-android` and `wasm32-unknown-unknown` installed.
- Xcode with an iOS 27 simulator runtime. Android SDK at `$ANDROID_HOME`, NDK 29, one AVD named `indopak-audit`.
- `/usr/bin/java` is a stub with no runtime behind it. Use Android Studio's JDK: `export JAVA_HOME="/Applications/Android Studio.app/Contents/jbr/Contents/Home"`.
- `bun` and `node` 24 exist. Installing dev tools with them inside this repository is fine.
- Reference source, read-only: `~/fo/.refs/nsh-v0.4.0` is exactly what is installed, including its `examples/` (`gallery`, `gallery-rs`, `embed-ios`, `embed-android`, `embed-gpui`, `rust-exports`, `host-echo`). `~/fo/.refs/nsh-main` is unreleased. `~/fo/.refs/react-native-firebase` and `~/fo/.refs/flutterfire` are the Firebase references.
- Sibling libraries, already built and tested by someone else: `~/fo/nsh-query` and `~/fo/nsh-form`. Each has a Rust crate and a TypeScript package with the same behavior. Read their READMEs. Do not edit them. If one has a bug, write it up in `docs/upstream-issues.md`, and work around it.
- Installed for this repository: the `z-nsh-engineer` agent and the skills under `.agents/skills`, by `z-project-init`. Start with `nsh`, `nsh-testing` and `nsh-design-guides`.

## Tools you may use to look at the real thing

You have full access to this machine. Use it. A headless pass alone never finishes visible or native work.

- `nsh test` headless, and `nsh test --target macos|ios|android|web`, which use real input, and `app.screenshot(path)`.
- `nsh run --target ios|android|macos|web`, `nsh package --target ...`, `xcodebuild`, `xcrun simctl`, Gradle, `adb`, and the Android emulator.
- The computer-use, ios-simulator and android-emulator plugins, the `mobile-mcp` server, `mobilecli`, the `mobile-automation` and `open-computer-use` skills for live capture, and `agent-browser` for the web.
- Save evidence as PNGs and logs under `docs/evidence/<area>/`, and look at every PNG you save. A screenshot nobody looked at proves nothing.

## Facts that bite on 0.4.0

Each of these was hit by a real run. Trust them over the docs.

- The upstream `nsh` skill follows NSH's `main` and is ahead of 0.4.0. Not in 0.4.0: `nsh update-manifest`, `nsh/updater`, the `Notifications` module, and the `notifications` capability. Check `.nsh/types` for TSX and the crate source in `~/.cargo/registry/src/*/nsh-core-0.4.0` for Rust.
- Real capability keys, from the build's own error: `network`, `webview`, `statusBar`, `clipboard`, `picker`, `speech`, `openUrl`, `process`, `fs`, `host`. A typo fails `nsh build` and passes `nsh check`. Run both.
- `If` and `Each` are globals in TSX. Importing them from `nsh` is a type error.
- `nsh check` needs an `App.tsx` at the package root, or an entry passed to it. Generated files in `.nsh/` are git-ignored, and `nsh` writes them.
- The docs' `nsh-engine = "0.1"` samples are stale. Dev-dependencies must be `0.4.0`, as all NSH crates must come from one place. The generated `Cargo.toml` has no `log` crate.
- `Headless::start` can return before the first frame, so `wait_for` something first or a step sees `on screen: []`.
- `Headless::shows` takes plain text. `wait_for`, `press` and TypeScript's `app.shows` take selectors. `wait_for_gone` also takes a timeout. `screen().count` returns a `Result`.
- `Signal::update` needs `T: Clone`. For state machines holding user types, pair `stored(..)` with a version `signal`. See `~/fo/nsh-query/crates/nsh-query/src/tracked.rs`.
- A component's signals are already disposed when its `cleanup` runs, so reading one there panics. Capture what cleanup needs in an `Rc<Cell<..>>`. `create_root` gives an owner that outlives the component, which suits caches and in-flight writes.
- `open`'s host handlers need annotated parameters: `async ({ id }: { id: number }) => ...`. Selector regexes use Rust's `regex` syntax, so no look-ahead. On a manual clock, `open(entry, { clock: {} })`, a test that took 13.7 s took 18 ms.
- A TSX app consumes a sibling package through `node_modules`, with `mkdir -p node_modules && ln -s <path> node_modules/<name>`. The bundler and `nsh check` both read it, and `tsconfig.json` needs no change. Overriding `compilerOptions.paths` there breaks the `nsh` types.
- `nsh package` needs no Xcode project and no Gradle, and has no setting for extra native SDKs, URL schemes or entitlements beyond the provisioning profile. Anything needing those goes through an embedding host: `NshAppView` with `app.handle(..)` on iOS, and `NshView` with `nsh.handle(..)` on Android, as `examples/embed-ios` and `examples/embed-android` do. The app talks to it with `host.call`, `host.post` and `host.on`, and must list the names in `capabilities.host`.
- Failed host calls reject with `ERR_ACCESS_DENIED` when undeclared, `ERR_NSH_HOST_ERROR` when unhandled or thrown, and `ERR_FEATURE_UNAVAILABLE_ON_PLATFORM` with no host.
- Bytecode loads only from the app bundle, the APK or a verified package.

## How to run this

Use the `z-workflow` skill. All subagents run on GLM-5.3-Flash with high thinking. Split the work into the areas named below, with disjoint files, each advancing alone through its own chain. Name these phases for every area: implement, audit, unit tests. Add native device testing to any area touching iOS, Android or desktop, and a vision phase to any area with a screen. End with a whole-tree smoke gate. Run audit and smoke until zero issues, capped at three rounds, and report honestly if a cap is reached rather than weakening a check.

Set this session's goal to the goal above, and keep working until the satisfaction criteria hold or you are truly blocked. When you are blocked on one area, finish every other area first. Do not stop to ask whether to continue.

## Hard rules

- No real accounts, no real credentials, no billing, and no signing in as anyone. Never type a password or create an account on any provider's site. Everything here must work in a sandbox, as described below.
- Never commit a secret, a real `google-services.json` or `GoogleService-Info.plist`, or a real client secret. Fixtures with obviously fake values go under `fixtures/`.
- Do not publish to crates.io or npm, do not change repository visibility, and do not push. Commit on `main` as each milestone passes, using Conventional Commits with the reason in the body.
- Comments are 1-2 lines and state a non-obvious constraint. Never narrate the next line. Dead code is deleted. No speculative abstractions.
- Docs read like a competent human wrote them: direct, concrete, no marketing filler. The `antislop-copy` and `code-comments` skills apply.
- Never invent an API. Look the name up, in the source for 0.4.0.
- A Rust gate is `cargo fmt --all -- --check`, `cargo clippy --all-targets -- -D warnings` and `cargo test`. A TSX gate is `nsh check`, `nsh build` with every warning fixed, and `nsh test`. No check is weakened, skipped or deleted to get a pass.
- Tests go through the UI on a manual clock, with no real network and no real time, except the labelled sandbox runs below. Every new test is seen to fail once, by breaking the code on purpose. Use `test-quality-guardrails`.
- `docs/STATUS.md` stays current with what is done, what was verified how, and what was not verified. A claim with no evidence is reported as unverified.
