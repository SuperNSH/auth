# Native licensing: what phase 2 must honor when vendoring library code

Phase 2 may take code from the libraries listed below instead of re-deriving it. This
doc records, per library, the license that binds a vendored copy, where that license
was verified, and the concrete attribution plan this repository follows when a copy
lands in the tree.

Verification date: 2026-11-07. Every license was read from the upstream repository
(LICENSE file and/or package metadata), cross-checked against the local read-only
clones in `~/fo/.refs` where they exist. Clone HEADs are recorded so a future
re-check can diff against the same revision.

## Verified licenses

| Library | License (SPDX) | Copyright | Verified where |
|---|---|---|---|
| AppAuth-iOS | Apache-2.0 | "The AppAuth for Android/iOS Authors" (per-file headers; LICENSE is the unmodified Apache text) | `~/fo/.refs/AppAuth-iOS/LICENSE` (HEAD `dfbb0e0`, 2026-11-02) + https://raw.githubusercontent.com/openid/AppAuth-iOS/master/LICENSE + `AppAuth.podspec` (`s.license = "Apache License, Version 2.0"`) |
| AppAuth-Android | Apache-2.0 | "Copyright 2015 The AppAuth for Android Authors. All Rights Reserved." (per-file headers) | `~/fo/.refs/AppAuth-Android/LICENSE` (HEAD `e5f5184`, 2026-03-22) + https://raw.githubusercontent.com/openid/AppAuth-Android/master/LICENSE + `library/build.gradle` POM license block; no NOTICE file in the repo |
| react-native-app-auth | MIT | "Copyright (c) 2017 Formidable Labs" | `~/fo/.refs/react-native-app-auth/LICENSE` (HEAD `ed4a3fa`, 2026-10-19) + https://raw.githubusercontent.com/FormidableLabs/react-native-app-auth/main/LICENSE + package.json `"license": "MIT"` |
| expo-auth-session | MIT | "Copyright (c) 2015-present 650 Industries, Inc. (aka Expo)" (monorepo root LICENSE) | https://raw.githubusercontent.com/expo/expo/main/LICENSE + `packages/expo-auth-session/package.json` (`"license": "MIT"`, v58.0.14); local clone `~/fo/.refs/expo-auth-session` (HEAD `03ed6a8`, 2026-11-06) |
| expo-secure-store | MIT | same monorepo root LICENSE as expo-auth-session | `packages/expo-secure-store/package.json` (`"license": "MIT"`, v58.0.2) at https://raw.githubusercontent.com/expo/expo/main/packages/expo-secure-store/package.json + the monorepo root LICENSE; not present in the local sparse clone, web-verified only |
| flutter_appauth | BSD-3-Clause | "Copyright (c) 2019, Michael Bui" (main package); "Copyright (c) 2020, Michael Bui" (platform interface) | `~/fo/.refs/flutter_appauth/flutter_appauth/LICENSE` and `flutter_appauth_platform_interface/LICENSE` (HEAD `3a0e0e6`, 2026-10-31) + https://raw.githubusercontent.com/MaikuB/flutter_appauth/master/flutter_appauth/LICENSE |
| flutter_secure_storage | BSD-3-Clause | "Copyright 2017 German Saprykin" | `~/fo/.refs/flutter_secure_storage/LICENSE` (HEAD `1012697`, 2026-11-01) + https://raw.githubusercontent.com/mogol/flutter_secure_storage/develop/LICENSE |
| keyring | MIT OR Apache-2.0 | per LICENSE-MIT / LICENSE-APACHE; maintained by the keyring-rs cooperative (Dan Brotsky et al., see `Contributors.md`) | crates.io API https://crates.io/api/v1/crates/keyring (`"license": "MIT OR Apache-2.0"`, v4.2.0) + repo https://github.com/open-source-cooperative/keyring-rs (`LICENSE-MIT`, `LICENSE-APACHE`, workspace Cargo.toml `license = "MIT OR Apache-2.0"`); the old `hwchen/keyring-rs` moved to the open-source-cooperative org |
| tauri-plugin-oauth | MIT OR Apache-2.0 | per LICENSE_MIT / LICENSE_APACHE-2.0 | repo https://github.com/FabianLars/tauri-plugin-oauth (files `LICENSE_MIT`, `LICENSE_APACHE-2.0`, Cargo.toml `license = "MIT OR Apache-2.0"`). Note: the `tauri-apps` org URL does not resolve (HTTP 404 on 2026-11-07); the crates.io `tauri-plugin-oauth` package points at the FabianLars repo, which is the canonical source |
| androidx.browser 1.8.0 | Apache-2.0 ("The Apache Software License, Version 2.0") | Google/AOSP per license headers in the androidx source | Maven POM https://dl.google.com/android/maven2/androidx/browser/browser/1.8.0/browser-1.8.0.pom, `<licenses>` section. Already consumed as a dependency by `examples/host-android/app/build.gradle.kts:46` |

Corrections to the phase-1 planning assumptions, each material:

- **AppAuth-iOS is Apache-2.0, not MIT.** A vendored copy therefore carries the
  Apache-2.0 obligations (license text distribution, §4(b) change notices), not just
  a copyright line.
- **flutter_appauth is BSD-3-Clause, not MIT.** The BSD non-endorsement clause binds
  code derived from it; see the per-license obligations below.
- **tauri-plugin-oauth's canonical repo is FabianLars/tauri-plugin-oauth.** Anything
  citing `tauri-apps/tauri-plugin-oauth` should be corrected; the org URL 404s.
- **keyring v4 is a facade.** The API moved to the `keyring-core` crate and the
  credential stores into separate crates (`apple-native-keyring-store`,
  `windows-native-keyring-store`, `zbus-secret-service-keyring-store`,
  `dbus-secret-service-keyring-store`, `linux-keyutils-keyring-store`,
  `android-native-keyring-store`, `db-keystore`). Licenses verified on crates.io
  (2026-11-07) for keyring-core, apple/windows-native-keyring-store, db-keystore and
  android-native-keyring-store: all `MIT OR Apache-2.0`. Verify the exact store
  crate's license before importing it; the ecosystem is uniform today but is made of
  separate artifacts.

## Per-license obligations for a vendored copy

### MIT — react-native-app-auth, expo-auth-session, expo-secure-store (and the MIT half of dual-licensed crates)

- Keep the copyright line and the permission notice in all copies or substantial
  portions of the software. Practically: the vendored file keeps its original header;
  `THIRD_PARTY_NOTICES.md` carries the exact copyright line plus the full MIT text.
- None of the MIT candidates here ships a NOTICE file, so nothing else must be
  propagated. Re-check at import time.

### BSD-3-Clause — flutter_secure_storage, flutter_appauth, flutter_appauth_platform_interface

- Everything required by MIT, plus clause 3: the names of the copyright holder and
  contributors may not be used to endorse or promote products derived from this
  software without specific prior written permission.
- Consequence: attribution in `THIRD_PARTY_NOTICES.md` is required, but prose like
  "secure storage powered by flutter_secure_storage" in README or marketing is not
  permitted without permission. Keep attribution factual and confined to the notices
  file and provenance records.

### Apache-2.0 — AppAuth-iOS, AppAuth-Android, androidx.browser (and the Apache half of keyring / tauri-plugin-oauth)

- Give every recipient a copy of the license text. `THIRD_PARTY_NOTICES.md`
  satisfies this for the app artifacts this repository ships.
- Keep all copyright, patent, trademark, and attribution notices from the source
  material. AppAuth-Android has no NOTICE file (repo top level checked 2026-11-07);
  its attribution lives in per-file headers of the form `Copyright 2015 The AppAuth
  for Android Authors. All Rights Reserved.` — vendored files must keep those
  headers verbatim. AppAuth-iOS is the same shape (unmodified Apache LICENSE text,
  attribution in file headers and the `CONTRIBUTORS` file).
- State significant changes made to modified files (§4(b)). For every vendored file
  we change, append a prominent notice (comment block) naming this repository, the
  upstream commit the file was taken at, and a summary of the change; mirror the list
  in the vendored directory's README.
- NOTICE files: none of the Apache candidates ships one today, so there is nothing
  to propagate; re-check at import, because upstream may add one, and an added
  NOTICE must be copied into `THIRD_PARTY_NOTICES.md` with its attributions intact.
- Dual `MIT OR Apache-2.0` crates: we exercise the Apache-2.0 side when vendoring,
  because it includes the explicit patent grant (§3), and record that choice in the
  notices entry. The extra cost is exactly the §4 obligations above.

## THIRD_PARTY_NOTICES.md plan (repository root)

One section per vendored artifact, plus one per dependency whose artifact is
distributed inside an app we build (androidx.browser today, even though it is a
Gradle dependency and not vendored source). Format per entry:

```
### <library name>
Source: <repo URL> at commit <hash> (tag/version <v>)
Vendored paths: vendor/<lib>/... (or the exact files, for partial copies)
Local changes: none | <summary, basis = upstream commit <hash>>
Copyright: <exact line from LICENSE or file headers>
License: <SPDX identifier>
<full license text>
```

Rules that make the file trustworthy:

- The entry lands in the same commit as the vendored code. A vendored directory
  without a notices entry is a broken gate, and the whole-tree smoke should grep
  `THIRD_PARTY_NOTICES.md` for every directory under `vendor/`.
- The no-secrets scanner keeps covering vendored paths. License texts are not
  credentials, but vendored constants can look like them, so if the scanner ever
  needs a pattern refinement for a vendored directory that refinement is recorded in
  `docs/STATUS.md` together with the reason — exemptions are never silent.
- When a vendored artifact is later upgraded or dropped, its notices entry moves or
  goes with it in the same commit.

## Vendored file headers

- Apache-2.0 files: keep the upstream header verbatim. If the file is modified, the
  §4(b) notice follows it, e.g. `// Modified by nsh-auth (2026-xx-xx) vs upstream
  <commit>: <what changed and why>`.
- MIT/BSD files: keep the copyright line and the permission notice in the file; the
  full text lives in `THIRD_PARTY_NOTICES.md`.
- New files we author inside a vendored directory follow the repository's normal
  comment rules and carry no upstream header, but the directory README states the
  upstream provenance of the directory as a whole, so no file is ambiguous about
  which license governs it.

## Commit and docs hygiene

- Conventional Commits: `chore(vendor): import <lib> <files> at <upstream-commit>`,
  with a body that states the reason (what was taken and why our own code was not
  enough), the SPDX identifier, and that `THIRD_PARTY_NOTICES.md` was updated in the
  same commit. Modifications to vendored files use `refactor(vendor):` (or
  `fix(vendor):`) with the same body fields; that is the durable record of §4(b)
  changes.
- `docs/STATUS.md` records each vendoring event and how attribution was verified
  (notices entry present, license re-read from upstream at the recorded commit).
  `docs/research.md` links here for the license facts so no other doc restates them.
- The vendored directory's own `README.md` (upstream URL, commit, files taken, list
  of local changes) is the source of truth the notices file summarizes; the two are
  updated together.

## What must not be vendored

- Copyleft-in-app licenses: GPL-2.0/3.0, AGPL, SSPL, and LGPL variants whose linkage
  story is unclear for statically linked Rust or ObjC. **Confirmed: none of the ten
  artifacts above carries such a license** — counting the dual-licensed Rust crates
  on both sides of their MIT OR Apache-2.0 split, the SPDX set is Apache-2.0 ×5
  (AppAuth-iOS, AppAuth-Android, androidx.browser, plus the Apache halves of keyring
  and tauri-plugin-oauth), MIT ×5 (react-native-app-auth, expo-auth-session,
  expo-secure-store, plus the MIT halves), BSD-3-Clause ×2 — twelve license grants
  across ten artifacts. The rule stays: SPDX is
  checked at import time, and anything outside the MIT/BSD/Apache-2.0 family needs
  an explicit decision recorded in this file before it enters the tree.
- Provider native SDKs (Google Sign-In, Facebook Login SDK, Apple's auth
  frameworks): reached through the embedding hosts at runtime, never copied into
  this repository. Their terms layer provider-specific conditions on top of a
  license, which vendoring would entangle us in for no benefit.
- Anything whose provenance cannot be pinned to a repo URL plus commit hash. The
  `tauri-apps` org 404 above is the worked example: an import proceeds only against
  a source that resolves.

## Trademark care

Provider logos, badges and sign-in button artwork (Google, Facebook, Discord,
GitHub, Apple, Microsoft, X) are trademark-governed, not copyright-governed: the
files themselves are often freely viewable, but their use in a UI is controlled by
each provider's brand guidelines. This repository's policy is unchanged by phase 2:

- No provider brand asset is vendored or committed here, ever. The demo renders
  provider-branded buttons according to each provider's brand rules, with the app
  owner supplying official assets at setup time (see `docs/providers.md` and
  `docs/setup.md`).
- The same restraint applies to library artwork: AppAuth-iOS's `appauth_lockup.svg`
  and similar are not copied, because we make no use that requires them.
- Text references to library names in attribution and provenance records are fine
  (that is required attribution, and for BSD-3-Clause it is the only permitted use of
  the copyright holders' names in derived-product contexts).
