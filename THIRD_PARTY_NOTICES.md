# Third-party notices

This repository builds parts of its native layers on other projects' work, in
three distinct ways, each with different license obligations:

- **Translated code** — AppAuth-Android's browser-selection and custom-tab
  binding files were translated from Java into Kotlin inside this repository's
  own Android module. This is the closest use to redistribution, so the full
  Apache-2.0 license text is reproduced below and the statement of changes is
  given per Apache-2.0 §4(b).
- **Adapted behavior** — small, documented behaviors from AppAuth-iOS,
  flutter_secure_storage and expo-secure-store were reimplemented in this
  repository's own Swift/Kotlin/Rust/TypeScript. No upstream source file is
  copied, modified or redistributed; each entry still records the upstream
  copyright, license, and what was taken.
- **Dependencies** — the keyring crate family, androidx.browser and, since
  phase 3, the native-SDK dependencies of the optional native adapters
  (GoogleSignIn-iOS, the Facebook iOS and Android SDKs, Google's Android
  Credential Manager artifacts) are consumed as built artifacts
  (cargo / Gradle / SPM), never vendored as source. Their entries record the
  exact versions this repository pins and their licenses; the out-of-family
  SDK licenses carry a recorded decision per
  [docs/research/native-licensing.md](docs/research/native-licensing.md).

One further project, tauri-plugin-oauth, is credited for two design ideas
adopted with no code copied.

License facts were verified from the upstream repositories and package metadata
on 2026-11-07; the sources are recorded in
[docs/research/native-licensing.md](docs/research/native-licensing.md) and, for
the phase-3 native SDKs, in
[docs/research/native-sdks.md](docs/research/native-sdks.md) §6. When a covered
artifact is upgraded or dropped, its entry here moves or goes with it in the
same commit.

## AppAuth-iOS

- Source: https://github.com/openid/AppAuth-iOS at commit `dfbb0e0`
  (master, 2026-11-02)
- Taken into: no upstream file is copied or vendored. Three behaviors were
  adapted into this repository's own code:
  - Guided-access pre-check (upstream
    `Sources/AppAuth/iOS/OIDExternalUserAgentIOS.m:150-152`): a guard in
    `native/ios/Sources/AuthHostModule.swift` rejects `auth.authorize` while
    Guided Access is enabled, rather than letting `ASWebAuthenticationSession`
    misbehave there with no diagnosis (rdar://40809553).
  - Session-retention invariant (upstream `OIDExternalUserAgentIOS.m:46-69`,
    FB12132525): documented in `AuthHostModule.swift` — the finished
    `ASWebAuthenticationSession` must outlive its dismiss transition (upstream
    parks it for 2 s on the main queue); never release it synchronously in the
    completion handler.
  - Refresh/expiry semantics (upstream `OIDAuthState`): a 60-second expiry
    tolerance and keep-if-absent refresh-token rotation (a refresh response
    without `refresh_token` keeps the previous one) in the shared core,
    `crates/nsh-auth` and `packages/nsh-auth`.
- Local changes: adaptation record, not a modification of upstream files. Basis
  = upstream commit `dfbb0e0`; changes = the three behaviors above,
  reimplemented from scratch in this repository's own code. Because no upstream
  file is modified or redistributed, no Apache-2.0 §4(b) file notices arise;
  this section is the changes statement the licensing plan calls for.
- Copyright: upstream per-file headers vary — Google Inc. (2015, 2016, 2020)
  and The AppAuth Authors / The AppAuth for iOS Authors (2016, 2017, 2019),
  verified across the source tree at `dfbb0e0`. The upstream LICENSE file is
  the unmodified Apache-2.0 text; upstream ships no NOTICE file.
- License: Apache-2.0. No upstream code is redistributed, so the license is
  included as a reference; the text is reproduced in full under AppAuth-Android
  below.

## AppAuth-Android

- Source: https://github.com/openid/AppAuth-Android at commit `e5f5184`
  (master, 2026-03-22)
- Translated paths: upstream `library/java/net/openid/appauth/browser/` —
  `BrowserSelector.java`, `CustomTabManager.java`, `BrowserDescriptor.java` —
  translated from Java to Kotlin under `native/android/`
  (`dev.nshauth.sandbox.auth`). This is a derivative work in source form; the
  license text below is provided to every recipient of this repository per
  Apache-2.0 §4(a).
- Changes made (Apache-2.0 §4(b) statement): the three files were translated
  Java to Kotlin and reduced to the mechanics this host uses — browser
  enumeration and disambiguation (`ACTION_VIEW` + `CATEGORY_BROWSABLE` with
  `http:` data, `MATCH_ALL` + `GET_RESOLVED_FILTER`, full-browser check,
  `CustomTabsService.ACTION_CUSTOM_TABS_CONNECTION` probe, default-browser
  preference), service binding with `warmup(0)`, session creation with
  `mayLaunchUrl` on the authorize URL, and the (package, signature set,
  version, useCustomTab) descriptor. The package namespace changed from
  `net.openid.appauth.browser` to this module's. Upstream's versioned
  browser-matcher catalogue (`Browsers`, `VersionedBrowserMatcher`,
  `VersionRange`, `DelimitedVersion`) and all request/token/`AuthState`
  machinery were not translated; the protocol stays in this repository's own
  core. Basis = upstream commit `e5f5184`.
- Copyright: Copyright 2015 The AppAuth for Android Authors. All Rights
  Reserved. (upstream per-file headers)
- License: Apache-2.0. Upstream ships no NOTICE file (repo top level checked
  2026-11-07); nothing further to propagate.

```text
                                 Apache License
                           Version 2.0, January 2004
                        http://www.apache.org/licenses/

   TERMS AND CONDITIONS FOR USE, REPRODUCTION, AND DISTRIBUTION

   1. Definitions.

      "License" shall mean the terms and conditions for use, reproduction,
      and distribution as defined by Sections 1 through 9 of this document.

      "Licensor" shall mean the copyright owner or entity authorized by
      the copyright owner that is granting the License.

      "Legal Entity" shall mean the union of the acting entity and all
      other entities that control, are controlled by, or are under common
      control with that entity. For the purposes of this definition,
      "control" means (i) the power, direct or indirect, to cause the
      direction or management of such entity, whether by contract or
      otherwise, or (ii) ownership of fifty percent (50%) or more of the
      outstanding shares, or (iii) beneficial ownership of such entity.

      "You" (or "Your") shall mean an individual or Legal Entity
      exercising permissions granted by this License.

      "Source" form shall mean the preferred form for making modifications,
      including but not limited to software source code, documentation
      source, and configuration files.

      "Object" form shall mean any form resulting from mechanical
      transformation or translation of a Source form, including but
      not limited to compiled object code, generated documentation,
      and conversions to other media types.

      "Work" shall mean the work of authorship, whether in Source or
      Object form, made available under the License, as indicated by a
      copyright notice that is included in or attached to the work
      (an example is provided in the Appendix below).

      "Derivative Works" shall mean any work, whether in Source or Object
      form, that is based on (or derived from) the Work and for which the
      editorial revisions, annotations, elaborations, or other modifications
      represent, as a whole, an original work of authorship. For the purposes
      of this License, Derivative Works shall not include works that remain
      separable from, or merely link (or bind by name) to the interfaces of,
      the Work and Derivative Works thereof.

      "Contribution" shall mean any work of authorship, including
      the original version of the Work and any modifications or additions
      to that Work or Derivative Works thereof, that is intentionally
      submitted to Licensor for inclusion in the Work by the copyright owner
      or by an individual or Legal Entity authorized to submit on behalf of
      the copyright owner. For the purposes of this definition, "submitted"
      means any form of electronic, verbal, or written communication sent
      to the Licensor or its representatives, including but not limited to
      communication on electronic mailing lists, source code control systems,
      and issue tracking systems that are managed by, or on behalf of, the
      Licensor for the purpose of discussing and improving the Work, but
      excluding communication that is conspicuously marked or otherwise
      designated in writing by the copyright owner as "Not a Contribution."

      "Contributor" shall mean Licensor and any individual or Legal Entity
      on behalf of whom a Contribution has been received by Licensor and
      subsequently incorporated within the Work.

   2. Grant of Copyright License. Subject to the terms and conditions of
      this License, each Contributor hereby grants to You a perpetual,
      worldwide, non-exclusive, no-charge, royalty-free, irrevocable
      copyright license to reproduce, prepare Derivative Works of,
      publicly display, publicly perform, sublicense, and distribute the
      Work and such Derivative Works in Source or Object form.

   3. Grant of Patent License. Subject to the terms and conditions of
      this License, each Contributor hereby grants to You a perpetual,
      worldwide, non-exclusive, no-charge, royalty-free, irrevocable
      (except as stated in this section) patent license to make, have made,
      use, offer to sell, sell, import, and otherwise transfer the Work,
      where such license applies only to those patent claims licensable
      by such Contributor that are necessarily infringed by their
      Contribution(s) alone or by combination of their Contribution(s)
      with the Work to which such Contribution(s) was submitted. If You
      institute patent litigation against any entity (including a
      cross-claim or counterclaim in a lawsuit) alleging that the Work
      or a Contribution incorporated within the Work constitutes direct
      or contributory patent infringement, then any patent licenses
      granted to You under this License for that Work shall terminate
      as of the date such litigation is filed.

   4. Redistribution. You may reproduce and distribute copies of the
      Work or Derivative Works thereof in any medium, with or without
      modifications, and in Source or Object form, provided that You
      meet the following conditions:

      (a) You must give any other recipients of the Work or
          Derivative Works a copy of this License; and

      (b) You must cause any modified files to carry prominent notices
          stating that You changed the files; and

      (c) You must retain, in the Source form of any Derivative Works
          that You distribute, all copyright, patent, trademark, and
          attribution notices from the Source form of the Work,
          excluding those notices that do not pertain to any part of
          the Derivative Works; and

      (d) If the Work includes a "NOTICE" text file as part of its
          distribution, then any Derivative Works that You distribute must
          include a readable copy of the attribution notices contained
          within such NOTICE file, excluding those notices that do not
          pertain to any part of the Derivative Works, in at least one
          of the following places: within a NOTICE text file distributed
          as part of the Derivative Works; within the Source form or
          documentation, if provided along with the Derivative Works; or,
          within a display generated by the Derivative Works, if and
          wherever such third-party notices normally appear. The contents
          of the NOTICE file are for informational purposes only and
          do not modify the License. You may add Your own attribution
          notices within Derivative Works that You distribute, alongside
          or as an addendum to the NOTICE text from the Work, provided
          that such additional attribution notices cannot be construed
          as modifying the License.

      You may add Your own copyright statement to Your modifications and
      may provide additional or different license terms and conditions
      for use, reproduction, or distribution of Your modifications, or
      for any such Derivative Works as a whole, provided Your use,
      reproduction, and distribution of the Work otherwise complies with
      the conditions stated in this License.

   5. Submission of Contributions. Unless You explicitly state otherwise,
      any Contribution intentionally submitted for inclusion in the Work
      by You to the Licensor shall be under the terms and conditions of
      this License, without any additional terms or conditions.
      Notwithstanding the above, nothing herein shall supersede or modify
      the terms of any separate license agreement you may have executed
      with Licensor regarding such Contributions.

   6. Trademarks. This License does not grant permission to use the trade
      names, trademarks, service marks, or product names of the Licensor,
      except as required for reasonable and customary use in describing the
      origin of the Work and reproducing the content of the NOTICE file.

   7. Disclaimer of Warranty. Unless required by applicable law or
      agreed to in writing, Licensor provides the Work (and each
      Contributor provides its Contributions) on an "AS IS" BASIS,
      WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
      implied, including, without limitation, any warranties or conditions
      of TITLE, NON-INFRINGEMENT, MERCHANTABILITY, or FITNESS FOR A
      PARTICULAR PURPOSE. You are solely responsible for determining the
      appropriateness of using or redistributing the Work and assume any
      risks associated with Your exercise of permissions under this License.

   8. Limitation of Liability. In no event and under no legal theory,
      whether in tort (including negligence), contract, or otherwise,
      unless required by applicable law (such as deliberate and grossly
      negligent acts) or agreed to in writing, shall any Contributor be
      liable to You for damages, including any direct, indirect, special,
      incidental, or consequential damages of any character arising as a
      result of this License or out of the use or inability to use the
      Work (including but not limited to damages for loss of goodwill,
      work stoppage, computer failure or malfunction, or any and all
      other commercial damages or losses), even if such Contributor
      has been advised of the possibility of such damages.

   9. Accepting Warranty or Additional Liability. While redistributing
      the Work or Derivative Works thereof, You may choose to offer,
      and charge a fee for, acceptance of support, warranty, indemnity,
      or other liability obligations and/or rights consistent with this
      License. However, in accepting such obligations, You may act only
      on Your own behalf and on Your sole responsibility, not on behalf
      of any other Contributor, and only if You agree to indemnify,
      defend, and hold each Contributor harmless for any liability
      incurred by, or claims asserted against, such Contributor by reason
      of your accepting any such warranty or additional liability.

   END OF TERMS AND CONDITIONS
```

## flutter_secure_storage

- Source: https://github.com/mogol/flutter_secure_storage at commit `1012697`
  (develop, 2026-11-01)
- Taken into: no source copied. Two key-generation hardening behaviors were
  ported into `native/android/dev/nshauth/sandbox/auth/SecureStore.kt` (upstream
  Android engine, `ciphers/` key-generation path):
  - StrongBox with explicit fallback: where
    `PackageManager.FEATURE_STRONGBOX_KEYSTORE` is available (API 28+), generate
    the AES key with `setIsStrongBoxBacked(true)`; on generation failure, retry
    without StrongBox.
  - `setUnlockedDeviceRequired(true)`: the key is unusable while the device is
    locked.
- Local changes: reimplementation inside this module's existing AES/GCM
  AndroidKeyStore key-generation path; basis = upstream commit `1012697`.
- Copyright: Copyright 2017 German Saprykin
- License: BSD-3-Clause

```text
BSD 3-Clause License

Copyright 2017 German Saprykin
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

* Redistributions of source code must retain the above copyright notice, this
  list of conditions and the following disclaimer.

* Redistributions in binary form must reproduce the above copyright notice,
  this list of conditions and the following disclaimer in the documentation
  and/or other materials provided with the distribution.

* Neither the name of the copyright holder nor the names of its
  contributors may be used to endorse or promote products derived from
  this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
```

Clause 3 note: the copyright holder's and contributors' names are not used to
endorse or promote derived products; attribution stays factual and confined to
this file and the provenance records in `docs/research/`.

## expo-secure-store

- Source: https://github.com/expo/expo (monorepo), `packages/expo-secure-store`
  at version 58.0.2 (package metadata verified 2026-11-07)
- Taken into: no source copied; the Expo modules core dependency makes
  standalone vendoring a non-starter, so only patterns were adapted into
  `native/ios/Sources/AuthKeychain.swift`:
  - OSStatus to human-readable message map (upstream
    `ios/SecureStoreExceptions.swift:21-69`): the common security-error codes
    map to text, with a `SecCopyErrorMessageString` fallback, so host-channel
    rejections are diagnosable without a lookup table.
  - Read-path error propagation (upstream `ios/SecureStoreModule.swift:170-183`):
    `load` throws on unexpected statuses and only `errSecItemNotFound` yields
    "absent", so a keychain failure can no longer masquerade as "no session
    stored" and silently trigger a re-auth loop.
- Local changes: both adapted to this module's delete-then-add store and its
  `AuthHostError` type; basis = upstream `packages/expo-secure-store` 58.0.2.
- Copyright: Copyright (c) 2015-present 650 Industries, Inc. (aka Expo)
  (monorepo root LICENSE)
- License: MIT

```text
The MIT License (MIT)

Copyright (c) 2015-present 650 Industries, Inc. (aka Expo)

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

## keyring crate family

- Consumed as cargo dependencies, not vendored. Pins:
  - `keyring-core` 1.0.1
  - `apple-native-keyring-store` 1.0.2
  - `windows-native-keyring-store` 1.1.0
  - `zbus-secret-service-keyring-store` 1.0.1
- Source: https://github.com/open-source-cooperative/keyring-rs (the 4.x
  workspace; each crate's license verified on crates.io, 2026-11-07). Used by
  the desktop secure-storage path behind the `SessionStore` trait
  (`crates/nsh-auth`).
- License: MIT OR Apache-2.0 (all four crates). Both texts ship upstream
  (`LICENSE-MIT`, `LICENSE-APACHE`) and are distributed with the crates by
  cargo itself, so they are not duplicated here. Choice recorded per
  docs/research/native-licensing.md: this repository exercises the Apache-2.0
  side of the dual license, for its explicit patent grant.
- Copyright: held by the keyring-rs cooperative and its contributors; the
  authoritative lines are in each crate's `LICENSE-MIT` / `LICENSE-APACHE`,
  distributed with the crate. Maintainer and contributor names are listed
  upstream (see the repository's `Contributors.md`).

## androidx.browser

- Dependency: `androidx.browser:browser:1.8.0`, consumed as a built AAR from
  the Google Maven repository by `examples/host-android/app/build.gradle.kts`;
  not vendored.
- License: Apache-2.0 ("The Apache Software License, Version 2.0" per the
  artifact's Maven POM, verified 2026-11-07). The artifact is distributed
  inside the built APK, so §4(a) applies and is satisfied by the license text
  reproduced in this file (see AppAuth-Android above).
- Copyright: Google and the Android Open Source Project, per the license
  headers in the androidx sources.

## GoogleSignIn-iOS

- Dependency: GoogleSignIn-iOS 10.1.0, consumed as an SPM source package from
  https://github.com/google/GoogleSignIn-iOS by `examples/host-ios`; not
  vendored. The built app embeds the compiled package, so Apache-2.0 §4(a)
  applies and is satisfied by the license text reproduced in this file (see
  AppAuth-Android above).
- Copyright: Copyright 2021 Google LLC (upstream public headers, e.g.
  `GIDConfiguration.h`); the repo LICENSE is the unmodified Apache-2.0 text
  (GitHub license API `spdx_id: apache-2.0`, verified 2026-11-07).
- Transitive source dependencies pulled by the same resolution — AppAuth-iOS
  3.x, GTMAppAuth, gtm-session-fetcher, GoogleUtilities, AppCheckCore — are
  Apache-2.0 projects per their own repositories
  (docs/research/native-sdks.md §6). AppAuth-iOS is already covered above;
  each remaining LICENSE is re-read, and its exact commit cited here, when
  the committed `Package.resolved` pins it.
- License: Apache-2.0 (text reproduced above under AppAuth-Android).

## Facebook iOS SDK (FacebookLogin)

- Dependency: the `FacebookLogin` product of facebook-ios-sdk v19.0.1,
  resolved as SPM binary XCFrameworks from Meta's tagged release, with
  SHA-256 checksums pinned in upstream `Package.swift`
  (https://github.com/facebook/facebook-ios-sdk); not vendored, and never
  redistributed standalone.
- Copyright: Copyright (c) Meta Platforms, Inc. and affiliates. All rights
  reserved. (LICENSE, main)
- License: **Facebook Platform License**
  (https://github.com/facebook/facebook-ios-sdk/blob/main/LICENSE; GitHub
  classifies it `NOASSERTION`). Outside the MIT/BSD/Apache-2.0 family, so
  per docs/research/native-licensing.md it enters only with the recorded
  decision below. Upstream also ships a NOTICE file (Mixpanel Apache-2.0
  attribution); the Apache-2.0 text it points to is already reproduced in
  this file under AppAuth-Android.

**Recorded decision (out-of-family license), 2026-11-07.**

- What the license permits and requires for our use: use, copy, modification
  and distribution of the SDK in source or binary form are permitted "for
  use in connection with the web services and APIs provided by Facebook",
  subject to the Facebook Platform Policy (http://developers.facebook.com/policy/),
  with the copyright notice kept in all copies or substantial portions. That
  is exactly the shape of an app-integration dependency: this repository
  embeds the SDK only inside example apps that talk to Facebook's own login
  services, and distributes no standalone copy of the SDK. The SDK binary
  enters an app because the developer's own build pulls it from Meta's
  tagged release at build time; nothing is vendored into this repository.
- Acceptance: the project accepts the Facebook Platform License for the
  optional native Facebook adapter only (the `auth.nativeSignIn` host-call path in
  the iOS and Android hosts). The browser-based flow remains the default
  Facebook sign-in in this repository, the native adapters are opt-in, and
  an app that does not enable them carries no Facebook SDK.
- Recorded here per docs/research/native-licensing.md's out-of-family rule;
  verification basis: docs/research/native-sdks.md §6 (LICENSE read at
  main, 2026-11-07). Full license text:

```text
Copyright (c) Meta Platforms, Inc. and affiliates. All rights reserved.

You are hereby granted a non-exclusive, worldwide, royalty-free license to use,
copy, modify, and distribute this software in source code or binary form for use
in connection with the web services and APIs provided by Facebook.

As with any software that integrates with the Facebook platform, your use of
this software is subject to the Facebook Platform Policy
[http://developers.facebook.com/policy/]. This copyright notice shall be
included in all copies or substantial portions of the software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
```

## Google Android SDKs (googleid, androidx.credentials)

- Dependencies: `com.google.android.libraries.identity.googleid:googleid`
  1.2.1 and `androidx.credentials:credentials` 1.6.0 (with
  `credentials-play-services-auth` at the same version), consumed as built
  AARs from the Google Maven repository by `examples/host-android`; not
  vendored.
- Licenses, per the artifacts' Maven POMs (fetched 2026-11-07):
  - `googleid` 1.2.1: **"Android Software Development Kit License"** —
    Google's SDK terms (https://developer.android.com/studio/terms.html, the
    POM's license URL), not an OSI license and outside the
    MIT/BSD/Apache-2.0 family, so the recorded acceptance below applies.
  - `androidx.credentials` 1.6.0: "The Apache Software License, Version
    2.0" — in family, same treatment as androidx.browser above; §4(a) is
    satisfied by the Apache-2.0 text reproduced in this file.
- Recorded acceptance (out-of-family license), 2026-11-07: Google's Android
  SDK terms govern development of Android applications with the SDK and
  govern the `googleid` artifact's distribution inside the example APKs. It
  is accepted here as a dependency of the optional native Google adapter
  only (the `auth.nativeSignIn` host-call path), pulled by the developer's own
  Gradle build from Google Maven, never vendored or redistributed
  standalone. The browser-based (Custom Tabs) flow remains the default
  Google sign-in in this repository, the native adapter is opt-in, and an
  app that does not enable it carries no `googleid` artifact. Verification
  basis: docs/research/native-sdks.md §4 and §6.
- Evaluated and skipped: `com.google.android.gms:play-services-auth` 22.0.0 —
  Google labels its GoogleSignIn API "outdated and no longer supported" in
  favor of Credential Manager (docs/research/native-sdks.md §4); not pinned,
  nothing distributed, so no entry beyond this line.

## Facebook Android SDK (facebook-login)

- Dependency: `com.facebook.android:facebook-login` 19.0.1, consumed as a
  built AAR from Maven Central (`repo1.maven.org`) by
  `examples/host-android`; not vendored, and never redistributed standalone.
- Copyright: Copyright (c) Meta Platforms, Inc. and affiliates. All rights
  reserved. (LICENSE.txt — same text as the iOS LICENSE)
- License: **Facebook Platform License** (Maven POM `<license><name>`; POM
  URL https://github.com/meta/facebook-android-sdk/blob/main/LICENSE.txt,
  verified 2026-11-07). The license text, the recorded decision and the
  NOTICE obligation are shared with the iOS SDK and recorded once under
  Facebook iOS SDK (FacebookLogin) above. Upstream's NOTICE.txt carries
  Apache-2.0 texts for the SDK's bundled third-party code; the Apache-2.0
  text is reproduced in this file under AppAuth-Android.

## tauri-plugin-oauth

- Source: https://github.com/FabianLars/tauri-plugin-oauth (canonical
  repository; the `tauri-apps` org URL does not resolve), version 2.1.0
  studied.
- No code copied; no license obligation arises. Two design ideas were adopted
  with independent implementation and are credited here:
  - Explicit `cancel()` shutdown: stopping the loopback listener by connecting
    to its own port so the accept loop returns (upstream's self-connect
    `cancel(port)`).
  - An optional fixed-port mode for providers that insist on an exact redirect
    port (upstream's configured fixed-port list); the default stays an
    OS-assigned port.
- This repository's loopback listener deliberately does not adopt the plugin's
  permissive request model (any path or method, weak `localhost` Host check, no
  timeout); its own validation is stricter. Recorded in
  docs/research/native-desktop.md.
- License: MIT OR Apache-2.0 (recorded for completeness; it would bind only if
  code were copied, which it is not).

## What is deliberately not here

- Provider trademarks and brand artwork. Google, Facebook, Discord, GitHub,
  Apple, Microsoft and X logos, badges and sign-in button artwork are
  trademark-governed, not copyright-governed; none is vendored or committed to
  this repository. The demo renders provider-branded buttons according to each
  provider's brand rules, with official assets the app owner supplies at setup
  time (docs/providers.md, docs/setup.md).
- Library artwork, such as AppAuth-iOS's `appauth_lockup.svg` — not copied; no
  use here requires it.
- Provider SDK code inside this repository. Since phase 3 the Google and
  Facebook SDKs are consumed as build-time dependencies when the optional
  native adapters are enabled (entries above, with the recorded decisions
  their out-of-family licenses require); Apple's auth frameworks are OS
  frameworks, not distributed by us. No provider SDK is vendored or copied
  into this repository, and none is redistributed standalone.
- Copyleft. No GPL, AGPL, SSPL or LGPL code is in this repository. Verified
  against every artifact studied in phase 2 (2026-11-07): the SPDX set is
  Apache-2.0, MIT and BSD-3-Clause only
  (docs/research/native-licensing.md). Any future import outside that family
  needs an explicit decision recorded there first; phase 3's out-of-family
  SDK licenses are dependencies, not imports, and carry their recorded
  decisions in the entries above.
