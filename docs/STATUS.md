# STATUS

Final status of the nsh-auth build. Every claim lists how it was verified;
anything not verified is stated as such. The brief is `docs/PROMPT.md`.

## Satisfaction criteria — all nine hold

| # | Criterion | Status | Evidence |
|---|-----------|--------|----------|
| 1 | `docs/research.md` cited; flow + registration per provider and surface | **VERIFIED** | `docs/research.md` (682 lines; per-provider sections with official URLs; five NSH 0.4.0 experiments run for real, logs in `docs/evidence/research/exp1–5`). Doc-accuracy audit converged in 2 rounds — citations spot-fetched against live pages (GitHub, Facebook, Google, Discord, Apple, Microsoft, X). |
| 2 | Gates pass: crate, package, native modules; `xcodebuild` + Gradle both hosts | **VERIFIED** | Whole-tree smoke round 2 (`tools/smoke.sh`): **all 11 steps clean** — cargo fmt/clippy `-D warnings`/test (31 tests), `nsh check`/`nsh build` zero warnings/`nsh test` + `bun test` (16 + 21), demo gates (22), mock/broker/tools bun suites (130/7/146), no-secrets scanner (498 files clean), iOS `BUILD SUCCEEDED` + gate passed, Android `BUILD SUCCESSFUL`. Coordinator ran the smoke. Native modules: Swift `swiftc -typecheck` vs SDK 27 + 0.4.0 frameworks; Kotlin `kotlinc` vs android.jar + shipped AAR. |
| 3 | Mock suite passes in Rust and TS: success, denial, wrong state, wrong nonce, expired code, refresh, single-flight, revoked refresh, sign-out | **VERIFIED** | Rust: 31 tests (`crates/nsh-auth/tests/`) cover the full named list incl. 8-parallel single-flight and epoch-guarded refresh; TS: 16 headless (`tests/auth.test.tsx`) + 21 protocol (`bun test`) mirror the list. Every new test proven red once by deliberate breakage (records in commit messages and area reports). |
| 4 | Authorize URLs asserted by tests; provider-domain screenshots on iOS simulator, Android emulator, macOS, web | **VERIFIED** | Tests: `authorize.rs` + `auth.test.tsx` pin byte-exact/regex URLs per provider (PKCE S256, state, scopes, redirect); regenerated `docs/evidence/desktop/authorize-urls.log` asserts all four live (4/4 S256 + state). Screenshots, all vision-checked (18/18 pass): `docs/evidence/<provider>/ios-simulator.png` (×4), `android-emulator.png` (×4), `macos.png` (google, github — recaptured in a clean browser profile), `web.png` (google, github). Each shows the provider's own domain rejecting the sandbox client id; no consent accepted, no credential typed. |
| 5 | Full loop against the mock through the real redirect mechanism on iOS, Android, macOS, web | **VERIFIED** (web via the documented paste-back bridge) | `mock/ios-loop.png` (ASWebAuthenticationSession), `mock/android-loop.png` + `mock/android-auto-loop.png` (intent filter; fully automatic — autoStart → Custom Tab → callback → session, no input, no tunnel), `mock/macos.png` (loopback listener, session window), `mock/web.png` (paste-back bridge: browser-received callback URL → PKCE exchange over real CORS → RS256 id-token nonce verified on screen). Platform limit stated honestly: nsh 0.4.0 has no inbound web redirect (browser refuses the custom scheme — recorded in `docs/upstream-issues.md`); the automatic leg exists on the other three surfaces. |
| 6 | Session survives restart on iOS and Android from secure storage; no token in plain storage or logs | **VERIFIED** | `mock/ios-restart.png` (immediate + 4.5-min restart, same token tail; whole-container grep 0 hits, `Library/Caches` never created after the zero-capacity URLCache fix, 1229-line log capture 0 tokens), `mock/android-restart.png` (Keystore-sealed `nsh-auth-store.json` mode 600, profile repopulated via persisted base; `run-as` grep 0 hits — session exists only as AES/GCM `iv`+`ct`). Keychain/Keystore are outside container greps; stated in the logs. |
| 7 | No client secret in any app bundle; GitHub broker path works against the mock | **VERIFIED** | iOS gate greps the whole built `.app` incl. bytecode (smoke round 2 passed after a comment literal that rode the sourcemap was reworded); Android gate greps fresh assets; scanner covers source + `examples/` (negative-tested with planted secrets). Broker: `tools/broker` holds `GITHUB_CLIENT_SECRET` env-only, refuses start without it, single `POST /token`; end-to-end bun test (mock on port 0 → broker → exchange → token authenticates at the mock); desktop + ts GitHub flows route through `brokerUrl` and assert no secret in any request. |
| 8 | Security-auditor pass, no open HIGH, report in `docs/security-review.md` | **VERIFIED** | Nine areas audited to convergence (rust ×3, ts ×3, iOS ×2, Android ×3, desktop ×3, mock ×2, providers ×2, research ×2, demo ×3); every high/medium fixed and re-audit-verified; accepted residuals documented with reasons. `docs/security-review.md`: verdict — no HIGH remains open. |
| 9 | README from clean clone → mock sign-in → registering real ids, without changing library code | **VERIFIED** | Clean-clone walkthrough round 2: followed literally; busy-port branch used as documented (`--port 0`); Path A ran the FULL automatic desktop loop live ending in "Mock sign-in complete"; all claimed suites pass in the clone (130/31/6/16/22/7); setup.md registration + broker steps match landed code. Round 1's 11 findings (4 high) fixed and committed (`8a8bc31`). |

## How the work ran

Ten areas (research, rust core, ts core, providers, mock, native-ios,
native-android, desktop+web, demo, docs) built in parallel by GLM-5.3-Flash
subagents under the z-workflow shape: implement → audit until clean (cap 3) →
gates → device proofs → vision. Coordinator verified every gate personally and
re-audited after each fix round. Milestone commits: `6ab2940`, `c1669a5`,
`8956486`, `8a8bc31`, final.

Device proofs found real bugs no static audit could: the ts host-store JSON
string contract (Android `requireString` fatal, iOS restore gap), iOS
URLSession caching tokens to `Cache.db-wal` in plaintext, the Android
capability ceiling without `network` (every fetch denied), `am start` sending
`action=null` (launch extras silently dropped), the web runtime's fatal
`env()`/`platform`/`lifecycle` imports, the mock's fixed issuer breaking the
emulator alias, and missing CORS for the web loop. Each was fixed and re-proven
on device.

## Honest limits

- **Web automatic redirect does not exist on nsh 0.4.0** (no inbound path;
  browser refuses the custom scheme — upstream issue filed). Criterion 5's web
  leg completes via the demo's documented paste-back bridge with a real
  browser-received callback URL; the exchange and ID-token verification are
  fully real.
- **Windows browser-open path is cfg(windows)**: verified statically (std
  quoting semantics cited in code) + green macOS gates; no Windows machine
  exists here. Documented accepted residual.
- **nsh-query cannot load on the 0.4.0 web runtime** (`lifecycle` import is
  web-fatal) — upstream issue filed for its owner; the demo ships a query-free
  `App.web.tsx` account variant on web.
- Hostless surfaces (no embedding host) end at paste-back by design; the
  README's Path B documents this honestly.
- The `nsh-auth-demo://` strings remaining in `tests/protocol.spec.ts` are
  arbitrary byte-exact test fixtures, not configuration.
- Vision judgments used pixel OCR + uiautomator/semantic dumps when the vision
  MCP rate-limited; every disclosure is in `docs/evidence/*/` logs.
