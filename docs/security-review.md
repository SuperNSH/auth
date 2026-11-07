# Security review

Criterion 8 of [docs/PROMPT.md](PROMPT.md): a `z-security-auditor` pass over redirect validation,
state and nonce checks, token storage, logging and URL handling, with no open high-severity
finding. This report compiles the per-area audit outcomes. Method: each area ran its own auditor
pass in capped rounds (max three); every fix was verified by re-audit in a later round; residuals
that survive are listed here with their justification rather than silently dropped.

Status at compile time: **every audited area converged clean; no HIGH finding is open.** The
docs walkthrough audit is listed below with its actual status.

## Per-area outcomes

### Rust core — `crates/nsh-auth`

- **Scope**: redirect/callback validation, state and nonce checks, session store trait, PKCE and
  single-flight refresh, sign-out with revocation, file persistence.
- **Rounds**: 3; final round clean.
- **Findings**:
  - Round 1 — 1 MEDIUM (single-flight refresh lost-wakeup: a waiter could miss the completing
    flight and hang or re-enter) — **fixed, verified**.
  - Round 1 — 3 LOW (callback origin check; stale-flight join; `0600` set after write, leaving a
    window where the token file is world-readable-per-umask) — **fixed, verified**.
  - Round 2 — 1 LOW (pending flag set after validation instead of before; scheme-only `http` arm
    in a redirect parser) — **fixed, verified**.
  - Round 3 — clean.
- **Accepted residuals**:
  - Same-thread apply/publish microtask window — inherent to the signal API the crate is built on;
    the session signal can observe a one-tick-stale value within a single thread. Documented, not
    fixable without changing the signal layer.
  - A legacy token file written wide-permission self-heals to `0600` on the first save after this
    fix; nothing rewrites already-shipped files.

### TypeScript core — `packages/nsh-auth`

- **Scope**: same protocol surface as the Rust core plus `handleRedirect`, the host launcher, the
  broker path, JWKS verification, session signals and restore.
- **Rounds**: 3; final round clean.
- **Findings**:
  - Round 1 — 1 MEDIUM (sign-out racing an in-flight refresh could resurrect a session after the
    user signed out) — **fixed, verified in round 2**.
  - Round 1 — 2 LOW (stale-callback availability after sign-out; README overclaimed what the
    no-host fallback can do) — **fixed, verified**.
  - Round 2 — 1 fresh MEDIUM (`deliverRedirect` missing an epoch guard: a redirect completing
    after a sign-out/re-sign-in cycle could apply to the wrong era) — **fixed, verified**.
  - Round 3 — clean; epoch guards confirmed complete at every suspension point.
- **Accepted residual**: post-save re-check microtask window on both the host and redirect paths —
  a store save and its immediate re-read can interleave within one microtask; bounded, benign, and
  documented.

### Native iOS — `native/ios` + `examples/host-ios`

- **Scope**: embedding host, capability declarations, URL scheme registration, Keychain storage,
  launcher plumbing.
- **Rounds**: 2; clean.
- **Findings**:
  - 2 MEDIUM — capability grant ceiling omitted `network` (fixed: host grants
    `{ host: auth.*, network: 127.0.0.1, localhost }`, nothing wider); callback scheme not
    validated against the app's own `CFBundleURLSchemes` (fixed: an inbound URL is accepted only
    on the registered scheme). Both **fixed, verified**.
  - 1 LOW — Keychain items not pinned to the device (fixed: `ThisDeviceOnly`, so backups never
    carry tokens). **Fixed, verified**.
- **Device-phase fixes beyond the audit**: a zero-capacity `URLCache` is installed in the
  AppDelegate before engine init — the device proof caught `URLSession` caching token responses
  in `Cache.db-wal` in plaintext. Found live on device, fixed, and covered by the storage checks.

### Native Android — `native/android` + `examples/host-android`

- **Scope**: intent filters, forged-intent resistance, return leg, secure storage, logging,
  backup surface.
- **Rounds**: 3; clean.
- **Findings**:
  - 2 HIGH — (1) forged-intent scheme/redirect validation: an intent carrying the registered
    scheme was forwarded without checking it against the allowlist (fixed: allowlist plus exact
    host/path match); (2) unreachable return leg on the emulator (fixed via
    `nsh.setParams` `params.auth { redirectUri, mockBaseUrl, autoStart }` so the host hands the
    redirect to the app deterministically). Both **fixed, verified**.
  - 3 LOW — extras only honored on cold start; `SecureStore` selectively drops entries on
    `AEADBadTagException` instead of crashing the app; `allowBackup=false`. All **fixed,
    verified**.
  - Round 2 — 1 LOW log-leak: callbacks were logged with query attached (fixed: logs carry
    `scheme://host/path` only, never the query). **Fixed, verified**.
- **Device-phase fixes**: `HOST_GRANT` network ceiling set to
  `127.0.0.1`/`localhost`/`10.0.2.2` (emulator host alias); the `ACTION_MAIN` gate was relaxed to
  creating-intent-only after the device run showed `am start` sends `action=null` — found live,
  fixed.
- **Accepted residual**: a forged intent carrying the *exact* registered scheme, host and path is
  host-side indistinguishable from a real provider redirect — this is inherent to custom-scheme
  OAuth on Android. The backstop is in the core: the state check is unconditional, so a forged
  redirect without the caller's `state` is dropped there. See the checklist's redirect row.

### Desktop + web launchers — `examples/host-desktop`, web path

- **Scope**: system-browser launch on Windows/Linux/macOS, loopback listener, redirect handling,
  token file storage, logging.
- **Rounds**: 3; clean.
- **Findings**:
  - 1 HIGH — Windows launched the browser through a shell split (`cmd /C start`), an argument
    injection sink for a provider-controlled URL. **Fixed**: `rundll32 url.dll,FileProtocolHandler`
    with a single argument — no shell, no splitting. Verified.
  - 1 MEDIUM — the authorization `state` and `nonce` were written to logs. **Fixed**: logs carry
    `redacted_url` (scheme + host + path only), unit-tested so the redaction cannot silently
    regress.
  - 1 LOW — `JsonFileStore` directory contract and a README doc drift. **Fixed, verified**.
- **Accepted residual**: the Windows proof is static-only (the sandbox has no Windows machine);
  the fix is verified by inspection and by the cross-platform launcher unit path, not by a live
  Windows run. Stated honestly rather than claimed.

### Mock + broker + scanner — `tools/mock-oauth`, `tools/broker`, `tools/check-no-secrets.mjs`

- **Scope**: the sandbox server, the reference token broker, and the no-secrets scanner.
- **Rounds**: 2; clean.
- **Findings**: 1 MEDIUM — the scanner did not scan `examples/` source, so a secret landing in an
  example tree would pass. **Fixed**, and verified by replicating the walk independently: the
  scanner's file set matches an independent recursive walk.
- **Design notes the audit reviewed and accepted**:
  - Broker: the client secret is environment-only; the broker refuses to start without it; it
    serves `POST /token` and nothing else on that path; it is CORS-free **by design** and this is
    documented — browser code must never be able to read it.
  - Mock: binds loopback only, sandbox-branded on every surface, echoes `state` verbatim on
    purpose (the client must validate it — that is what makes client bugs observable), and derives
    the issuer from the request `Host` with an authority-shape guard (an integration-driven choice
    for emulator/tunnel aliases; it remains a loopback dev tool, holds no real credentials, and
    makes no production claim).
  - The scanner's negative tests exercise the real entry point, not a reimplementation.

### Providers — `docs/providers.md`, `fixtures/provider-catalog.json`

- **Scope**: per-provider endpoint, scope, redirect, quirk, registration and brand facts against
  live official documentation.
- **Rounds**: 2 (fact-check audit); clean after fixes.
- **Findings**:
  - 2 HIGH — GitHub token check/reset routes were written in the legacy `.../token/{access_token}`
    path form; the documented API is `POST`/`PATCH /applications/{client_id}/token` with
    `access_token` in the body. **Fixed** in both files against the live REST docs.
  - 2 MEDIUM — the Facebook button fill was stated as the brand blue while the cited UX page names
    `5890FF` for the button. **Fixed**: both values are now stated with their own labels from the
    same page.
  - 2 LOW — the X example client id was syntactically valid with no visible fake marker. **Fixed**:
    replaced with an id that decodes to `nsh-sandbox-not-real00000000:1:ci`.

### Research — `docs/research.md`

- **Rounds**: 2; clean after fixes.
- **Findings**: 1 MEDIUM (GitHub token lifetimes were stale: refresh tokens and expiry now match
  the current docs) and 3 LOW (citation and path mismatches). All **fixed, verified**.

### Demo — `examples/demo`

- **Scope**: per-provider buttons against brand rules, mock provider wiring, session screen, forms,
  profile, web runtime compatibility.
- **Rounds**: 3; the final round verified clean with 1 MEDIUM fixed after the round cap — the
  form input border was stacking instead of replacing and its binding was not reactive. Fixed and
  verified after the cap, reported honestly here.
- **Audit outcomes**: complex trademarks are deliberately not drawn (documented in the button
  marks note) rather than approximated; mock/real provider paths are realm-aligned so sandbox and
  real flows cannot cross; the profile query cache is scoped per provider; web-runtime fatals
  (`env()`, `platform`, `lifecycle` imports) removed, with a query-free `App.web.tsx` for the web
  target; brand-token colors verified correct (ICC-sRGB checked).

### Docs walkthrough audit

- **Status**: not run at the time this file was compiled — it runs separately; see
  [docs/STATUS.md](STATUS.md) for its outcome.

## Cross-cutting checklist

| Topic | What the audited tree does | Status |
| --- | --- | --- |
| Redirect validation | iOS: inbound URL accepted only on the scheme registered in `CFBundleURLSchemes`. Android: forged-intent allowlist with exact host/path match; extras cold-start-only. TS core: `handleRedirect` epoch-guarded at every suspension point. Rust core: callback origin check. Backstop everywhere: the `state` check is unconditional in the core, on both cores' paths. | All fixes verified; Android exact-scheme forgery residual documented above |
| `state` | Generated crypto-random per sign-in; validated before any exchange; the mock echoes `state` verbatim on purpose so client validation stays observable and testable; wrong-`state` and missing-`state` mock tests pass on both cores | Clean |
| `nonce` | Generated per authorization, bound into the ID token, verified after JWKS signature check on every provider that mints one; wrong-`nonce` mock tests pass | Clean |
| Token storage | iOS: Keychain `ThisDeviceOnly`; zero-capacity `URLCache` installed before engine init so `URLSession` never caches token responses. Android: Keystore-backed SecureStore, `allowBackup=false`, selective `AEADBadTagException` drop. Desktop: `0600` file under the user profile, set before write; legacy wide file self-heals on first save. No token ever in plain `Storage` — asserted by the storage tests | Clean; desktop file is 0600-not-Keychain-grade by documented design (see docs/threats.md) |
| Logging | Desktop: `redacted_url` (scheme/host/path) unit-tested. Android: round-2 log-leak fixed to `scheme://host/path` only. Neither core logs tokens, codes, `state` or `nonce` | Clean |
| URL handling | No embedded web view anywhere (Google's `disallowed_useragent`, and it would expose credentials to the app): ASWebAuthenticationSession, Custom Tabs, system browser only. Windows launch is single-argv `rundll32 url.dll,FileProtocolHandler` (no shell split). Mock binds `127.0.0.1` only; broker is env-secret-only, `POST /token`-only and CORS-free by design; the network capability ceilings grant loopback hosts only (`127.0.0.1`, `localhost`, `10.0.2.2` on the emulator) | Clean |

## Verdict

**No HIGH finding remains open.** All five HIGH findings raised across the audits — the two
Android forged-intent/return-leg findings, the Windows shell-split browser launch, and the two
GitHub route errors in the provider docs — were fixed and verified by re-audit. Remaining known
limitations are the accepted residuals above, each with its justification in place.
