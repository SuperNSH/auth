# Upstream issues

Bugs found in the sibling libraries this repository builds on — `~/fo/nsh-query` and
`~/fo/nsh-form` — are recorded here. The rule: a bug gets a written-up entry, and any workaround
in this repository's code carries a comment pointing at that entry. A bug is never silently worked
around, and those repositories are never edited from here (they are owned elsewhere and read-only
for this build).

Entries are appended at the join — the coordinator's end-of-build pass collects issues found by
the area agents into this file — so if you hit an upstream bug while building your area, keep the
detail (what you did, what happened, what you expected) available for the join even before an
entry exists.

## Entry template

```
### <short title>
- Found in: <nsh-query | nsh-form>, <crate or package, component>
- What happens: <observed behavior, with the input that triggers it>
- Expected: <what the sibling library's own docs or API imply>
- Hit while: <what this repo was doing when found>
- Workaround here: <what this repo does instead, and where>
- Suggested upstream fix: <one line, or "none — report as-is">
```

## Entries

nsh 0.4.0 runtime issues use the same template — `nsh` is upstream of both cores — with the area
that hit the issue named at the end.

### embed-ios AppDelegate-window lifecycle predates the UIScene requirement
- Found in: nsh 0.4.0, `examples/embed-ios`
- What happens: the example's app lifecycle is sceneless (an AppDelegate that owns `UIWindow`).
  Apps built with iOS SDK 26+ require the UIScene lifecycle (`UIApplicationSceneManifest`); building
  the example as-is on a current SDK fails or behaves undefined at launch.
- Expected: Apple's current SDKs require scene-based lifecycle for new builds; the shipped example
  should demonstrate the lifecycle it compiles against.
- Hit while: native-ios built the embedding host; our host uses a `SceneDelegate` instead, with
  identical `NshAppView` calls (the view API itself is lifecycle-agnostic).
- Workaround here: `examples/host-ios` uses a SceneDelegate; the `NshAppView` calls match
  `examples/embed-ios` one-for-one.
- Suggested upstream fix: ship `examples/embed-ios` with a scene manifest + `SceneDelegate` (or
  gate both variants in the example). Reported by native-ios.

### Bundled nsh skill documents capabilities that do not exist in nsh-core 0.4.0
- Found in: nsh 0.4.0, bundled skill docs vs `nsh-core` `access.rs`
- What happens: the skill (which follows main) lists the `notifications` capability and the
  `nsh/updater` module; neither exists in nsh-core 0.4.0 (`access.rs` enumerates the real set:
  `network`, `webview`, `statusBar`, `clipboard`, `picker`, `speech`, `openUrl`, `process`, `fs`,
  `host`). Following the skill on 0.4.0 produces capability declarations that fail the build.
- Expected: installed skill docs should match the installed binary's capability set.
- Hit while: research reconciled the skill against `.nsh/types` and the crate source.
- Workaround here: trust `.nsh/types` (and `~/.cargo/registry/src/*/nsh-core-0.4.0`) over the
  bundled skill whenever they disagree on 0.4.0.
- Suggested upstream fix: version-scope the skill to the release it ships with. Reported by
  research.

### Web runtime drops fetch `RequestInit.cache` at the transport boundary
- Found in: nsh 0.4.0, web runtime, `web/fetch.rs:1571-1578`
- What happens: `RequestInit.cache` is typed and parsed, then dropped — `HttpRequest` has no
  `cache` field — so a fetch with `cache: "no-store"` still went through the browser's HTTP cache.
  Concretely: token responses were landed in `URLCache` (plaintext, `Cache.db-wal`) despite the
  app asking for no caching.
- Expected: a parsed-and-typed option must reach the transport; "no-store" must mean no store.
- Hit while: ts core verified token transport on web.
- Workaround here: hosts must install a zero-capacity `URLCache` before engine init (our iOS host
  does this in the AppDelegate); the library cannot fix it from inside the app on 0.4.0.
- Suggested upstream fix: add `cache` to `HttpRequest` and honor `no-store` (or reject the option
  loudly instead of silently dropping it). Reported by ts core.

### `import { platform } from "nsh"` and `import { lifecycle } from "nsh"` fatally crash the web runtime
- Found in: nsh 0.4.0, web runtime, module exports (`platform`, `lifecycle`)
- What happens: importing either binding crashes a web app even when the value is never read —
  the import itself trips `Function.prototype.apply` on undefined at the wasm→JS boundary.
  Escalation: `nsh-query`'s `createQuery` calls `untracked(lifecycle)` internally, so any app using
  nsh-query cannot load on web at all.
- Expected: importing an exported binding must never crash; unused imports must be inert.
- Hit while: demo removed web-runtime fatals; the web target needed a query-free `App.web.tsx`.
- Workaround here: `examples/demo` ships `App.web.tsx` without nsh-query (and without `platform` /
  `lifecycle` imports) for the web target.
- Suggested upstream fix: define both bindings for the web target (or export them lazily).
  **This is the big one for `~/fo/nsh-query`'s owner** — nsh-query is unusable on web on 0.4.0
  through no fault of its own. Reported by demo.

### Web runtime crashes on `env()` inside arbitrary class-value math
- Found in: nsh 0.4.0, web runtime, CSS class-value handling
- What happens: a class like `pt-[calc(env(safe-area-inset-top)+16px)]` crashes rendering on the
  web target, while the same class renders fine on native targets.
- Expected: arbitrary class-value math, including `env()`, should pass through as CSS like any
  other target.
- Hit while: demo styled the session screen for notched devices.
- Workaround here: the demo uses static padding on web; no `env()` in class values.
- Suggested upstream fix: pass arbitrary values through to CSS on web, or document the supported
  subset. Reported by demo.

### Web `openUrl` has no inbound-redirect path: automatic web OAuth redirects are impossible
- Found in: nsh 0.4.0, web runtime, `openUrl` / inbound URL handling
- What happens: `openUrl` calls `window.open(url, "_blank")` and there is no API for receiving a
  URL back (no `window`, no `location`, no inbound-URL channel). An OAuth `redirect_uri` on web can
  therefore never return control to the app by itself.
- Expected: RFC 8252's web counterpart needs some redirect return path; `open` + inbound URL is
  the documented pairing on every other target.
- Hit while: desktop+web verification closed the loop against the mock on web.
- Workaround here: paste-back bridging is the only loop — a script on the `redirect_uri` page
  reads `location.search` and hands the callback URL to the app, which calls
  `auth.handleRedirect(url)`; documented honestly in `packages/nsh-auth/README.md`.
- Suggested upstream fix: expose an inbound-URL bridge (e.g. a `postMessage`/poll channel or a
  `location`-reading API) on the web target. Reported by desktop+web verification.

- **nsh-core 0.4.0: a control that unmounts itself after spawning multi-poll work from its own listener loses that work.** `ambient::spawn` tasks are detached (dropping the `Task` handle does NOT cancel — `element/task.rs` `detached: true`), so the oft-assumed "dropped handle cancels the task" is false. The real hazard: a listener living inside a `when(...)` region ends when the flip unmounts the control, and the run's owner disposal cancels tasks spawned from that listener before later polls. Reproduced in `examples/host-desktop` sign-out: poll 1 ran (local effects), poll 2 (the provider revoke) never arrived — with the handle retained; fixed by rooting the task in the `create_root` owner (`Owner::run`). Suggested sweep: any fire-and-forget spawn from a self-unmounting control. — reported by desktop+web.
- **nsh 0.4.0 headless engine: `ReqwestHttp` futures inside engine-spawned tasks never progress** — local effects run, `reqwest` logs "starting new connection", then silence; no TCP connect reaches the server; no panic. Reproduced twice under `nsh test`-style headless runs; the live desktop app's auto-start path (spawn from the `App` component body, long-lived owner) works. Root cause is in the core/engine/tokio interplay and needs a core-area investigation. Workaround: inject an in-process transport in tests; run flows from long-lived owners. — reported by desktop+web.
