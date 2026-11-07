# STATUS

Progress tracker for the nsh-auth build. Every claim here must say how it was
verified; a claim with no evidence is reported as unverified. Updated as
milestones pass. The brief is `docs/PROMPT.md`; its hard rules bind every agent.

## Current phase

Workflow planning: a single `workflow-launcher` agent is parsing the brief into
areas and phase chains per the `z-workflow` skill. Nothing is built yet.

## Satisfaction criteria (from docs/PROMPT.md)

| # | Criterion | Status | Evidence |
|---|-----------|--------|----------|
| 1 | `docs/research.md` exists, cited, answers flow + registration per provider and per surface | unverified | — |
| 2 | Gates pass for crate, package, native modules; `xcodebuild` and Gradle builds of both hosts pass | unverified | — |
| 3 | Mock suite passes in Rust and TS: success, denial, wrong state, wrong nonce, expired code, refresh, single-flight refresh, revoked refresh, sign-out | unverified | — |
| 4 | Google/Facebook/Discord/GitHub authorize URLs asserted by tests; looked-at screenshots show provider domain on iOS simulator, Android emulator, macOS or web | unverified | — |
| 5 | Full loop against mock through the real redirect mechanism on iOS simulator, Android emulator, macOS, web; screenshots saved and looked at | unverified | — |
| 6 | Session survives app restart on iOS and Android from secure storage; test or log check shows no token in plain storage or logs | unverified | — |
| 7 | No client secret in any app bundle; GitHub broker path works against the mock | unverified | — |
| 8 | `z-security-auditor` pass reports no open high-severity finding; report in `docs/security-review.md` | unverified | — |
| 9 | README works from clean clone to mock sign-in to registering real client ids, without changing library code | unverified | — |

## Done

- Nothing yet beyond the repository skeleton and this file.

## Not verified / honest notes

- Everything above is unverified as of the start of the build.
