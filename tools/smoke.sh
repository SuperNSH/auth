#!/usr/bin/env bash
# Whole-tree smoke gate for nsh-auth. Runs every area's documented gate in
# order and stops at the first failure. Run from anywhere:
#
#   bash tools/smoke.sh
#
# Steps and their authoritative sources (INSPECTED before writing this file):
#   a-c  repo root Cargo gates. Root Cargo.toml workspace members = only
#        ["crates/nsh-auth"]; examples/host-desktop is its own crate and is
#        covered by its area's verification, not by these root gates.
#   d    packages/nsh-auth/README.md: `nsh check && nsh build && nsh test &&
#        bun test`, all exit 0. bunfig.toml here scopes `bun test` to
#        tests/protocol.spec.ts (the nsh/test suites belong to `nsh test`).
#   e    examples/demo/README.md: `nsh check`, `nsh build` ("read every warn
#        as a finding"), `nsh test`. The --target macos look test is a
#        device-phase extra, not part of this headless gate.
#   f,g  tools/mock-oauth/README.md and tools/broker/package.json: bun test.
#   h    tools/tests/ (the scanner suite). `bun test` from tools/ recurses
#        into mock-oauth and broker suites already run by steps f/g — kept
#        as specified; a duplicate run is redundant, never weaker.
#   i    node tools/check-no-secrets.mjs — the script defaults its scan root
#        to the repository root when run from anywhere.
#   j    examples/host-ios/build-gate.sh — self-contained: builds the demo
#        bundle and xcodebuilds against this repo's pinned "nsh-auth"
#        simulator; needs Xcode + that simulator to exist.
#   k    examples/host-android/build-gate.sh — JAVA_HOME/ANDROID_HOME are
#        exported here (the script also exports the same values itself).

set -euo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
LAST_STEP="(startup)"
LOG="$(mktemp)"
trap 'echo "SMOKE GATE FAILED [$LAST_STEP]" >&2' ERR
trap 'rm -f "$LOG"' EXIT

banner() {
    LAST_STEP="$1"
    printf '\n==> %s\n' "$1"
}

die() {
    echo "SMOKE GATE FAILED [$LAST_STEP]: $*" >&2
    exit 1
}

cd "$ROOT"

banner "a/11 cargo fmt (repo root)"
cargo fmt --all -- --check

banner "b/11 cargo clippy -D warnings (repo root: crates/nsh-auth)"
cargo clippy --all-targets -- -D warnings

banner "c/11 cargo test (repo root)"
cargo test

banner "d/11 TypeScript core gates (packages/nsh-auth)"
(
    cd "$ROOT/packages/nsh-auth"
    nsh check
    # Zero warnings is the gate: build output must not contain the word at all.
    if ! nsh build >"$LOG" 2>&1; then
        cat "$LOG"
        die "nsh build failed"
    fi
    warn_count="$(grep -ci warning "$LOG" || true)"
    if [ "$warn_count" -ne 0 ]; then
        cat "$LOG"
        die "nsh build emitted $warn_count warning(s)"
    fi
    nsh test
    bun test
)

banner "e/11 demo gates (examples/demo)"
(
    cd "$ROOT/examples/demo"
    nsh check
    if ! nsh build >"$LOG" 2>&1; then
        cat "$LOG"
        die "nsh build failed"
    fi
    warn_count="$(grep -ci warning "$LOG" || true)"
    if [ "$warn_count" -ne 0 ]; then
        cat "$LOG"
        die "nsh build emitted $warn_count warning(s)"
    fi
    nsh test
)

banner "f/11 mock provider suite (tools/mock-oauth)"
(
    cd "$ROOT/tools/mock-oauth"
    bun test
)

banner "g/11 broker suite (tools/broker)"
(
    cd "$ROOT/tools/broker"
    bun test
)

banner "h/11 tools suite incl. no-secrets scanner tests (tools/tests)"
(
    cd "$ROOT/tools"
    bun test
)

banner "i/11 no-secrets scan (node tools/check-no-secrets.mjs)"
(
    cd "$ROOT"
    node tools/check-no-secrets.mjs
)

banner "j/11 iOS embedding host gate (examples/host-ios: bundle + xcodebuild)"
(
    cd "$ROOT/examples/host-ios"
    bash build-gate.sh
)

banner "k/11 Android embedding host gate (examples/host-android: bundle + gradle)"
(
    export JAVA_HOME="/Applications/Android Studio.app/Contents/jbr/Contents/Home"
    export ANDROID_HOME="$HOME/Library/Android/sdk"
    cd "$ROOT/examples/host-android"
    bash build-gate.sh
)

printf '\nSMOKE GATE PASSED: all 11 steps clean.\n'
