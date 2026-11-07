#!/bin/sh
# Unit asserts for the pure sign-in math in native/ios/Sources/AuthSignInMath.swift.
# The code ships for iOS, but it is pure Foundation (no UIKit/SDK types), so the
# runner compiles for the host with plain swiftc — a simulator binary would need
# DYLD_ROOT_PATH to even start. Covers the epoch-ms conversion the channel
# contract requires and a known SHA-256 vector. Any mismatch exits non-zero.
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
SRC="$SCRIPT_DIR/../Sources/AuthSignInMath.swift"
OUT=$(mktemp -d)
trap 'rm -rf "$OUT"' EXIT

cat > "$OUT/main.swift" <<'EOF'
import Foundation

var failures = 0
func assertEq<T: Equatable>(_ actual: T, _ expected: T, _ label: String) {
    if actual != expected {
        print("FAIL \(label): \(actual) != \(expected)")
        failures += 1
    }
}

// Facebook expiresAt must be epoch MILLISECONDS: the channel contract,
// the Android module (Date.getTime()) and Session.expiresAt all use ms.
assertEq(
    AuthSignInMath.facebookExpiresAt(Date(timeIntervalSince1970: 1_700_000_000.5)),
    1_700_000_000_500,
    "facebookExpiresAt sub-second precision"
)
assertEq(
    AuthSignInMath.facebookExpiresAt(Date(timeIntervalSince1970: 0)),
    0,
    "facebookExpiresAt epoch zero"
)

// NIST SHA-256 vector for "abc".
assertEq(
    AuthSignInMath.sha256Hex("abc"),
    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    "sha256Hex NIST vector"
)
// Lowercase hex, 64 chars (Apple's canonical nonce form).
assertEq(AuthSignInMath.sha256Hex("nonce").count, 64, "sha256Hex length")
assertEq(AuthSignInMath.sha256Hex("nonce"), AuthSignInMath.sha256Hex("nonce").lowercased(), "sha256Hex lowercase")

if failures > 0 {
    print("auth-signin-math: \(failures) failure(s)")
    exit(1)
}
print("auth-signin-math: all asserts passed")
EOF

swiftc "$SRC" "$OUT/main.swift" -o "$OUT/auth-signin-math-test"
"$OUT/auth-signin-math-test"
