// Pure helpers for NativeSignInModule, extracted with no SDK imports so they
// can be unit-asserted (native/ios/tests/auth-signin-math-test.sh).

import CryptoKit
import Foundation

enum AuthSignInMath {
    /// Apple's anti-replay rule: ASAuthorizationOpenIDRequest carries
    /// SHA-256-hex(raw) in lowercase; the core verifies id_token.nonce == it.
    static func sha256Hex(_ raw: String) -> String {
        SHA256.hash(data: Data(raw.utf8)).map { String(format: "%02x", $0) }.joined()
    }

    /// Session.expiresAt is wall-clock epoch MILLISECONDS (the Android module
    /// sends Date.getTime()); seconds would read as an already-expired session.
    static func facebookExpiresAt(_ date: Date) -> Int {
        Int(date.timeIntervalSince1970 * 1000)
    }
}
