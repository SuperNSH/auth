//! PKCE (RFC 7636, S256) and the `state` and `nonce` values, all from the
//! operating system's CSPRNG.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rand::{RngCore, rngs::OsRng};
use sha2::{Digest, Sha256};

/// 64 random bytes: 86 base64url characters, inside RFC 7636's 43..128.
const VERIFIER_BYTES: usize = 64;
/// 32 random bytes: 43 base64url characters, matching common provider sizes.
const STATE_BYTES: usize = 32;

pub(crate) fn random_token() -> String {
    let mut bytes = [0u8; STATE_BYTES];
    OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

pub(crate) fn code_verifier() -> String {
    let mut bytes = [0u8; VERIFIER_BYTES];
    OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

pub(crate) fn code_challenge(verifier: &str) -> String {
    let digest = Sha256::digest(verifier.as_bytes());
    URL_SAFE_NO_PAD.encode(digest)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn s256_matches_the_rfc_7636_example() {
        // Appendix B test vector: proves the challenge is SHA-256, not SHA-1
        // or plain base64 of the verifier.
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        assert_eq!(
            code_challenge(verifier),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }

    #[test]
    fn tokens_are_url_safe_and_distinct() {
        let a = random_token();
        let b = random_token();
        assert_eq!(a.len(), 43);
        assert_ne!(a, b);
        assert!(
            a.bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
        );
        assert!(code_verifier().len() >= 43);
    }
}
