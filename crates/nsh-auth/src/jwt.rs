//! ID-token claim reading and RS256 verification against a provider's JWKS.

use crate::error::AuthError;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rsa::sha2::Sha256;
use rsa::signature::Verifier;
use rsa::{
    BigUint, RsaPublicKey,
    pkcs1v15::{Signature, VerifyingKey},
};

/// What an id token is checked against when one arrives.
#[derive(Debug, Clone)]
pub struct IdTokenChecks<'a> {
    /// The nonce sent in the authorize request, when one was sent.
    pub nonce: Option<&'a str>,
    /// The expected `iss`; skipped when the provider's issuer varies by
    /// tenant (Microsoft).
    pub issuer: Option<&'a str>,
    /// The app's client id, which must appear in `aud`.
    pub audience: &'a str,
    pub now_ms: i64,
}

/// The token's claims without any signature check. For inspection and for
/// providers with no JWKS; sign-in paths verify first when keys exist.
pub fn claims(token: &str) -> Result<serde_json::Value, AuthError> {
    let (header, claims, _) = split(token)?;
    check_alg(&header)?;
    Ok(claims)
}

/// Verifies the token's RS256 signature against `jwks` and checks the
/// binding claims, returning the claims.
pub(crate) fn verify(
    token: &str,
    jwks: &serde_json::Value,
    checks: &IdTokenChecks<'_>,
) -> Result<serde_json::Value, AuthError> {
    let (header, claims, _) = split(token)?;
    check_alg(&header)?;
    let signature = decode_signature(token)?;
    let public = jwks_public_key(jwks, header.get("kid").and_then(|k| k.as_str()))?;

    VerifyingKey::<Sha256>::new(public)
        .verify(signing_input(token).as_bytes(), &signature)
        .map_err(|_| AuthError::Unknown("id token signature verification failed".to_owned()))?;

    if let Some(exp) = claims.get("exp").and_then(|v| v.as_i64())
        && exp * 1000 <= checks.now_ms
    {
        return Err(AuthError::Unknown("id token is expired".to_owned()));
    }
    if let Some(expected) = checks.nonce {
        let got = claims.get("nonce").and_then(|v| v.as_str());
        if got != Some(expected) {
            return Err(AuthError::NonceMismatch);
        }
    }
    if let Some(expected) = checks.issuer {
        let got = claims.get("iss").and_then(|v| v.as_str());
        if got != Some(expected) {
            return Err(AuthError::Unknown(format!(
                "id token issuer is {got:?}, expected {expected:?}"
            )));
        }
    }
    let audience_ok = match claims.get("aud") {
        Some(serde_json::Value::String(aud)) => aud == checks.audience,
        Some(serde_json::Value::Array(auds)) => {
            auds.iter().any(|a| a.as_str() == Some(checks.audience))
        }
        _ => false,
    };
    if !audience_ok {
        return Err(AuthError::Unknown(
            "id token audience does not include this client id".to_owned(),
        ));
    }
    Ok(claims)
}

/// Everything before the second dot: the bytes the signature covers.
fn signing_input(token: &str) -> &str {
    &token[..token.rfind('.').unwrap_or(0)]
}

fn split(token: &str) -> Result<(serde_json::Value, serde_json::Value, String), AuthError> {
    let mut parts = token.split('.');
    let (Some(header), Some(claims), Some(signature), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(AuthError::Unknown(
            "id token is not three dot-separated parts".to_owned(),
        ));
    };
    Ok((
        decode_json(header)?,
        decode_json(claims)?,
        signature.to_owned(),
    ))
}

fn decode_json(part: &str) -> Result<serde_json::Value, AuthError> {
    let raw = URL_SAFE_NO_PAD
        .decode(part)
        .map_err(|_| AuthError::Unknown("id token part is not base64url".to_owned()))?;
    serde_json::from_slice(&raw)
        .map_err(|_| AuthError::Unknown("id token part is not JSON".to_owned()))
}

fn check_alg(header: &serde_json::Value) -> Result<(), AuthError> {
    let alg = header
        .get("alg")
        .and_then(|a| a.as_str())
        .unwrap_or_default();
    if alg != "RS256" {
        return Err(AuthError::Unknown(format!(
            "id token alg is {alg:?}; only RS256 is accepted"
        )));
    }
    Ok(())
}

fn decode_signature(token: &str) -> Result<Signature, AuthError> {
    let raw = URL_SAFE_NO_PAD
        .decode(token.rsplit('.').next().unwrap_or_default())
        .map_err(|_| AuthError::Unknown("id token signature is not base64url".to_owned()))?;
    Signature::try_from(raw.as_slice())
        .map_err(|e| AuthError::Unknown(format!("id token signature is malformed: {e}")))
}

fn jwks_public_key(jwks: &serde_json::Value, kid: Option<&str>) -> Result<RsaPublicKey, AuthError> {
    let keys = jwks
        .get("keys")
        .and_then(|k| k.as_array())
        .ok_or_else(|| AuthError::Unknown("jwks carries no keys array".to_owned()))?;
    // With no kid on the token the first signing key is used: providers with
    // one key (Apple's current set) do not send one either.
    let key = keys
        .iter()
        .find(|k| {
            k.get("kty").and_then(|t| t.as_str()) == Some("RSA")
                && (kid.is_none() || k.get("kid").and_then(|i| i.as_str()) == kid)
        })
        .ok_or_else(|| AuthError::Unknown("no RSA jwks key matches this id token".to_owned()))?;
    let component = |field: &str| -> Result<BigUint, AuthError> {
        let raw = key
            .get(field)
            .and_then(|v| v.as_str())
            .ok_or_else(|| AuthError::Unknown(format!("jwks key has no {field}")))?;
        let bytes = URL_SAFE_NO_PAD
            .decode(raw)
            .map_err(|_| AuthError::Unknown(format!("jwks key {field} is not base64url")))?;
        Ok(BigUint::from_bytes_be(&bytes))
    };
    RsaPublicKey::new(component("n")?, component("e")?)
        .map_err(|e| AuthError::Unknown(format!("jwks key is not usable: {e}")))
}
