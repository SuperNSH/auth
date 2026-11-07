//! The error type every auth operation fails with.

/// Everything a sign-in, refresh or sign-out can fail with. `NoLauncher` is
/// part of the shared surface for embedding hosts (no system browser to open
/// the authorize URL); this core never opens URLs, so it never returns it.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AuthError {
    #[error("the user denied the request")]
    AccessDenied,
    #[error("the callback state does not match the authorize request")]
    StateMismatch,
    #[error("the id token nonce does not match the authorize request")]
    NonceMismatch,
    #[error("the authorization code expired or was already used")]
    ExpiredCode,
    #[error("the refresh token grant is no longer valid")]
    InvalidGrant,
    #[error("network error: {0}")]
    Network(String),
    #[error("the token broker failed: {0}")]
    BrokerError(String),
    #[error("the session store failed: {0}")]
    StoreError(String),
    #[error("no launcher available to open the authorize URL")]
    NoLauncher,
    #[error("{0}")]
    Unknown(String),
}
