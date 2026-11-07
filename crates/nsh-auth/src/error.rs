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
    #[error("server error: {0}")]
    ServerError(String),
    #[error("the token broker failed: {0}")]
    BrokerError(String),
    #[error("the session store failed: {0}")]
    StoreError(String),
    #[error("no launcher available to open the authorize URL")]
    NoLauncher,
    #[error("{0}")]
    Unknown(String),
}

impl AuthError {
    /// Whether the failed operation is worth retrying with the same session:
    /// transient failures (network, a provider or broker 5xx) clear on
    /// their own and leave the session intact. Fatal ones — a denied
    /// request, a revoked grant, a mismatched `state` or `nonce`, a
    /// broker's 4xx refusal — answer the same however often they are
    /// retried, and refresh answers a fatal failure by signing out.
    pub fn is_retryable(&self) -> bool {
        matches!(self, AuthError::Network(_) | AuthError::ServerError(_))
    }
}
