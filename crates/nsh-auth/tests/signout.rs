//! Sign-out: revocation at the provider, local clearing and signal reset;
//! and restoring a persisted session on a fresh service (the core half of
//! the restart proof — the secure-storage half belongs to the hosts).

mod common;

use common::{mock_config, setup, setup_with, sign_in};
use nsh_auth::{AuthError, AuthStatus, ProviderId, SessionStore};
use std::sync::Arc;

#[tokio::test]
async fn sign_out_revokes_clears_and_resets_the_signals() {
    let setup = setup(mock_config);
    sign_in(&setup).await;
    assert_eq!(setup.mock.count("/revoke"), 0);

    setup.auth.sign_out().await.expect("sign out");

    assert_eq!(setup.mock.count("/revoke"), 1);
    let body = setup.mock.requests("/revoke")[0].body.clone();
    assert!(
        body.contains("token=rt-1"),
        "revokes the refresh token: {body}"
    );
    assert_eq!(setup.auth.session.get_untracked(), None);
    assert_eq!(setup.auth.user.get_untracked(), None);
    assert_eq!(setup.auth.status.get_untracked(), AuthStatus::SignedOut);
    assert_eq!(setup.auth.error.get_untracked(), None);
    assert_eq!(setup.store.load("mock").unwrap(), None);
}

/// A 5xx revoke is a transient failure of the provider's side (retryable,
/// status only), and the local sign-out stands regardless: tokens are
/// cleared first, revocation reports separately.
#[tokio::test]
async fn a_5xx_revoke_failure_is_transient_and_the_local_sign_out_stands() {
    let setup = setup(mock_config);
    sign_in(&setup).await;
    setup.mock.set("/revoke", 503, "revoke on fire".to_owned());

    let error = setup.auth.sign_out().await.expect_err("a 5xx revoke fails");

    assert!(matches!(error, AuthError::ServerError(_)), "{error:?}");
    assert!(error.is_retryable());
    let message = format!("{error}");
    assert!(message.contains("503"), "{message}");
    assert!(!message.contains("revoke on fire"), "{message}");
    assert_eq!(setup.auth.status.get_untracked(), AuthStatus::SignedOut);
    assert_eq!(setup.store.load("mock").unwrap(), None);
}

#[tokio::test]
async fn sign_out_with_no_session_stays_clean() {
    let setup = setup(mock_config);
    setup.auth.sign_out().await.expect("sign out with nothing");
    assert_eq!(setup.mock.count("/revoke"), 0);
    assert_eq!(setup.auth.status.get_untracked(), AuthStatus::SignedOut);
}

#[tokio::test]
async fn a_persisted_session_restores_into_a_fresh_service() {
    let first = setup(mock_config);
    let session = sign_in(&first).await;
    let shared_store = Arc::clone(&first.store);

    // A new service on the same store: what an app restart looks like.
    let second = setup_with(mock_config, shared_store);
    assert_eq!(second.auth.session.get_untracked(), None);

    let restored = second
        .auth
        .restore(ProviderId::Mock)
        .expect("restore reads the store")
        .expect("a session was persisted");

    assert_eq!(restored, session);
    assert_eq!(second.auth.session.get_untracked().as_ref(), Some(&session));
    assert_eq!(second.auth.status.get_untracked(), AuthStatus::SignedIn);
}
