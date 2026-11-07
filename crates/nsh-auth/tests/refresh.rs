//! Refresh: session update, rotation semantics, single-flight under
//! parallel callers, the revoked-grant sign-out, and which failures are
//! transient enough to retry.

mod common;

use common::{arm_token, callback, mock_config, query_pair, setup, sign_in};
use nsh_auth::{AuthError, AuthStatus, ProviderId, Session, SessionStore};
use serde_json::json;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};

#[tokio::test]
async fn refresh_updates_the_session_and_the_store() {
    let setup = setup(mock_config);
    sign_in(&setup).await;
    setup.mock.set(
        "/token",
        200,
        json!({"access_token": "at-2", "refresh_token": "rt-2", "expires_in": 3600}).to_string(),
    );

    let session = setup.auth.refresh().await.expect("refresh");

    assert_eq!(session.access_token, "at-2");
    assert_eq!(session.refresh_token.as_deref(), Some("rt-2"));
    assert_eq!(session.expires_at, common::NOW_MS + 3_600_000);
    // The response carries no id token: the previous one is kept.
    assert!(session.id_token.is_some());
    assert_eq!(setup.auth.session.get_untracked().as_ref(), Some(&session));
    assert_eq!(setup.store.load("mock").unwrap().as_ref(), Some(&session));
    assert_eq!(setup.auth.status.get_untracked(), AuthStatus::SignedIn);

    // The refresh request is a public-client request: the grant, the token
    // and the client id, and nothing else.
    let body = setup.mock.requests("/token")[1].body.clone();
    assert!(body.contains("grant_type=refresh_token"), "{body}");
    assert!(body.contains("refresh_token=rt-1"), "{body}");
    assert!(body.contains(common::CLIENT_ID), "{body}");
    assert!(!body.to_ascii_lowercase().contains("secret"), "{body}");
}

#[tokio::test]
async fn eight_parallel_refreshes_share_one_token_request() {
    let setup = setup(mock_config);
    sign_in(&setup).await;
    setup.mock.set(
        "/token",
        200,
        json!({"access_token": "at-2", "refresh_token": "rt-2", "expires_in": 3600}).to_string(),
    );

    let auth = &setup.auth;
    let (a, b, c, d, e, f, g, h) = tokio::join!(
        auth.refresh(),
        auth.refresh(),
        auth.refresh(),
        auth.refresh(),
        auth.refresh(),
        auth.refresh(),
        auth.refresh(),
        auth.refresh(),
    );
    for result in [a, b, c, d, e, f, g, h] {
        let session = result.expect("every caller shares the one refresh");
        assert_eq!(session.access_token, "at-2");
    }

    let refreshes = setup
        .mock
        .requests("/token")
        .iter()
        .filter(|recorded| recorded.body.contains("grant_type=refresh_token"))
        .count();
    assert_eq!(refreshes, 1, "eight callers, exactly one HTTP refresh");
    assert_eq!(
        setup.auth.session.get_untracked().unwrap().access_token,
        "at-2"
    );
}

#[tokio::test]
async fn revoked_refresh_token_signs_out() {
    let setup = setup(mock_config);
    sign_in(&setup).await;
    setup
        .mock
        .set("/token", 400, json!({"error": "invalid_grant"}).to_string());

    let error = setup
        .auth
        .refresh()
        .await
        .expect_err("a revoked grant fails");

    assert_eq!(error, AuthError::InvalidGrant);
    assert_eq!(setup.auth.session.get_untracked(), None);
    assert_eq!(setup.auth.user.get_untracked(), None);
    assert_eq!(setup.auth.status.get_untracked(), AuthStatus::SignedOut);
    assert_eq!(
        setup.auth.error.get_untracked(),
        Some(AuthError::InvalidGrant)
    );
    assert_eq!(
        setup.store.load("mock").unwrap(),
        None,
        "the dead session is dropped"
    );
}

/// RFC 6749 §5.1/§6: rotation is optional, so a refresh response may omit
/// `refresh_token`. Dropping the previous token there strands the session
/// (AppAuth-iOS keeps it, OIDAuthState.m:400-402).
#[tokio::test]
async fn refresh_omitting_refresh_token_keeps_the_previous_one() {
    let setup = setup(mock_config);
    sign_in(&setup).await; // rt-1
    setup.mock.set(
        "/token",
        200,
        json!({"access_token": "at-2", "expires_in": 3600}).to_string(),
    );

    let session = setup.auth.refresh().await.expect("refresh");

    assert_eq!(session.access_token, "at-2");
    assert_eq!(session.refresh_token.as_deref(), Some("rt-1"));
    let stored = setup.store.load("mock").unwrap().expect("stored session");
    assert_eq!(stored.refresh_token.as_deref(), Some("rt-1"));

    // The kept token still refreshes: the session is not stranded.
    setup.mock.set(
        "/token",
        200,
        json!({"access_token": "at-3", "refresh_token": "rt-3", "expires_in": 3600}).to_string(),
    );
    let session = setup
        .auth
        .refresh()
        .await
        .expect("refresh with the kept token");
    assert_eq!(session.refresh_token.as_deref(), Some("rt-3"));
    let body = setup.mock.requests("/token")[2].body.clone();
    assert!(body.contains("refresh_token=rt-1"), "{body}");
}

#[tokio::test]
async fn refresh_without_a_session_or_token_fails_cleanly() {
    let setup = setup(mock_config);
    let error = setup.auth.refresh().await.expect_err("no session");
    assert!(matches!(error, AuthError::Unknown(message) if message.contains("no session")));

    // GitHub issues no refresh token; a session without one cannot refresh.
    let session = Session {
        provider: ProviderId::Github,
        access_token: "gh".to_owned(),
        refresh_token: None,
        id_token: None,
        expires_at: 0,
        scope: String::new(),
    };
    setup.auth.session.set(Some(session));
    let error = setup.auth.refresh().await.expect_err("no refresh token");
    assert!(matches!(error, AuthError::Unknown(message) if message.contains("refresh token")));
}

/// The app signs in again while an older refresh hangs: the new session owns
/// the signals and the store from then on. The token endpoint moves to
/// /token2 so the hanging /token request cannot answer the fresh sign-in.
async fn re_sign_in(setup: &common::Setup, access_token: &str, refresh_token: &str) -> Session {
    let mut config = mock_config(&setup.mock);
    config.token_url = setup.mock.url("/token2");
    setup.auth.register(config);
    let request = setup
        .auth
        .authorize_request(ProviderId::Mock)
        .expect("authorize");
    let nonce = query_pair(&request.url, "nonce");
    let state = query_pair(&request.url, "state");
    arm_token(
        &setup.mock,
        "/token2",
        access_token,
        Some(refresh_token),
        Some(&nonce),
    );
    setup
        .auth
        .complete(ProviderId::Mock, &callback("code-2", &state))
        .await
        .expect("second sign in")
}

/// Polls `future` to readiness, giving slow mock responses time to land;
/// `None` after a deadline, so a bug fails instead of hanging the suite.
fn poll_until_ready<F: Future>(mut future: Pin<&mut F>, cx: &mut Context<'_>) -> Option<F::Output> {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match future.as_mut().poll(cx) {
            Poll::Ready(output) => return Some(output),
            Poll::Pending if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(25));
            }
            Poll::Pending => return None,
        }
    }
}

#[tokio::test]
async fn an_orphaned_flight_is_not_joined_by_a_newer_session() {
    let setup = setup(mock_config);
    sign_in(&setup).await; // rt-1

    // Start refreshing rt-1 against a slow token endpoint, then abandon the
    // caller: the flight stays in the slot, orphaned.
    setup.mock.set(
        "/token",
        200,
        json!({"access_token": "at-2", "refresh_token": "rt-2", "expires_in": 3600}).to_string(),
    );
    setup.mock.set_delay("/token", 400);
    let mut cx = Context::from_waker(Waker::noop());
    {
        let mut first = std::pin::pin!(setup.auth.refresh());
        assert!(
            first.as_mut().poll(&mut cx).is_pending(),
            "the slow refresh starts its flight"
        );
    }

    let fresh = re_sign_in(&setup, "at-9", "rt-9").await;
    assert_eq!(setup.auth.session.get_untracked().as_ref(), Some(&fresh));

    // The newer session's refresh must start its own flight, not join the
    // orphaned rt-1 one and publish its stale answer.
    arm_token(&setup.mock, "/token2", "at-10", Some("rt-10"), None);
    let session = setup.auth.refresh().await.expect("refresh the new session");
    assert_eq!(session.access_token, "at-10");
    assert_eq!(
        setup.auth.session.get_untracked().unwrap().access_token,
        "at-10"
    );
    assert_eq!(
        setup.store.load("mock").unwrap().unwrap().access_token,
        "at-10"
    );
}

#[tokio::test]
async fn a_stale_refresh_answer_is_not_applied_over_a_newer_session() {
    let setup = setup(mock_config);
    sign_in(&setup).await; // rt-1

    // A refresh of rt-1 that lands after the app has already signed in
    // again: its answer goes to its caller only, never to the signals.
    setup.mock.set(
        "/token",
        200,
        json!({"access_token": "at-2", "refresh_token": "rt-2", "expires_in": 3600}).to_string(),
    );
    setup.mock.set_delay("/token", 400);
    let mut cx = Context::from_waker(Waker::noop());
    let mut first = std::pin::pin!(setup.auth.refresh());
    assert!(first.as_mut().poll(&mut cx).is_pending());

    let fresh = re_sign_in(&setup, "at-9", "rt-9").await;

    let late = poll_until_ready(first.as_mut(), &mut cx).expect("the slow refresh finishes");
    assert_eq!(
        late.expect("the old token still refreshes").access_token,
        "at-2"
    );
    assert_eq!(setup.auth.session.get_untracked().as_ref(), Some(&fresh));
    assert_eq!(setup.store.load("mock").unwrap().as_ref(), Some(&fresh));
}

/// Transient and fatal failures answer differently (AppAuth-iOS
/// OIDAuthStateErrorDelegate): a 5xx is worth retrying with the session
/// intact, a revoked grant is not.
#[test]
fn retryability_classifies_transient_and_fatal_errors() {
    for transient in [
        AuthError::Network("connection reset".to_owned()),
        AuthError::ServerError("503".to_owned()),
    ] {
        assert!(transient.is_retryable(), "{transient:?}");
    }
    for fatal in [
        AuthError::AccessDenied,
        AuthError::StateMismatch,
        AuthError::NonceMismatch,
        AuthError::ExpiredCode,
        AuthError::InvalidGrant,
        // A broker's 4xx refusal is fatal; its 5xx arrives as ServerError.
        AuthError::BrokerError("broker returned status 401".to_owned()),
        AuthError::StoreError("disk full".to_owned()),
        AuthError::NoLauncher,
        AuthError::Unknown("odd shape".to_owned()),
    ] {
        assert!(!fatal.is_retryable(), "{fatal:?}");
    }
}

#[tokio::test]
async fn a_server_error_during_refresh_is_transient_and_keeps_the_session() {
    let setup = setup(mock_config);
    sign_in(&setup).await;
    // A plain-text 503: the status, not a JSON error code, is what makes
    // this transient.
    setup.mock.set("/token", 503, "backend on fire".to_owned());

    let error = setup
        .auth
        .refresh()
        .await
        .expect_err("5xx fails the refresh");

    assert!(matches!(error, AuthError::ServerError(_)), "{error:?}");
    assert!(error.is_retryable());
    // Status only, never the server-controlled body: it flows into the
    // error signal and host logs (the TS core reports status only).
    let message = format!("{error}");
    assert!(message.contains("503"), "{message}");
    assert!(!message.contains("backend on fire"), "{message}");
    // Transient: the session, the store and the status stay as they were.
    let session = setup.auth.session.get_untracked().expect("session intact");
    assert_eq!(session.access_token, "at-1");
    assert_eq!(
        setup.store.load("mock").unwrap().unwrap().access_token,
        "at-1"
    );
    assert_eq!(setup.auth.status.get_untracked(), AuthStatus::SignedIn);

    // The retry after the server recovers still works.
    setup.mock.set(
        "/token",
        200,
        json!({"access_token": "at-2", "refresh_token": "rt-2", "expires_in": 3600}).to_string(),
    );
    let session = setup.auth.refresh().await.expect("retry refreshes");
    assert_eq!(session.access_token, "at-2");
}

#[tokio::test]
async fn a_network_failure_during_refresh_is_transient() {
    let setup = setup(mock_config);
    sign_in(&setup).await;
    // A port with nothing listening: the connection itself fails.
    let dead = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let port = dead.local_addr().unwrap().port();
    drop(dead);
    let mut config = mock_config(&setup.mock);
    config.token_url = format!("http://127.0.0.1:{port}/token");
    setup.auth.register(config);

    let error = setup.auth.refresh().await.expect_err("dead endpoint");

    assert!(matches!(error, AuthError::Network(_)), "{error:?}");
    assert!(error.is_retryable());
    assert!(setup.auth.session.get_untracked().is_some());
    assert_eq!(
        setup.store.load("mock").unwrap().unwrap().access_token,
        "at-1"
    );
    assert_eq!(setup.auth.status.get_untracked(), AuthStatus::SignedIn);
}
