//! The return leg against the loopback mock: success, denial, wrong state,
//! wrong nonce, expired code, tampered id token and the broker path.

mod common;

use common::{
    CLIENT_ID, REDIRECT_URI, Setup, arm_success, arm_token, authorize_mock, callback, mock_config,
    query_pair, setup, sign_in, tamper_claims,
};
use nsh_auth::{AuthConfig, AuthError, AuthStatus, ProviderId, SessionStore};
use serde_json::json;

#[tokio::test]
async fn success_loop_sets_session_user_and_persists() {
    let setup = setup(mock_config);
    let session = sign_in(&setup).await;

    assert_eq!(session.provider, ProviderId::Mock);
    assert_eq!(session.access_token, "at-1");
    assert_eq!(session.refresh_token.as_deref(), Some("rt-1"));
    assert!(session.id_token.is_some());
    assert_eq!(session.expires_at, common::NOW_MS + 3_600_000);
    assert_eq!(session.scope, "openid email profile");

    assert_eq!(setup.auth.session.get_untracked().as_ref(), Some(&session));
    let user = setup.auth.user.get_untracked().expect("user signal set");
    assert_eq!(user.sub, "u1");
    assert_eq!(user.name.as_deref(), Some("Mock User"));
    assert_eq!(user.email.as_deref(), Some("mock@example.test"));
    assert_eq!(user.email_verified, Some(true));
    assert_eq!(user.picture.as_deref(), Some("https://mock.test/u1.png"));
    assert_eq!(setup.auth.status.get_untracked(), AuthStatus::SignedIn);
    assert_eq!(setup.auth.error.get_untracked(), None);
    assert_eq!(setup.store.load("mock").unwrap().as_ref(), Some(&session));
}

#[tokio::test]
async fn denial_maps_to_access_denied() {
    let setup = setup(mock_config);
    let (_, state) = authorize_mock(&setup.auth);
    let url = format!(
        "{REDIRECT_URI}?error=access_denied&error_description=The+user+denied+the+request&state={state}"
    );
    let error = setup
        .auth
        .complete(ProviderId::Mock, &url)
        .await
        .expect_err("denial must fail");
    assert_eq!(error, AuthError::AccessDenied);
    assert_eq!(setup.auth.session.get_untracked(), None);
    assert_eq!(setup.auth.status.get_untracked(), AuthStatus::Idle);
    assert_eq!(setup.store.load("mock").unwrap(), None);
}

#[tokio::test]
async fn wrong_state_is_rejected() {
    let setup = setup(mock_config);
    let (nonce, _state) = authorize_mock(&setup.auth);
    arm_success(&setup.mock, &nonce);
    let error = setup
        .auth
        .complete(ProviderId::Mock, &callback("code-1", "attacker-state"))
        .await
        .expect_err("state mismatch must fail");
    assert_eq!(error, AuthError::StateMismatch);
    assert_eq!(setup.auth.session.get_untracked(), None);
    assert_eq!(
        setup.mock.count("/token"),
        0,
        "no exchange without a valid state"
    );
}

#[tokio::test]
async fn wrong_nonce_is_rejected() {
    let setup = setup(mock_config);
    let (_, state) = authorize_mock(&setup.auth);
    arm_success(&setup.mock, "a-different-nonce");
    let error = setup
        .auth
        .complete(ProviderId::Mock, &callback("code-1", &state))
        .await
        .expect_err("nonce mismatch must fail");
    assert_eq!(error, AuthError::NonceMismatch);
    assert_eq!(setup.auth.session.get_untracked(), None);
}

#[tokio::test]
async fn expired_code_maps_to_expired_code_error() {
    let setup = setup(mock_config);
    let (_, state) = authorize_mock(&setup.auth);
    setup.mock.set(
        "/token",
        400,
        json!({"error": "invalid_grant", "error_description": "code has expired"}).to_string(),
    );
    let error = setup
        .auth
        .complete(ProviderId::Mock, &callback("used-code", &state))
        .await
        .expect_err("an invalid code must fail");
    assert_eq!(error, AuthError::ExpiredCode);
    assert_eq!(setup.auth.session.get_untracked(), None);
    // A failed attempt is not an in-progress one.
    assert_eq!(setup.auth.status.get_untracked(), AuthStatus::Idle);
}

#[tokio::test]
async fn tampered_id_token_signature_is_rejected() {
    let setup = setup(mock_config);
    let (nonce, state) = authorize_mock(&setup.auth);
    let honest = common::sign_id_token(Some(&nonce), common::NOW_MS);
    let tampered = tamper_claims(&honest, "sub", "attacker");
    setup.mock.set(
        "/token",
        200,
        json!({
            "access_token": "at-1",
            "id_token": tampered,
            "expires_in": 3600,
        })
        .to_string(),
    );
    let error = setup
        .auth
        .complete(ProviderId::Mock, &callback("code-1", &state))
        .await
        .expect_err("a tampered id token must fail");
    assert!(
        matches!(&error, AuthError::Unknown(message) if message.contains("signature")),
        "expected a signature failure, got {error:?}"
    );
    assert_eq!(setup.auth.session.get_untracked(), None);
}

#[tokio::test]
async fn id_token_with_a_good_signature_passes() {
    // The success loop proves the positive case end to end; this names it.
    let setup = setup(mock_config);
    let session = sign_in(&setup).await;
    let id_token = session.id_token.expect("id token present");
    let claims = nsh_auth::claims(&id_token).expect("claims parse");
    assert_eq!(claims.get("sub").and_then(|s| s.as_str()), Some("u1"));
    assert_eq!(claims.get("aud").and_then(|a| a.as_str()), Some(CLIENT_ID));
}

#[tokio::test]
async fn github_exchange_goes_through_the_broker_with_no_secret() {
    let setup = setup(|mock| {
        let mut config = AuthConfig::for_provider(ProviderId::Github)
            .client_id(CLIENT_ID)
            .redirect_uri(REDIRECT_URI);
        // The provider token endpoint is configured but must stay untouched:
        // a confidential exchange belongs to the broker, which holds the
        // secret. No `client_secret` field exists in AuthConfig at all.
        config.token_url = mock.url("/token");
        config.userinfo_url = Some(mock.url("/userinfo"));
        config.broker_url = Some(mock.url("/broker"));
        config
    });
    setup.mock.set(
        "/broker",
        200,
        json!({"access_token": "gh-1", "scope": "read:user user:email"}).to_string(),
    );
    let request = setup
        .auth
        .authorize_request(ProviderId::Github)
        .expect("authorize");
    assert!(
        !common::has_pair(&request.url, "code_challenge"),
        "github takes no pkce"
    );
    let state = query_pair(&request.url, "state");

    let session = setup
        .auth
        .complete(ProviderId::Github, &callback("gh-code", &state))
        .await
        .expect("brokered sign in");

    assert_eq!(session.access_token, "gh-1");
    assert_eq!(setup.mock.count("/broker"), 1);
    assert_eq!(
        setup.mock.count("/token"),
        0,
        "the app never calls the secret endpoint"
    );
    let body = setup.mock.requests("/broker")[0].body.clone();
    assert!(
        body.contains("\"github\""),
        "broker body carries the provider: {body}"
    );
    assert!(
        body.contains("authorization_code"),
        "broker body carries the grant: {body}"
    );
    assert!(
        body.contains("gh-code"),
        "broker body carries the code: {body}"
    );
    assert!(
        !body.to_ascii_lowercase().contains("secret"),
        "no secret may appear in the broker request: {body}"
    );
    assert!(setup.auth.session.get_untracked().is_some());
    assert!(
        setup.auth.user.get_untracked().is_some(),
        "userinfo fetched with the token"
    );
}

#[tokio::test]
async fn an_unconfigured_provider_is_refused() {
    let setup: Setup = setup(|_| {
        AuthConfig::for_provider(ProviderId::Mock)
            .client_id(CLIENT_ID)
            .redirect_uri(REDIRECT_URI)
    });
    let error = setup
        .auth
        .authorize_request(ProviderId::Google)
        .expect_err("google was never configured");
    assert!(matches!(error, AuthError::Unknown(message) if message.contains("google")));
}

/// A config whose redirect is neither loopback nor a fixed https origin: an
/// OIDC stand-in for the web and custom-scheme redirect kinds.
fn oidc_config(mock: &common::MockServer, redirect_uri: &str) -> AuthConfig {
    let mut config = AuthConfig::for_provider(ProviderId::GenericOidc)
        .client_id(CLIENT_ID)
        .redirect_uri(redirect_uri);
    config.auth_url = mock.url("/authorize");
    config.token_url = mock.url("/token");
    config.userinfo_url = Some(mock.url("/userinfo"));
    config.jwks_url = Some(mock.url("/jwks"));
    config
}

/// One authorize + complete against `url` (the STATE placeholder is
/// replaced), so each origin attempt gets a fresh, valid state.
async fn try_origin(
    setup: &common::Setup,
    provider: ProviderId,
    url: &str,
) -> Result<nsh_auth::Session, AuthError> {
    let request = setup.auth.authorize_request(provider).expect("authorize");
    let state = query_pair(&request.url, "state");
    let nonce = query_pair(&request.url, "nonce");
    arm_token(&setup.mock, "/token", "at-1", Some("rt-1"), Some(&nonce));
    let callback_url = url.replace("STATE", &state);
    setup.auth.complete(provider, &callback_url).await
}

fn assert_rejected(result: Result<nsh_auth::Session, AuthError>) {
    match result {
        Err(AuthError::Unknown(message)) => assert!(
            message.contains("redirect"),
            "expected a redirect mismatch, got {message:?}"
        ),
        other => panic!("a foreign-origin callback must be rejected, got {other:?}"),
    }
}

#[tokio::test]
async fn wrong_origin_callback_is_rejected() {
    let setup = setup(mock_config);

    // Loopback redirect: a fresh loopback port is the RFC 8252 flow; any
    // other origin, scheme or host is not.
    try_origin(
        &setup,
        ProviderId::Mock,
        "http://127.0.0.1:9101/callback?code=c&state=STATE",
    )
    .await
    .expect("a fresh loopback port is allowed");
    for url in [
        "https://127.0.0.1:8914/callback?code=c&state=STATE",
        "http://evil.example.test/callback?code=c&state=STATE",
        "com.example:/callback?code=c&state=STATE",
    ] {
        assert_rejected(try_origin(&setup, ProviderId::Mock, url).await);
    }
    assert_eq!(
        setup.mock.count("/token"),
        1,
        "only the matching origin exchanged"
    );

    // Web redirect: same origin only — scheme, host and port all matter.
    setup
        .auth
        .register(oidc_config(&setup.mock, "https://app.example.test/cb"));
    try_origin(
        &setup,
        ProviderId::GenericOidc,
        "https://app.example.test/cb?code=c&state=STATE",
    )
    .await
    .expect("the registered origin is allowed");
    for url in [
        "https://evil.example.test/cb?code=c&state=STATE",
        "https://app.example.test:8443/cb?code=c&state=STATE",
        "http://app.example.test/cb?code=c&state=STATE",
    ] {
        assert_rejected(try_origin(&setup, ProviderId::GenericOidc, url).await);
    }

    // Custom scheme: the scheme is the whole comparison.
    setup
        .auth
        .register(oidc_config(&setup.mock, "com.nsh.auth:/callback"));
    try_origin(
        &setup,
        ProviderId::GenericOidc,
        "com.nsh.auth:/callback?code=c&state=STATE",
    )
    .await
    .expect("the registered scheme is allowed");
    assert_rejected(
        try_origin(
            &setup,
            ProviderId::GenericOidc,
            "com.other:/callback?code=c&state=STATE",
        )
        .await,
    );
}

#[tokio::test]
async fn a_plain_http_redirect_off_loopback_accepts_no_callback() {
    let setup = setup(mock_config);

    // A misconfigured non-loopback http redirect: authorize itself refuses,
    // and no http callback origin is accepted for it afterwards — not even
    // one on the same host.
    setup
        .auth
        .register(oidc_config(&setup.mock, "http://app.example.test/cb"));
    let error = setup
        .auth
        .authorize_request(ProviderId::GenericOidc)
        .expect_err("plain http off loopback is not a redirect kind");
    assert!(matches!(&error, AuthError::Unknown(m) if m.contains("redirect")));

    for url in [
        "http://app.example.test/cb?code=c&state=whatever",
        "http://anything.example.test/cb?code=c&state=whatever",
    ] {
        assert_rejected(setup.auth.complete(ProviderId::GenericOidc, url).await);
    }
    assert_eq!(
        setup.mock.count("/token"),
        0,
        "no exchange for a misconfigured redirect"
    );
}
