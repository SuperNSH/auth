//! OAuth and social sign-in for Native Shell Rust apps: provider
//! definitions, PKCE, `state` and `nonce`, authorize-URL building, callback
//! validation, token exchange and refresh, ID-token verification against the
//! provider's JWKS, revocation and a session store, published as signals.
//!
//! Pure protocol and state: no UI, no platform bindings, no client secret
//! anywhere. A confidential provider (GitHub, Apple's secret JWT, Facebook's
//! classic manual-flow shape) is reached through `AuthConfig::broker_url`,
//! which names the app owner's broker process; the secret lives there. The
//! embedding host opens the authorize URL, catches the redirect (loopback
//! listener, custom scheme or web redirect) and holds secure storage.
//!
//! `Auth::new` makes signals, so it must run where a reactive runtime is
//! entered: a component body, or `nsh_core::element::create_root`.

mod callback;
mod clock;
mod error;
mod flight;
mod http;
mod jwt;
mod pkce;
mod provider;
mod session;
mod store;
mod token;

pub use clock::{Clock, SystemClock};
pub use error::AuthError;
pub use http::{BoxFuture, Http, HttpReply, ReqwestHttp};
pub use jwt::{IdTokenChecks, claims};
pub use provider::{AuthConfig, AuthorizeRequest, ProviderId, RedirectKind};
pub use session::{AuthStatus, Session, UserInfo};
pub use store::{JsonFileStore, MemoryStore, SessionStore};

use flight::{RefreshFlight, RefreshFut};
use nsh_core::prelude::*;
use provider::def;
use std::collections::HashMap;
use std::sync::Arc;
use token::Transport;

/// The `state`, `nonce` and PKCE verifier of one authorize request, held
/// until its callback arrives. Single use: `complete` consumes it.
struct PendingAuth {
    state: String,
    nonce: Option<String>,
    verifier: Option<String>,
}

/// The auth service: one signal set for the active session, one config per
/// provider, single-flight refresh. Construct it under an owner that
/// outlives its use (`create_root` suits app-wide state).
pub struct Auth {
    pub session: Signal<Option<Session>>,
    pub user: Signal<Option<UserInfo>>,
    pub status: Signal<AuthStatus>,
    pub error: Signal<Option<AuthError>>,
    configs: Stored<HashMap<ProviderId, AuthConfig>>,
    pending: Stored<HashMap<ProviderId, PendingAuth>>,
    /// One in-flight refresh shared by parallel callers; the active session
    /// is single, so one flight covers every provider.
    refresh_flight: Stored<Option<Arc<RefreshFlight>>>,
    store: Arc<dyn SessionStore>,
    clock: Arc<dyn Clock>,
    http: Arc<dyn Http>,
}

impl Auth {
    pub fn new(
        config: AuthConfig,
        store: Arc<dyn SessionStore>,
        clock: Arc<dyn Clock>,
        http: Arc<dyn Http>,
    ) -> Self {
        let mut configs = HashMap::new();
        configs.insert(config.provider, config);
        Self {
            session: signal(None),
            user: signal(None),
            status: signal(AuthStatus::Idle),
            error: signal(None),
            configs: stored(configs),
            pending: stored(HashMap::new()),
            refresh_flight: stored(None),
            store,
            clock,
            http,
        }
    }

    /// Adds or replaces one provider's config, keeping the same signal set.
    pub fn register(&self, config: AuthConfig) {
        self.configs.with(|c| {
            c.insert(config.provider, config);
        });
    }

    fn config_of(&self, provider: ProviderId) -> Result<AuthConfig, AuthError> {
        self.configs
            .with(|c| c.get(&provider).cloned())
            .ok_or_else(|| AuthError::Unknown(format!("{} is not configured", provider.as_str())))
    }

    /// The callback must land on the redirect the app registered: a code
    /// delivered to another origin is not ours to use, whatever its state
    /// says. Loopback ports are exempt — RFC 8252 lets the OS pick a fresh
    /// port per request — web origins compare scheme, host and port, custom
    /// schemes compare the scheme itself, and plain http is accepted only on
    /// loopback: a non-loopback http redirect_uri matches nothing.
    fn check_callback_origin(callback_url: &str, redirect_uri: &str) -> Result<(), AuthError> {
        let reject = |what: &str| {
            AuthError::Unknown(format!(
                "callback does not match the configured redirect_uri: {what}"
            ))
        };
        let parse = |url: &str| {
            url::Url::parse(url)
                .map_err(|e| AuthError::Unknown(format!("redirect URL is not a URL: {e}")))
        };
        let callback = parse(callback_url)?;
        let redirect = parse(redirect_uri)?;
        let loopback_host = |url: &url::Url| {
            matches!(url.host(), Some(url::Host::Ipv4(a)) if a.is_loopback())
                || matches!(url.host(), Some(url::Host::Ipv6(a)) if a.is_loopback())
        };
        let same = match redirect.scheme() {
            // Plain http is a redirect only on loopback: a non-loopback
            // http redirect_uri is a misconfiguration, and no callback —
            // not even a same-origin one — is accepted for it.
            "http" => {
                loopback_host(&redirect) && callback.scheme() == "http" && loopback_host(&callback)
            }
            "https" => {
                callback.scheme() == "https"
                    && callback.host() == redirect.host()
                    && callback.port_or_known_default() == redirect.port_or_known_default()
            }
            // Custom schemes carry no authority: the scheme is the whole
            // comparison.
            scheme => callback.scheme() == scheme,
        };
        if same {
            Ok(())
        } else {
            Err(reject("scheme or origin differs"))
        }
    }

    fn transport_of(&self, config: &AuthConfig) -> Transport {
        Transport {
            http: Arc::clone(&self.http),
            config: config.clone(),
        }
    }

    /// Builds the provider's authorize URL and records the `state`, `nonce`
    /// and PKCE verifier its callback will be checked against. The host
    /// opens `url` and routes the redirect by `redirect`.
    pub fn authorize_request(&self, provider: ProviderId) -> Result<AuthorizeRequest, AuthError> {
        let config = self.config_of(provider)?;
        let def = def(provider);
        let state = pkce::random_token();
        let nonce = config.use_nonce.then(pkce::random_token);
        let verifier = config.use_pkce.then(pkce::code_verifier);
        let mut url = url::Url::parse(&config.auth_url)
            .map_err(|e| AuthError::Unknown(format!("authorize URL is not a URL: {e}")))?;
        {
            let mut pairs = url.query_pairs_mut();
            pairs.append_pair("response_type", "code");
            pairs.append_pair("client_id", &config.client_id);
            pairs.append_pair("redirect_uri", &config.redirect_uri);
            if !config.scopes.is_empty() {
                pairs.append_pair("scope", &config.scopes.join(def.scope_separator));
            }
            pairs.append_pair("state", &state);
            if let Some(nonce) = &nonce {
                pairs.append_pair("nonce", nonce);
            }
            if let Some(verifier) = &verifier {
                pairs.append_pair("code_challenge", &pkce::code_challenge(verifier));
                pairs.append_pair("code_challenge_method", "S256");
            }
            for (key, value) in def.authorize_extras {
                pairs.append_pair(key, value);
            }
        }
        // The redirect must be classifiable before any flow state exists: a
        // misconfigured redirect_uri must not leave a live pending entry.
        let redirect = RedirectKind::of(&config.redirect_uri)?;
        self.pending.with(|p| {
            p.insert(
                provider,
                PendingAuth {
                    state,
                    nonce,
                    verifier,
                },
            );
        });
        Ok(AuthorizeRequest {
            url: url.to_string(),
            redirect,
        })
    }

    /// The full return leg: validate the callback, exchange the code (through
    /// the broker when one is configured), verify the id token when the
    /// provider has a JWKS, fetch the user, persist the session and publish
    /// the signals.
    pub async fn complete(
        &self,
        provider: ProviderId,
        callback_url: &str,
    ) -> Result<Session, AuthError> {
        let config = self.config_of(provider)?;
        let callback = callback::parse(callback_url)?;
        Self::check_callback_origin(callback_url, &config.redirect_uri)?;
        if let Some(error) = callback.error {
            return Err(match error.as_str() {
                "access_denied" => AuthError::AccessDenied,
                other => AuthError::Unknown(format!(
                    "{other}: {}",
                    callback.error_description.unwrap_or_default()
                )),
            });
        }
        // The pending entry is consumed whether or not the state matches:
        // state is single-use, so a mismatched probe burns the flow.
        let pending = self.pending.with(|p| p.remove(&provider));
        let Some(pending) = pending else {
            return Err(AuthError::StateMismatch);
        };
        if callback.state.as_deref() != Some(pending.state.as_str()) {
            return Err(AuthError::StateMismatch);
        }
        let Some(code) = callback.code else {
            return Err(AuthError::Unknown(
                "callback carries neither code nor error".to_owned(),
            ));
        };

        let was = self.status.get_untracked();
        self.status.set(AuthStatus::SigningIn);
        // Any failure from here on is a failed sign-in attempt, not an
        // in-progress one: the status goes back to what it was.
        match self.finish_sign_in(provider, &config, &code, pending).await {
            Ok(session) => Ok(session),
            Err(error) => {
                self.status.set(was);
                Err(error)
            }
        }
    }

    async fn finish_sign_in(
        &self,
        provider: ProviderId,
        config: &AuthConfig,
        code: &str,
        pending: PendingAuth,
    ) -> Result<Session, AuthError> {
        let transport = self.transport_of(config);
        let tokens = transport
            .exchange_code(code, pending.verifier.as_deref())
            .await?;

        let def = def(provider);
        let claims = match &tokens.id_token {
            Some(id_token) if config.jwks_url.is_some() => {
                let jwks = transport.jwks().await?;
                Some(jwt::verify(
                    id_token,
                    &jwks,
                    &jwt::IdTokenChecks {
                        nonce: pending.nonce.as_deref(),
                        issuer: def.issuer,
                        audience: &config.client_id,
                        now_ms: self.clock.now_ms(),
                    },
                )?)
            }
            // No JWKS configured: claims are read unverified. Providers
            // without keys endpoints issue no signature to check.
            Some(id_token) => Some(jwt::claims(id_token)?),
            None => None,
        };

        let user = match &config.userinfo_url {
            Some(_) => Some(transport.userinfo(&tokens.access_token).await?),
            None => claims.as_ref().map(UserInfo::from_claims),
        };
        let session = Session {
            provider,
            access_token: tokens.access_token,
            refresh_token: tokens.refresh_token,
            id_token: tokens.id_token,
            expires_at: tokens
                .expires_in
                .map(|s| self.clock.now_ms() + s * 1000)
                .unwrap_or(0),
            scope: tokens
                .scope
                .unwrap_or_else(|| config.scopes.join(def.scope_separator)),
        };
        self.store.save(provider.as_str(), &session)?;
        self.publish(Some(session.clone()), user, AuthStatus::SignedIn);
        Ok(session)
    }

    /// Refreshes the active session's access token. Parallel callers share
    /// one in-flight exchange. A revoked grant signs the app out.
    pub async fn refresh(&self) -> Result<Session, AuthError> {
        let Some(current) = self.session.get_untracked() else {
            return Err(AuthError::Unknown("no session to refresh".to_owned()));
        };
        let Some(refresh_token) = current.refresh_token.clone() else {
            return Err(AuthError::Unknown(format!(
                "{} issues no refresh token",
                current.provider.as_str()
            )));
        };
        self.status.set(AuthStatus::Refreshing);
        let config = self.config_of(current.provider)?;
        let (future, started) = self.join_or_start_refresh(config, refresh_token);
        let result = future.await;
        if let Some(mine) = started {
            // Take the flight slot back only if a later refresh did not
            // already replace it.
            self.refresh_flight.with(|f| {
                if f.as_ref().is_some_and(|flight| Arc::ptr_eq(flight, &mine)) {
                    *f = None;
                }
            });
        }
        // A sign-in that landed while this refresh was in flight owns the
        // signals and the store now; a stale flight's answer must not be
        // saved or published over it. The caller still gets its answer.
        let still_current = self.session.get_untracked().is_some_and(|live| {
            live.provider == current.provider
                && live.refresh_token.as_deref() == current.refresh_token.as_deref()
        });
        match result {
            Ok(mut session) => {
                if session.refresh_token.is_none() {
                    session.refresh_token = current.refresh_token.clone();
                }
                if session.id_token.is_none() {
                    session.id_token = current.id_token.clone();
                }
                if still_current {
                    self.store.save(session.provider.as_str(), &session)?;
                    let user = self.user.get_untracked();
                    self.publish(Some(session.clone()), user, AuthStatus::SignedIn);
                }
                Ok(session)
            }
            Err(error) => {
                if error == AuthError::InvalidGrant {
                    // The provider dropped the grant: local sign-out is the
                    // only honest state left.
                    if still_current {
                        self.local_sign_out();
                        self.error.set(Some(error.clone()));
                    }
                } else if still_current {
                    self.error.set(Some(error.clone()));
                    self.status.set(AuthStatus::SignedIn);
                }
                Err(error)
            }
        }
    }

    fn join_or_start_refresh(
        &self,
        config: AuthConfig,
        refresh_token: String,
    ) -> (RefreshFut, Option<Arc<RefreshFlight>>) {
        let existing = self.refresh_flight.with(|f| f.clone());
        // Only a flight started for this same refresh token may be joined:
        // an orphaned flight for an older token belongs to a session that
        // is no longer current.
        if let Some(flight) = existing
            && flight.is_for(&refresh_token)
        {
            return (RefreshFlight::join(flight), None);
        }
        let http = Arc::clone(&self.http);
        let clock = Arc::clone(&self.clock);
        let provider = config.provider;
        let scopes = config.scopes.join(" ");
        // The work is pure HTTP over owned data, so the flight's future is
        // Send and no signal is touched off the engine thread.
        let work: flight::Work = {
            let refresh_token = refresh_token.clone();
            Box::pin(async move {
                let transport = Transport { http, config };
                let tokens = transport.exchange_refresh(&refresh_token).await?;
                Ok(Session {
                    provider,
                    access_token: tokens.access_token,
                    refresh_token: tokens.refresh_token,
                    id_token: tokens.id_token,
                    expires_at: tokens
                        .expires_in
                        .map(|s| clock.now_ms() + s * 1000)
                        .unwrap_or(0),
                    scope: tokens.scope.unwrap_or(scopes),
                })
            })
        };
        let (flight, future) = RefreshFlight::start(work, refresh_token);
        self.refresh_flight.with(|f| *f = Some(Arc::clone(&flight)));
        (future, Some(flight))
    }

    /// Revokes the session's tokens at the provider (when it has a revocation
    /// endpoint or a broker), clears the store and resets the signals. Local
    /// state is cleared first: a failed revoke must not keep tokens around.
    pub async fn sign_out(&self) -> Result<(), AuthError> {
        let session = self.session.get_untracked();
        self.local_sign_out();
        if let Some(session) = session {
            let config = self.config_of(session.provider)?;
            let transport = self.transport_of(&config);
            let token = session
                .refresh_token
                .as_deref()
                .unwrap_or(&session.access_token);
            return transport.revoke(token).await;
        }
        Ok(())
    }

    /// Loads a persisted session into the signals (app restart). The user
    /// signal refills on the next userinfo fetch, which hosts trigger
    /// themselves.
    pub fn restore(&self, provider: ProviderId) -> Result<Option<Session>, AuthError> {
        match self.store.load(provider.as_str())? {
            Some(session) => {
                self.session.set(Some(session.clone()));
                self.status.set(AuthStatus::SignedIn);
                Ok(Some(session))
            }
            None => Ok(None),
        }
    }

    fn publish(&self, session: Option<Session>, user: Option<UserInfo>, status: AuthStatus) {
        self.session.set(session);
        self.user.set(user);
        self.status.set(status);
        self.error.set(None);
    }

    fn local_sign_out(&self) {
        if let Some(session) = self.session.get_untracked()
            && let Err(error) = self.store.clear(session.provider.as_str())
        {
            // The store failed to clear: say so rather than hide it.
            self.error.set(Some(error));
        }
        self.publish(None, None, AuthStatus::SignedOut);
    }
}
