//! The built-in providers: endpoints, default scopes, redirect rules and
//! quirks. Endpoints verified against each provider's current official docs
//! (Google identity protocols, Meta manual login flow, Discord OAuth2, GitHub
//! authorizing OAuth apps, Sign in with Apple REST API, Microsoft Entra v2.0
//! OIDC, X OAuth 2.0 authorization code flow).

use crate::error::AuthError;
use serde::{Deserialize, Serialize};
use url::Url;

/// The providers built in. `GenericOidc` and `Mock` carry no endpoints of
/// their own: the app supplies every URL.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderId {
    Google,
    Facebook,
    Discord,
    Github,
    Apple,
    Microsoft,
    X,
    GenericOidc,
    Mock,
}

impl ProviderId {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Google => "google",
            Self::Facebook => "facebook",
            Self::Discord => "discord",
            Self::Github => "github",
            Self::Apple => "apple",
            Self::Microsoft => "microsoft",
            Self::X => "x",
            Self::GenericOidc => "generic_oidc",
            Self::Mock => "mock",
        }
    }

    /// Whether the provider's token endpoint needs a client secret. Such an
    /// app must be configured with a `broker_url`; hosts use this to explain
    /// why no secret is embedded.
    pub fn confidential(self) -> bool {
        def(self).confidential
    }
}

/// How the redirect comes back (RFC 8252): a loopback HTTP listener the
/// desktop host opens, a private-use URI scheme the mobile host registers, or
/// a page on the app's own web origin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RedirectKind {
    Loopback { port: u16 },
    CustomScheme { scheme: String },
    WebRedirect,
}

impl RedirectKind {
    /// Classifies a redirect URI. Plain `http` is only allowed on loopback;
    /// anywhere else it is a configuration error, not a redirect.
    pub fn of(uri: &str) -> Result<Self, AuthError> {
        let url = Url::parse(uri)
            .map_err(|e| AuthError::Unknown(format!("redirect_uri is not a URL: {e}")))?;
        // IP hosts parse as Ipv4/Ipv6, not Domain: "127.0.0.1" included.
        let loopback = matches!(url.host(), Some(url::Host::Ipv4(a)) if a.is_loopback())
            || matches!(url.host(), Some(url::Host::Ipv6(a)) if a.is_loopback());
        match url.scheme() {
            "http" if loopback => Ok(Self::Loopback {
                port: url.port_or_known_default().unwrap_or(80),
            }),
            "https" => Ok(Self::WebRedirect),
            scheme if scheme != "http" && scheme != "https" => Ok(Self::CustomScheme {
                scheme: scheme.to_owned(),
            }),
            _ => Err(AuthError::Unknown(
                "redirect_uri must be https, a loopback http URL or a custom scheme".to_owned(),
            )),
        }
    }
}

/// What `authorize_request` hands the host: the URL to open, and how to
/// expect the redirect back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizeRequest {
    pub url: String,
    pub redirect: RedirectKind,
}

/// One provider's built-in rules. `confidential` marks providers whose token
/// endpoint needs a client secret (GitHub, Apple's per-request secret JWT,
/// Facebook's classic manual-flow shape): such an app must set `broker_url`,
/// and the secret lives on the operator's broker, never in the app.
pub(crate) struct ProviderDef {
    pub auth_url: &'static str,
    pub token_url: &'static str,
    pub userinfo_url: Option<&'static str>,
    pub revoke_url: Option<&'static str>,
    pub jwks_url: Option<&'static str>,
    pub scopes: &'static [&'static str],
    pub scope_separator: &'static str,
    pub use_pkce: bool,
    pub use_nonce: bool,
    pub confidential: bool,
    pub issuer: Option<&'static str>,
    pub authorize_extras: &'static [(&'static str, &'static str)],
}

pub(crate) fn def(id: ProviderId) -> ProviderDef {
    match id {
        ProviderId::Google => ProviderDef {
            auth_url: "https://accounts.google.com/o/oauth2/v2/auth",
            token_url: "https://oauth2.googleapis.com/token",
            userinfo_url: Some("https://openidconnect.googleapis.com/v1/userinfo"),
            revoke_url: Some("https://oauth2.googleapis.com/revoke"),
            jwks_url: Some("https://www.googleapis.com/oauth2/v3/certs"),
            scopes: &["openid", "profile", "email"],
            scope_separator: " ",
            use_pkce: true,
            use_nonce: true,
            confidential: false,
            issuer: Some("https://accounts.google.com"),
            // Without these Google issues no refresh token at all, and only
            // on the first consent (docs/providers.md, catalog).
            authorize_extras: &[("access_type", "offline"), ("prompt", "consent")],
        },
        ProviderId::Facebook => ProviderDef {
            // OIDC code flow on Graph v27.0 (the docs' sampled pin; a
            // version is guaranteed for two years): code_challenge is
            // required and the secret becomes optional when the verifier is
            // sent, so the public path runs secretless. The classic manual
            // flow (secret required) stays behind the broker.
            auth_url: "https://www.facebook.com/v27.0/dialog/oauth",
            token_url: "https://graph.facebook.com/v27.0/oauth/access_token",
            userinfo_url: Some("https://graph.facebook.com/v27.0/me?fields=id,name,email,picture"),
            revoke_url: Some("https://graph.facebook.com/v27.0/me/permissions"),
            jwks_url: Some("https://www.facebook.com/.well-known/oauth/openid/jwks/"),
            scopes: &["openid", "public_profile", "email"],
            scope_separator: " ",
            use_pkce: true,
            use_nonce: true,
            confidential: false,
            issuer: None,
            authorize_extras: &[],
        },
        ProviderId::Discord => ProviderDef {
            // Public clients: PKCE without a secret. Default scopes skip the
            // OIDC ones; asking for `openid` adds an id_token on verified apps.
            auth_url: "https://discord.com/oauth2/authorize",
            token_url: "https://discord.com/api/oauth2/token",
            userinfo_url: Some("https://discord.com/api/users/@me"),
            revoke_url: Some("https://discord.com/api/oauth2/token/revoke"),
            jwks_url: None,
            scopes: &["identify", "email"],
            scope_separator: " ",
            use_pkce: true,
            use_nonce: false,
            confidential: false,
            issuer: None,
            authorize_extras: &[],
        },
        ProviderId::Github => ProviderDef {
            // PKCE S256 is supported on the authorize leg ("plain" is not),
            // and the exchange still requires the client secret: the code
            // and its verifier go through the broker, which holds the
            // secret. OAuth-app tokens do not expire by default and there is
            // no app-side revocation endpoint: sign-out is local.
            auth_url: "https://github.com/login/oauth/authorize",
            token_url: "https://github.com/login/oauth/access_token",
            userinfo_url: Some("https://api.github.com/user"),
            revoke_url: None,
            jwks_url: None,
            scopes: &["read:user", "user:email"],
            scope_separator: " ",
            use_pkce: true,
            use_nonce: false,
            confidential: true,
            issuer: None,
            authorize_extras: &[],
        },
        ProviderId::Apple => ProviderDef {
            // form_post is mandatory once scopes are requested: the code
            // arrives as a form body at the https Return URL, and the
            // receiving relay turns it into the callback URL. The token and
            // revoke endpoints need an ES256 client-secret JWT: the broker
            // signs it.
            auth_url: "https://appleid.apple.com/auth/authorize",
            token_url: "https://appleid.apple.com/auth/token",
            userinfo_url: None,
            revoke_url: Some("https://appleid.apple.com/auth/revoke"),
            jwks_url: Some("https://appleid.apple.com/auth/keys"),
            scopes: &["openid", "name", "email"],
            scope_separator: " ",
            use_pkce: false,
            use_nonce: true,
            confidential: true,
            issuer: Some("https://appleid.apple.com"),
            authorize_extras: &[("response_mode", "form_post")],
        },
        ProviderId::Microsoft => ProviderDef {
            // Entra v2.0 common tenant. `offline_access` is what returns a
            // refresh token. No token-revocation endpoint exists on the
            // identity platform, so sign-out is local. The issuer claim is
            // tenant-dependent and is not checked.
            auth_url: "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
            token_url: "https://login.microsoftonline.com/common/oauth2/v2.0/token",
            userinfo_url: Some("https://graph.microsoft.com/oidc/userinfo"),
            revoke_url: None,
            jwks_url: Some("https://login.microsoftonline.com/common/discovery/v2.0/keys"),
            scopes: &["openid", "profile", "email", "offline_access", "User.Read"],
            scope_separator: " ",
            use_pkce: true,
            use_nonce: true,
            confidential: false,
            issuer: None,
            authorize_extras: &[],
        },
        ProviderId::X => ProviderDef {
            // X requires PKCE and state on every authorize request; the
            // current endpoints live on x.com / api.x.com.
            auth_url: "https://x.com/i/oauth2/authorize",
            token_url: "https://api.x.com/2/oauth2/token",
            userinfo_url: Some("https://api.x.com/2/users/me"),
            revoke_url: Some("https://api.x.com/2/oauth2/revoke"),
            jwks_url: None,
            scopes: &["users.read", "tweet.read", "offline.access"],
            scope_separator: " ",
            use_pkce: true,
            use_nonce: false,
            confidential: false,
            issuer: None,
            authorize_extras: &[],
        },
        ProviderId::GenericOidc | ProviderId::Mock => ProviderDef {
            auth_url: "",
            token_url: "",
            userinfo_url: None,
            revoke_url: None,
            jwks_url: None,
            scopes: &["openid", "profile", "email", "offline_access"],
            scope_separator: " ",
            use_pkce: true,
            use_nonce: true,
            confidential: false,
            issuer: None,
            authorize_extras: &[],
        },
    }
}

/// How the app talks to one provider: `for_provider` fills the endpoints,
/// default scopes and PKCE/nonce rules from the definition; the app overrides
/// what differs. No client secret exists anywhere in this struct: a
/// confidential provider is reached through `broker_url`, which names the
/// app owner's broker process holding the secret.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuthConfig {
    pub provider: ProviderId,
    pub client_id: String,
    pub redirect_uri: String,
    pub scopes: Vec<String>,
    pub auth_url: String,
    pub token_url: String,
    pub userinfo_url: Option<String>,
    pub revoke_url: Option<String>,
    pub jwks_url: Option<String>,
    pub broker_url: Option<String>,
    pub use_pkce: bool,
    pub use_nonce: bool,
}

impl AuthConfig {
    /// The provider's definition, with empty URLs where the app must supply
    /// them (`GenericOidc`, `Mock`).
    pub fn for_provider(id: ProviderId) -> Self {
        let def = def(id);
        Self {
            provider: id,
            client_id: String::new(),
            redirect_uri: String::new(),
            scopes: def.scopes.iter().map(|s| (*s).to_owned()).collect(),
            auth_url: def.auth_url.to_owned(),
            token_url: def.token_url.to_owned(),
            userinfo_url: def.userinfo_url.map(str::to_owned),
            revoke_url: def.revoke_url.map(str::to_owned),
            jwks_url: def.jwks_url.map(str::to_owned),
            broker_url: None,
            use_pkce: def.use_pkce,
            use_nonce: def.use_nonce,
        }
    }

    pub fn client_id(mut self, client_id: impl Into<String>) -> Self {
        self.client_id = client_id.into();
        self
    }

    pub fn redirect_uri(mut self, redirect_uri: impl Into<String>) -> Self {
        self.redirect_uri = redirect_uri.into();
        self
    }

    /// Replaces the default scopes with `scopes`.
    pub fn scopes(mut self, scopes: impl Into<Vec<String>>) -> Self {
        self.scopes = scopes.into();
        self
    }
}
