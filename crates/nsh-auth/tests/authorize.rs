//! Satisfaction criterion: the authorize URL of every provider, asserted
//! exactly — scheme, host, path, scopes, `state`, `nonce` where used, and
//! `code_challenge`/`code_challenge_method=S256` where the provider takes
//! PKCE. No network is touched: only the URL is built.

mod common;

use common::{CLIENT_ID, REDIRECT_URI, has_pair, query_pair, setup};
use nsh_auth::{AuthConfig, ProviderId, RedirectKind};

struct Expected {
    provider: ProviderId,
    host: &'static str,
    path: &'static str,
    scope: &'static str,
    pkce: bool,
    nonce: bool,
}

fn cases() -> Vec<Expected> {
    vec![
        Expected {
            provider: ProviderId::Google,
            host: "accounts.google.com",
            path: "/o/oauth2/v2/auth",
            scope: "openid email profile",
            pkce: true,
            nonce: true,
        },
        Expected {
            provider: ProviderId::Facebook,
            host: "www.facebook.com",
            path: "/v26.0/dialog/oauth",
            scope: "public_profile,email",
            pkce: false,
            nonce: false,
        },
        Expected {
            provider: ProviderId::Discord,
            host: "discord.com",
            path: "/oauth2/authorize",
            scope: "identify email",
            pkce: true,
            nonce: false,
        },
        Expected {
            provider: ProviderId::Github,
            host: "github.com",
            path: "/login/oauth/authorize",
            scope: "read:user user:email",
            pkce: false,
            nonce: false,
        },
        Expected {
            provider: ProviderId::Apple,
            host: "appleid.apple.com",
            path: "/auth/authorize",
            scope: "name email",
            pkce: false,
            nonce: true,
        },
        Expected {
            provider: ProviderId::Microsoft,
            host: "login.microsoftonline.com",
            path: "/common/oauth2/v2.0/authorize",
            scope: "openid email profile offline_access",
            pkce: true,
            nonce: true,
        },
        Expected {
            provider: ProviderId::X,
            host: "twitter.com",
            path: "/i/oauth2/authorize",
            scope: "users.read tweet.read offline.access",
            pkce: true,
            nonce: false,
        },
        // Generic OIDC and Mock take every endpoint from the app.
        Expected {
            provider: ProviderId::GenericOidc,
            host: "idp.example.test",
            path: "/authorize",
            scope: "openid email profile",
            pkce: true,
            nonce: true,
        },
        Expected {
            provider: ProviderId::Mock,
            host: "mock.localhost.test",
            path: "/authorize",
            scope: "openid email profile",
            pkce: true,
            nonce: true,
        },
    ]
}

#[test]
fn authorize_url_for_every_provider() {
    for case in cases() {
        let config = AuthConfig::for_provider(case.provider)
            .client_id(CLIENT_ID)
            .redirect_uri(REDIRECT_URI);
        let setup = setup(move |mock| {
            let mut config = config;
            if config.auth_url.is_empty() {
                config.auth_url = format!("https://{}{}", case.host, case.path);
                config.token_url = mock.url("/token");
            }
            config
        });
        let request = setup
            .auth
            .authorize_request(case.provider)
            .expect("authorize request");
        let url = url::Url::parse(&request.url).expect("authorize url parses");

        let name = case.provider.as_str();
        assert_eq!(url.scheme(), "https", "{name}");
        assert_eq!(url.host_str(), Some(case.host), "{name}");
        assert_eq!(url.path(), case.path, "{name}");
        assert_eq!(query_pair(&request.url, "response_type"), "code", "{name}");
        assert_eq!(query_pair(&request.url, "client_id"), CLIENT_ID, "{name}");
        assert_eq!(
            query_pair(&request.url, "redirect_uri"),
            REDIRECT_URI,
            "{name}"
        );
        assert_eq!(query_pair(&request.url, "scope"), case.scope, "{name}");

        let state = query_pair(&request.url, "state");
        assert!(!state.is_empty(), "{name}: state must be present");
        assert!(
            state
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_'),
            "{name}"
        );

        if case.nonce {
            let nonce = query_pair(&request.url, "nonce");
            assert!(!nonce.is_empty(), "{name}: nonce must be present");
        } else {
            assert!(
                !has_pair(&request.url, "nonce"),
                "{name}: no nonce expected"
            );
        }

        if case.pkce {
            let challenge = query_pair(&request.url, "code_challenge");
            assert_eq!(challenge.len(), 43, "{name}: S256 of 32 bytes is 43 chars");
            assert!(
                challenge
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_'),
                "{name}: challenge must be base64url"
            );
            assert_eq!(
                query_pair(&request.url, "code_challenge_method"),
                "S256",
                "{name}"
            );
        } else {
            assert!(
                !has_pair(&request.url, "code_challenge"),
                "{name}: no PKCE expected"
            );
            assert!(!has_pair(&request.url, "code_challenge_method"), "{name}");
        }

        if case.provider == ProviderId::Apple {
            assert_eq!(query_pair(&request.url, "response_mode"), "query", "apple");
        }
        assert_eq!(
            request.redirect,
            RedirectKind::Loopback { port: 8914 },
            "{name}: redirect kind"
        );
    }
}

#[test]
fn redirect_kind_classifies_redirects() {
    assert_eq!(
        RedirectKind::of("http://127.0.0.1:8914/callback").unwrap(),
        RedirectKind::Loopback { port: 8914 }
    );
    assert_eq!(
        RedirectKind::of("com.nsh.auth:/callback?code=x").unwrap(),
        RedirectKind::CustomScheme {
            scheme: "com.nsh.auth".to_owned()
        }
    );
    assert_eq!(
        RedirectKind::of("https://app.example.test/callback").unwrap(),
        RedirectKind::WebRedirect
    );
    // Plain http off loopback is a misconfiguration, not a redirect.
    assert!(RedirectKind::of("http://app.example.test/callback").is_err());
}
