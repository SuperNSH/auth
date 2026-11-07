//! Token exchange, refresh, revocation, userinfo and JWKS fetches. Every
//! request here carries only public-client fields: no client secret exists
//! in this crate, and a confidential provider's secret lives on the operator
//!'s broker reached through `config.broker_url`.

use crate::error::AuthError;
use crate::http::{Http, HttpReply};
use crate::provider::{AuthConfig, ProviderId};
use crate::session::UserInfo;
use serde_json::json;
use std::sync::Arc;

#[derive(Debug, Clone)]
pub(crate) struct TokenResponse {
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub id_token: Option<String>,
    pub expires_in: Option<i64>,
    pub scope: Option<String>,
}

/// Which grant a token request was for: `invalid_grant` maps differently
/// (an expired code vs a revoked refresh token).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Grant {
    Code,
    Refresh,
}

/// The endpoints of one configured provider, held as owned data so exchange
/// futures are `Send` and shareable between parallel refresh callers.
pub(crate) struct Transport {
    pub http: Arc<dyn Http>,
    pub config: AuthConfig,
}

impl Transport {
    pub async fn exchange_code(
        &self,
        code: &str,
        verifier: Option<&str>,
    ) -> Result<TokenResponse, AuthError> {
        let mut form = vec![
            ("grant_type", "authorization_code".to_owned()),
            ("code", code.to_owned()),
            ("redirect_uri", self.config.redirect_uri.clone()),
            ("client_id", self.config.client_id.clone()),
        ];
        if let Some(verifier) = verifier {
            form.push(("code_verifier", verifier.to_owned()));
        }
        self.token(&form, Grant::Code).await
    }

    pub async fn exchange_refresh(&self, refresh_token: &str) -> Result<TokenResponse, AuthError> {
        let form = vec![
            ("grant_type", "refresh_token".to_owned()),
            ("refresh_token", refresh_token.to_owned()),
            ("client_id", self.config.client_id.clone()),
        ];
        self.token(&form, Grant::Refresh).await
    }

    async fn token(
        &self,
        form: &[(&str, String)],
        grant: Grant,
    ) -> Result<TokenResponse, AuthError> {
        let reply = match &self.config.broker_url {
            // The broker is the only path for confidential providers; it
            // forwards the same fields and adds the secret on its side.
            Some(broker) => self.broker(broker, form).await?,
            None => {
                self.http
                    .post_form(&self.config.token_url, form, None)
                    .await?
            }
        };
        parse_token_response(&reply, grant)
    }

    async fn broker(&self, url: &str, form: &[(&str, String)]) -> Result<HttpReply, AuthError> {
        let mut body = json!({"provider": self.config.provider.as_str()});
        for (key, value) in form {
            body[*key] = json!(value);
        }
        let reply = self.http.post_json(url, &body, None).await?;
        if !reply.ok() {
            return Err(broker_status_error(reply.status));
        }
        Ok(reply)
    }

    pub async fn userinfo(&self, access_token: &str) -> Result<UserInfo, AuthError> {
        let url = self.config.userinfo_url.as_deref().ok_or_else(|| {
            AuthError::Unknown(format!(
                "{} has no userinfo endpoint",
                self.config.provider.as_str()
            ))
        })?;
        let reply = self.http.get_json(url, Some(access_token)).await?;
        check_status(&reply, "userinfo")?;
        let value: serde_json::Value =
            serde_json::from_str(&reply.body).map_err(|e| AuthError::Unknown(e.to_string()))?;
        Ok(UserInfo::from_json(&value))
    }

    pub async fn jwks(&self) -> Result<serde_json::Value, AuthError> {
        let url = self.config.jwks_url.as_deref().ok_or_else(|| {
            AuthError::Unknown(format!(
                "{} has no jwks endpoint",
                self.config.provider.as_str()
            ))
        })?;
        let reply = self.http.get_json(url, None).await?;
        check_status(&reply, "jwks")?;
        serde_json::from_str(&reply.body).map_err(|e| AuthError::Unknown(e.to_string()))
    }

    pub async fn revoke(&self, token: &str) -> Result<(), AuthError> {
        if let Some(broker) = &self.config.broker_url {
            let body = json!({
                "provider": self.config.provider.as_str(),
                "grant_type": "revoke",
                "token": token,
            });
            let reply = self.http.post_json(broker, &body, None).await?;
            if !reply.ok() {
                return Err(broker_status_error(reply.status));
            }
            return Ok(());
        }
        let Some(url) = self.config.revoke_url.clone() else {
            // GitHub and the Microsoft identity platform have no token
            // revocation endpoint: sign-out is local only.
            return Ok(());
        };
        let reply = match self.config.provider {
            // Facebook revokes with DELETE /me/permissions and a bearer.
            ProviderId::Facebook => self.http.delete(&url, token).await?,
            _ => {
                self.http
                    .post_form(&url, &[("token", token.to_owned())], None)
                    .await?
            }
        };
        if !reply.ok() {
            return Err(status_error("revoke", reply.status));
        }
        Ok(())
    }
}

fn check_status(reply: &HttpReply, what: &str) -> Result<(), AuthError> {
    if reply.ok() {
        Ok(())
    } else {
        Err(status_error(what, reply.status))
    }
}

/// Every non-ok reply follows one rule, shared with the token endpoint
/// and the broker: the status only is reported — the body is
/// server-controlled text that would flow into the error signal and host
/// logs — and a 5xx is the endpoint's own transient failure (`ServerError`,
/// retryable), anything less is a refusal retrying cannot change.
fn status_error(what: &str, status: u16) -> AuthError {
    if status >= 500 {
        AuthError::ServerError(format!("{what} returned {status}"))
    } else {
        AuthError::Unknown(format!("{what} returned {status}"))
    }
}

/// The broker's failures split like a provider's (the rule shared with the
/// TS core): a 5xx is a transient server error worth retrying, a 4xx is
/// the broker refusing the request for good. Status only — the body is
/// the broker's text, not ours to flow into error signals and logs.
fn broker_status_error(status: u16) -> AuthError {
    if status >= 500 {
        AuthError::ServerError(format!("broker returned status {status}"))
    } else {
        AuthError::BrokerError(format!("broker returned status {status}"))
    }
}

fn parse_token_response(reply: &HttpReply, grant: Grant) -> Result<TokenResponse, AuthError> {
    // A 5xx is transient whatever its body says (RFC 6749 §5.2 maps
    // `server_error` to 500): classified so callers may retry it. The
    // status only is reported — the body is server-controlled text that
    // would flow into the error signal and host logs.
    if reply.status >= 500 {
        return Err(AuthError::ServerError(format!(
            "token endpoint returned {}",
            reply.status
        )));
    }
    let body: serde_json::Value = serde_json::from_str(&reply.body).map_err(|_| {
        AuthError::Unknown(format!(
            "token endpoint returned {} and no JSON",
            reply.status
        ))
    })?;
    if !reply.ok() {
        let code = body
            .get("error")
            .and_then(|e| e.as_str())
            .unwrap_or("unknown");
        let description = body
            .get("error_description")
            .and_then(|d| d.as_str())
            .unwrap_or_default();
        return Err(match (code, grant) {
            ("invalid_grant", Grant::Refresh) => AuthError::InvalidGrant,
            ("invalid_grant", Grant::Code) => AuthError::ExpiredCode,
            _ => AuthError::Unknown(format!("token endpoint error {code}: {description}")),
        });
    }
    Ok(TokenResponse {
        access_token: body
            .get("access_token")
            .and_then(|t| t.as_str())
            .ok_or_else(|| AuthError::Unknown("token response has no access_token".to_owned()))?
            .to_owned(),
        refresh_token: body
            .get("refresh_token")
            .and_then(|t| t.as_str())
            .map(str::to_owned),
        id_token: body
            .get("id_token")
            .and_then(|t| t.as_str())
            .map(str::to_owned),
        expires_in: body.get("expires_in").and_then(|t| t.as_i64()),
        scope: body
            .get("scope")
            .and_then(|t| t.as_str())
            .map(str::to_owned),
    })
}
