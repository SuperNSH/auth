//! Sessions, the normalized user identity and the status a host renders.

use crate::provider::ProviderId;
use serde::{Deserialize, Serialize};

/// One signed-in provider session. `expires_at` is milliseconds since the
/// epoch; 0 means the provider sent no expiry (GitHub tokens do not expire).
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct Session {
    pub provider: ProviderId,
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub id_token: Option<String>,
    pub expires_at: i64,
    pub scope: String,
}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Tokens never reach logs or test-failure output.
        f.debug_struct("Session")
            .field("provider", &self.provider)
            .field("access_token", &"[redacted]")
            .field(
                "refresh_token",
                &self.refresh_token.as_ref().map(|_| "[redacted]"),
            )
            .field("id_token", &self.id_token.as_ref().map(|_| "[redacted]"))
            .field("expires_at", &self.expires_at)
            .field("scope", &self.scope)
            .finish()
    }
}

/// How far ahead of expiry a session counts as expired: a refresh sent
/// inside this window could carry a token that dies mid-request, so callers
/// refresh proactively instead. AppAuth's state objects use the same 60 s
/// tolerance (OIDAuthState.m).
pub const EXPIRY_TOLERANCE_MS: i64 = 60_000;

impl Session {
    /// Whether the access token is expired at `now_ms`: true at expiry and
    /// already true [`EXPIRY_TOLERANCE_MS`] before it. Never when the
    /// provider set no expiry (GitHub tokens do not expire).
    pub fn expired(&self, now_ms: i64) -> bool {
        self.expires_at != 0 && now_ms.saturating_add(EXPIRY_TOLERANCE_MS) >= self.expires_at
    }
}

/// The user identity, normalized across provider shapes. `raw` keeps the full
/// provider response for app-specific fields.
#[derive(Clone, PartialEq, Serialize, Deserialize, Debug)]
pub struct UserInfo {
    pub sub: String,
    pub name: Option<String>,
    pub email: Option<String>,
    pub email_verified: Option<bool>,
    pub picture: Option<String>,
    pub raw: serde_json::Value,
}

impl UserInfo {
    /// Normalizes a userinfo response. Providers agree on none of the field
    /// names: `sub`/`id`, `name`/`global_name`/`username`/`login`,
    /// `email_verified`/`verified`, `picture`/`avatar_url`, and X nests
    /// everything under `data`.
    pub(crate) fn from_json(value: &serde_json::Value) -> Self {
        let data = value.get("data").unwrap_or(value);
        Self {
            sub: str_or_number(data, &["sub", "id"]).unwrap_or_default(),
            name: field(data, &["name", "global_name", "username", "login"]),
            email: field(data, &["email"]),
            email_verified: bool_field(data, &["email_verified", "verified"]),
            picture: picture_field(data),
            raw: value.clone(),
        }
    }

    /// Builds the identity from verified id-token claims, for providers with
    /// no userinfo endpoint (Apple).
    pub(crate) fn from_claims(claims: &serde_json::Value) -> Self {
        Self {
            sub: str_or_number(claims, &["sub", "id"]).unwrap_or_default(),
            name: field(claims, &["name"]),
            email: field(claims, &["email"]),
            email_verified: bool_field(claims, &["email_verified"]),
            picture: picture_field(claims),
            raw: claims.clone(),
        }
    }
}

fn field(data: &serde_json::Value, names: &[&str]) -> Option<String> {
    names
        .iter()
        .find_map(|name| data.get(*name).and_then(|v| v.as_str()))
        .map(str::to_owned)
}

fn bool_field(data: &serde_json::Value, names: &[&str]) -> Option<bool> {
    names
        .iter()
        .find_map(|name| data.get(*name).and_then(|v| v.as_bool()))
}

fn str_or_number(data: &serde_json::Value, names: &[&str]) -> Option<String> {
    names.iter().find_map(|name| {
        data.get(*name).and_then(|v| {
            v.as_str()
                .map(str::to_owned)
                .or_else(|| v.as_i64().map(|n| n.to_string()))
        })
    })
}

/// Facebook sends `picture` as `{"data": {"url": ...}}`; everyone else sends a
/// string. Discord's `avatar` is a hash, not a URL, so it is skipped.
fn picture_field(data: &serde_json::Value) -> Option<String> {
    data.get("picture")
        .and_then(|p| match p {
            serde_json::Value::String(url) => Some(url.clone()),
            other => other
                .pointer("/data/url")
                .and_then(|u| u.as_str())
                .map(str::to_owned),
        })
        .or_else(|| {
            data.get("avatar_url")
                .and_then(|v| v.as_str())
                .map(str::to_owned)
        })
}

/// What the auth service is doing, as a signal a host renders.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthStatus {
    Idle,
    SigningIn,
    Refreshing,
    SignedIn,
    SignedOut,
}
