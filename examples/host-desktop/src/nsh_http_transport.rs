//! The transport seam for the launcher's flows: `nsh_auth::Http` over the
//! sibling `nsh-http` client, whose transport is `nsh_core::prelude::fetch` —
//! the engine's own network stack. The crate's default `ReqwestHttp` opens
//! its own sockets, bypassing the platform transport, and phase 2 reported
//! its futures stalling inside engine-spawned tasks under headless runs
//! (docs/upstream-issues.md); measured comparison in
//! `~/fo/nsh-http/docs/decision.md`. This adapter lives here, not in
//! `crates/nsh-auth`, because that crate must stay buildable and testable
//! outside any engine, where fetch has no context.
//!
//! Bridge, forced by 0.4.0's types: every future on the engine's executor is
//! deliberately `!Send` (`nsh-http` middleware.rs, `nsh-core` `Answer`/`Task`
//! hold `Rc`), while `nsh_auth::Http` demands `Send` futures. So each call
//! hands the client future to the engine's executor with `spawn` (which
//! takes `!Send` futures) and awaits only a `Send` oneshot receipt — the
//! `!Send` value never crosses a thread, and no `unsafe` bridges the types.

use std::future::Future;
use std::sync::Arc;

use nsh_auth::{AuthError, BoxFuture, Http, HttpReply, ReqwestHttp};
use nsh_core::platform::HttpBody;
use nsh_core::prelude::{HttpRequest, HttpResponse, spawn};
use nsh_http::Error as NshHttpError;

/// The transports `--transport` accepts.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub(crate) enum TransportKind {
    /// `nsh-http` over the platform fetch: the engine's stack, the app's
    /// default.
    #[default]
    Nsh,
    /// `crates/nsh-auth`'s reqwest + rustls client: the escape hatch that
    /// bypasses the platform transport.
    Reqwest,
}

pub(crate) fn parse_transport(name: &str) -> Option<TransportKind> {
    match name {
        "nsh" => Some(TransportKind::Nsh),
        "reqwest" => Some(TransportKind::Reqwest),
        _ => None,
    }
}

/// The transport the flows run on, plus the startup line naming it — the
/// store log's counterpart, so the active transport is never silent.
pub(crate) fn select(kind: TransportKind) -> Result<(Arc<dyn Http>, String), String> {
    match kind {
        TransportKind::Nsh => {
            let note = "transport: nsh-http over the platform fetch".to_owned();
            Ok((Arc::new(NshHttpTransport::new()), note))
        }
        TransportKind::Reqwest => {
            let note = "transport: reqwest (bypasses the platform transport)".to_owned();
            let http = ReqwestHttp::new().map_err(|error| error.to_string())?;
            Ok((Arc::new(http), note))
        }
    }
}

/// `nsh_auth::Http` over `nsh_http::HttpClient::send_request`: absolute-URL
/// requests through nsh-http's pipeline (timeout, retry, observation) onto
/// the engine's fetch. No base URL — OAuth endpoints arrive absolute.
pub struct NshHttpTransport {
    client: nsh_http::HttpClient,
}

impl NshHttpTransport {
    /// No timeout of its own: the flow's watchdog cancels the task, which
    /// drops the fetch future — nsh-http's composed cancellation.
    pub fn new() -> Self {
        Self {
            client: nsh_http::HttpClient::builder().build(),
        }
    }
}

impl Default for NshHttpTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl NshHttpTransport {
    /// One pipeline round trip. Runs the `!Send` client future as an engine
    /// task on the engine thread and reports completion through the oneshot:
    /// only this `Send` receipt is held across the caller's `await`.
    fn send(
        &self,
        request: HttpRequest,
    ) -> impl Future<Output = Result<HttpResponse, NshHttpError>> + Send {
        let client = self.client.clone();
        let (sender, receiver) = tokio::sync::oneshot::channel();
        spawn(async move {
            let _ = sender.send(client.send_request(request).await);
        });
        async move {
            // Err: the spawned task was cancelled with the flow (watchdog,
            // owner disposal) or panicked before answering.
            match receiver.await {
                Ok(outcome) => outcome,
                Err(_) => Err(NshHttpError::Network {
                    message: "the flow task ended before the request did".to_owned(),
                }),
            }
        }
    }
}

fn request(method: &str, url: &str, headers: Vec<(String, String)>, body: Vec<u8>) -> HttpRequest {
    HttpRequest {
        method: method.to_owned(),
        url: url.to_owned(),
        headers,
        body: if body.is_empty() {
            HttpBody::Empty
        } else {
            HttpBody::Bytes(body)
        },
        follow_redirects: true,
    }
}

fn bearer_headers(bearer: Option<&str>, base: &[(&str, &str)]) -> Vec<(String, String)> {
    let mut headers: Vec<(String, String)> = base
        .iter()
        .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
        .collect();
    if let Some(token) = bearer {
        headers.push(("authorization".to_owned(), format!("Bearer {token}")));
    }
    headers
}

/// Maps the send outcome onto the seam's reply shape, explicitly: a status
/// (2xx or not) is a reply — the crate reads `invalid_grant` bodies and
/// makes 5xx a retryable `ServerError` itself — while every transport-level
/// taxonomy case lands in `AuthError`. `Network` and `Timeout` map to the
/// retryable `AuthError::Network`, `Cancelled` joins them (it surfaces only
/// when the owning flow task is going away), and a capability refusal maps
/// to `Unknown`: it answers the same however often it is retried, as
/// nsh-http's own `is_retryable` says.
fn into_reply(outcome: Result<HttpResponse, NshHttpError>) -> Result<HttpReply, AuthError> {
    match outcome {
        Ok(response) => Ok(HttpReply {
            status: response.status(),
            body: String::from_utf8_lossy(&response.body).into_owned(),
        }),
        Err(NshHttpError::HttpStatus { status, body, .. }) => Ok(HttpReply { status, body }),
        Err(NshHttpError::Network { message }) => Err(AuthError::Network(message)),
        Err(NshHttpError::Timeout) => Err(AuthError::Network(
            "timeout: the request passed its deadline".to_owned(),
        )),
        Err(NshHttpError::Cancelled) => Err(AuthError::Network(
            "cancelled: the request was aborted".to_owned(),
        )),
        Err(NshHttpError::RefusedByCapability { message }) => Err(AuthError::Unknown(format!(
            "refused by capability: {message}"
        ))),
        // Unreachable through `send_request` (no typed decoding); mapped so
        // the taxonomy is covered in full.
        Err(NshHttpError::Decode { message, .. }) => {
            Err(AuthError::Unknown(format!("decode: {message}")))
        }
    }
}

impl Http for NshHttpTransport {
    fn post_form<'a>(
        &'a self,
        url: &'a str,
        form: &'a [(&'a str, String)],
        bearer: Option<&'a str>,
    ) -> BoxFuture<'a, Result<HttpReply, AuthError>> {
        let body = url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs(form.iter().map(|(key, value)| (*key, value.as_str())))
            .finish();
        let headers = bearer_headers(
            bearer,
            &[
                ("accept", "application/json"),
                ("content-type", "application/x-www-form-urlencoded"),
            ],
        );
        let url = url.to_owned();
        Box::pin(async move {
            let outcome = self
                .send(request("POST", &url, headers, body.into_bytes()))
                .await;
            into_reply(outcome)
        })
    }

    fn get_json<'a>(
        &'a self,
        url: &'a str,
        bearer: Option<&'a str>,
    ) -> BoxFuture<'a, Result<HttpReply, AuthError>> {
        let headers = bearer_headers(bearer, &[("accept", "application/json")]);
        let url = url.to_owned();
        Box::pin(async move {
            let outcome = self.send(request("GET", &url, headers, Vec::new())).await;
            into_reply(outcome)
        })
    }

    fn post_json<'a>(
        &'a self,
        url: &'a str,
        body: &'a serde_json::Value,
        bearer: Option<&'a str>,
    ) -> BoxFuture<'a, Result<HttpReply, AuthError>> {
        // No content-type here: the client stamps application/json on a
        // non-empty body, and a caller-set one would win anyway.
        let headers = bearer_headers(bearer, &[("accept", "application/json")]);
        let body = body.to_string().into_bytes();
        let url = url.to_owned();
        Box::pin(async move {
            let outcome = self.send(request("POST", &url, headers, body)).await;
            into_reply(outcome)
        })
    }

    fn delete<'a>(
        &'a self,
        url: &'a str,
        bearer: &'a str,
    ) -> BoxFuture<'a, Result<HttpReply, AuthError>> {
        let headers = bearer_headers(Some(bearer), &[("accept", "application/json")]);
        let url = url.to_owned();
        Box::pin(async move {
            let outcome = self
                .send(request("DELETE", &url, headers, Vec::new()))
                .await;
            into_reply(outcome)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nsh_core::platform::HttpHead;

    fn response(status: u16) -> Result<HttpResponse, NshHttpError> {
        Ok(HttpResponse {
            head: HttpHead {
                status,
                headers: vec![("content-type".to_owned(), "application/json".to_owned())],
                ..HttpHead::default()
            },
            body: br#"{"ok":true}"#.to_vec(),
        })
    }

    #[test]
    fn the_taxonomy_maps_case_by_case() {
        let cases: [(NshHttpError, AuthError); 5] = [
            (
                NshHttpError::Network {
                    message: "io: connection refused".to_owned(),
                },
                AuthError::Network("io: connection refused".to_owned()),
            ),
            (
                NshHttpError::Timeout,
                AuthError::Network("timeout: the request passed its deadline".to_owned()),
            ),
            (
                NshHttpError::Cancelled,
                AuthError::Network("cancelled: the request was aborted".to_owned()),
            ),
            (
                NshHttpError::RefusedByCapability {
                    message: "host is not granted".to_owned(),
                },
                AuthError::Unknown("refused by capability: host is not granted".to_owned()),
            ),
            (
                NshHttpError::Decode {
                    message: "expected value".to_owned(),
                    body: String::new(),
                },
                AuthError::Unknown("decode: expected value".to_owned()),
            ),
        ];
        for (error, expected) in cases {
            let mapped = into_reply(Err(error)).expect_err("a transport failure is an error");
            assert_eq!(mapped, expected);
        }
    }

    #[test]
    fn retryability_survives_the_mapping_where_it_should() {
        // The crate retries only what is_retryable allows: a mapped timeout
        // stays retryable, a mapped refusal does not.
        assert!(
            into_reply(Err(NshHttpError::Timeout))
                .unwrap_err()
                .is_retryable()
        );
        assert!(
            into_reply(Err(NshHttpError::Network {
                message: "offline".to_owned()
            }))
            .unwrap_err()
            .is_retryable()
        );
        assert!(
            !into_reply(Err(NshHttpError::RefusedByCapability {
                message: "no".to_owned()
            }))
            .unwrap_err()
            .is_retryable()
        );
    }

    #[test]
    fn a_status_is_a_reply_whatever_its_code_so_the_crate_classifies_it() {
        for status in [200_u16, 400, 500] {
            let outcome = into_reply(response(status));
            let reply = outcome.expect("a status is never a transport error");
            assert_eq!(reply.status, status);
            assert_eq!(reply.ok(), (200..300).contains(&status));
            assert_eq!(reply.body, r#"{"ok":true}"#);
        }
    }
}
