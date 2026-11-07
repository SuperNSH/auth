//! The HTTP seam. Tests inject a loopback implementation; the default is
//! reqwest over rustls.

use crate::error::AuthError;
use std::future::Future;
use std::pin::Pin;

/// A future the engine (or a host runtime) can poll from any thread.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// One reply: status and body, which is all OAuth endpoints need.
#[derive(Debug, Clone)]
pub struct HttpReply {
    pub status: u16,
    pub body: String,
}

impl HttpReply {
    pub fn ok(&self) -> bool {
        (200..300).contains(&self.status)
    }
}

/// The HTTP calls the flows make. Implementations must never add a client
/// secret to a request: confidential providers are reached through the
/// broker, not through extra headers here.
pub trait Http: Send + Sync + 'static {
    /// POST `form` as `application/x-www-form-urlencoded` with
    /// `Accept: application/json` (GitHub answers form-encoded otherwise).
    fn post_form<'a>(
        &'a self,
        url: &'a str,
        form: &'a [(&'a str, String)],
        bearer: Option<&'a str>,
    ) -> BoxFuture<'a, Result<HttpReply, AuthError>>;

    /// GET `url` with `Accept: application/json` and an optional bearer token.
    fn get_json<'a>(
        &'a self,
        url: &'a str,
        bearer: Option<&'a str>,
    ) -> BoxFuture<'a, Result<HttpReply, AuthError>>;

    /// POST a JSON body to `url` (the token broker seam).
    fn post_json<'a>(
        &'a self,
        url: &'a str,
        body: &'a serde_json::Value,
        bearer: Option<&'a str>,
    ) -> BoxFuture<'a, Result<HttpReply, AuthError>>;

    /// DELETE `url` with a bearer token (Facebook sign-out).
    fn delete<'a>(
        &'a self,
        url: &'a str,
        bearer: &'a str,
    ) -> BoxFuture<'a, Result<HttpReply, AuthError>>;
}

/// The default transport. Its futures must be polled inside a tokio runtime;
/// an embedding host runs one.
#[derive(Debug, Clone)]
pub struct ReqwestHttp {
    client: reqwest::Client,
}

impl ReqwestHttp {
    pub fn new() -> Result<Self, AuthError> {
        let client = reqwest::Client::builder()
            .use_rustls_tls()
            .build()
            .map_err(|e| AuthError::Network(e.to_string()))?;
        Ok(Self { client })
    }
}

fn network(error: reqwest::Error) -> AuthError {
    AuthError::Network(error.to_string())
}

impl ReqwestHttp {
    async fn reply(&self, request: reqwest::RequestBuilder) -> Result<HttpReply, AuthError> {
        let response = request.send().await.map_err(network)?;
        let status = response.status().as_u16();
        // Error statuses keep the body: OAuth endpoints report failures in it.
        let body = response.text().await.map_err(network)?;
        Ok(HttpReply { status, body })
    }
}

impl Http for ReqwestHttp {
    fn post_form<'a>(
        &'a self,
        url: &'a str,
        form: &'a [(&'a str, String)],
        bearer: Option<&'a str>,
    ) -> BoxFuture<'a, Result<HttpReply, AuthError>> {
        let body = url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs(form.iter().map(|(k, v)| (*k, v.as_str())))
            .finish();
        Box::pin(async move {
            let mut request = self
                .client
                .post(url)
                .header("accept", "application/json")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(body);
            if let Some(token) = bearer {
                request = request.bearer_auth(token);
            }
            self.reply(request).await
        })
    }

    fn get_json<'a>(
        &'a self,
        url: &'a str,
        bearer: Option<&'a str>,
    ) -> BoxFuture<'a, Result<HttpReply, AuthError>> {
        Box::pin(async move {
            let mut request = self.client.get(url).header("accept", "application/json");
            if let Some(token) = bearer {
                request = request.bearer_auth(token);
            }
            self.reply(request).await
        })
    }

    fn post_json<'a>(
        &'a self,
        url: &'a str,
        body: &'a serde_json::Value,
        bearer: Option<&'a str>,
    ) -> BoxFuture<'a, Result<HttpReply, AuthError>> {
        Box::pin(async move {
            let mut request = self
                .client
                .post(url)
                .header("accept", "application/json")
                .json(body);
            if let Some(token) = bearer {
                request = request.bearer_auth(token);
            }
            self.reply(request).await
        })
    }

    fn delete<'a>(
        &'a self,
        url: &'a str,
        bearer: &'a str,
    ) -> BoxFuture<'a, Result<HttpReply, AuthError>> {
        Box::pin(async move {
            let request = self
                .client
                .delete(url)
                .header("accept", "application/json")
                .bearer_auth(bearer);
            self.reply(request).await
        })
    }
}
