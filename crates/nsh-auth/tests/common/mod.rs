//! Shared harness: a loopback OAuth mock server, a loopback `Http` impl, a
//! manual clock and a reactive-runtime setup.
//!
//! UI-through-UI tests do not apply to this protocol crate: it has no UI, so
//! the whole loop is proven at the protocol level against this in-process
//! server on 127.0.0.1 — never the real network, never a real provider. All
//! client ids are the obviously fake `nsh-auth-sandbox-client`.

// Each test binary links this module but exercises only part of it.
#![allow(dead_code)]

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use nsh_auth::{
    Auth, AuthConfig, AuthError, BoxFuture, Clock, Http, HttpReply, MemoryStore, ProviderId,
};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;

pub const NOW_MS: i64 = 1_767_258_000_000; // 2026-01-01T04:46:40Z
pub const CLIENT_ID: &str = "nsh-auth-sandbox-client";
pub const REDIRECT_URI: &str = "http://127.0.0.1:8914/callback";

pub struct ManualClock(AtomicI64);

impl ManualClock {
    pub fn new(ms: i64) -> Self {
        Self(AtomicI64::new(ms))
    }

    pub fn set(&self, ms: i64) {
        self.0.store(ms, Ordering::SeqCst);
    }
}

impl Clock for ManualClock {
    fn now_ms(&self) -> i64 {
        self.0.load(Ordering::SeqCst)
    }
}

#[derive(Clone)]
pub struct Recorded {
    pub method: String,
    pub path: String,
    pub body: String,
}

/// One in-process provider: token, userinfo, JWKS, revoke and broker
/// endpoints with per-test canned responses and request recording.
pub struct MockServer {
    pub base: String,
    responses: Arc<Mutex<HashMap<String, (u16, String)>>>,
    delays: Arc<Mutex<HashMap<String, u64>>>,
    counts: Arc<Mutex<HashMap<String, usize>>>,
    requests: Arc<Mutex<Vec<Recorded>>>,
}

impl MockServer {
    pub fn start() -> Self {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind loopback");
        let port = listener.local_addr().expect("addr").port();
        let responses = Arc::new(Mutex::new(default_responses()));
        let delays = Arc::new(Mutex::new(HashMap::new()));
        let counts = Arc::new(Mutex::new(HashMap::new()));
        let requests = Arc::new(Mutex::new(Vec::new()));
        {
            let responses = Arc::clone(&responses);
            let delays = Arc::clone(&delays);
            let counts = Arc::clone(&counts);
            let requests = Arc::clone(&requests);
            // Serves until the test process ends; a test makes few requests.
            thread::spawn(move || {
                for stream in listener.incoming() {
                    let Ok(stream) = stream else { break };
                    let responses = Arc::clone(&responses);
                    let delays = Arc::clone(&delays);
                    let counts = Arc::clone(&counts);
                    let requests = Arc::clone(&requests);
                    // One thread per connection: a delayed response must not
                    // block the paths other tests in this run still need.
                    thread::spawn(move || {
                        let mut stream = stream;
                        serve(&mut stream, &responses, &delays, &counts, &requests);
                    });
                }
            });
        }
        Self {
            base: format!("http://127.0.0.1:{port}"),
            responses,
            delays,
            counts,
            requests,
        }
    }

    /// Delays `path`'s responses by `ms`, letting a test interleave other
    /// work while one request hangs.
    pub fn set_delay(&self, path: &str, ms: u64) {
        self.delays.lock().unwrap().insert(path.to_owned(), ms);
    }

    pub fn url(&self, path: &str) -> String {
        format!("{}{path}", self.base)
    }

    pub fn set(&self, path: &str, status: u16, body: impl Into<String>) {
        self.responses
            .lock()
            .unwrap()
            .insert(path.to_owned(), (status, body.into()));
    }

    pub fn count(&self, path: &str) -> usize {
        *self.counts.lock().unwrap().get(path).unwrap_or(&0)
    }

    pub fn requests(&self, path: &str) -> Vec<Recorded> {
        self.requests
            .lock()
            .unwrap()
            .iter()
            .filter(|recorded| recorded.path == path)
            .cloned()
            .collect()
    }
}

fn default_responses() -> HashMap<String, (u16, String)> {
    HashMap::from([
        (
            "/token".to_owned(),
            (
                200,
                json!({
                    "access_token": "at-1",
                    "refresh_token": "rt-1",
                    "expires_in": 3600,
                    "scope": "openid email profile",
                })
                .to_string(),
            ),
        ),
        (
            "/userinfo".to_owned(),
            (
                200,
                json!({
                    "sub": "u1",
                    "name": "Mock User",
                    "email": "mock@example.test",
                    "email_verified": true,
                    "picture": "https://mock.test/u1.png",
                })
                .to_string(),
            ),
        ),
        ("/jwks".to_owned(), (200, jwks_body())),
        ("/revoke".to_owned(), (200, "{}".to_owned())),
        (
            "/broker".to_owned(),
            (500, json!({"error": "broker not armed"}).to_string()),
        ),
    ])
}

fn serve(
    stream: &mut TcpStream,
    responses: &Mutex<HashMap<String, (u16, String)>>,
    delays: &Mutex<HashMap<String, u64>>,
    counts: &Mutex<HashMap<String, usize>>,
    requests: &Mutex<Vec<Recorded>>,
) {
    let Some((method, path, body)) = read_request(stream) else {
        return;
    };
    *counts.lock().unwrap().entry(path.clone()).or_insert(0) += 1;
    if let Some(ms) = delays.lock().unwrap().get(&path) {
        thread::sleep(std::time::Duration::from_millis(*ms));
    }
    requests.lock().unwrap().push(Recorded {
        method,
        path: path.clone(),
        body,
    });
    let (status, response) = responses
        .lock()
        .unwrap()
        .get(&path)
        .cloned()
        .unwrap_or((404, json!({"error": "no such endpoint"}).to_string()));
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        404 => "Not Found",
        500 => "Internal Server Error",
        _ => "Status",
    };
    let reply = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{response}",
        response.len()
    );
    let _ = stream.write_all(reply.as_bytes());
}

fn read_request(stream: &mut TcpStream) -> Option<(String, String, String)> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    let header_end = loop {
        let read = stream.read(&mut chunk).ok()?;
        if read == 0 {
            return None;
        }
        buf.extend_from_slice(&chunk[..read]);
        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break pos;
        }
    };
    let headers: HashMap<String, String> = String::from_utf8_lossy(&buf[..header_end])
        .lines()
        .skip(1)
        .filter_map(|line| {
            line.split_once(':')
                .map(|(key, value)| (key.to_ascii_lowercase(), value.trim().to_owned()))
        })
        .collect();
    let content_length: usize = headers
        .get("content-length")
        .and_then(|value| value.parse().ok())
        .unwrap_or(0);
    while buf.len() < header_end + 4 + content_length {
        let read = stream.read(&mut chunk).ok()?;
        if read == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..read]);
    }
    let text = String::from_utf8_lossy(&buf).into_owned();
    let mut lines = text[..header_end].split("\r\n");
    let request_line = lines.next()?;
    let mut parts = request_line.split(' ');
    let method = parts.next()?.to_owned();
    let raw_path = parts.next()?.to_owned();
    let path = raw_path.split('?').next().unwrap_or_default().to_owned();
    Some((method, path, text[header_end + 4..].to_owned()))
}

/// The test transport: real HTTP over loopback sockets, with the blocking
/// IO on tokio's blocking pool so the future yields. It must yield: the
/// single-flight proof needs parallel callers to observe a pending flight.
pub struct LoopbackHttp;

impl LoopbackHttp {
    fn send(
        url: &str,
        method: &str,
        content_type: Option<&str>,
        body: &str,
        bearer: Option<&str>,
    ) -> Result<HttpReply, AuthError> {
        let parsed = url::Url::parse(url).map_err(|e| AuthError::Network(e.to_string()))?;
        let host = parsed
            .host_str()
            .ok_or_else(|| AuthError::Network("no host".to_owned()))?
            .to_owned();
        let port = parsed
            .port_or_known_default()
            .ok_or_else(|| AuthError::Network("no port".to_owned()))?;
        let mut target = parsed.path().to_owned();
        if target.is_empty() {
            target.push('/');
        }
        if let Some(query) = parsed.query() {
            target.push('?');
            target.push_str(query);
        }
        let mut request = format!(
            "{method} {target} HTTP/1.1\r\nHost: {host}:{port}\r\nAccept: application/json\r\nConnection: close\r\n"
        );
        if let Some(token) = bearer {
            request.push_str(&format!("Authorization: Bearer {token}\r\n"));
        }
        if let Some(content_type) = content_type {
            request.push_str(&format!("Content-Type: {content_type}\r\n"));
        }
        if !body.is_empty() {
            request.push_str(&format!("Content-Length: {}\r\n", body.len()));
        }
        request.push_str("\r\n");
        request.push_str(body);

        let mut stream = TcpStream::connect((host.as_str(), port))
            .map_err(|e| AuthError::Network(e.to_string()))?;
        stream
            .write_all(request.as_bytes())
            .map_err(|e| AuthError::Network(e.to_string()))?;
        let mut response = String::new();
        stream
            .read_to_string(&mut response)
            .map_err(|e| AuthError::Network(e.to_string()))?;
        let status = response
            .split(' ')
            .nth(1)
            .and_then(|code| code.parse().ok())
            .ok_or_else(|| AuthError::Network("malformed response".to_owned()))?;
        let body_start = response
            .find("\r\n\r\n")
            .ok_or_else(|| AuthError::Network("no response body".to_owned()))?
            + 4;
        Ok(HttpReply {
            status,
            body: response[body_start..].to_owned(),
        })
    }
}

impl Http for LoopbackHttp {
    fn post_form<'a>(
        &'a self,
        url: &'a str,
        form: &'a [(&'a str, String)],
        bearer: Option<&'a str>,
    ) -> BoxFuture<'a, Result<HttpReply, AuthError>> {
        let body = url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs(form.iter().map(|(key, value)| (*key, value.as_str())))
            .finish();
        Box::pin(async move {
            let url = url.to_owned();
            let bearer = bearer.map(str::to_owned);
            tokio::task::spawn_blocking(move || {
                Self::send(
                    &url,
                    "POST",
                    Some("application/x-www-form-urlencoded"),
                    &body,
                    bearer.as_deref(),
                )
            })
            .await
            .map_err(|e| AuthError::Network(e.to_string()))?
        })
    }

    fn get_json<'a>(
        &'a self,
        url: &'a str,
        bearer: Option<&'a str>,
    ) -> BoxFuture<'a, Result<HttpReply, AuthError>> {
        Box::pin(async move {
            let url = url.to_owned();
            let bearer = bearer.map(str::to_owned);
            tokio::task::spawn_blocking(move || {
                Self::send(&url, "GET", None, "", bearer.as_deref())
            })
            .await
            .map_err(|e| AuthError::Network(e.to_string()))?
        })
    }

    fn post_json<'a>(
        &'a self,
        url: &'a str,
        body: &'a Value,
        bearer: Option<&'a str>,
    ) -> BoxFuture<'a, Result<HttpReply, AuthError>> {
        let body = body.to_string();
        Box::pin(async move {
            let url = url.to_owned();
            let bearer = bearer.map(str::to_owned);
            tokio::task::spawn_blocking(move || {
                Self::send(
                    &url,
                    "POST",
                    Some("application/json"),
                    &body,
                    bearer.as_deref(),
                )
            })
            .await
            .map_err(|e| AuthError::Network(e.to_string()))?
        })
    }

    fn delete<'a>(
        &'a self,
        url: &'a str,
        bearer: &'a str,
    ) -> BoxFuture<'a, Result<HttpReply, AuthError>> {
        Box::pin(async move {
            let url = url.to_owned();
            let bearer = bearer.to_owned();
            tokio::task::spawn_blocking(move || Self::send(&url, "DELETE", None, "", Some(&bearer)))
                .await
                .map_err(|e| AuthError::Network(e.to_string()))?
        })
    }
}

pub fn test_key() -> &'static rsa::RsaPrivateKey {
    static KEY: std::sync::OnceLock<rsa::RsaPrivateKey> = std::sync::OnceLock::new();
    KEY.get_or_init(|| {
        let mut rng = rand::rngs::OsRng;
        rsa::RsaPrivateKey::new(&mut rng, 2048).expect("test key")
    })
}

fn b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

pub fn jwks_body() -> String {
    use rsa::traits::PublicKeyParts;
    let key = test_key();
    json!({
        "keys": [{
            "kty": "RSA",
            "use": "sig",
            "kid": "test-key",
            "n": b64(&key.n().to_bytes_be()),
            "e": b64(&key.e().to_bytes_be()),
        }]
    })
    .to_string()
}

pub fn sign_id_token(nonce: Option<&str>, now_ms: i64) -> String {
    use rsa::pkcs1v15::SigningKey;
    use rsa::sha2::Sha256;
    use rsa::signature::Signer;
    let key = test_key();
    let header = json!({"alg": "RS256", "kid": "test-key", "typ": "JWT"});
    let claims = json!({
        "iss": "https://mock.test",
        "aud": CLIENT_ID,
        "sub": "u1",
        "nonce": nonce,
        "name": "Mock User",
        "email": "mock@example.test",
        "email_verified": true,
        "exp": now_ms / 1000 + 3600,
        "iat": now_ms / 1000,
    });
    let signed = format!(
        "{}.{}",
        b64(header.to_string().as_bytes()),
        b64(claims.to_string().as_bytes())
    );
    let signature: Box<[u8]> = SigningKey::<Sha256>::new(key.clone())
        .sign(signed.as_bytes())
        .into();
    format!("{}.{}", signed, b64(&signature))
}

/// Re-signs nothing: takes a valid token and swaps the claims for the
/// attacker's, keeping the honest signature. Verification must reject it.
pub fn tamper_claims(token: &str, claim: &str, value: &str) -> String {
    let mut parts: Vec<String> = token.split('.').map(str::to_owned).collect();
    let raw = URL_SAFE_NO_PAD
        .decode(&parts[1])
        .expect("claims are base64url");
    let mut claims: Value = serde_json::from_slice(&raw).expect("claims are JSON");
    claims[claim] = json!(value);
    parts[1] = b64(claims.to_string().as_bytes());
    parts.join(".")
}

pub struct Setup {
    pub auth: Auth,
    pub mock: MockServer,
    pub store: Arc<MemoryStore>,
    pub clock: Arc<ManualClock>,
    _entered: nsh_core::element::reactive::Entered,
    _runtime: &'static nsh_core::element::reactive::Runtime,
}

pub fn setup(config_of: impl FnOnce(&MockServer) -> AuthConfig) -> Setup {
    setup_with(config_of, Arc::new(MemoryStore::new()))
}

pub fn setup_with(
    config_of: impl FnOnce(&MockServer) -> AuthConfig,
    store: Arc<MemoryStore>,
) -> Setup {
    let mock = MockServer::start();
    let config = config_of(&mock);
    let clock = Arc::new(ManualClock::new(NOW_MS));
    // Signals need a reactive runtime entered and an owner that outlives the
    // test: leak one of each for the harness's life.
    let runtime: &'static nsh_core::element::reactive::Runtime = Box::leak(Box::default());
    let _entered = runtime.enter();
    let (_owner, auth) = nsh_core::element::create_root(|| {
        Auth::new(config, store.clone(), clock.clone(), Arc::new(LoopbackHttp))
    });
    // Owner is Copy and disposal is explicit in nsh-core: dropping the handle
    // keeps the root's signals alive for the test's life.
    Setup {
        auth,
        mock,
        store,
        clock,
        _entered,
        _runtime: runtime,
    }
}

pub fn mock_config(mock: &MockServer) -> AuthConfig {
    let mut config = AuthConfig::for_provider(ProviderId::Mock)
        .client_id(CLIENT_ID)
        .redirect_uri(REDIRECT_URI);
    config.auth_url = mock.url("/authorize");
    config.token_url = mock.url("/token");
    config.userinfo_url = Some(mock.url("/userinfo"));
    config.jwks_url = Some(mock.url("/jwks"));
    config.revoke_url = Some(mock.url("/revoke"));
    config
}

pub fn query_pair(url: &str, key: &str) -> String {
    url::Url::parse(url)
        .expect("authorize url")
        .query_pairs()
        .find(|(name, _)| name == key)
        .map(|(_, value)| value.into_owned())
        .unwrap_or_default()
}

pub fn has_pair(url: &str, key: &str) -> bool {
    url::Url::parse(url)
        .expect("authorize url")
        .query_pairs()
        .any(|(name, _)| name == key)
}

/// Arms any path with a token response; the id token is signed when a
/// `nonce` is given.
pub fn arm_token(
    mock: &MockServer,
    path: &str,
    access_token: &str,
    refresh_token: Option<&str>,
    nonce: Option<&str>,
) {
    mock.set(
        path,
        200,
        json!({
            "access_token": access_token,
            "refresh_token": refresh_token,
            "id_token": nonce.map(|n| sign_id_token(Some(n), NOW_MS)),
            "expires_in": 3600,
            "scope": "openid email profile",
        })
        .to_string(),
    );
}

/// Arms the mock token endpoint with a full response: tokens plus an id
/// token signed by the test key, embedding `nonce`.
pub fn arm_success(mock: &MockServer, nonce: &str) {
    mock.set(
        "/token",
        200,
        json!({
            "access_token": "at-1",
            "refresh_token": "rt-1",
            "id_token": sign_id_token(Some(nonce), NOW_MS),
            "expires_in": 3600,
            "scope": "openid email profile",
        })
        .to_string(),
    );
}

/// Authorizes against the mock provider and returns its (nonce, state).
pub fn authorize_mock(auth: &Auth) -> (String, String) {
    let request = auth.authorize_request(ProviderId::Mock).expect("authorize");
    (
        query_pair(&request.url, "nonce"),
        query_pair(&request.url, "state"),
    )
}

pub fn callback(code: &str, state: &str) -> String {
    format!("{REDIRECT_URI}?code={code}&state={state}")
}

/// Drives the full mock loop once; the returned session is also in the
/// signals and the store.
pub async fn sign_in(setup: &Setup) -> nsh_auth::Session {
    let (nonce, state) = authorize_mock(&setup.auth);
    arm_success(&setup.mock, &nonce);
    setup
        .auth
        .complete(ProviderId::Mock, &callback("code-1", &state))
        .await
        .expect("sign in")
}
