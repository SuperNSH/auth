//! Headless checks of the launcher screen: it renders, the loopback origin
//! is shown, and a bad `--provider` value is reported instead of opened.
//! No test presses a provider button — that would open a real browser.
//! The sign-out press goes to a loopback mock provider only: no real
//! network, no real account.

use std::future::Future;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::task::Poll;
use std::thread;
use std::time::{Duration, Instant};

use nsh_auth::{
    AuthError, BoxFuture, Http, HttpReply, MemoryStore, ProviderId, Session, SessionStore,
};
use nsh_core::prelude::*;
use nsh_engine::{EngineConfig, Root};
use nsh_testing::{Headless, UreqNetwork};

use crate::flow::{Launcher, Opener};
use crate::nsh_http_transport::TransportKind;
use crate::options::Options;
use crate::ui::launcher_screen;

fn options(provider: Option<&'static str>) -> Options {
    Options {
        provider: provider.map(str::to_owned),
        ..Options::default()
    }
}

fn test_launcher(provider: Option<&'static str>) -> Launcher {
    Launcher::connect_with(Arc::new(MemoryStore::new()), &options(provider))
        .expect("the test launcher starts")
}

#[component]
fn IdleScreen() -> impl IntoElement {
    launcher_screen(test_launcher(None))
}

#[component]
fn UnknownProviderScreen() -> impl IntoElement {
    launcher_screen(test_launcher(Some("nope")))
}

fn start<C: Component>() -> Result<Headless, String>
where
    C::Props: Default,
{
    Headless::start(EngineConfig::new(Root::of::<C>())).map_err(|error| error.to_string())
}

#[test]
fn the_screen_offers_the_providers_over_a_loopback_listener() -> Result<(), String> {
    let mut app = start::<IdleScreen>()?;
    app.wait_for("Continue with Google")?;
    assert!(app.screen().shows("Continue with GitHub"));
    assert!(app.screen().shows("Mock provider"));
    // The bound port is OS-assigned, so the prefix is what a test can know.
    let texts = app.screen().texts();
    assert!(
        texts
            .iter()
            .any(|text| text.starts_with("Listening on http://127.0.0.1:")),
        "{texts:?}"
    );
    assert!(!app.screen().shows("Signed in"));
    assert!(!app.screen().shows("Sign out"));
    Ok(())
}

#[test]
fn an_unknown_provider_argument_is_reported_not_opened() -> Result<(), String> {
    let mut app = start::<UnknownProviderScreen>()?;
    app.wait_for("Unknown provider \"nope\". Try google, facebook, discord, github or mock.")?;
    assert!(!app.screen().shows("Signed in"));
    Ok(())
}

/// The store and options the sign-out screen's launcher is built from,
/// armed by the test before the engine starts (the component runs elsewhere).
static SIGN_OUT_FIXTURE: Mutex<Option<(Arc<MemoryStore>, Options)>> = Mutex::new(None);

#[component]
fn SignedInScreen() -> impl IntoElement {
    let (store, options) = SIGN_OUT_FIXTURE
        .lock()
        .expect("the fixture locks")
        .clone()
        .expect("the sign-out fixture is armed");
    launcher_screen(
        Launcher::connect_with_http(store, Arc::new(LoopbackHttp), &options)
            .expect("the test launcher starts"),
    )
}

/// Generous because the machine may be busy; a working revoke lands in
/// milliseconds on loopback.
const REVOKE_WINDOW: Duration = Duration::from_secs(10);

/// A loopback stand-in for the mock provider: it records what reaches its
/// revoke endpoint. 127.0.0.1 only — no real network is involved.
struct MockRevoke {
    base: String,
    revokes: Arc<Mutex<Vec<String>>>,
}

impl MockRevoke {
    fn start() -> Self {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("the mock provider binds");
        let port = listener.local_addr().expect("the mock address").port();
        let revokes = Arc::new(Mutex::new(Vec::new()));
        let recorded = Arc::clone(&revokes);
        // Serves until the test process ends; the launcher makes one request.
        thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { break };
                let recorded = Arc::clone(&recorded);
                thread::spawn(move || serve_one(&mut stream, &recorded));
            }
        });
        Self {
            base: format!("http://127.0.0.1:{port}"),
            revokes,
        }
    }

    fn count(&self) -> usize {
        self.revokes.lock().expect("the mock locks").len()
    }

    fn first_body(&self) -> String {
        self.revokes
            .lock()
            .expect("the mock locks")
            .first()
            .cloned()
            .unwrap_or_default()
    }
}

fn serve_one(stream: &mut TcpStream, recorded: &Mutex<Vec<String>>) {
    let Some((path, body)) = read_request(stream) else {
        return;
    };
    let (status, reply) = if path == "/mock/revoke" {
        recorded.lock().expect("the mock locks").push(body);
        ("200 OK", "{}".to_owned())
    } else {
        ("404 Not Found", "{\"error\":\"no endpoint\"}".to_owned())
    };
    let http = format!(
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{reply}",
        reply.len()
    );
    let _ = stream.write_all(http.as_bytes());
}

fn read_request(stream: &mut TcpStream) -> Option<(String, String)> {
    let mut buf = Vec::new();
    let mut chunk = [0_u8; 4096];
    let header_end = loop {
        let read = stream.read(&mut chunk).ok()?;
        if read == 0 {
            return None;
        }
        buf.extend_from_slice(&chunk[..read]);
        if let Some(pos) = buf.windows(4).position(|window| window == b"\r\n\r\n") {
            break pos;
        }
    };
    let headers = String::from_utf8_lossy(&buf[..header_end]).to_ascii_lowercase();
    let length = headers
        .lines()
        .find_map(|line| line.strip_prefix("content-length:"))
        .and_then(|value| value.trim().parse().ok())
        .unwrap_or(0);
    while buf.len() < header_end + 4 + length {
        let read = stream.read(&mut chunk).ok()?;
        if read == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..read]);
    }
    let text = String::from_utf8_lossy(&buf).into_owned();
    let request_line = text[..header_end].lines().next()?;
    let path = request_line
        .split(' ')
        .nth(1)?
        .split('?')
        .next()
        .unwrap_or_default()
        .to_owned();
    Some((path, text[header_end + 4..].to_owned()))
}

/// Pends once, then a timer thread wakes the task's waker: a future that
/// needs a second poll, with no tokio involved.
fn later(after: Duration) -> impl Future<Output = ()> {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::task::Waker;
    let done = Arc::new(AtomicBool::new(false));
    let waker_slot: Arc<Mutex<Option<Waker>>> = Arc::new(Mutex::new(None));
    let flag = Arc::clone(&done);
    let slot = Arc::clone(&waker_slot);
    thread::spawn(move || {
        thread::sleep(after);
        flag.store(true, Ordering::SeqCst);
        if let Some(waker) = slot.lock().expect("the waker slot locks").take() {
            waker.wake();
        }
    });
    struct Later {
        done: Arc<AtomicBool>,
        slot: Arc<Mutex<Option<Waker>>>,
    }
    impl Future for Later {
        type Output = ();
        fn poll(self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<()> {
            if self.done.load(Ordering::SeqCst) {
                return Poll::Ready(());
            }
            *self.slot.lock().expect("the waker slot locks") = Some(cx.waker().clone());
            Poll::Pending
        }
    }
    Later {
        done,
        slot: waker_slot,
    }
}

/// The test transport: plain HTTP over loopback sockets, inline in the
/// future — the core crate's `LoopbackHttp` pattern without
/// `spawn_blocking` (not a dependency here); a loopback round trip is
/// brief enough to block the engine thread for.
struct LoopbackHttp;

impl LoopbackHttp {
    /// The pairs are token-shaped (no reserved characters), so joining is
    /// the form encoding this test needs.
    fn form(pairs: &[(&str, String)]) -> String {
        pairs
            .iter()
            .map(|(key, value)| format!("{key}={value}"))
            .collect::<Vec<_>>()
            .join("&")
    }

    /// `http://127.0.0.1:port/...` only; there is nowhere else to reach.
    fn send(
        method: &str,
        url: &str,
        content_type: Option<(&str, String)>,
        bearer: Option<&str>,
    ) -> Result<HttpReply, AuthError> {
        let rest = url.strip_prefix("http://").ok_or_else(|| {
            AuthError::Network("the test transport reaches http loopback only".to_owned())
        })?;
        let (authority, path) = rest
            .split_once('/')
            .ok_or_else(|| AuthError::Network("no path in the URL".to_owned()))?;
        let (host, port) = authority
            .split_once(':')
            .ok_or_else(|| AuthError::Network("no port in the URL".to_owned()))?;
        let port = port
            .parse::<u16>()
            .map_err(|e| AuthError::Network(e.to_string()))?;
        let mut request = format!(
            "{method} /{path} HTTP/1.1\r\nHost: {authority}\r\nAccept: application/json\r\nConnection: close\r\n"
        );
        if let Some(token) = bearer {
            request.push_str(&format!("Authorization: Bearer {token}\r\n"));
        }
        let mut body = String::new();
        if let Some((kind, content)) = content_type {
            body = content;
            request.push_str(&format!(
                "Content-Type: {kind}\r\nContent-Length: {}\r\n",
                body.len()
            ));
        }
        request.push_str("\r\n");
        request.push_str(&body);
        let mut stream =
            TcpStream::connect((host, port)).map_err(|e| AuthError::Network(e.to_string()))?;
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
        let content = Self::form(form);
        Box::pin(async move {
            // A real transport needs several polls (one per await): pend
            // once, so the test fails if the task dies with the button.
            later(Duration::from_millis(50)).await;
            Self::send(
                "POST",
                url,
                Some(("application/x-www-form-urlencoded", content)),
                bearer,
            )
        })
    }

    fn get_json<'a>(
        &'a self,
        url: &'a str,
        bearer: Option<&'a str>,
    ) -> BoxFuture<'a, Result<HttpReply, AuthError>> {
        Box::pin(async move { Self::send("GET", url, None, bearer) })
    }

    fn post_json<'a>(
        &'a self,
        url: &'a str,
        body: &'a nsh_core::JsonValue,
        bearer: Option<&'a str>,
    ) -> BoxFuture<'a, Result<HttpReply, AuthError>> {
        let content = body.to_string();
        Box::pin(
            async move { Self::send("POST", url, Some(("application/json", content)), bearer) },
        )
    }

    fn delete<'a>(
        &'a self,
        url: &'a str,
        bearer: &'a str,
    ) -> BoxFuture<'a, Result<HttpReply, AuthError>> {
        Box::pin(async move { Self::send("DELETE", url, None, Some(bearer)) })
    }
}

/// Pressing Sign out unmounts the button, ending the run that made its
/// listener; the revoke, which needs several polls, must survive that.
#[test]
fn the_sign_out_revoke_reaches_the_provider_mock() -> Result<(), String> {
    let mock = MockRevoke::start();
    let store = Arc::new(MemoryStore::new());
    // What an app restart looks like: a persisted session the launcher
    // restores at connect, so the screen offers Sign out.
    store
        .save(
            "mock",
            &Session {
                provider: ProviderId::Mock,
                access_token: "at-signout".to_owned(),
                refresh_token: Some("rt-signout".to_owned()),
                id_token: None,
                expires_at: 0,
                scope: "openid email profile".to_owned(),
            },
        )
        .expect("the session seeds");
    *SIGN_OUT_FIXTURE.lock().expect("the fixture locks") = Some((
        Arc::clone(&store),
        Options {
            mock_url: Some(mock.base.clone()),
            ..Options::default()
        },
    ));

    let mut app = start::<SignedInScreen>()?;
    app.wait_for("Sign out")?;
    assert!(app.screen().shows("Signed in"));
    app.press("Sign out")?;

    let deadline = Instant::now() + REVOKE_WINDOW;
    while mock.count() == 0 {
        assert!(
            Instant::now() < deadline,
            "the sign-out revoke never reached the provider mock"
        );
        thread::sleep(Duration::from_millis(10));
    }
    assert!(
        mock.first_body().contains("token=rt-signout"),
        "revokes the refresh token: {}",
        mock.first_body()
    );
    // The local half stands too: the button goes, the status resets, the
    // store is cleared — and only then can the revoke be observed.
    app.wait_for_gone("Sign out", REVOKE_WINDOW)?;
    assert!(app.screen().shows("Signed out"));
    assert_eq!(store.load("mock").expect("the store reads"), None);
    Ok(())
}

// --- The full mock flow through the selected transport ----------------------
//
// Phase 2 reported (docs/upstream-issues.md): a token flow's ReqwestHttp
// future never progressed under nsh-test-style headless runs. These tests run
// the complete loop — authorize URL, redirect through the real loopback
// callback server, exchange, userinfo, session — through the transport
// `--transport` selects, against an in-test loopback mock. On 2026-11-07 the
// reqwest leg of the loop completes here, so the stall does not reproduce
// under this harness; the reqwest test stands as the probe that fails the
// deadline if it ever comes back. Loopback only: every URL is 127.0.0.1,
// nothing real is ever contacted.

/// Generous because the machine may be busy; a working loop lands in
/// milliseconds.
const FLOW_WINDOW: Duration = Duration::from_secs(30);

/// One request the mock provider saw.
#[derive(Clone)]
struct RecordedRequest {
    method: String,
    path: String,
    query: String,
    authorization: Option<String>,
    body: String,
}

/// The loopback stand-in for the mock provider: the authorize, token,
/// userinfo and revoke endpoints in the provider shapes the crate expects,
/// plus the recordings the wire assertions read back.
struct MockProvider {
    base: String,
    requests: Arc<Mutex<Vec<RecordedRequest>>>,
}

impl MockProvider {
    fn start() -> Self {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("the mock provider binds");
        let port = listener.local_addr().expect("the mock address").port();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let recorded = Arc::clone(&requests);
        thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { break };
                let recorded = Arc::clone(&recorded);
                thread::spawn(move || serve_mock(&mut stream, &recorded));
            }
        });
        Self {
            base: format!("http://127.0.0.1:{port}"),
            requests,
        }
    }

    fn requests(&self) -> Vec<RecordedRequest> {
        self.requests
            .lock()
            .expect("the mock recordings lock")
            .clone()
    }
}

fn serve_mock(stream: &mut TcpStream, recorded: &Mutex<Vec<RecordedRequest>>) {
    let Some(request) = read_mock_request(stream) else {
        return;
    };
    recorded
        .lock()
        .expect("the mock recordings lock")
        .push(request.clone());
    let header = |name: &str| {
        request
            .authorization
            .as_deref()
            .filter(|_| name == "authorization")
            .map(str::to_owned)
    };
    match (request.method.as_str(), request.path.as_str()) {
        // The provider leg of the browser round trip: echo `state`, send the
        // code back to the registered redirect, as a real provider would.
        ("GET", "/mock/authorize") => {
            let state = query_param(&request.query, "state").unwrap_or_default();
            let redirect_uri = query_param(&request.query, "redirect_uri")
                .map(|value| percent_decode(&value))
                .unwrap_or_default();
            let location = format!("{redirect_uri}?code=sandbox-code&state={state}");
            mock_respond(stream, "302 Found", &[("Location", location)], "");
        }
        ("POST", "/mock/token") => mock_respond(
            stream,
            "200 OK",
            &[],
            r#"{"access_token":"at-nsh-http","refresh_token":"rt-nsh-http","expires_in":3600,"scope":"openid profile email"}"#,
        ),
        ("GET", "/mock/userinfo") => {
            if header("authorization").as_deref() == Some("Bearer at-nsh-http") {
                mock_respond(
                    stream,
                    "200 OK",
                    &[],
                    r#"{"sub":"user-sandbox","name":"Sandbox User","email":"sandbox.user@test.invalid","email_verified":true}"#,
                );
            } else {
                mock_respond(stream, "401 Unauthorized", &[], r#"{"error":"no bearer"}"#);
            }
        }
        ("POST", "/mock/revoke") => mock_respond(stream, "200 OK", &[], "{}"),
        _ => mock_respond(stream, "404 Not Found", &[], r#"{"error":"no endpoint"}"#),
    }
}

fn mock_respond(stream: &mut TcpStream, status: &str, headers: &[(&str, String)], body: &str) {
    let mut response = format!("HTTP/1.1 {status}\r\n");
    for (name, value) in headers {
        response.push_str(&format!("{name}: {value}\r\n"));
    }
    response.push_str(&format!(
        "Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    ));
    let _ = stream.write_all(response.as_bytes());
}

fn read_mock_request(stream: &mut TcpStream) -> Option<RecordedRequest> {
    let mut buf = Vec::new();
    let mut chunk = [0_u8; 4096];
    let header_end = loop {
        let read = stream.read(&mut chunk).ok()?;
        if read == 0 {
            return None;
        }
        buf.extend_from_slice(&chunk[..read]);
        if let Some(pos) = buf.windows(4).position(|window| window == b"\r\n\r\n") {
            break pos;
        }
    };
    let head = String::from_utf8_lossy(&buf[..header_end]).to_ascii_lowercase();
    let length = head
        .lines()
        .find_map(|line| line.strip_prefix("content-length:"))
        .and_then(|value| value.trim().parse().ok())
        .unwrap_or(0);
    while buf.len() < header_end + 4 + length {
        let read = stream.read(&mut chunk).ok()?;
        if read == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..read]);
    }
    let text = String::from_utf8_lossy(&buf).into_owned();
    let request_line = text[..header_end].lines().next()?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next()?.to_owned();
    let target = parts.next()?;
    let (path, query) = match target.split_once('?') {
        Some((path, query)) => (path.to_owned(), query.to_owned()),
        None => (target.to_owned(), String::new()),
    };
    // The header NAME is matched case-insensitively; the VALUE keeps its
    // case — "Bearer" must not read back as "bearer".
    let authorization = text[..header_end].lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.trim()
            .eq_ignore_ascii_case("authorization")
            .then(|| value.trim().to_owned())
    });
    Some(RecordedRequest {
        method,
        path,
        query,
        authorization,
        body: text[header_end + 4..].to_owned(),
    })
}

/// The first `name` pair of a raw query string, percent-encoded as received.
fn query_param(query: &str, name: &str) -> Option<String> {
    query
        .split('&')
        .find_map(|pair| pair.split_once('=').filter(|(key, _)| *key == name))
        .map(|(_, value)| value.to_owned())
}

/// Form-urlencoded decoding: `%XX` and `+`, which is how the crate
/// serializes the authorize URL's query.
fn percent_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'+' => {
                out.push(b' ');
                index += 1;
            }
            b'%' if index + 2 < bytes.len() => {
                let hex = std::str::from_utf8(&bytes[index + 1..index + 3])
                    .ok()
                    .and_then(|hex| u8::from_str_radix(hex, 16).ok());
                match hex {
                    Some(byte) => {
                        out.push(byte);
                        index += 3;
                    }
                    None => {
                        out.push(b'%');
                        index += 1;
                    }
                }
            }
            byte => {
                out.push(byte);
                index += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// One raw loopback response: status, headers, body.
type LoopbackResponse = (u16, Vec<(String, String)>, String);

/// One raw loopback GET: status, headers, body. Refuses anything that is not
/// `http://127.0.0.1:<port>/...` — the test browser reaches loopback only.
fn loopback_get(url: &str) -> Result<LoopbackResponse, String> {
    let rest = url
        .strip_prefix("http://")
        .ok_or_else(|| "the test browser reaches http loopback only".to_owned())?;
    let (authority, path) = rest
        .split_once('/')
        .ok_or_else(|| "no path in the URL".to_owned())?;
    let (host, port) = authority
        .split_once(':')
        .ok_or_else(|| "no port in the URL".to_owned())?;
    if host != "127.0.0.1" {
        return Err(format!("the test browser refuses non-loopback host {host}"));
    }
    let port = port.parse::<u16>().map_err(|error| error.to_string())?;
    let mut stream = TcpStream::connect((host, port)).map_err(|error| error.to_string())?;
    let request = format!("GET /{path} HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\n\r\n");
    stream
        .write_all(request.as_bytes())
        .map_err(|error| error.to_string())?;
    let mut response = String::new();
    stream
        .read_to_string(&mut response)
        .map_err(|error| error.to_string())?;
    let mut lines = response.lines();
    let status_line = lines.next().ok_or("no status line")?;
    let status = status_line
        .split(' ')
        .nth(1)
        .and_then(|code| code.parse().ok())
        .ok_or_else(|| format!("malformed status line: {status_line}"))?;
    let mut headers = Vec::new();
    for line in lines {
        if line.is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            headers.push((name.trim().to_owned(), value.trim().to_owned()));
        }
    }
    let body = response
        .split_once("\r\n\r\n")
        .map(|(_, body)| body.to_owned())
        .unwrap_or_default();
    Ok((status, headers, body))
}

/// Plays the browser: GET the authorize URL and follow its redirect to the
/// loopback callback. The only stand-in for the system browser — everything
/// after it is the launcher's real flow.
fn browser_opener() -> Opener {
    Arc::new(|url: &str| {
        let (status, headers, _body) = loopback_get(url)?;
        if !(300..400).contains(&status) {
            return Err(format!(
                "the mock authorize returned {status}, not a redirect"
            ));
        }
        let location = headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("location"))
            .map(|(_, value)| value.clone())
            .ok_or_else(|| "no Location header on the redirect".to_owned())?;
        let (status, _headers, _body) = loopback_get(&location)?;
        if status != 200 {
            return Err(format!("the callback leg returned {status}"));
        }
        Ok(())
    })
}

/// The store and options the flow screens' launchers are built from, armed
/// by each test before the engine starts (the component runs elsewhere).
#[derive(Clone)]
struct FlowFixture {
    store: Arc<MemoryStore>,
    options: Options,
}

static FLOW_NSH_FIXTURE: Mutex<Option<FlowFixture>> = Mutex::new(None);
static FLOW_REQWEST_FIXTURE: Mutex<Option<FlowFixture>> = Mutex::new(None);

fn arm_flow(
    cell: &'static Mutex<Option<FlowFixture>>,
    transport: TransportKind,
) -> (MockProvider, Arc<MemoryStore>) {
    let mock = MockProvider::start();
    let store = Arc::new(MemoryStore::new());
    *cell.lock().expect("the fixture locks") = Some(FlowFixture {
        store: Arc::clone(&store),
        options: Options {
            mock_url: Some(mock.base.clone()),
            transport,
            ..Options::default()
        },
    });
    (mock, store)
}

fn flow_screen(cell: &'static Mutex<Option<FlowFixture>>) -> impl IntoElement {
    let fixture = cell
        .lock()
        .expect("the fixture locks")
        .clone()
        .expect("the flow fixture is armed");
    let mut launcher =
        Launcher::connect_with(fixture.store, &fixture.options).expect("the flow launcher starts");
    launcher.opener = browser_opener();
    launcher_screen(launcher)
}

#[component]
fn NshFlowScreen() -> impl IntoElement {
    flow_screen(&FLOW_NSH_FIXTURE)
}

#[component]
fn ReqwestFlowScreen() -> impl IntoElement {
    flow_screen(&FLOW_REQWEST_FIXTURE)
}

/// The engine runs with a real network stack behind the platform fetch, so
/// the exchange reaches the loopback mock; every URL the flow builds is
/// 127.0.0.1.
fn start_with_loopback_network<C: Component>() -> Result<Headless, String>
where
    C::Props: Default,
{
    let mut config = EngineConfig::new(Root::of::<C>());
    config.network = Some(Arc::new(UreqNetwork::new()));
    Headless::start(config).map_err(|error| error.to_string())
}

fn flow_requests(mock: &MockProvider, path: &str) -> Vec<RecordedRequest> {
    mock.requests()
        .into_iter()
        .filter(|request| request.path == path)
        .collect()
}

/// THE regression test for the phase-2 finding: the full mock flow —
/// authorize, exchange, userinfo, session — completes through the platform
/// transport inside the headless engine, where ReqwestHttp's future stalls.
#[test]
fn the_mock_flow_completes_through_the_platform_transport() -> Result<(), String> {
    let _ = env_logger::try_init();
    let (mock, store) = arm_flow(&FLOW_NSH_FIXTURE, TransportKind::Nsh);
    let mut app = start_with_loopback_network::<NshFlowScreen>()?;
    app.wait_for("Mock provider")?;
    app.press("Mock provider")?;

    app.wait_for_within("Signed in", FLOW_WINDOW)
        .map_err(|error| {
            format!(
                "the exchange did not complete: {error}; screen: {:?}; mock saw: {:?}",
                app.screen().texts(),
                mock.requests()
                    .iter()
                    .map(|request| &request.path)
                    .collect::<Vec<_>>()
            )
        })?;

    // The wire: the exchange POSTed the code with PKCE, and userinfo rode on
    // the exchanged access token.
    let token_posts = flow_requests(&mock, "/mock/token");
    let body = token_posts
        .first()
        .map(|request| request.body.clone())
        .unwrap_or_default();
    assert!(body.contains("grant_type=authorization_code"), "{body}");
    assert!(body.contains("code=sandbox-code"), "{body}");
    assert!(
        body.contains("code_verifier="),
        "PKCE verifier sent: {body}"
    );
    assert!(body.contains("client_id=nsh-auth-sandbox-client"), "{body}");
    assert!(
        body.contains("redirect_uri=http%3A%2F%2F127.0.0.1%3A"),
        "{body}"
    );
    let userinfos = flow_requests(&mock, "/mock/userinfo");
    assert_eq!(userinfos.len(), 1, "userinfo fetched once");
    assert_eq!(
        userinfos[0].authorization.as_deref(),
        Some("Bearer at-nsh-http")
    );

    // The outcome: session restored to the screen and the store, tokens kept
    // off the screen.
    assert!(
        app.screen()
            .texts()
            .iter()
            .any(|text| text.contains("Sandbox User")),
        "the user identity shows: {:?}",
        app.screen().texts()
    );
    assert!(
        !app.screen()
            .texts()
            .iter()
            .any(|text| text.contains("at-nsh-http")),
        "tokens never reach the screen: {:?}",
        app.screen().texts()
    );
    let session = store
        .load("mock")
        .expect("the store reads")
        .expect("the session persisted");
    assert_eq!(session.provider, ProviderId::Mock);
    assert_eq!(session.access_token, "at-nsh-http");
    assert_eq!(session.scope, "openid profile email");
    Ok(())
}

/// The `--transport reqwest` escape hatch kept working: the same full loop
/// as the platform-transport test, on the crate's reqwest client. It doubles
/// as the phase-2 stall probe — that finding was reqwest's future never
/// progressing inside the engine-spawned flow task, which would fail this
/// deadline (seen in phase 2's own runs; not reproduced here on 2026-11-07).
#[test]
fn the_reqwest_escape_hatch_also_completes_the_mock_flow() -> Result<(), String> {
    let _ = env_logger::try_init();
    let (mock, store) = arm_flow(&FLOW_REQWEST_FIXTURE, TransportKind::Reqwest);
    let mut app = start_with_loopback_network::<ReqwestFlowScreen>()?;
    app.wait_for("Mock provider")?;
    app.press("Mock provider")?;
    app.wait_for_within("Signed in", FLOW_WINDOW)
        .map_err(|error| {
            format!(
                "the exchange did not complete under ReqwestHttp within {FLOW_WINDOW:?} \
             (the phase-2 stall?): {error}; mock saw: {:?}",
                mock.requests()
                    .iter()
                    .map(|request| &request.path)
                    .collect::<Vec<_>>()
            )
        })?;
    // A pass must be a full loop, not a lucky frame: the exchange and
    // userinfo hit the mock and the session persisted.
    let session = store
        .load("mock")
        .expect("the store reads")
        .expect("the session persisted under reqwest");
    assert_eq!(session.access_token, "at-nsh-http");
    assert_eq!(flow_requests(&mock, "/mock/token").len(), 1);
    assert_eq!(flow_requests(&mock, "/mock/userinfo").len(), 1);
    Ok(())
}
