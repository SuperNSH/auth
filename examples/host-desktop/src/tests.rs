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
use nsh_testing::Headless;

use crate::flow::Launcher;
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
