//! The loopback callback server: binds 127.0.0.1 (OS-assigned port unless
//! pinned) and hands the first valid `/callback` request of a sign-in to
//! that flow.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::time::Duration;

const CALLBACK_PATH: &str = "/callback";
/// A silent client must not hold a connection open for long.
const READ_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_REQUEST_BYTES: usize = 8192;

pub(crate) struct CallbackServer {
    port: u16,
    /// The current flow's sender; `None` means no sign-in is waiting, and a
    /// connection then gets a "nothing is pending" page. `take`d on use, so
    /// one registration serves exactly one callback.
    registration: Mutex<Option<mpsc::Sender<String>>>,
    /// Set by `cancel()`; the accept loop checks it after each connection.
    cancelled: AtomicBool,
    /// Signalled when the accept loop has exited and the listener is closed.
    closed_receiver: Mutex<mpsc::Receiver<()>>,
}

impl CallbackServer {
    /// Binds 127.0.0.1. `None` lets the OS assign a free port, which every
    /// loopback provider in `docs/providers.md` accepts; `Some(port)` pins an
    /// exact port for providers that require a pre-registered one (the
    /// fixed-port option of tauri-plugin-oauth 2.1.0, MIT OR Apache-2.0).
    /// Path, method, Host, byte cap and timeout checks apply either way.
    pub(crate) fn bind(fixed_port: Option<u16>) -> std::io::Result<Arc<Self>> {
        let listener = TcpListener::bind(("127.0.0.1", fixed_port.unwrap_or(0)))?;
        let port = listener.local_addr()?.port();
        let (closed_sender, closed_receiver) = mpsc::channel();
        let server = Arc::new(Self {
            port,
            registration: Mutex::new(None),
            cancelled: AtomicBool::new(false),
            closed_receiver: Mutex::new(closed_receiver),
        });
        let loop_server = Arc::clone(&server);
        std::thread::Builder::new()
            .name("nsh-auth-callback".to_owned())
            .spawn(move || {
                accept_loop(listener, loop_server);
                let _ = closed_sender.send(());
            })?;
        Ok(server)
    }

    /// The redirect URI registered for this run, as the providers see it.
    pub(crate) fn redirect_uri(&self) -> String {
        format!("http://127.0.0.1:{port}{CALLBACK_PATH}", port = self.port)
    }

    /// The receiver the current flow waits on.
    pub(crate) fn register(&self) -> mpsc::Receiver<String> {
        let (sender, receiver) = mpsc::channel();
        *self.lock() = Some(sender);
        receiver
    }

    /// Retires the current registration: a callback that arrives now finds
    /// nothing pending and is dropped.
    pub(crate) fn clear(&self) {
        *self.lock() = None;
    }

    /// Stops the accept loop: the flag goes up first, then a connection to
    /// our own listener unblocks the pending `accept` (tauri-plugin-oauth
    /// 2.1.0's `cancel(port)` shutdown, MIT OR Apache-2.0). The loop exits
    /// once the connection being handled returns; the port closes with the
    /// listener. Callbacks arriving after this are refused.
    pub(crate) fn cancel(&self) {
        if self.cancelled.swap(true, Ordering::SeqCst) {
            return;
        }
        // A failed connect means the listener is already gone; the loop sees
        // the flag on its next iteration either way.
        let _ = TcpStream::connect(("127.0.0.1", self.port));
    }

    /// Blocks until the accept loop has exited and the port is closed, or
    /// `timeout` elapses. Hosts and tests await this instead of guessing.
    pub(crate) fn wait_closed(&self, timeout: Duration) -> bool {
        let receiver = self
            .closed_receiver
            .lock()
            .expect("accept-loop signal mutex is not poisoned");
        match receiver.recv_timeout(timeout) {
            Ok(()) => true,
            Err(mpsc::RecvTimeoutError::Disconnected) => true,
            Err(mpsc::RecvTimeoutError::Timeout) => false,
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Option<mpsc::Sender<String>>> {
        self.registration
            .lock()
            .expect("callback registration mutex is not poisoned")
    }
}

/// The human-facing reason a bind failed, distinguishing a pinned
/// `--redirect-port` from the usual OS-assigned bind.
pub(crate) fn bind_error(fixed_port: Option<u16>, error: &std::io::Error) -> String {
    match fixed_port {
        Some(port) => format!(
            "could not bind the callback listener on 127.0.0.1:{port} (--redirect-port): {error}; close whatever holds the port or pick another",
        ),
        None => format!("could not bind a loopback port for the callback listener: {error}"),
    }
}

fn accept_loop(listener: TcpListener, server: Arc<CallbackServer>) {
    for stream in listener.incoming() {
        // The cancel connection is dropped unread; its only job is waking
        // accept so the listener can close.
        if server.cancelled.load(Ordering::SeqCst) {
            break;
        }
        match stream {
            Ok(stream) => handle_connection(stream, &server),
            Err(error) => log::debug!("callback accept failed: {error}"),
        }
    }
}

fn handle_connection(mut stream: TcpStream, server: &CallbackServer) {
    let _ = stream.set_read_timeout(Some(READ_TIMEOUT));
    let mut buffered = Vec::with_capacity(1024);
    let mut chunk = [0_u8; 1024];
    loop {
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                buffered.extend_from_slice(&chunk[..n]);
                if buffered.windows(4).any(|part| part == b"\r\n\r\n")
                    || buffered.len() > MAX_REQUEST_BYTES
                {
                    break;
                }
            }
            Err(_) => return respond(&mut stream, "400 Bad Request", &bad_request()),
        }
    }
    let head = String::from_utf8_lossy(&buffered);
    let Some(request_line) = head.lines().next() else {
        return respond(&mut stream, "400 Bad Request", &bad_request());
    };
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or_default();
    let target = parts.next().unwrap_or_default();
    let path = target.split('?').next().unwrap_or_default();
    // A Host that is not this listener is a rebinding probe, not a browser
    // following the registered redirect.
    let host = format!("host: 127.0.0.1:{}", server.port);
    let host_ok = head.lines().any(|line| line.eq_ignore_ascii_case(&host));
    if method != "GET" {
        respond(&mut stream, "405 Method Not Allowed", &not_found());
    } else if path != CALLBACK_PATH {
        respond(&mut stream, "404 Not Found", &not_found());
    } else if !host_ok {
        respond(&mut stream, "403 Forbidden", &not_found());
    } else {
        // The query string is passed on percent-encoded, as it arrived.
        let callback_url = format!("http://127.0.0.1:{}{target}", server.port);
        let delivered = server
            .lock()
            .take()
            .is_some_and(|sender| sender.send(callback_url).is_ok());
        if delivered {
            respond(&mut stream, "200 OK", &callback_received());
        } else {
            respond(&mut stream, "200 OK", &nothing_pending());
        }
    }
}

fn respond(stream: &mut TcpStream, status: &str, body: &str) {
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len(),
    );
    let _ = stream.write_all(response.as_bytes());
    let _ = stream.flush();
}

fn page(body: &str) -> String {
    format!("<!doctype html><meta charset=\"utf-8\"><title>nsh-auth</title><p>{body}</p>")
}

fn callback_received() -> String {
    page("Sign-in received. You can close this tab and return to the app.")
}

fn nothing_pending() -> String {
    page("No sign-in is waiting for a callback.")
}

fn not_found() -> String {
    page("This server only answers the sign-in callback.")
}

fn bad_request() -> String {
    page("The request could not be read.")
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::io::BufRead;
    use std::io::BufReader;
    use std::net::SocketAddr;

    /// One HTTP exchange against the bound server; returns status, body and
    /// a reader over the rest.
    fn exchange(server: &CallbackServer, request: &str) -> (u16, String) {
        let mut stream = TcpStream::connect(("127.0.0.1", server.port)).expect("connect");
        stream.write_all(request.as_bytes()).expect("write");
        let mut reader = BufReader::new(stream);
        let mut status_line = String::new();
        reader.read_line(&mut status_line).expect("status");
        let status = status_line
            .split_whitespace()
            .nth(1)
            .and_then(|code| code.parse().ok())
            .expect("status code");
        let mut content_length = 0_usize;
        loop {
            let mut line = String::new();
            reader.read_line(&mut line).expect("header");
            let line = line.trim();
            if line.is_empty() {
                break;
            }
            if let Some(length) = line
                .to_ascii_lowercase()
                .strip_prefix("content-length: ")
                .and_then(|length| length.trim().parse().ok())
            {
                content_length = length;
            }
        }
        let mut body = vec![0_u8; content_length];
        reader.read_exact(&mut body).expect("body");
        (status, String::from_utf8_lossy(&body).into_owned())
    }

    fn request(host: &str, target: &str) -> String {
        format!("GET {target} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n")
    }

    #[test]
    fn the_registered_flow_receives_one_callback_url() {
        let server = CallbackServer::bind(None).expect("bind");
        let receiver = server.register();
        let port = server.port;
        let query = "code=sandbox-code&state=sandbox-state";
        let (status, body) = exchange(
            &server,
            &request(&format!("127.0.0.1:{port}"), &format!("/callback?{query}")),
        );
        assert_eq!(status, 200);
        assert!(body.contains("Sign-in received"), "{body}");
        let url = receiver
            .recv_timeout(Duration::from_secs(2))
            .expect("callback URL");
        // The query is handed on percent-encoded, exactly as it arrived.
        assert_eq!(url, format!("http://127.0.0.1:{port}/callback?{query}"));
        // Single use: a second request finds nothing pending.
        let (_status, body) = exchange(
            &server,
            &request(&format!("127.0.0.1:{port}"), "/callback?x=1"),
        );
        assert!(body.contains("No sign-in is waiting"), "{body}");
        assert!(receiver.recv_timeout(Duration::from_millis(200)).is_err());
    }

    #[test]
    fn a_wrong_path_or_host_or_method_is_refused() {
        let server = CallbackServer::bind(None).expect("bind");
        let _receiver = server.register();
        let port = server.port;
        let host = format!("127.0.0.1:{port}");
        let (status, _) = exchange(&server, &request(&host, "/other?code=1"));
        assert_eq!(status, 404);
        // A Host that is not this listener is a rebinding probe.
        let (status, _) = exchange(&server, &request("evil.example.test", "/callback?code=1"));
        assert_eq!(status, 403);
        let (status, _) = exchange(
            &server,
            &format!(
                "POST /callback HTTP/1.1\r\nHost: {host}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            ),
        );
        assert_eq!(status, 405);
    }

    #[test]
    fn cancel_unblocks_the_accept_loop_and_closes_the_port() {
        let server = CallbackServer::bind(None).expect("bind");
        let port = server.port;
        let receiver = server.register();
        // One handled exchange puts the loop back into a blocking accept;
        // that pending accept is what cancel() must wake. No probe
        // connections follow: cancel() itself has to do the unblocking.
        let host = format!("127.0.0.1:{port}");
        let _ = exchange(&server, &request(&host, "/nothing"));
        std::thread::sleep(Duration::from_millis(50));
        server.cancel();
        assert!(
            server.wait_closed(Duration::from_secs(2)),
            "accept loop did not end after cancel()"
        );
        // With the loop gone the listener is dropped: connects are refused.
        let address: SocketAddr = format!("127.0.0.1:{port}").parse().expect("address");
        assert!(
            TcpStream::connect_timeout(&address, Duration::from_millis(500)).is_err(),
            "the port stayed open after cancel()"
        );
        // A cancelled server delivers nothing, not even to a live registration.
        assert!(receiver.recv_timeout(Duration::from_millis(100)).is_err());
    }

    #[test]
    fn a_pinned_port_binds_and_serves_the_callback_on_it() {
        // A port that is free right now, released for the pinned bind.
        let probe = TcpListener::bind(("127.0.0.1", 0)).expect("probe bind");
        let port = probe.local_addr().expect("probe addr").port();
        drop(probe);
        let server = CallbackServer::bind(Some(port)).expect("pinned bind");
        assert_eq!(server.port, port);
        assert!(
            server
                .redirect_uri()
                .ends_with(&format!(":{port}{CALLBACK_PATH}")),
            "{}",
            server.redirect_uri()
        );
        let receiver = server.register();
        let host = format!("127.0.0.1:{port}");
        let (status, body) = exchange(&server, &request(&host, "/callback?code=x&state=y"));
        assert_eq!(status, 200);
        assert!(body.contains("Sign-in received"), "{body}");
        assert_eq!(
            receiver.recv_timeout(Duration::from_secs(2)).expect("url"),
            format!("http://127.0.0.1:{port}/callback?code=x&state=y")
        );
        server.cancel();
    }

    #[test]
    fn a_taken_pinned_port_is_a_clear_error() {
        let holder = TcpListener::bind(("127.0.0.1", 0)).expect("holder bind");
        let port = holder.local_addr().expect("holder addr").port();
        let error = match CallbackServer::bind(Some(port)) {
            Ok(_) => panic!("binding a held port must fail"),
            Err(error) => error,
        };
        let message = bind_error(Some(port), &error);
        assert!(message.contains(&format!("127.0.0.1:{port}")), "{message}");
        assert!(message.contains("--redirect-port"), "{message}");
        assert!(message.contains("already in use"), "{message}");
        // Held only by the test's own listener; released at scope end.
        drop(holder);
    }
}
