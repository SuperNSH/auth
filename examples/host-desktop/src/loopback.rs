//! The loopback callback server: binds 127.0.0.1 on an OS-assigned port and
//! hands the first valid `/callback` request of a sign-in to that flow.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
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
}

impl CallbackServer {
    /// Binds and starts the accept thread, which lives for the app run; the
    /// process owns the listener, so nothing needs to stop it by hand.
    pub(crate) fn bind() -> std::io::Result<Arc<Self>> {
        // Port 0: the OS assigns a free port, and the redirect URI must
        // carry the one actually bound.
        let listener = TcpListener::bind(("127.0.0.1", 0))?;
        let port = listener.local_addr()?.port();
        let server = Arc::new(Self {
            port,
            registration: Mutex::new(None),
        });
        let loop_server = Arc::clone(&server);
        std::thread::Builder::new()
            .name("nsh-auth-callback".to_owned())
            .spawn(move || accept_loop(listener, loop_server))?;
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

    fn lock(&self) -> std::sync::MutexGuard<'_, Option<mpsc::Sender<String>>> {
        self.registration
            .lock()
            .expect("callback registration mutex is not poisoned")
    }
}

fn accept_loop(listener: TcpListener, server: Arc<CallbackServer>) {
    for stream in listener.incoming() {
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
        let server = CallbackServer::bind().expect("bind");
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
        let server = CallbackServer::bind().expect("bind");
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
}
