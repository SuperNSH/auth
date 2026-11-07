//! The sign-in flow and the state the screen binds to. This module is the
//! only one that names the `nsh-auth` API.

use std::sync::Arc;
use std::time::Duration;

use nsh_auth::{
    Auth, AuthConfig, Http, MemoryStore, ProviderId, ReqwestHttp, SessionStore, SystemClock,
};
use nsh_core::prelude::*;

use crate::browser::open_system_browser;
use crate::loopback::CallbackServer;
use crate::options::Options;

/// The sandbox client id: fake on purpose, shared with the core's tests. No
/// real client id is ever registered or embedded here.
const SANDBOX_CLIENT_ID: &str = "nsh-auth-sandbox-client";

/// The browser can sit on a consent screen for a while; past this the
/// launcher stands the flow down instead of leaving the screen disabled.
const FLOW_TIMEOUT: Duration = Duration::from_secs(10 * 60);

pub(crate) struct ProviderRow {
    pub(crate) id: ProviderId,
    pub(crate) label: &'static str,
    pub(crate) tag: Option<&'static str>,
}

pub(crate) static PROVIDERS: [ProviderRow; 5] = [
    ProviderRow {
        id: ProviderId::Google,
        label: "Continue with Google",
        tag: None,
    },
    ProviderRow {
        id: ProviderId::Facebook,
        label: "Continue with Facebook",
        tag: Some("via broker"),
    },
    ProviderRow {
        id: ProviderId::Discord,
        label: "Continue with Discord",
        tag: None,
    },
    ProviderRow {
        id: ProviderId::Github,
        label: "Continue with GitHub",
        tag: Some("via broker"),
    },
    ProviderRow {
        id: ProviderId::Mock,
        label: "Mock provider",
        tag: Some("local"),
    },
];

/// Apple, Microsoft and X are omitted: their desktop flows are not loopback
/// ones (Apple redirects by form post), so they are not offered here.
pub(crate) fn parse_provider(name: &str) -> Option<ProviderId> {
    match name {
        "google" => Some(ProviderId::Google),
        "facebook" => Some(ProviderId::Facebook),
        "discord" => Some(ProviderId::Discord),
        "github" => Some(ProviderId::Github),
        "mock" => Some(ProviderId::Mock),
        _ => None,
    }
}

/// Everything the screen binds to. `Clone` so closures capture it cheaply.
#[derive(Clone)]
pub(crate) struct Launcher {
    pub(crate) auth: Arc<Auth>,
    pub(crate) server: Option<Arc<CallbackServer>>,
    pub(crate) session: Signal<Option<nsh_auth::Session>>,
    pub(crate) user: Signal<Option<nsh_auth::UserInfo>>,
    pub(crate) status: Signal<nsh_auth::AuthStatus>,
    pub(crate) error: Signal<Option<nsh_auth::AuthError>>,
    pub(crate) active: Signal<bool>,
    pub(crate) local_error: Signal<Option<SharedString>>,
    pub(crate) redirect_origin: SharedString,
    pub(crate) startup_provider: Option<ProviderId>,
    generation: Stored<u64>,
    /// The flow's handles: the watchdog cancels the work through them and a
    /// new flow cancels the abandoned one. (A dropped `Spawned` does not
    /// cancel: `spawn` detaches its tasks.)
    pending: Stored<Option<Spawned<()>>>,
    watchdog: Stored<Option<Spawned<()>>>,
    /// The in-flight sign-out, kept alongside them. Its task is rooted on
    /// `owner`, not on the button's run, so it survives the button going.
    sign_out_task: Stored<Option<Spawned<()>>>,
    /// The launcher's own root owner (`create_root`): fire-and-forget work
    /// is rooted here so it outlives the run that made the control.
    owner: Owner,
}

impl Launcher {
    /// The launcher the app runs with: sessions persisted in the store the
    /// command line chose — OS credential store by default on macOS and
    /// Windows, 0600 JSON files otherwise. The active store is logged here,
    /// so a fallback is visible in the proof log.
    pub(crate) fn connect() -> Result<Self, String> {
        let options = Options::from_env();
        let (store, store_note) = crate::session_store::select(&options)?;
        log::info!("{store_note}");
        Self::connect_with(store, &options)
    }

    /// `store` and `options` are injected so tests run on `MemoryStore` with
    /// no filesystem and no command line.
    pub(crate) fn connect_with(
        store: Arc<dyn SessionStore>,
        options: &Options,
    ) -> Result<Self, String> {
        let http = Arc::new(ReqwestHttp::new().map_err(|error| error.to_string())?);
        Self::connect_with_http(store, http, options)
    }

    /// `http` is injected too so tests run on an in-process transport; the
    /// app itself always runs on reqwest.
    pub(crate) fn connect_with_http(
        store: Arc<dyn SessionStore>,
        http: Arc<dyn Http>,
        options: &Options,
    ) -> Result<Self, String> {
        let (server, redirect, bind_error) = match CallbackServer::bind(options.redirect_port) {
            Ok(server) => {
                let redirect = server.redirect_uri();
                (Some(server), redirect, None)
            }
            Err(error) => (
                None,
                "http://127.0.0.1:0/callback".to_owned(),
                Some(SharedString::from(crate::loopback::bind_error(
                    options.redirect_port,
                    &error,
                ))),
            ),
        };
        // Runs where a reactive runtime is entered: the caller is a component
        // body (or a test's headless component). Dropping the owner handle
        // does not dispose the root — only `Owner::dispose` would — so the
        // signals live past this function, which is what the app wants.
        let (owner, auth) = nsh_core::element::create_root(|| {
            let first = build_config(PROVIDERS[0].id, &redirect, options);
            let auth = Auth::new(first, store, Arc::new(SystemClock), http);
            for row in PROVIDERS.iter().skip(1) {
                auth.register(build_config(row.id, &redirect, options));
            }
            auth
        });
        // A persisted session from an earlier run comes back as the window
        // opens; the user identity refills at the next sign-in.
        for row in &PROVIDERS {
            match auth.restore(row.id) {
                Ok(Some(session)) => {
                    log::info!(
                        "restored a {} session from storage",
                        session.provider.as_str()
                    )
                }
                Ok(None) => {}
                Err(error) => log::info!("restoring {} failed: {error}", row.id.as_str()),
            }
        }
        let startup_provider = options.provider.as_deref().and_then(parse_provider);
        let unknown = match (options.provider.as_deref(), startup_provider) {
            (Some(name), None) => Some(SharedString::from(format!(
                "Unknown provider \"{name}\". Try google, facebook, discord, github or mock."
            ))),
            _ => None,
        };
        let launcher = Self {
            session: auth.session,
            user: auth.user,
            status: auth.status,
            error: auth.error,
            auth: Arc::new(auth),
            server,
            active: signal(false),
            local_error: signal(None),
            redirect_origin: redirect.into(),
            startup_provider,
            generation: stored(0_u64),
            pending: stored(None),
            watchdog: stored(None),
            sign_out_task: stored(None),
            owner,
        };
        let initial_error = unknown.or(bind_error);
        if let Some(message) = initial_error {
            launcher.local_error.set(Some(message));
        }
        Ok(launcher)
    }
}

/// One provider's config: the crate fills the endpoints, scopes and
/// PKCE/nonce rules; the launcher adds the loopback redirect of this run,
/// the sandbox client id, and the broker seam for confidential providers
/// (their code exchange needs a secret, which lives on the broker process,
/// never in this app).
///
/// The mock is the one provider with no endpoints of its own: they come from
/// the mock server's route table (`tools/mock-oauth/README.md`), `--mock-url`
/// replaces the base.
fn build_config(provider: ProviderId, redirect_uri: &str, options: &Options) -> AuthConfig {
    let mut config = AuthConfig::for_provider(provider)
        .client_id(SANDBOX_CLIENT_ID)
        .redirect_uri(redirect_uri.to_owned());
    if provider.confidential() {
        config.broker_url = Some(options.broker_url.clone());
    }
    if provider == ProviderId::Mock {
        let base = options
            .mock_url
            .as_deref()
            .unwrap_or("http://127.0.0.1:8755")
            .trim_end_matches('/')
            .to_owned();
        config.auth_url = format!("{base}/mock/authorize");
        config.token_url = format!("{base}/mock/token");
        config.userinfo_url = Some(format!("{base}/mock/userinfo"));
        config.revoke_url = Some(format!("{base}/mock/revoke"));
        config.jwks_url = Some(format!("{base}/mock/.well-known/jwks.json"));
    }
    config
}

/// The authorize URL as the log may show it: `state` and `nonce` are
/// anti-CSRF secrets, so their values are replaced; every other pair is
/// proof and stays verbatim.
fn redacted_url(url: &str) -> String {
    let Some((base, query)) = url.split_once('?') else {
        return url.to_owned();
    };
    let pairs: Vec<String> = query
        .split('&')
        .map(|pair| match pair.split_once('=') {
            Some(("state", _)) | Some(("nonce", _)) => {
                let (key, _) = pair.split_once('=').expect("checked above");
                format!("{key}=<redacted>")
            }
            _ => pair.to_owned(),
        })
        .collect();
    format!("{base}?{}", pairs.join("&"))
}

/// Starts a sign-in: build the authorize URL with the crate, open the system
/// browser at it, and wait once on the loopback server for the redirect.
pub(crate) fn sign_in(launcher: &Launcher, provider: ProviderId) {
    if launcher.active.get_untracked() {
        return;
    }
    let Some(server) = launcher.server.as_ref() else {
        return;
    };
    launcher.local_error.set(None);
    launcher.active.set(true);
    let attempt = launcher.generation.with(|generation| {
        *generation += 1;
        *generation
    });
    let receiver = server.register();
    // Built by the crate (PKCE, state, nonce). The log keeps the URL with the
    // `state` and `nonce` values redacted — they are anti-CSRF secrets, and
    // stderr can end up in a shared file. The exact URL is what
    // `--print-urls` puts on stdout and what the browser carries.
    let request = match launcher.auth.authorize_request(provider) {
        Ok(request) => request,
        Err(error) => {
            launcher
                .local_error
                .set(Some(SharedString::from(error.to_string())));
            launcher.active.set(false);
            return;
        }
    };
    log::info!("authorize {provider:?} -> {}", redacted_url(&request.url));

    let auth = Arc::clone(&launcher.auth);
    let active = launcher.active;
    let local_error = launcher.local_error;
    let generation = launcher.generation;
    let flow_server = Arc::clone(server);
    let origin = launcher.redirect_origin.clone();
    let pending = launcher.pending;
    let watchdog = launcher.watchdog;
    // A leftover from an ended flow is finished; from an abandoned one it is
    // cancelled here either way, together with its no-longer-wanted watchdog.
    if let Some(previous) = pending.replace(None) {
        previous.cancel();
    }
    if let Some(previous) = watchdog.replace(None) {
        previous.cancel();
    }
    let task = spawn(async move {
        let opened = blocking(move || open_system_browser(&request.url)).await;
        let opened = opened.unwrap_or_else(|error| Err(error.to_string()));
        if let Err(message) = opened {
            local_error.set(Some(SharedString::from(format!(
                "Couldn't open the browser: {message}. The authorize URL is in the log."
            ))));
            flow_server.clear();
            active.set(false);
            return;
        }
        log::info!("browser opened; waiting for the callback on {origin}");
        // One use: this receiver gets exactly one URL, then the registration
        // is spent and later connections find nothing pending.
        let callback = blocking(move || receiver.recv()).await;
        let callback_url = match callback {
            Ok(Ok(url)) => url,
            Ok(Err(_)) | Err(_) => {
                active.set(false);
                return;
            }
        };
        // A callback in hand ends the waiting window: the watchdog stands
        // down and a late duplicate finds no registration.
        generation.with(|generation| *generation += 1);
        flow_server.clear();
        log::info!("callback received on {origin}; completing the {provider:?} flow");
        match auth.complete(provider, &callback_url).await {
            Ok(session) => log::info!("{provider:?} sign-in complete (scope: {})", session.scope),
            Err(error) => log::info!("{provider:?} sign-in failed: {error}"),
        }
        active.set(false);
    });
    // Held, not dropped: a dropped `Task` cancels, which would kill both the
    // flow and its timeout before either ran.
    pending.replace(Some(task));
    let timeout_server = Arc::clone(server);
    watchdog.replace(Some(set_timeout(FLOW_TIMEOUT, move || {
        // Only the flow this watchdog was set for; a newer one re-armed it.
        if generation.with(|generation| *generation) == attempt && active.get_untracked() {
            timeout_server.clear();
            if let Some(task) = pending.replace(None) {
                task.cancel();
            }
            active.set(false);
            log::info!("sign-in timed out; no callback within 10 minutes");
        }
    })));
}

pub(crate) fn sign_out(launcher: &Launcher) {
    let auth = Arc::clone(&launcher.auth);
    // Rooted on the launcher's owner: the press unmounts the button, whose
    // run owns the task — rooted there it dies before the revoke's last poll.
    let task = launcher.owner.run(|| {
        spawn(async move {
            match auth.sign_out().await {
                Ok(()) => log::info!("signed out"),
                Err(error) => log::info!("sign-out failed: {error}"),
            }
        })
    });
    launcher.sign_out_task.replace(Some(task));
}

/// `--print-urls`: build the flow's authorize URL and print exactly it on
/// stdout. No listener wait, no browser, no storage side effects.
///
/// Runs with no app around it, so the reactive runtime is entered here —
/// `Auth::new` makes signals and needs one.
pub fn print_authorize_url(options: &Options) -> std::process::ExitCode {
    let Some(provider) = options.provider.as_deref().and_then(parse_provider) else {
        eprintln!("--print-urls needs --provider google|facebook|discord|github|mock");
        return std::process::ExitCode::FAILURE;
    };
    // `MemoryStore`: the URL is printed, never completed, so nothing lands
    // on disk from a proof run.
    let server = match CallbackServer::bind(options.redirect_port) {
        Ok(server) => server,
        Err(error) => {
            eprintln!(
                "{}",
                crate::loopback::bind_error(options.redirect_port, &error)
            );
            return std::process::ExitCode::FAILURE;
        }
    };
    let http = match ReqwestHttp::new() {
        Ok(http) => http,
        Err(error) => {
            eprintln!("{error}");
            return std::process::ExitCode::FAILURE;
        }
    };
    let runtime = nsh_core::element::reactive::Runtime::default();
    let _entered = runtime.enter();
    let (_owner, request) = nsh_core::element::create_root(|| {
        let auth = Auth::new(
            build_config(provider, &server.redirect_uri(), options),
            Arc::new(MemoryStore::new()),
            Arc::new(SystemClock),
            Arc::new(http),
        );
        auth.authorize_request(provider)
    });
    // The redirect URI was all the listener was needed for; stop its accept
    // thread instead of leaving it until process exit, and let a pinned
    // `--redirect-port` become reusable at once. Best effort only: a client
    // mid-read can hold the loop for its remaining read timeout.
    server.cancel();
    let _ = server.wait_closed(Duration::from_secs(1));
    match request {
        Ok(request) => {
            println!("{}", request.url);
            std::process::ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("{error}");
            std::process::ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::redacted_url;

    /// The shape of a real launcher URL: everything except the two secret
    /// values must survive the log verbatim.
    #[test]
    fn the_log_redacts_state_and_nonce_but_keeps_the_rest() {
        let url = "https://accounts.google.com/o/oauth2/v2/auth?response_type=code&client_id=nsh-auth-sandbox-client&redirect_uri=http%3A%2F%2F127.0.0.1%3A63333%2Fcallback&scope=openid+email+profile&state=S3CRET&nonce=N3CRET&code_challenge=CH4LLENGE&code_challenge_method=S256";
        let logged = redacted_url(url);
        assert!(logged.contains("state=<redacted>"), "{logged}");
        assert!(logged.contains("nonce=<redacted>"), "{logged}");
        assert!(!logged.contains("S3CRET"), "{logged}");
        assert!(!logged.contains("N3CRET"), "{logged}");
        assert!(logged.contains("code_challenge=CH4LLENGE"), "{logged}");
        assert!(logged.contains("scope=openid+email+profile"), "{logged}");
        assert!(
            logged.starts_with("https://accounts.google.com/o/oauth2/v2/auth?"),
            "{logged}"
        );
    }

    #[test]
    fn a_url_without_a_query_is_logged_unchanged() {
        assert_eq!(
            redacted_url("https://accounts.google.com/o/oauth2/v2/auth"),
            "https://accounts.google.com/o/oauth2/v2/auth"
        );
    }
}
