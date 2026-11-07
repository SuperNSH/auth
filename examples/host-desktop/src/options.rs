//! The launcher's command line, parsed once and shared by `main.rs` and the
//! app root. Plain Rust, no NSH, so tests build values directly.

pub const USAGE: &str = "nsh-auth desktop launcher

Usage: cargo run -p host-desktop -- [options]

  --provider <id>        Start sign-in for google|facebook|discord|github|mock.
  --print-urls           Print the provider's authorize URL on stdout and exit.
  --mock-url <url>       Base URL of the local mock provider
                         (default http://127.0.0.1:8755).
  --broker-url <url>     Base URL of the token broker for confidential clients
                         (default http://127.0.0.1:8756).
  --store <json|keyring> Where sessions live. `keyring` is the OS credential
                         store (Keychain, Credential Manager) and the default
                         on macOS and Windows; `json` is the 0600 files under
                         ~/.nsh-auth-desktop and the default on Linux.
  --redirect-port <port> Pin the loopback callback port instead of an
                         OS-assigned one, for providers that require an exact
                         registered port.
  -h, --help             Show this help.";

#[derive(Clone)]
pub struct Options {
    /// `--provider <id>`: the flow the window starts on launch, if it names
    /// one this launcher offers.
    pub provider: Option<String>,
    /// Base URL the mock provider is reached at when the crate's catalog
    /// default is not the one in use.
    pub mock_url: Option<String>,
    /// The token broker that confidential providers (GitHub) exchange
    /// through; no client secret ever lives in this app.
    pub broker_url: String,
    /// `--store <json|keyring>`: which store backs sessions; `None` asks for
    /// the per-OS default. `pub(crate)`: `StoreKind` is an internal type.
    pub(crate) store: Option<crate::session_store::StoreKind>,
    /// `--redirect-port <port>`: pin the loopback callback port; `None`
    /// binds an OS-assigned port.
    pub redirect_port: Option<u16>,
    /// `--print-urls`: print one authorize URL on stdout and exit.
    pub print_urls: bool,
    pub help: bool,
    /// A known flag lost its value, or nothing usable was given at all.
    pub invalid: bool,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            provider: None,
            mock_url: None,
            broker_url: "http://127.0.0.1:8756".to_owned(),
            store: None,
            redirect_port: None,
            print_urls: false,
            help: false,
            invalid: false,
        }
    }
}

impl Options {
    /// Unknown flags are warned about and ignored so `nsh run` can hand the
    /// binary its own arguments; a value-less known flag is a mistake.
    pub fn from_env() -> Self {
        Self::from_args(
            std::env::args_os()
                .skip(1)
                .map(|arg| arg.to_string_lossy().into_owned()),
        )
    }

    /// The parser over any argument stream, so tests run it without a
    /// process command line.
    pub fn from_args(args: impl Iterator<Item = String>) -> Self {
        let mut options = Self::default();
        let mut args = args;
        while let Some(arg) = args.next() {
            let slot = match arg.as_str() {
                "--provider" => Some(0),
                "--mock-url" => Some(1),
                "--broker-url" => Some(2),
                "--store" => Some(3),
                "--redirect-port" => Some(4),
                "--print-urls" => {
                    options.print_urls = true;
                    None
                }
                "--help" | "-h" => {
                    options.help = true;
                    None
                }
                other => {
                    eprintln!("nsh-auth desktop: ignoring unknown argument `{other}`");
                    None
                }
            };
            if let Some(slot) = slot {
                match args.next() {
                    Some(value) if !value.starts_with("--") => match slot {
                        0 => options.provider = Some(value),
                        1 => options.mock_url = Some(value),
                        2 => options.broker_url = value,
                        3 => match crate::session_store::parse_store(&value) {
                            Some(kind) => options.store = Some(kind),
                            None => {
                                eprintln!(
                                    "nsh-auth desktop: `--store` takes json or keyring, not `{value}`"
                                );
                                options.invalid = true;
                            }
                        },
                        _ => match value.parse::<u16>() {
                            Ok(port) if port != 0 => options.redirect_port = Some(port),
                            _ => {
                                eprintln!(
                                    "nsh-auth desktop: `--redirect-port` needs a TCP port between 1 and 65535"
                                );
                                options.invalid = true;
                            }
                        },
                    },
                    _ => {
                        eprintln!("nsh-auth desktop: `{arg}` needs a value");
                        options.invalid = true;
                    }
                }
            }
        }
        options
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::session_store::StoreKind;

    fn args(list: &[&str]) -> Options {
        Options::from_args(list.iter().map(|arg| (*arg).to_owned()))
    }

    #[test]
    fn store_parses_both_kinds_and_defaults_to_none() {
        assert_eq!(args(&["--store", "json"]).store, Some(StoreKind::Json));
        assert_eq!(
            args(&["--store", "keyring"]).store,
            Some(StoreKind::Keyring)
        );
        assert_eq!(args(&[]).store, None);
    }

    #[test]
    fn an_unknown_store_kind_or_a_missing_value_is_invalid() {
        assert!(args(&["--store", "plaintext"]).invalid);
        assert!(args(&["--store"]).invalid);
    }

    #[test]
    fn redirect_port_parses_a_usable_port_only() {
        assert_eq!(
            args(&["--redirect-port", "18089"]).redirect_port,
            Some(18_089)
        );
        // Port 0 is the OS-assigned default; asking for it by name is a typo.
        assert!(args(&["--redirect-port", "0"]).invalid);
        assert!(args(&["--redirect-port", "70000"]).invalid);
        assert!(args(&["--redirect-port", "callback"]).invalid);
        assert!(args(&["--redirect-port"]).invalid);
    }

    #[test]
    fn existing_flags_keep_their_slots() {
        let options = args(&[
            "--provider",
            "mock",
            "--mock-url",
            "http://127.0.0.1:9999",
            "--broker-url",
            "http://127.0.0.1:9998",
            "--print-urls",
        ]);
        assert_eq!(options.provider.as_deref(), Some("mock"));
        assert_eq!(options.mock_url.as_deref(), Some("http://127.0.0.1:9999"));
        assert_eq!(options.broker_url, "http://127.0.0.1:9998");
        assert!(options.print_urls);
        assert!(!options.invalid);
    }
}
