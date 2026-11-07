//! The launcher's command line, parsed once and shared by `main.rs` and the
//! app root. Plain Rust, no NSH, so tests build values directly.

pub const USAGE: &str = "nsh-auth desktop launcher

Usage: cargo run -p host-desktop -- [options]

  --provider <id>     Start sign-in for google|facebook|discord|github|mock.
  --print-urls        Print the provider's authorize URL on stdout and exit.
  --mock-url <url>    Base URL of the local mock provider
                      (default http://127.0.0.1:8755).
  --broker-url <url>  Base URL of the token broker for confidential clients
                      (default http://127.0.0.1:8760).
  -h, --help          Show this help.";

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
            broker_url: "http://127.0.0.1:8760".to_owned(),
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
        let mut options = Self::default();
        let mut args = std::env::args_os()
            .skip(1)
            .map(|arg| arg.to_string_lossy().into_owned());
        while let Some(arg) = args.next() {
            let slot = match arg.as_str() {
                "--provider" => Some(0),
                "--mock-url" => Some(1),
                "--broker-url" => Some(2),
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
                        _ => options.broker_url = value,
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
