//! `cargo run`: `--print-urls` prints one authorize URL; otherwise the app
//! runs on the machine's native backend.

#![cfg_attr(target_os = "windows", windows_subsystem = "windows")]

#[cfg(target_os = "linux")]
use nsh_platform_linux as platform;
#[cfg(target_os = "macos")]
use nsh_platform_macos as platform;
#[cfg(target_os = "windows")]
use nsh_platform_windows as platform;

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn main() -> std::process::ExitCode {
    let options = host_desktop::Options::from_env();
    // Proof logs (the authorize URL, the callback, the outcome) are stderr at
    // info by default; stdout stays clean for `--print-urls`.
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    if options.invalid {
        eprintln!("{}", host_desktop::USAGE);
        return std::process::ExitCode::FAILURE;
    }
    if options.help {
        println!("{}", host_desktop::USAGE);
        return std::process::ExitCode::SUCCESS;
    }
    if options.print_urls {
        return host_desktop::print_authorize_url(&options);
    }
    run_window()
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn run_window() -> std::process::ExitCode {
    let app_id = "dev.nshauth.desktop";
    let theme = nsh_base::Theme::from_json(include_str!("../theme.json"))
        .expect("the launcher theme is valid");
    platform::run_app(
        platform::AppSource::Rust(
            platform::Root::of::<host_desktop::App>()
                .tokens(theme.into_tokens())
                .app_id(app_id),
        ),
        platform::AppOptions {
            title: "nsh-auth desktop".to_owned(),
            #[cfg(any(target_os = "linux", target_os = "windows"))]
            app_id: app_id.to_owned(),
            size: (480, 640),
            ..Default::default()
        },
    )
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
compile_error!("Run this binary on macOS, Windows or Linux.");
