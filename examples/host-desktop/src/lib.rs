//! The nsh-auth desktop launcher: a sign-in screen over the system browser
//! and a 127.0.0.1 loopback callback. `nsh.json` `"root"` names [`App`].

mod browser;
mod flow;
mod loopback;
mod nsh_http_transport;
mod options;
mod session_store;
mod ui;

#[cfg(test)]
mod tests;

pub use flow::print_authorize_url;
pub use options::{Options, USAGE};

use nsh_base::theme;
use nsh_core::prelude::*;

use crate::flow::{Launcher, sign_in};

/// The app's UI set (`nsh.json` `"rust"`): what `nsh run` mounts and `cargo
/// run` starts.
#[native_module("host-desktop/native")]
fn native(registry: &mut Registry) {
    registry.register::<App>();
}

/// The root: connect once (loopback bind + the crate's `Auth`), then the one
/// screen. A `--provider <id>` argument starts that flow as the window opens.
#[component]
pub fn App() -> impl IntoElement {
    match Launcher::connect() {
        Ok(launcher) => {
            if let Some(provider) = launcher.startup_provider {
                sign_in(&launcher, provider);
            }
            view()
                .flex_1()
                .bg(move || theme().background)
                .text_color(move || theme().foreground)
                .child(ui::launcher_screen(launcher))
                .into_element()
        }
        Err(message) => start_error(message).into_element(),
    }
}

/// Startup failed before any flow could run: say what and stop here.
fn start_error(message: String) -> impl IntoElement {
    view()
        .flex_1()
        .bg(move || theme().background)
        .text_color(move || theme().destructive)
        .p_6()
        .items_center()
        .justify_center()
        .child(text(message).text_sm())
}
