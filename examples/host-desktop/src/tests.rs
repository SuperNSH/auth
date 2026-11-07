//! Headless checks of the launcher screen: it renders, the loopback origin
//! is shown, and a bad `--provider` value is reported instead of opened.
//! No test presses a provider button — that would open a real browser.

use std::sync::Arc;

use nsh_auth::MemoryStore;
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
