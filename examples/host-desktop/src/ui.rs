//! The launcher's screen and its styled controls: an outline button per
//! provider, the crate's status, error and session signals, sign-out.

use nsh_base::{button, theme};
use nsh_core::prelude::*;

use crate::flow::{Launcher, PROVIDERS, ProviderRow, sign_in, sign_out};

pub(crate) fn launcher_screen(launcher: Launcher) -> impl IntoElement {
    let status = status_line(launcher.clone());
    let local_error = local_error_line(launcher.clone());
    let crate_error = crate_error_line(launcher.clone());
    let session = launcher.clone();
    let sign_out_card = launcher;
    view()
        .flex_1()
        .p_6()
        .gap_5()
        .max_w_96()
        .child(header())
        .child(listener_line(&session))
        .child(providers(&session))
        .child(status)
        .child(local_error)
        .child(crate_error)
        .child(when(
            move || session.session.with(|session| session.is_some()),
            move || session_card(session.clone()),
        ))
        .child(when(
            move || sign_out_card.session.with(|session| session.is_some()),
            move || sign_out_button(sign_out_card.clone()),
        ))
}

fn header() -> impl IntoElement {
    view()
        .gap_1()
        .child(text("Sign in").text_xl().font_weight(FontWeight::SEMIBOLD))
        .child(
            text("Opens your browser; the redirect returns to this machine.")
                .text_sm()
                .text_color(move || theme().muted_foreground),
        )
}

fn listener_line(launcher: &Launcher) -> impl IntoElement {
    // Bound once per run, so the value form is correct: it never changes.
    text(format!("Listening on {}", launcher.redirect_origin))
        .text_sm()
        .text_color(move || theme().muted_foreground)
}

fn providers(launcher: &Launcher) -> impl IntoElement {
    view()
        .gap_2()
        .children(PROVIDERS.iter().map(|row| provider_button(launcher, row)))
}

fn provider_button(launcher: &Launcher, row: &ProviderRow) -> impl IntoElement {
    let state = launcher.clone();
    let launcher = launcher.clone();
    let id = row.id;
    let label = row.label;
    let tag = row.tag;
    button()
        .disabled(move || state.active.get() || state.server.is_none())
        .on_press(move || sign_in(&launcher, id))
        .h_9()
        .flex_row()
        .items_center()
        .justify_between()
        .px_4()
        .rounded(move || theme().radius)
        .border_1()
        .border_color(move || theme().input)
        .hover(|s| s.bg(move || theme().accent))
        .active(|s| s.opacity(0.7))
        .focus(|s| s.outline(px(2.0)).outline_color(move || theme().ring))
        .disabled_style(|s| s.opacity(0.4))
        .child(
            text(label)
                .text_sm()
                .font_weight(FontWeight::MEDIUM)
                .text_color(move || theme().foreground),
        )
        .child(tag.map(|tag| {
            text(tag)
                .text_sm()
                .text_color(move || theme().muted_foreground)
        }))
}

fn status_line(launcher: Launcher) -> impl IntoElement {
    text(move || {
        launcher
            .status
            .with(|status| status_text(*status).to_owned())
    })
    .text_sm()
    .text_color(move || theme().muted_foreground)
}

fn status_text(status: nsh_auth::AuthStatus) -> &'static str {
    match status {
        nsh_auth::AuthStatus::Idle => "Idle",
        nsh_auth::AuthStatus::SigningIn => "Waiting for the browser to return…",
        nsh_auth::AuthStatus::Refreshing => "Refreshing the session…",
        nsh_auth::AuthStatus::SignedIn => "Signed in",
        nsh_auth::AuthStatus::SignedOut => "Signed out",
    }
}

/// Launcher-side failures (bind, browser), near where the flow was started.
fn local_error_line(launcher: Launcher) -> impl IntoElement {
    let present = launcher.clone();
    let message = launcher;
    when(
        move || present.local_error.with(|error| error.is_some()),
        move || {
            let message = message.clone();
            text(move || {
                message
                    .local_error
                    .with(|error| error.clone())
                    .unwrap_or_else(|| SharedString::from(""))
            })
            .text_sm()
            .text_color(move || theme().destructive)
        },
    )
}

/// The crate's `error` signal: what the provider or the exchange said.
fn crate_error_line(launcher: Launcher) -> impl IntoElement {
    let present = launcher.clone();
    let message = launcher;
    when(
        move || present.error.with(|error| error.is_some()),
        move || {
            let message = message.clone();
            text(move || {
                message
                    .error
                    .with(|error| error.as_ref().map(|error| error.to_string()))
                    .unwrap_or_default()
            })
            .text_sm()
            .text_color(move || theme().destructive)
        },
    )
}

fn session_card(launcher: Launcher) -> impl IntoElement {
    let provider = launcher.clone();
    let scope = launcher.clone();
    let expires = launcher.clone();
    let user = launcher;
    view()
        .gap_2()
        .p_4()
        .rounded(move || theme().radius)
        .border_1()
        .border_color(move || theme().border)
        .bg(move || theme().card)
        .child(
            text("Signed in")
                .text_sm()
                .font_weight(FontWeight::SEMIBOLD),
        )
        // Individual fields only: `Session` also holds the tokens, and they
        // never reach the screen or the log.
        .child(detail_row("Provider", move || {
            provider.session.with(|session| {
                session
                    .as_ref()
                    .map(|session| session.provider.as_str().to_owned())
                    .unwrap_or_else(|| "—".to_owned())
            })
        }))
        .child(detail_row("Scope", move || {
            scope.session.with(|session| {
                session
                    .as_ref()
                    .map(|session| session.scope.clone())
                    .unwrap_or_else(|| "—".to_owned())
            })
        }))
        .child(detail_row("Token expires", move || {
            expires.session.with(|session| {
                session
                    .as_ref()
                    .map(|session| expiry_text(session.expires_at))
                    .unwrap_or_else(|| "—".to_owned())
            })
        }))
        .child(
            text(move || {
                user.user
                    .with(|user| user.as_ref().map(user_line))
                    .unwrap_or_default()
            })
            .text_sm(),
        )
}

/// `expires_at` is milliseconds since the epoch; 0 means the provider sent
/// no expiry (GitHub tokens do not expire).
fn expiry_text(expires_at: i64) -> String {
    if expires_at == 0 {
        "No expiry".to_owned()
    } else {
        format!("Unix ms {expires_at}")
    }
}

/// Name and email when the provider sent them; `sub` otherwise.
fn user_line(user: &nsh_auth::UserInfo) -> String {
    match (&user.name, &user.email) {
        (Some(name), Some(email)) => format!("{name} <{email}>"),
        (Some(name), None) => name.clone(),
        (None, Some(email)) => email.clone(),
        (None, None) => user.sub.clone(),
    }
}

fn detail_row(label: &'static str, value: impl Fn() -> String + 'static) -> impl IntoElement {
    view()
        .flex_row()
        .gap_3()
        .child(
            text(label)
                .text_sm()
                .text_color(move || theme().muted_foreground),
        )
        .child(text(value).text_sm().flex_1().tabular_nums())
}

fn sign_out_button(launcher: Launcher) -> impl IntoElement {
    button()
        .on_press(move || sign_out(&launcher))
        .h_9()
        .flex_row()
        .items_center()
        .px_4()
        .rounded(move || theme().radius)
        .border_1()
        .border_color(move || theme().destructive)
        .hover(|s| s.bg(move || theme().accent))
        .active(|s| s.opacity(0.7))
        .focus(|s| s.outline(px(2.0)).outline_color(move || theme().ring))
        .child(
            text("Sign out")
                .text_sm()
                .font_weight(FontWeight::MEDIUM)
                .text_color(move || theme().destructive),
        )
}
