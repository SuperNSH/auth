//! Opens the system browser at the authorize URL. On every platform the URL
//! travels as one argv entry to a fixed program; no shell re-parses it.

use std::process::Command;

/// Waits for the opener itself, which exits at once; the browser stays open.
pub(crate) fn open_system_browser(url: &str) -> Result<(), String> {
    let mut command = browser_command(url);
    match command.status() {
        Ok(status) if status.success() => Ok(()),
        Ok(status) => Err(format!("{} exited with {status}", program_of(&command))),
        Err(error) => Err(format!("could not run {}: {error}", program_of(&command))),
    }
}

fn program_of(command: &Command) -> String {
    command.get_program().to_string_lossy().into_owned()
}

#[cfg(target_os = "macos")]
fn browser_command(url: &str) -> Command {
    let mut command = Command::new("open");
    command.arg(url);
    command
}

#[cfg(target_os = "linux")]
fn browser_command(url: &str) -> Command {
    let mut command = Command::new("xdg-open");
    command.arg(url);
    command
}

#[cfg(target_os = "windows")]
fn browser_command(url: &str) -> Command {
    // rundll32 is no shell: the URL stays one argv entry. `cmd /C start`
    // would re-parse the line, and std quotes an argument only for spaces,
    // tabs and quotes (library/std/src/sys/pal/windows/process.rs) — never
    // for `&` — so the authorize URL would be split at its first `&`.
    let mut command = Command::new("rundll32");
    command.args(["url.dll,FileProtocolHandler", url]);
    command
}
