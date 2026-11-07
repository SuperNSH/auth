//! Which `SessionStore` backs the launcher: the OS credential store via the
//! `nsh-auth-keyring` crate where the platform has one (the default on
//! macOS and Windows), the crate's 0600 JSON files otherwise or by explicit
//! `--store json`. The active store is named in the startup log, so a
//! fallback is never silent.

use std::path::PathBuf;
use std::sync::Arc;

use nsh_auth::{JsonFileStore, SessionStore};

use crate::options::Options;

/// The store kinds `--store` accepts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum StoreKind {
    Json,
    Keyring,
}

pub(crate) fn parse_store(name: &str) -> Option<StoreKind> {
    match name {
        "json" => Some(StoreKind::Json),
        "keyring" => Some(StoreKind::Keyring),
        _ => None,
    }
}

/// Keyring is the default where an OS credential store exists to back it;
/// Linux keeps the JSON files as its default because a Secret Service daemon
/// is not guaranteed there (headless sessions, minimal window managers).
pub(crate) fn default_kind() -> StoreKind {
    if cfg!(any(target_os = "macos", target_os = "windows")) {
        StoreKind::Keyring
    } else {
        StoreKind::Json
    }
}

/// The store the launcher runs with, plus the startup line naming it. When
/// the default asks for a store this binary lacks, the fallback to JSON is
/// returned with the reason logged at warn — visible, never silent.
pub(crate) fn select(options: &Options) -> Result<(Arc<dyn SessionStore>, String), String> {
    let requested = options.store.unwrap_or_else(default_kind);
    match open(requested) {
        Ok(chosen) => Ok(chosen),
        Err(reason) if options.store.is_none() => {
            log::warn!("falling back to the JSON file store: {reason}");
            open(StoreKind::Json)
        }
        Err(reason) => Err(reason),
    }
}

fn open(kind: StoreKind) -> Result<(Arc<dyn SessionStore>, String), String> {
    match kind {
        StoreKind::Json => {
            let directory = sessions_dir();
            let store = JsonFileStore::new(directory.clone()).map_err(|error| error.to_string())?;
            let note = format!(
                "sessions: JSON files, mode 0600, in {}",
                directory.display()
            );
            Ok((Arc::new(store), note))
        }
        StoreKind::Keyring => keyring_store(),
    }
}

/// The OS credential store, compiled only under the `keyring` cargo feature
/// (`crates/nsh-auth-keyring`: one credential per session field). No file
/// fallback is armed here — an unreachable OS store fails construction or
/// the operation with its own clear message, and the launcher's default
/// fallback to JSON is logged at warn.
#[cfg(feature = "keyring")]
fn keyring_store() -> Result<(Arc<dyn SessionStore>, String), String> {
    let store = nsh_auth_keyring::KeyringStore::new().map_err(|error| error.to_string())?;
    let platform = if cfg!(target_os = "macos") {
        "macOS Keychain"
    } else if cfg!(target_os = "windows") {
        "Windows Credential Manager"
    } else {
        "freedesktop Secret Service"
    };
    let note = format!("sessions: {platform} (OS credential store via nsh-auth-keyring)");
    Ok((Arc::new(store), note))
}

#[cfg(not(feature = "keyring"))]
fn keyring_store() -> Result<(Arc<dyn SessionStore>, String), String> {
    Err(
        "the OS credential store is not built into this binary (rebuild without --no-default-features)"
            .to_owned(),
    )
}

/// The directory `JsonFileStore` keeps its per-provider files in
/// (`<dir>/<provider>.json`), under the user's home, created 0700 so the
/// 0600 files are never world-reachable.
fn sessions_dir() -> PathBuf {
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    let directory = home.join(".nsh-auth-desktop");
    #[cfg(unix)]
    {
        use std::fs::DirBuilder;
        use std::os::unix::fs::DirBuilderExt;
        if !directory.exists() {
            // 0700 before any token file can land in it; the store then
            // writes its files 0600 inside.
            let _ = DirBuilder::new().mode(0o700).create(directory.clone());
        }
    }
    #[cfg(not(unix))]
    let _ = &directory;
    directory
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::options::Options;

    #[test]
    fn the_default_follows_the_platform() {
        let expected = if cfg!(any(target_os = "macos", target_os = "windows")) {
            StoreKind::Keyring
        } else {
            StoreKind::Json
        };
        assert_eq!(default_kind(), expected);
    }

    #[test]
    fn json_opens_everywhere_and_names_its_mode() {
        let options = Options {
            store: Some(StoreKind::Json),
            ..Options::default()
        };
        let (_store, note) = select(&options).expect("the JSON store opens");
        assert!(note.contains("0600"), "{note}");
    }
}
