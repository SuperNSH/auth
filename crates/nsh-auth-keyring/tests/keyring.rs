//! KeyringStore: field-per-entry round-trips, the 2560-byte cap before the
//! OS is touched, torn state, and the visible file fallback — always on
//! against keyring-core's mock store, plus the real macOS Keychain behind
//! `NSH_AUTH_KEYRING_REAL=1` (sandbox data only; every entry is removed).

use keyring_core::Error as KeyringError;
use keyring_core::api::CredentialStoreApi;
use keyring_core::mock;
use nsh_auth::ProviderId;
use nsh_auth_keyring::{Backend, KeyringStore, MAX_FIELD_BYTES, Session, SessionStore};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

fn session(access_token: &str, refresh_token: Option<&str>, id_token: Option<&str>) -> Session {
    Session {
        provider: ProviderId::Google,
        access_token: access_token.to_owned(),
        refresh_token: refresh_token.map(str::to_owned),
        id_token: id_token.map(str::to_owned),
        expires_at: 1_767_258_000_000,
        scope: "openid email profile".to_owned(),
    }
}

fn mock_keyring() -> (KeyringStore, Arc<mock::Store>) {
    let store = mock::Store::new().expect("mock store");
    let keyring = KeyringStore::with_store("nsh-auth.test", store.clone()).expect("keyring store");
    (keyring, store)
}

fn temp_dir(tag: &str) -> PathBuf {
    std::env::temp_dir().join(format!("nsh-auth-keyring-{tag}-{}", std::process::id()))
}

/// A store whose every operation is unreachable, the shape Linux shows
/// when no Secret Service daemon runs.
struct NoDaemonStore;

impl CredentialStoreApi for NoDaemonStore {
    fn vendor(&self) -> String {
        "no-daemon".to_owned()
    }

    fn id(&self) -> String {
        "no-daemon".to_owned()
    }

    fn build(
        &self,
        _service: &str,
        _user: &str,
        _modifiers: Option<&HashMap<&str, &str>>,
    ) -> keyring_core::Result<keyring_core::Entry> {
        Err(KeyringError::NoStorageAccess(Box::new(
            std::io::Error::other("no secret service daemon"),
        )))
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

#[test]
fn mock_store_round_trips_each_field() {
    let (keyring, _) = mock_keyring();
    assert_eq!(keyring.load("google").unwrap(), None);

    keyring
        .save("google", &session("at-1", Some("rt-1"), Some("id-1")))
        .unwrap();
    assert_eq!(
        keyring.load("google").unwrap(),
        Some(session("at-1", Some("rt-1"), Some("id-1")))
    );

    // A second provider never crosses into the first.
    keyring.save("mock", &session("m-at", None, None)).unwrap();
    assert_eq!(
        keyring.load("mock").unwrap(),
        Some(session("m-at", None, None))
    );
    assert_eq!(
        keyring.load("google").unwrap().unwrap().access_token,
        "at-1"
    );

    // Overwriting without optional fields drops their entries: a stale
    // refresh token must not survive its own removal.
    keyring
        .save("google", &session("at-2", None, None))
        .unwrap();
    assert_eq!(
        keyring.load("google").unwrap(),
        Some(session("at-2", None, None))
    );

    keyring.clear("google").unwrap();
    keyring.clear("mock").unwrap();
    assert_eq!(keyring.load("google").unwrap(), None);
    // Clearing what is not there is fine.
    keyring.clear("google").unwrap();

    let error = keyring.save("", &session("at", None, None)).unwrap_err();
    assert!(
        format!("{error}").contains("key must not be empty"),
        "{error}"
    );
}

#[test]
fn oversized_fields_are_rejected_before_the_store() {
    let (keyring, mock) = mock_keyring();
    keyring
        .save("google", &session("at-1", None, None))
        .unwrap();

    // The access entry fails loudly if reached: the cap must fire first.
    let armed = mock
        .build("nsh-auth.test", "google.access_token", None)
        .unwrap();
    let cred: &mock::Cred = armed.as_any().downcast_ref().unwrap();
    cred.set_error(KeyringError::PlatformFailure(Box::new(
        std::io::Error::other("the OS was reached"),
    )));

    let oversized = session(&"a".repeat(MAX_FIELD_BYTES + 1), None, None);
    let error = keyring.save("google", &oversized).unwrap_err();
    let message = format!("{error}");
    assert!(message.contains("2560"), "{message}");
    assert!(message.contains("google.access_token"), "{message}");
    assert!(!message.contains("the OS was reached"), "{message}");
    // The armed error is one-shot and still queued: consume it so the
    // intactness check reads the real state.
    let _ = armed.get_secret();
    // Nothing was written: the previous session is intact.
    assert_eq!(
        keyring.load("google").unwrap().unwrap().access_token,
        "at-1"
    );

    // An oversized id token gets the same treatment.
    let oversized = session("at-2", None, Some(&"i".repeat(MAX_FIELD_BYTES + 1)));
    let error = keyring.save("google", &oversized).unwrap_err();
    assert!(format!("{error}").contains("google.id_token"), "{error}");
    keyring.clear("google").unwrap();
}

#[test]
fn meta_without_an_access_token_is_a_clear_error() {
    let (keyring, mock) = mock_keyring();
    keyring
        .save("google", &session("at-1", Some("rt-1"), None))
        .unwrap();

    // Tear the store behind its back: meta stays, access goes.
    mock.build("nsh-auth.test", "google.access_token", None)
        .unwrap()
        .delete_credential()
        .unwrap();

    let error = keyring.load("google").unwrap_err();
    let message = format!("{error}");
    assert!(message.contains("access_token"), "{message}");
    assert!(message.contains("clear the session"), "{message}");
    keyring.clear("google").unwrap();
}

/// A save that dies mid-overwrite (here: the id-token write fails after
/// the access write landed) must read as no session, never as a mix of
/// the new and the old one.
#[test]
fn a_torn_overwrite_never_reads_as_a_mixed_session() {
    let (keyring, mock) = mock_keyring();
    keyring
        .save("google", &session("at-1", Some("rt-1"), Some("id-1")))
        .unwrap();

    let armed = mock
        .build("nsh-auth.test", "google.id_token", None)
        .unwrap();
    let cred: &mock::Cred = armed.as_any().downcast_ref().unwrap();
    cred.set_error(KeyringError::PlatformFailure(Box::new(
        std::io::Error::other("torn write"),
    )));

    let error = keyring
        .save("google", &session("at-2", Some("rt-2"), Some("id-2")))
        .unwrap_err();
    let message = format!("{error}");
    assert!(message.contains("google.id_token"), "{message}");

    // Torn, not mixed: the half-overwritten session loads as absent.
    assert_eq!(keyring.load("google").unwrap(), None);
    keyring.clear("google").unwrap();
}

#[test]
fn a_reachable_store_stays_on_the_keyring_and_leaves_no_probe() {
    let (keyring, mock) = mock_keyring();
    let dir = temp_dir("reachable");
    let probed =
        KeyringStore::with_store_and_fallback("nsh-auth.test", mock.clone(), &dir).unwrap();
    assert_eq!(probed.backend(), Backend::OsKeyring);
    // The probe cleaned up after itself: the mock keeps built credentials
    // as specifiers, but none of them holds a secret.
    let leftovers = mock
        .search(&HashMap::from([("service", "nsh-auth.test"), ("user", "")]))
        .unwrap();
    for entry in leftovers {
        assert!(
            matches!(entry.get_secret(), Err(KeyringError::NoEntry)),
            "construction leaves no secrets"
        );
    }
    // The reachable store really serves from the keyring: another store
    // over the same mock sees its entries.
    probed.save("google", &session("at-1", None, None)).unwrap();
    assert_eq!(
        keyring.load("google").unwrap().unwrap().access_token,
        "at-1"
    );
    probed.clear("google").unwrap();
    assert_eq!(keyring.load("google").unwrap(), None);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn an_unreachable_store_falls_back_visibly_to_the_file() {
    let dir = temp_dir("fallback");
    let keyring =
        KeyringStore::with_store_and_fallback("nsh-auth.test", Arc::new(NoDaemonStore), &dir)
            .unwrap();

    assert_eq!(keyring.backend(), Backend::FileFallback);
    keyring
        .save("google", &session("at-1", Some("rt-1"), None))
        .unwrap();
    assert_eq!(
        keyring.load("google").unwrap(),
        Some(session("at-1", Some("rt-1"), None))
    );
    keyring.clear("google").unwrap();
    assert_eq!(keyring.load("google").unwrap(), None);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// `new()` must never fail silently on a platform it cannot serve: without
/// a keyring backend the constructor says so instead of guessing.
#[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
#[test]
fn new_on_an_unsupported_platform_is_a_clear_error() {
    let error = KeyringStore::new().unwrap_err();
    assert!(
        format!("{error}").contains("no OS keyring backend"),
        "{error}"
    );
}

/// Deletes every field entry of the throwaway service when dropped, so a
/// panic on any intermediate unwrap still leaves the real Keychain clean.
#[cfg(target_os = "macos")]
struct KeychainCleanup {
    store: Arc<apple_native_keyring_store::keychain::Store>,
    service: String,
}

#[cfg(target_os = "macos")]
impl Drop for KeychainCleanup {
    fn drop(&mut self) {
        for field in ["access_token", "refresh_token", "id_token", "meta"] {
            if let Ok(entry) = self
                .store
                .build(&self.service, &format!("google.{field}"), None)
            {
                // Best effort: the test's own assertions report real
                // failures; the guard only guarantees no leftovers.
                let _ = entry.delete_credential();
            }
        }
    }
}

/// The real macOS login Keychain, this Mac only: sandbox data (fake
/// tokens, a throwaway service), every entry removed even if the test
/// panics midway. CI and clean clones skip it: set
/// `NSH_AUTH_KEYRING_REAL=1` to run.
#[cfg(target_os = "macos")]
#[test]
fn real_keychain_round_trips_each_field_and_cleans_up() {
    if std::env::var("NSH_AUTH_KEYRING_REAL").is_err() {
        eprintln!("skipping: set NSH_AUTH_KEYRING_REAL=1 to exercise the real Keychain");
        return;
    }
    let service = format!("nsh-auth.keyring-test.{}", std::process::id());
    let native = apple_native_keyring_store::keychain::Store::new().expect("login keychain");
    let _cleanup = KeychainCleanup {
        store: native.clone(),
        service: service.clone(),
    };
    let keyring = KeyringStore::with_store(&service, native.clone()).unwrap();
    assert_eq!(keyring.service(), service);

    keyring
        .save("google", &session("at-1", Some("rt-1"), Some("id-1")))
        .unwrap();
    assert_eq!(
        keyring.load("google").unwrap(),
        Some(session("at-1", Some("rt-1"), Some("id-1")))
    );
    keyring
        .save("google", &session("at-2", None, None))
        .unwrap();
    assert_eq!(
        keyring.load("google").unwrap(),
        Some(session("at-2", None, None))
    );

    let oversized = session(&"a".repeat(MAX_FIELD_BYTES + 1), None, None);
    let error = keyring.save("google", &oversized).unwrap_err();
    assert!(format!("{error}").contains("2560"), "{error}");

    keyring.clear("google").unwrap();
    assert_eq!(keyring.load("google").unwrap(), None);
    let leftovers = native
        .search(&HashMap::from([("service", service.as_str())]))
        .unwrap();
    assert!(leftovers.is_empty(), "every test entry is removed");
}
