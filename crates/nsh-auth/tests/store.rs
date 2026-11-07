//! Store round-trips: memory and the 0600 JSON file store.

mod common;

use nsh_auth::{
    EXPIRY_TOLERANCE_MS, JsonFileStore, MemoryStore, ProviderId, Session, SessionStore,
};
use std::sync::atomic::{AtomicUsize, Ordering};

fn session(access_token: &str) -> Session {
    Session {
        provider: ProviderId::Mock,
        access_token: access_token.to_owned(),
        refresh_token: Some("rt-1".to_owned()),
        id_token: Some("header.claim.sig".to_owned()),
        expires_at: 1_767_258_000_000,
        scope: "openid email profile".to_owned(),
    }
}

#[test]
fn memory_store_round_trips() {
    let store = MemoryStore::new();
    assert_eq!(store.load("mock").unwrap(), None);
    store.save("mock", &session("at-1")).unwrap();
    assert_eq!(store.load("mock").unwrap(), Some(session("at-1")));
    store.save("mock", &session("at-2")).unwrap();
    assert_eq!(store.load("mock").unwrap(), Some(session("at-2")));
    store.clear("mock").unwrap();
    assert_eq!(store.load("mock").unwrap(), None);
    // Clearing what is not there is fine.
    store.clear("mock").unwrap();
}

static DIR_COUNTER: AtomicUsize = AtomicUsize::new(0);

#[test]
fn json_file_store_round_trips_owner_only() {
    let dir = std::env::temp_dir().join(format!(
        "nsh-auth-store-test-{}-{}",
        std::process::id(),
        DIR_COUNTER.fetch_add(1, Ordering::SeqCst)
    ));
    let store = JsonFileStore::new(&dir).unwrap();
    assert_eq!(store.load("mock").unwrap(), None);
    store.save("mock", &session("at-1")).unwrap();
    assert_eq!(store.load("mock").unwrap(), Some(session("at-1")));

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(dir.join("mock.json"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "the session file is owner-only");
    }

    store.clear("mock").unwrap();
    assert_eq!(store.load("mock").unwrap(), None);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn session_expiry_follows_the_clock() {
    let mut session = session("at-1");
    // Valid while more than the tolerance remains, expired from 60 s out.
    assert!(!session.expired(1_767_258_000_000 - EXPIRY_TOLERANCE_MS - 1));
    assert!(session.expired(1_767_258_000_000));
    // 0 means the provider set no expiry (GitHub): never expired.
    session.expires_at = 0;
    assert!(!session.expired(i64::MAX));
}

/// A session with half the tolerance left counts as expired: a refresh
/// sent then could carry a token that dies mid-request (AppAuth refreshes
/// with the same 60 s margin, OIDAuthState.m).
#[test]
fn a_session_expiring_in_30s_counts_as_expired() {
    let session = session("at-1"); // expires at 1_767_258_000_000
    assert!(session.expired(1_767_258_000_000 - 30_000));
    // One past the tolerance it is still good.
    assert!(!session.expired(1_767_258_000_000 - EXPIRY_TOLERANCE_MS - 1));
}
