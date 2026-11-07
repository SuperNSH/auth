//! OS-keyring session storage for `nsh-auth` desktop apps, behind the same
//! [`SessionStore`] trait: macOS login Keychain, Windows Credential
//! Manager, Linux Secret Service (keyring-core plus one platform store
//! crate per OS).
//!
//! Entries are one credential per session field (`access_token`,
//! `refresh_token`, `id_token`, `meta`) under one namespaced service,
//! never a whole session in one credential: Windows caps a credential
//! blob at `CRED_MAX_CREDENTIAL_BLOB_SIZE` (2560 bytes, enforced by
//! [`MAX_FIELD_BYTES`] on every platform before the OS is touched), and a
//! provider's tokens plus id token can exceed that.
//!
//! Platform residuals, stated: the macOS Keychain names the creating
//! binary in each item's ACL, so an unsigned rebuild can raise the
//! "wants to access" prompt — keyring exposes no ACL control, and the
//! prompt is the OS doing its job. Linux without a Secret Service daemon
//! never fails silently: [`KeyringStore::new`] returns a clear store
//! error there, and [`KeyringStore::with_fallback`] probes at
//! construction and reports the 0600 JSON-file delegate through
//! [`KeyringStore::backend`]. Mobile apps keep their host stores
//! (Keychain, Keystore); this crate is the desktop option.

pub use nsh_auth::{self, Session, SessionStore};

use keyring_core::{CredentialStore, Entry, Error as KeyringError};
use nsh_auth::{AuthError, JsonFileStore, ProviderId};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Arc;

/// The service every entry lives under. Providers and fields are separated
/// by the entry's user: `"<provider>.<field>"`.
pub const DEFAULT_SERVICE: &str = "nsh-auth";

/// The most bytes one field entry may hold. Windows Credential Manager
/// caps a credential blob at `CRED_MAX_CREDENTIAL_BLOB_SIZE` (2560); the
/// same cap is enforced on every platform, before the OS is touched, so
/// an oversized session fails with one message everywhere.
pub const MAX_FIELD_BYTES: usize = 2560;

/// The user of the entry `with_fallback` writes and deletes to learn
/// whether the OS store is reachable at all.
const PROBE_USER: &str = "keyring-probe";

const FIELD_ACCESS: &str = "access_token";
const FIELD_REFRESH: &str = "refresh_token";
const FIELD_ID: &str = "id_token";
/// The non-secret fields of a session, stored as JSON. Written last: its
/// presence is what `load` treats as "a session is stored here".
const FIELD_META: &str = "meta";

/// Which backing store a [`KeyringStore`] is serving from. The fallback
/// switch is made once, at construction, and is always visible here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backend {
    /// The OS keyring: Keychain, Credential Manager or Secret Service.
    OsKeyring,
    /// The 0600 JSON file `with_fallback` armed because the OS store was
    /// unreachable at construction (Linux without a Secret Service
    /// daemon, a locked login keychain). A visible downgrade, not secure
    /// storage.
    FileFallback,
}

/// The non-secret half of a [`Session`], stored as the `meta` entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct SessionMeta {
    provider: ProviderId,
    expires_at: i64,
    scope: String,
}

/// A [`SessionStore`] over the OS keyring: one credential per session
/// field, all under one service.
#[derive(Debug)]
pub struct KeyringStore {
    service: String,
    store: Arc<CredentialStore>,
    fallback: Option<JsonFileStore>,
    backend: Backend,
}

impl KeyringStore {
    /// The platform keyring under [`DEFAULT_SERVICE`].
    ///
    /// # Errors
    /// A store error naming the platform failure; on Linux without a
    /// Secret Service daemon the first operation fails with a clear
    /// message naming [`KeyringStore::with_fallback`].
    pub fn new() -> Result<Self, AuthError> {
        Self::with_service(DEFAULT_SERVICE)
    }

    /// The platform keyring under `service`. The Keychain treats an empty
    /// service as a wildcard match, so one is refused.
    pub fn with_service(service: &str) -> Result<Self, AuthError> {
        let store = platform_store()?;
        Self::build(service, store, None)
    }

    /// The platform keyring with a documented fallback: construction
    /// probes the OS store, and when it is unreachable (Linux without a
    /// Secret Service daemon, a locked login keychain) the store serves
    /// from a 0600 JSON file in `dir` instead, visible through
    /// [`backend`][KeyringStore::backend]. Any other probe failure is
    /// returned, never downgraded.
    pub fn with_fallback(dir: impl Into<PathBuf>) -> Result<Self, AuthError> {
        Self::with_service_and_fallback(DEFAULT_SERVICE, dir)
    }

    /// [`with_fallback`][KeyringStore::with_fallback] under `service`.
    pub fn with_service_and_fallback(
        service: &str,
        dir: impl Into<PathBuf>,
    ) -> Result<Self, AuthError> {
        let store = platform_store()?;
        let file = JsonFileStore::new(dir)?;
        Self::build(service, store, Some(file))
    }

    /// A store over a caller-supplied keyring (a custom backend, a test
    /// mock). No fallback is armed; the store's own errors surface as-is.
    pub fn with_store(service: &str, store: Arc<CredentialStore>) -> Result<Self, AuthError> {
        Self::build(service, store, None)
    }

    /// [`with_store`][KeyringStore::with_store] plus the file fallback of
    /// [`with_fallback`][KeyringStore::with_fallback].
    pub fn with_store_and_fallback(
        service: &str,
        store: Arc<CredentialStore>,
        dir: impl Into<PathBuf>,
    ) -> Result<Self, AuthError> {
        let file = JsonFileStore::new(dir)?;
        Self::build(service, store, Some(file))
    }

    fn build(
        service: &str,
        store: Arc<CredentialStore>,
        fallback: Option<JsonFileStore>,
    ) -> Result<Self, AuthError> {
        if service.is_empty() {
            return Err(AuthError::StoreError(
                "keyring service must not be empty: the Keychain treats an empty service as a wildcard match".to_owned(),
            ));
        }
        let mut this = Self {
            service: service.to_owned(),
            store,
            fallback,
            backend: Backend::OsKeyring,
        };
        if this.fallback.is_some() && !this.probe_reachable()? {
            this.backend = Backend::FileFallback;
        }
        Ok(this)
    }

    /// The backend actually serving reads and writes.
    pub fn backend(&self) -> Backend {
        self.backend
    }

    /// The service every entry of this store lives under.
    pub fn service(&self) -> &str {
        &self.service
    }

    /// Writes and deletes a probe entry: `false` means the OS store is
    /// unreachable (the `with_fallback` case); any other failure is a
    /// real store error and is returned.
    fn probe_reachable(&self) -> Result<bool, AuthError> {
        let entry = match self.store.build(&self.service, PROBE_USER, None) {
            Ok(entry) => entry,
            Err(KeyringError::NoStorageAccess(_)) => return Ok(false),
            Err(error) => return Err(self.keyring_error(PROBE_USER, error)),
        };
        match entry.set_secret(b"probe") {
            Ok(()) => {}
            Err(KeyringError::NoStorageAccess(_)) => return Ok(false),
            Err(error) => return Err(self.keyring_error(PROBE_USER, error)),
        }
        match entry.delete_credential() {
            Ok(()) | Err(KeyringError::NoEntry) => Ok(true),
            Err(error) => Err(self.keyring_error(PROBE_USER, error)),
        }
    }

    fn file_delegate(&self) -> Option<&JsonFileStore> {
        if self.backend == Backend::FileFallback {
            self.fallback.as_ref()
        } else {
            None
        }
    }

    fn entry(&self, user: &str) -> Result<Entry, AuthError> {
        self.store
            .build(&self.service, user, None)
            .map_err(|error| self.keyring_error(user, error))
    }

    fn set_field(&self, user: &str, bytes: &[u8]) -> Result<(), AuthError> {
        check_field_size(user, bytes)?;
        self.entry(user)?
            .set_secret(bytes)
            .map_err(|error| self.keyring_error(user, error))
    }

    fn get_field(&self, user: &str) -> Result<Option<Vec<u8>>, AuthError> {
        match self.entry(user)?.get_secret() {
            Ok(bytes) => Ok(Some(bytes)),
            Err(KeyringError::NoEntry) => Ok(None),
            Err(error) => Err(self.keyring_error(user, error)),
        }
    }

    fn del_field(&self, user: &str) -> Result<(), AuthError> {
        match self.entry(user)?.delete_credential() {
            Ok(()) | Err(KeyringError::NoEntry) => Ok(()),
            Err(error) => Err(self.keyring_error(user, error)),
        }
    }

    /// `None` for optional fields is a deleted entry, not a kept one: a
    /// stale refresh token must not survive its own removal.
    fn set_or_clear_field(
        &self,
        key: &str,
        field: &str,
        value: Option<&str>,
    ) -> Result<(), AuthError> {
        match value {
            Some(value) => self.set_field(&user(key, field), value.as_bytes()),
            None => self.del_field(&user(key, field)),
        }
    }

    fn opt_string(&self, key: &str, field: &str) -> Result<Option<String>, AuthError> {
        self.get_field(&user(key, field))?
            .map(|bytes| utf8(&user(key, field), &bytes))
            .transpose()
    }

    fn keyring_error(&self, user: &str, error: KeyringError) -> AuthError {
        let hint = if matches!(error, KeyringError::NoStorageAccess(_)) {
            " (the OS store is unreachable: on Linux this means no Secret Service daemon; \
             KeyringStore::with_fallback arms the documented file fallback)"
        } else {
            ""
        };
        AuthError::StoreError(format!("{}.{user}: {error}{hint}", self.service))
    }

    fn save_keyring(&self, key: &str, session: &Session) -> Result<(), AuthError> {
        let meta = SessionMeta {
            provider: session.provider,
            expires_at: session.expires_at,
            scope: session.scope.clone(),
        };
        let meta_bytes = serde_json::to_vec(&meta)
            .map_err(|e| AuthError::StoreError(format!("session meta serialization: {e}")))?;
        // Every field is size-checked before anything is touched: an
        // oversized session is rejected as a no-op, not written halfway.
        check_field_size(&user(key, FIELD_ACCESS), session.access_token.as_bytes())?;
        if let Some(token) = session.refresh_token.as_deref() {
            check_field_size(&user(key, FIELD_REFRESH), token.as_bytes())?;
        }
        if let Some(token) = session.id_token.as_deref() {
            check_field_size(&user(key, FIELD_ID), token.as_bytes())?;
        }
        check_field_size(&user(key, FIELD_META), &meta_bytes)?;
        // Meta is deleted first and written last: it is the completion
        // marker `load` keys on, so a save that dies mid-overwrite leaves
        // either no session at all or the fully written new one — never a
        // mix of the new fields with the old session's.
        self.del_field(&user(key, FIELD_META))?;
        self.set_field(&user(key, FIELD_ACCESS), session.access_token.as_bytes())?;
        self.set_or_clear_field(key, FIELD_REFRESH, session.refresh_token.as_deref())?;
        self.set_or_clear_field(key, FIELD_ID, session.id_token.as_deref())?;
        self.set_field(&user(key, FIELD_META), &meta_bytes)
    }
}

impl SessionStore for KeyringStore {
    fn save(&self, key: &str, session: &Session) -> Result<(), AuthError> {
        check_key(key)?;
        match self.file_delegate() {
            Some(file) => file.save(key, session),
            None => self.save_keyring(key, session),
        }
    }

    fn load(&self, key: &str) -> Result<Option<Session>, AuthError> {
        check_key(key)?;
        if let Some(file) = self.file_delegate() {
            return file.load(key);
        }
        let Some(meta_bytes) = self.get_field(&user(key, FIELD_META))? else {
            return Ok(None);
        };
        let meta: SessionMeta = serde_json::from_slice(&meta_bytes).map_err(|e| {
            AuthError::StoreError(format!(
                "{}: session meta is not valid JSON: {e}",
                user(key, FIELD_META)
            ))
        })?;
        let access_user = user(key, FIELD_ACCESS);
        let Some(access) = self.get_field(&access_user)? else {
            return Err(AuthError::StoreError(format!(
                "{access_user}: the keyring holds session meta but no access token; \
                 clear the session and sign in again"
            )));
        };
        Ok(Some(Session {
            provider: meta.provider,
            access_token: utf8(&access_user, &access)?,
            refresh_token: self.opt_string(key, FIELD_REFRESH)?,
            id_token: self.opt_string(key, FIELD_ID)?,
            expires_at: meta.expires_at,
            scope: meta.scope,
        }))
    }

    fn clear(&self, key: &str) -> Result<(), AuthError> {
        check_key(key)?;
        if let Some(file) = self.file_delegate() {
            return file.clear(key);
        }
        self.del_field(&user(key, FIELD_ACCESS))?;
        self.del_field(&user(key, FIELD_REFRESH))?;
        self.del_field(&user(key, FIELD_ID))?;
        self.del_field(&user(key, FIELD_META))
    }
}

fn user(key: &str, field: &str) -> String {
    format!("{key}.{field}")
}

/// One field entry may hold at most [`MAX_FIELD_BYTES`], checked before
/// the OS is touched so an oversized value fails with one message on every
/// platform and writes nothing.
fn check_field_size(user: &str, bytes: &[u8]) -> Result<(), AuthError> {
    if bytes.len() > MAX_FIELD_BYTES {
        return Err(AuthError::StoreError(format!(
            "{user} is {} bytes, over the {MAX_FIELD_BYTES}-byte credential cap \
             (Windows CRED_MAX_CREDENTIAL_BLOB_SIZE); nothing was written",
            bytes.len()
        )));
    }
    Ok(())
}

fn check_key(key: &str) -> Result<(), AuthError> {
    if key.is_empty() {
        return Err(AuthError::StoreError(
            "session key must not be empty".to_owned(),
        ));
    }
    Ok(())
}

fn utf8(name: &str, bytes: &[u8]) -> Result<String, AuthError> {
    String::from_utf8(bytes.to_vec())
        .map_err(|_| AuthError::StoreError(format!("{name}: stored bytes are not valid UTF-8")))
}

#[cfg(target_os = "macos")]
fn platform_store() -> Result<Arc<CredentialStore>, AuthError> {
    let store = apple_native_keyring_store::keychain::Store::new()
        .map_err(|e| AuthError::StoreError(format!("macOS keychain store: {e}")))?;
    Ok(store)
}

#[cfg(target_os = "windows")]
fn platform_store() -> Result<Arc<CredentialStore>, AuthError> {
    let store = windows_native_keyring_store::Store::new()
        .map_err(|e| AuthError::StoreError(format!("windows credential store: {e}")))?;
    Ok(store)
}

#[cfg(target_os = "linux")]
fn platform_store() -> Result<Arc<CredentialStore>, AuthError> {
    let store = zbus_secret_service_keyring_store::Store::new()
        .map_err(|e| AuthError::StoreError(format!("secret service store: {e}")))?;
    Ok(store)
}

#[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
fn platform_store() -> Result<Arc<CredentialStore>, AuthError> {
    Err(AuthError::StoreError(
        "no OS keyring backend on this platform; mobile hosts bring their own Keychain/Keystore stores".to_owned(),
    ))
}
