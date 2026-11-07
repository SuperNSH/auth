//! Session storage behind a trait, with two stores shipped.

use crate::error::AuthError;
use crate::session::Session;
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::sync::Mutex;

/// Where sessions persist. Keys are provider slugs (`"google"`). Secure
/// stores (Keychain, Keystore, DPAPI, Secret Service) live in the embedding
/// hosts; this trait is the seam they implement.
pub trait SessionStore: Send + Sync + 'static {
    fn save(&self, key: &str, session: &Session) -> Result<(), AuthError>;
    fn load(&self, key: &str) -> Result<Option<Session>, AuthError>;
    fn clear(&self, key: &str) -> Result<(), AuthError>;
}

/// In-memory store: tests and processes that need no persistence.
#[derive(Debug, Default)]
pub struct MemoryStore {
    sessions: Mutex<HashMap<String, Session>>,
}

impl MemoryStore {
    pub fn new() -> Self {
        Self::default()
    }
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    // A panicking holder leaves valid data; a poisoned lock is still usable.
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

impl SessionStore for MemoryStore {
    fn save(&self, key: &str, session: &Session) -> Result<(), AuthError> {
        lock(&self.sessions).insert(key.to_owned(), session.clone());
        Ok(())
    }

    fn load(&self, key: &str) -> Result<Option<Session>, AuthError> {
        Ok(lock(&self.sessions).get(key).cloned())
    }

    fn clear(&self, key: &str) -> Result<(), AuthError> {
        lock(&self.sessions).remove(key);
        Ok(())
    }
}

/// Desktop file store: one JSON file per session. The file is mode 0600
/// where the platform has file modes; that is a desktop-app baseline, not
/// secure storage — mobile hosts bring Keychain/Keystore stores.
#[derive(Debug, Clone)]
pub struct JsonFileStore {
    dir: PathBuf,
}

impl JsonFileStore {
    pub fn new(dir: impl Into<PathBuf>) -> Result<Self, AuthError> {
        let dir = dir.into();
        fs::create_dir_all(&dir)
            .map_err(|e| AuthError::StoreError(format!("{}: {e}", dir.display())))?;
        Ok(Self { dir })
    }

    fn path(&self, key: &str) -> PathBuf {
        // Keys are provider slugs; no path traversal surface.
        self.dir.join(format!("{key}.json"))
    }
}

impl SessionStore for JsonFileStore {
    fn save(&self, key: &str, session: &Session) -> Result<(), AuthError> {
        let path = self.path(key);
        let json = serde_json::to_string(session)
            .map_err(|e| AuthError::StoreError(format!("session serialization: {e}")))?;
        write_owner_only(&path, json.as_bytes())?;
        Ok(())
    }

    fn load(&self, key: &str) -> Result<Option<Session>, AuthError> {
        let path = self.path(key);
        match fs::read(&path) {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .map(Some)
                .map_err(|e| AuthError::StoreError(format!("{}: {e}", path.display()))),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(AuthError::StoreError(format!("{}: {e}", path.display()))),
        }
    }

    fn clear(&self, key: &str) -> Result<(), AuthError> {
        match fs::remove_file(self.path(key)) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(AuthError::StoreError(e.to_string())),
        }
    }
}

/// Writes the bytes so the file is never readable beyond its owner: created
/// with mode 0600 (no write-then-chmod window), and narrowed afterwards in
/// case a wider file already existed at the path.
#[cfg(unix)]
fn write_owner_only(path: &std::path::Path, bytes: &[u8]) -> Result<(), AuthError> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    use std::os::unix::fs::PermissionsExt;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| AuthError::StoreError(format!("{}: {e}", path.display())))?;
    file.write_all(bytes)
        .map_err(|e| AuthError::StoreError(format!("{}: {e}", path.display())))?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .map_err(|e| AuthError::StoreError(format!("{}: {e}", path.display())))
}

#[cfg(not(unix))]
fn write_owner_only(path: &std::path::Path, bytes: &[u8]) -> Result<(), AuthError> {
    fs::write(path, bytes).map_err(|e| AuthError::StoreError(format!("{}: {e}", path.display())))
}
