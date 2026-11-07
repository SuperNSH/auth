//! Where sessions live: under the user's home, in a directory only they can
//! enter (0700), so the crate's 0600 files are never world-reachable.

use std::path::PathBuf;

/// The directory the crate's `JsonFileStore` keeps its per-provider files in
/// (`<dir>/<provider>.json`; the dir argument is what `JsonFileStore::new`
/// takes).
pub(crate) fn sessions_dir() -> PathBuf {
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
