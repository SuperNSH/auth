//! Time, injectable so tests run on a manual clock.

use std::time::{SystemTime, UNIX_EPOCH};

/// Milliseconds since the Unix epoch. Implemented by hosts' clocks too.
pub trait Clock: Send + Sync + 'static {
    fn now_ms(&self) -> i64;
}

/// The wall clock.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_ms(&self) -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or_default()
    }
}
