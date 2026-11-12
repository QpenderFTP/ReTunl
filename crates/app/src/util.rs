//! Small helpers the whole app uses.

use std::sync::{Mutex, MutexGuard};

/// Lock a mutex. A thread that panicked while holding it does not take the
/// data with it: the next one goes on with what is there.
pub fn locked<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// Run work that waits (a process, a dialog, the disk) off the async threads.
pub async fn blocking<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> Result<T, String> {
    tokio::task::spawn_blocking(f).await.map_err(|e| e.to_string())
}
