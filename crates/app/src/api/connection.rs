//! Connecting, live statistics and the log.

use serde::Serialize;

use super::{St, R};
use crate::engine::{LogLine, Poll};

#[tauri::command]
pub async fn connect(st: St<'_>) -> R<()> {
    st.connect().await
}

#[tauri::command]
pub async fn disconnect(st: St<'_>) -> R<()> {
    st.engine.stop().await;
    Ok(())
}

#[tauri::command]
pub async fn poll(st: St<'_>, connections: bool) -> R<Poll> {
    Ok(st.engine.poll(connections).await)
}

#[tauri::command]
pub async fn close_connection(st: St<'_>, id: String) -> R<()> {
    st.engine.close_connection(&id).await
}

#[tauri::command]
pub async fn close_all_connections(st: St<'_>) -> R<()> {
    st.engine.close_all().await
}

#[derive(Serialize)]
pub struct Logs {
    lines: Vec<LogLine>,
    last: u64,
}

#[tauri::command]
pub fn get_logs(st: St<'_>, after: u64) -> Logs {
    let (lines, last) = st.engine.logs_after(after);
    Logs { lines, last }
}

#[tauri::command]
pub fn clear_logs(st: St<'_>) {
    st.engine.clear_logs();
}
