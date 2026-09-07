//! Live drag-detect, drag-transfer and process input-idle ordinals. Ordinal
//! numbers and the pure decisions live with the win32u decoder.

#[cfg(target_os = "oxide-kernel")]
#[path = "drag/live.rs"]
mod live;
#[cfg(target_os = "oxide-kernel")]
pub(crate) use live::{mark_idle_for_current, route};
