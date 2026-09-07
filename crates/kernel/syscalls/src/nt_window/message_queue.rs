//! Live message-queue ordinals: quit, thread posts, replies and waits.
//! Ordinal numbers and the pure decisions live with the win32u decoder.

#[cfg(target_os = "oxide-kernel")]
#[path = "message_queue/live.rs"]
mod live;
#[cfg(target_os = "oxide-kernel")]
pub(crate) use live::{msg_wait, route};
