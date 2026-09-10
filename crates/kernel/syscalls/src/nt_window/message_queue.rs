//! Live message-queue ordinals: quit, thread posts, replies and waits.
//! Module manifest: live routes ordinals; wait_live owns object/queue waiting;
//! ready applies the same message-class predicate before and during parking.
//! Ordinal numbers and result encoding live with the win32u decoder.

#[cfg(target_os = "oxide-kernel")]
#[path = "message_queue/live.rs"]
mod live;
#[cfg(target_os = "oxide-kernel")]
pub(crate) use live::route;
#[cfg(target_os = "oxide-kernel")]
#[path = "message_queue/wait_live.rs"]
mod wait_live;
#[cfg(target_os = "oxide-kernel")]
pub(crate) use wait_live::msg_wait;
#[cfg(target_os = "oxide-kernel")]
#[path = "message_queue/ready.rs"]
mod ready;
