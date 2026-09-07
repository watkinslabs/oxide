// Module manifest: retrieval-time hardware-message processing.
//   context.rs — resolve the ladder's inputs against canonical window state
//   live.rs    — drive the ladder, suspending at every window-procedure call
#[cfg(target_os = "oxide-kernel")]
#[path = "hardware/context.rs"]
mod context;
#[cfg(target_os = "oxide-kernel")]
#[path = "hardware/live.rs"]
mod live;
#[cfg(target_os = "oxide-kernel")]
pub(crate) use live::{cancel_thread, process_for_current, PendingHardware, Stage};
