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
pub(crate) use live::{cancel_thread, process_for_current, PendingHardware, Selected, Stage};

#[cfg(all(target_os = "oxide-kernel", feature = "debug-winpump"))]
#[path = "hardware/trace_on.rs"]
mod trace;
#[cfg(all(target_os = "oxide-kernel", not(feature = "debug-winpump")))]
#[path = "hardware/trace_off.rs"]
mod trace;

#[cfg(target_os = "oxide-kernel")]
#[path = "hardware/delivery.rs"]
mod delivery;
#[cfg(target_os = "oxide-kernel")]
pub(crate) use delivery::{deliver_for_current, note_get};
