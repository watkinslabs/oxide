//! Module manifest: bounded paint preparation state and live Send continuation.
#[path="paint_callbacks/work.rs"] mod work;
pub(crate) use work::*;

#[cfg(target_os = "oxide-kernel")]
#[path = "paint_callbacks/live.rs"]
mod live;
#[cfg(target_os = "oxide-kernel")]
pub(crate) use live::{for_current, resume, cancel_current_thread, cancel_window_current, dispose_for_current, reap_retired_current};
