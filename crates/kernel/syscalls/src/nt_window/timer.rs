//! Window-timer ordinals: arm and disarm `WM_TIMER` and `WM_SYSTIMER` (`31t§4`).

#[path = "timer/raw.rs"]
mod raw;
// The ordinal constants and decode are consumed by the live router only.

#[cfg(target_os = "oxide-kernel")]
#[path = "timer/live.rs"]
mod live;
#[cfg(target_os = "oxide-kernel")]
pub(crate) use live::dispatch;
