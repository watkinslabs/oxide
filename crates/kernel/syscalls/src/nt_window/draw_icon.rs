//! Live icon and cursor drawing. The ordinal number and the pass plan live
//! with the win32u decoder.

#[cfg(target_os = "oxide-kernel")]
#[path = "draw_icon/live.rs"]
mod live;
#[cfg(target_os = "oxide-kernel")]
pub(crate) use live::route;
