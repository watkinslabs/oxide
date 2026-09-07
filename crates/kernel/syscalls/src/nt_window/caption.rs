//! Caption-bar drawing helper (`NtUserDrawCaptionTemp`).

#[path = "caption/raw.rs"]
mod raw;

#[cfg(target_os = "oxide-kernel")]
#[path = "caption/live.rs"]
mod live;
#[cfg(target_os = "oxide-kernel")]
pub(crate) use live::route;
