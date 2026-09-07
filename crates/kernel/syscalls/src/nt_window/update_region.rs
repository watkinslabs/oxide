//! Update-region ordinals: validate, invalidate by region, and read or exclude
//! a window's pending update coverage (`31fl§5`).

#[path = "update_region/raw.rs"]
mod raw;

#[cfg(target_os = "oxide-kernel")]
#[path = "update_region/live.rs"]
mod live;
#[cfg(target_os = "oxide-kernel")]
pub(crate) use live::route;
