//! Menu ordinals beyond item editing: the system menu, whole-menu properties,
//! the default and highlighted items, hit testing, tracking and cancellation.

#[path = "menu_raw/raw.rs"]
mod raw;
pub(crate) use raw::*;

#[cfg(target_os = "oxide-kernel")]
#[path = "menu_raw/live.rs"]
mod live;
#[cfg(target_os = "oxide-kernel")]
pub(crate) use live::route;
