// Module manifest: raw ordinal numbers and codecs (raw), the tracking session
// and its message classification (session), the popup-menu window procedure
// decisions (popup_proc), the live popup windows (popup_window), the modal
// tracking loop (track_live), and the live ordinal routing (live).
//! Menu ordinals beyond item editing: the system menu, whole-menu properties,
//! the default and highlighted items, hit testing, tracking and cancellation.

#[path = "menu_raw/raw.rs"]
mod raw;
pub(crate) use raw::*;

#[path = "menu_raw/session.rs"]
pub(crate) mod session;
#[path = "menu_raw/popup_proc.rs"]
pub(crate) mod popup_proc;

#[cfg(target_os = "oxide-kernel")]
#[path = "menu_raw/entry.rs"]
mod entry;
#[cfg(target_os = "oxide-kernel")]
#[path = "menu_raw/popup_window.rs"]
mod popup_window;
#[cfg(target_os = "oxide-kernel")]
#[path = "menu_raw/track_live.rs"]
mod track_live;
#[cfg(target_os = "oxide-kernel")]
#[path = "menu_raw/popup_live.rs"]
mod popup_live;
#[cfg(target_os = "oxide-kernel")]
pub(crate) use popup_live::popup_menu_window_proc;

#[cfg(target_os = "oxide-kernel")]
#[path = "menu_raw/live.rs"]
mod live;
#[cfg(target_os = "oxide-kernel")]
pub(crate) use live::route;
