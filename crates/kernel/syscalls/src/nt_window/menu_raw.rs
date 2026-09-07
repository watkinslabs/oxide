// Module manifest: raw ordinal numbers and codecs (raw), the menu bar of a
// window and its two tracking entries (bar), the popup item painting
// (popup_paint), the tracking session
// and its message classification (session), the popup-menu window procedure
// decisions (popup_proc), the live popup windows (popup_window), the modal
// tracking loop driver (track_live), the effects it applies (track_effects), and the live ordinal routing (live).
//! Menu ordinals beyond item editing: the system menu, whole-menu properties,
//! the default and highlighted items, hit testing, tracking and cancellation.

#[path = "menu_raw/raw.rs"]
mod raw;

#[path = "menu_raw/session.rs"]
pub(crate) mod session;
#[path = "menu_raw/popup_proc.rs"]
pub(crate) mod popup_proc;

#[cfg(target_os = "oxide-kernel")]
#[path = "menu_raw/entry.rs"]
mod entry;
#[cfg(target_os = "oxide-kernel")]
pub(crate) use entry::with_entry;
#[cfg(target_os = "oxide-kernel")]
#[path = "menu_raw/bar.rs"]
pub(crate) mod bar;
#[cfg(target_os = "oxide-kernel")]
#[path = "menu_raw/popup_paint.rs"]
mod popup_paint;
#[cfg(target_os = "oxide-kernel")]
pub(crate) use popup_paint::paint_popup_menu_window;
#[cfg(target_os = "oxide-kernel")]
#[path = "menu_raw/popup_window.rs"]
mod popup_window;
#[cfg(target_os = "oxide-kernel")]
#[path = "menu_raw/track_effects.rs"]
mod track_effects;
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
