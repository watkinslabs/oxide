//! Erase-only resources owned by the existing paint callback continuation.
use ipc::win32_gdi::PaintBacking;
#[derive(Clone, Copy, Debug)]
pub(crate) struct ErasePrepared {
    pub hwnd: u32, pub dc: u32, pub nc_region: u32, pub client_region: u32,
    pub tid: u64, pub redraw_token: u64, pub layout: PaintBacking,
}
#[cfg(target_os = "oxide-kernel")]
#[path = "erase_live.rs"]
mod live;
#[cfg(target_os = "oxide-kernel")]
pub(crate) use live::{begin_for_current, finish_for_current, discard_for_current};
