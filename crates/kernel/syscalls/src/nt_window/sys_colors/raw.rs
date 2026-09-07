//! System-colour set admission. An index outside the role table names no
//! colour and is skipped rather than failing the whole request.
use ipc::win32_gdi::SystemColor;

pub(crate) const ORDINAL: u64 = 0x1586;
/// Broadcast after the colours change so every window repaints.
pub(crate) const WM_SYSCOLORCHANGE: u32 = 0x0015;
/// The redraw that follows the broadcast.
pub(crate) const REPAINT_FLAGS: u32 = ipc::win32_window::RDW_INVALIDATE | ipc::win32_window::RDW_ERASE
    | ipc::win32_window::RDW_UPDATENOW | ipc::win32_window::RDW_ALLCHILDREN;

/// # C: O(1)
pub(crate) fn role(index: i32) -> Option<SystemColor> {
    if index < 0 { return None; }
    SystemColor::from_index(index as u32)
}

/// A count that is not positive names no colour to change. # C: O(1)
pub(crate) const fn admitted(count: i32) -> bool { count > 0 }

#[cfg(test)]
#[path = "../tests/sys_colors_raw.rs"]
mod tests;
