//! Ordinal decode: each entry is one shape of redraw request or update query.
use ipc::win32_window::{RDW_ALLCHILDREN, RDW_ERASE, RDW_ERASENOW, RDW_FRAME, RDW_INVALIDATE, RDW_VALIDATE};

pub(crate) const EXCLUDE_UPDATE_RGN: u64 = 0x13c3;
pub(crate) const GET_UPDATE_RECT: u64 = 0x1455;
pub(crate) const GET_UPDATE_RGN: u64 = 0x1456;
pub(crate) const INVALIDATE_RECT: u64 = 0x148c;
pub(crate) const INVALIDATE_RGN: u64 = 0x148d;
pub(crate) const VALIDATE_RECT: u64 = 0x15f1;
pub(crate) const VALIDATE_RGN: u64 = 0x15f2;

/// Reported when a region entry names no window. A rectangle entry instead
/// treats the absent window as the whole desktop.
pub(crate) const ERROR_INVALID_WINDOW_HANDLE: u32 = 1400;
/// A rectangle entry naming no window repaints the whole desktop tree at
/// once, whichever direction the entry asked for.
pub(crate) const DESKTOP_REDRAW_FLAGS: u32 = RDW_ALLCHILDREN | RDW_INVALIDATE | RDW_FRAME | RDW_ERASE | RDW_ERASENOW;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) enum Request {
    /// A rectangle or region redraw of one window; `hwnd` zero means the desktop.
    Redraw { hwnd: u64, rect: u64, region: u64, flags: u32 },
    /// A region entry naming no window reports the invalid-handle error.
    NoWindow,
    ReadUpdateRect { hwnd: u64, rect: u64, erase: bool },
    ReadUpdateRgn { hwnd: u64, region: u64, erase: bool },
    ExcludeUpdate { dc: u64, hwnd: u64 },
}

/// # C: O(1)
pub(crate) fn decode(ordinal: u64, args: [u64; 3]) -> Option<Request> {
    let erase = args[2] != 0;
    match ordinal {
        VALIDATE_RECT if args[0] == 0 => Some(Request::Redraw { hwnd: 0, rect: 0, region: 0, flags: DESKTOP_REDRAW_FLAGS }),
        VALIDATE_RECT => Some(Request::Redraw { hwnd: args[0], rect: args[1], region: 0, flags: RDW_VALIDATE }),
        VALIDATE_RGN if args[0] == 0 => Some(Request::NoWindow),
        VALIDATE_RGN => Some(Request::Redraw { hwnd: args[0], rect: 0, region: args[1], flags: RDW_VALIDATE }),
        INVALIDATE_RECT if args[0] == 0 => Some(Request::Redraw { hwnd: 0, rect: 0, region: 0, flags: DESKTOP_REDRAW_FLAGS }),
        INVALIDATE_RECT => Some(Request::Redraw { hwnd: args[0], rect: args[1], region: 0,
            flags: RDW_INVALIDATE | if erase { RDW_ERASE } else { 0 } }),
        INVALIDATE_RGN if args[0] == 0 => Some(Request::NoWindow),
        INVALIDATE_RGN => Some(Request::Redraw { hwnd: args[0], rect: 0, region: args[1],
            flags: RDW_INVALIDATE | if erase { RDW_ERASE } else { 0 } }),
        GET_UPDATE_RECT => Some(Request::ReadUpdateRect { hwnd: args[0], rect: args[1], erase }),
        GET_UPDATE_RGN => Some(Request::ReadUpdateRgn { hwnd: args[0], region: args[1], erase }),
        EXCLUDE_UPDATE_RGN => Some(Request::ExcludeUpdate { dc: args[0], hwnd: args[1] }),
        _ => None,
    }
}

#[cfg(test)]
#[path = "../tests/update_region_raw.rs"]
mod tests;
