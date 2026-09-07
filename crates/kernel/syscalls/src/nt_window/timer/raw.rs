//! Ordinal decode and result encoding for the four window-timer entries.
use ipc::win32_window::{WM_SYSTIMER, WM_TIMER};

pub(crate) const SET_ORDINAL: u64 = 0x1594;
pub(crate) const SET_SYSTEM_ORDINAL: u64 = 0x158b;
pub(crate) const KILL_ORDINAL: u64 = 0x149b;
pub(crate) const KILL_SYSTEM_ORDINAL: u64 = 0x149a;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) enum Request {
    /// `proc` is the client `TIMERPROC`, delivered as the `WM_TIMER` lparam.
    Arm { hwnd: u64, message: u32, id: u64, timeout_ms: u32, proc: u64 },
    Disarm { hwnd: u64, message: u32, id: u64 },
}

/// The system-timer entries carry no procedure and no tolerance. # C: O(1)
pub(crate) fn decode(ordinal: u64, args: [u64; 5]) -> Option<Request> {
    match ordinal {
        SET_ORDINAL => Some(Request::Arm { hwnd: args[0], message: WM_TIMER, id: args[1], timeout_ms: args[2] as u32, proc: args[3] }),
        SET_SYSTEM_ORDINAL => Some(Request::Arm { hwnd: args[0], message: WM_SYSTIMER, id: args[1], timeout_ms: args[2] as u32, proc: 0 }),
        KILL_ORDINAL => Some(Request::Disarm { hwnd: args[0], message: WM_TIMER, id: args[1] }),
        KILL_SYSTEM_ORDINAL => Some(Request::Disarm { hwnd: args[0], message: WM_SYSTIMER, id: args[1] }),
        _ => None,
    }
}

/// An armed timer reports its id; an id of zero reports plain success instead,
/// which is what a windowed arm naming id zero produces. # C: O(1)
pub(crate) const fn arm_result(id: u64) -> u64 { if id == 0 { 1 } else { id } }

#[cfg(test)]
#[path = "../tests/timer_raw.rs"]
mod tests;
