//! Class-long ABI. Reads arrive as `NtUserCallHwndParam` methods, writes as
//! their own three ordinals; both name the same canonical class record and
//! share the window-long error encoding.
use ipc::win32_window::LongPtrError;
use crate::nt_win32_long_error::finish;

pub(crate) const SET_CLASS_LONG: u64 = 0x153e;
pub(crate) const SET_CLASS_LONG_PTR: u64 = 0x153f;
pub(crate) const SET_CLASS_WORD: u64 = 0x1540;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ClassLong { pub hwnd: u64, pub offset: i32, pub width: usize, pub ansi: bool }

/// Decode one class-long write, normalising the value to the written width.
/// # C: O(1)
pub(crate) fn decode_set(ordinal: u64, args: [u64; 4]) -> Option<(ClassLong, u64)> {
    let (width, ansi) = match ordinal {
        SET_CLASS_LONG => (4, args[3] as u32 != 0),
        SET_CLASS_LONG_PTR => (8, args[3] as u32 != 0),
        SET_CLASS_WORD => (2, true),
        _ => return None,
    };
    let value = match width { 2 => args[2] as u16 as u64, 4 => args[2] as u32 as i32 as i64 as u64, _ => args[2] };
    Some((ClassLong { hwnd: args[0], offset: args[1] as u32 as i32, width, ansi }, value))
}

/// Run one class-long access against the canonical owner and encode its answer.
/// # C: O(owner work)
pub(crate) fn access_with(request: ClassLong, access: impl FnOnce(ClassLong) -> Result<u64, LongPtrError>,
    last_error: impl FnMut(u32)) -> u64 {
    finish(access(request), request.width, last_error)
}

#[cfg(target_os = "oxide-kernel")]
#[path = "class_raw/kernel.rs"]
mod kernel;
#[cfg(target_os = "oxide-kernel")]
pub(crate) use kernel::{dispatch_set, get};

#[cfg(test)]
#[path = "tests/class_raw.rs"]
mod tests;
