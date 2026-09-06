//! Class-long ABI. Reads arrive as `NtUserCallHwndParam` methods, writes as
//! their own three ordinals; both name the same canonical class record and
//! share the window-long error encoding.
use ipc::win32_window::LongPtrError;
use crate::nt_win32_long_error::finish;

pub(crate) const SET_CLASS_LONG: u64 = 0x153e;
pub(crate) const SET_CLASS_LONG_PTR: u64 = 0x153f;
pub(crate) const SET_CLASS_WORD: u64 = 0x1540;

/// `NtUserCallHwndParam` methods, in the client enum's order.
pub(crate) const GET_CLASS_LONG_A: u32 = 2;
pub(crate) const GET_CLASS_LONG_W: u32 = 3;
pub(crate) const GET_CLASS_LONG_PTR_A: u32 = 4;
pub(crate) const GET_CLASS_LONG_PTR_W: u32 = 5;
pub(crate) const GET_CLASS_WORD: u32 = 6;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ClassLong { pub hwnd: u64, pub offset: i32, pub width: usize, pub ansi: bool }

/// Decode one class-long read; every other method belongs to another owner.
/// # C: O(1)
pub(crate) fn decode_get(method: u32, hwnd: u64, param: u64) -> Option<ClassLong> {
    let (width, ansi) = match method {
        GET_CLASS_LONG_A => (4, true),
        GET_CLASS_LONG_W => (4, false),
        GET_CLASS_LONG_PTR_A => (8, true),
        GET_CLASS_LONG_PTR_W => (8, false),
        GET_CLASS_WORD => (2, true),
        _ => return None,
    };
    Some(ClassLong { hwnd, offset: param as u32 as i32, width, ansi })
}

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
