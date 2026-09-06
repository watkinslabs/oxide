//! Width-normalized window-long setters and Win32 result encoding.
use ipc::win32_window::LongPtrError;
pub(crate) const SET_LONG: u64 = 0x15a3;
pub(crate) const SET_PTR: u64 = 0x15a4;
pub(crate) const SET_WORD: u64 = 0x15ad;
const ERROR_INVALID_PARAMETER: u32 = 87;
const ERROR_INVALID_WINDOW_HANDLE: u32 = 1400;
const ERROR_INVALID_INDEX: u32 = 1413;
const ERROR_NOT_ENOUGH_MEMORY: u32 = 8;
const ERROR_CALL_NOT_IMPLEMENTED: u32 = 120;
const GWLP_USERDATA: i32 = -21;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SetRequest { pub hwnd: u64, pub index: i32, pub width: usize, pub value: u64, pub ansi: bool }

/// Decode only claimed setters; unused arguments never affect admission. # C: O(1)
pub(crate) fn decode(ordinal: u64, args: [u64; 4]) -> Option<SetRequest> {
    let width = match ordinal { SET_LONG => 4, SET_PTR => 8, SET_WORD => 2, _ => return None };
    let value = match width { 2 => args[2] as u16 as u64, 4 => args[2] as u32 as i32 as i64 as u64, _ => args[2] };
    Some(SetRequest { hwnd: args[0], index: args[1] as u32 as i32, width, value, ansi: width == 2 || args[3] as u32 != 0 })
}

/// Encode failure separately from successful zero; success retains caller LastError. # C: O(1)
pub(crate) fn finish(result: Result<u64, LongPtrError>, width: usize, mut last_error: impl FnMut(u32)) -> u64 {
    match result {
        Ok(value) => match width { 2 => value as u16 as u64, 4 => value as u32 as u64, _ => value },
        Err(error) => {
            last_error(match error {
                LongPtrError::InvalidWindow => ERROR_INVALID_WINDOW_HANDLE,
                LongPtrError::InvalidIndex => ERROR_INVALID_INDEX,
                LongPtrError::InvalidSize => ERROR_INVALID_PARAMETER,
                LongPtrError::NoMemory => ERROR_NOT_ENOUGH_MEMORY,
                LongPtrError::OwnerTransaction => ERROR_CALL_NOT_IMPLEMENTED,
            });
            0
        }
    }
}

/// Preserve pre-owner rejection ordering, then invoke exactly one canonical mutation.
/// # C: O(owner work)
pub(crate) fn set_with(request: SetRequest, set: impl FnOnce(SetRequest) -> Result<u64, LongPtrError>,
    mut last_error: impl FnMut(u32)) -> u64 {
    if request.width == 2 && request.index < 0 && request.index != GWLP_USERDATA {
        last_error(ERROR_INVALID_INDEX); return 0;
    }
    if request.hwnd == 0xffff || request.hwnd == u64::MAX {
        last_error(ERROR_INVALID_PARAMETER); return 0;
    }
    finish(set(request), request.width, last_error)
}

#[cfg(target_os = "oxide-kernel")]
#[path = "long_raw/kernel.rs"]
mod kernel;
#[cfg(target_os = "oxide-kernel")]
pub(crate) use kernel::{dispatch, get};

#[cfg(test)]
#[path = "long_raw/tests.rs"]
mod tests;
