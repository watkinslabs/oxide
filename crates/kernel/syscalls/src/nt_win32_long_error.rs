//! Win32 result encoding shared by the window-long and class-long setters:
//! failure answers zero and names a LastError, success keeps the caller's.
use ipc::win32_window::LongPtrError;

pub(crate) const ERROR_INVALID_PARAMETER: u32 = 87;
pub(crate) const ERROR_INVALID_WINDOW_HANDLE: u32 = 1400;
pub(crate) const ERROR_INVALID_INDEX: u32 = 1413;
pub(crate) const ERROR_NOT_ENOUGH_MEMORY: u32 = 8;
pub(crate) const ERROR_CALL_NOT_IMPLEMENTED: u32 = 120;

/// # C: O(1)
pub(crate) const fn win32_error(error: LongPtrError) -> u32 {
    match error {
        LongPtrError::InvalidWindow => ERROR_INVALID_WINDOW_HANDLE,
        LongPtrError::InvalidIndex => ERROR_INVALID_INDEX,
        LongPtrError::InvalidSize => ERROR_INVALID_PARAMETER,
        LongPtrError::NoMemory => ERROR_NOT_ENOUGH_MEMORY,
        LongPtrError::OwnerTransaction => ERROR_CALL_NOT_IMPLEMENTED,
    }
}

/// Encode failure separately from successful zero. # C: O(1)
pub(crate) fn finish(result: Result<u64, LongPtrError>, width: usize, mut last_error: impl FnMut(u32)) -> u64 {
    match result {
        Ok(value) => match width { 2 => value as u16 as u64, 4 => value as u32 as u64, _ => value },
        Err(error) => { last_error(win32_error(error)); 0 }
    }
}

#[cfg(test)]
#[path = "nt_win32_long_error/tests.rs"]
mod tests;
