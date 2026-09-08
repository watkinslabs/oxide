//! `NtUserCallNoParam` multiplexer: the desktop-scoped queries and the two
//! thread-lifetime notifications, selected by a code rather than an ordinal.
//!
//! Every code the reference defines is answered here. An unknown code answers
//! zero — the multiplexer's result is a `ULONG_PTR` the caller uses directly as
//! a window handle or a tick count, so an `NTSTATUS` returned in that position
//! is read as a valid handle and is never what the reference does.

pub(crate) const ORDINAL: u64 = 0x133c;

/// The answer an unrecognised code carries. Zero, never a status: the caller
/// reads this word as a handle or a count.
pub(crate) const UNHANDLED: u64 = 0;

/// Every code the multiplexer defines, in the reference's order. The
/// discriminant is the wire code.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub(crate) enum Code {
    GetDesktopWindow = 0,
    GetDialogBaseUnits = 1,
    GetLastInputTime = 2,
    GetProgmanWindow = 3,
    GetShellWindow = 4,
    GetTaskmanWindow = 5,
    DisplayModeChanged = 6,
    ExitingThread = 7,
    ThreadDetach = 8,
}

/// The codes the multiplexer defines, in wire order.
pub(crate) const CODES: [Code; 9] = [
    Code::GetDesktopWindow, Code::GetDialogBaseUnits, Code::GetLastInputTime, Code::GetProgmanWindow,
    Code::GetShellWindow, Code::GetTaskmanWindow, Code::DisplayModeChanged, Code::ExitingThread, Code::ThreadDetach,
];

/// Decode one wire code. The multiplexer's code argument is a `ULONG`, so the
/// high half of the machine word carries nothing and is not consulted.
/// # C: O(1)
pub(crate) fn code(value: u64) -> Option<Code> { CODES.get(value as u32 as usize).copied() }

/// The dialog base units word: the average character cell scaled to the system
/// DPI, width in the low half-word and height in the high half-word of one
/// DWORD, each truncated to its half-word as the packing does.
///
/// The clamp away from zero is this kernel's, not the reference's: a zero base
/// unit divides by zero in every dialog-unit conversion the client then makes.
/// # C: O(1)
pub(crate) fn dialog_base_units(width: i32, height: i32, dpi: i32) -> u64 {
    let scale = |value: i32| (value.saturating_mul(dpi).checked_div(USER_DEFAULT_SCREEN_DPI).unwrap_or(value).max(1) as u32) & 0xffff;
    (scale(width) as u64) | ((scale(height) as u64) << 16)
}

/// The density every scaled metric is stated against.
pub(crate) const USER_DEFAULT_SCREEN_DPI: i32 = 96;

/// `WM_DISPLAYCHANGE` carries the colour depth in wParam and the packed
/// resolution in lParam. # C: O(1)
pub(crate) fn display_change_lparam(width: u32, height: u32) -> i64 {
    ((width & 0xffff) | ((height & 0xffff) << 16)) as i64
}

#[cfg(target_os = "oxide-kernel")]
#[path = "no_param/kernel.rs"]
pub(crate) mod kernel;
#[cfg(test)]
#[path = "tests/no_param.rs"]
mod tests;
