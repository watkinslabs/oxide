//! `NtUserCallOneParam` multiplexer: one argument, one code, sixteen codes.
//!
//! Every code the reference defines is answered. An unknown code answers zero
//! and nothing else — the result word is used directly as a brush, a pen, a
//! metric or a previous DPI context, so an `NTSTATUS` in that position is read
//! as a valid object and is never what the reference does.
extern crate alloc;
use alloc::vec::Vec;

pub(crate) const ORDINAL: u64 = 0x133d;

/// The answer an unrecognised code carries. # C: O(1)
pub(crate) const UNHANDLED: u64 = 0;

/// Every code the multiplexer defines, in the reference's order. The
/// discriminant is the wire code.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub(crate) enum Code {
    CreateCursorIcon = 0,
    EnableDc = 1,
    EnableThunkLock = 2,
    GetIconParam = 3,
    GetMenuItemCount = 4,
    GetPrimaryMonitorRect = 5,
    GetSysColor = 6,
    GetSysColorBrush = 7,
    GetSysColorPen = 8,
    GetSystemMetrics = 9,
    GetVirtualScreenRect = 10,
    SetKeyboardAutoRepeat = 11,
    SetThreadDpiAwarenessContext = 12,
    D3dkmtOpenAdapterFromGdiDisplayName = 13,
    GetAsyncKeyboardState = 14,
    GetDeskPattern = 15,
}

/// The codes the multiplexer defines, in wire order.
pub(crate) const CODES: [Code; 16] = [
    Code::CreateCursorIcon, Code::EnableDc, Code::EnableThunkLock, Code::GetIconParam,
    Code::GetMenuItemCount, Code::GetPrimaryMonitorRect, Code::GetSysColor, Code::GetSysColorBrush,
    Code::GetSysColorPen, Code::GetSystemMetrics, Code::GetVirtualScreenRect, Code::SetKeyboardAutoRepeat,
    Code::SetThreadDpiAwarenessContext, Code::D3dkmtOpenAdapterFromGdiDisplayName, Code::GetAsyncKeyboardState,
    Code::GetDeskPattern,
];

/// # C: O(1)
pub(crate) fn code(value: u64) -> Option<Code> { CODES.get(value as u32 as usize).copied() }

/// Characters the desktop-pattern query buffer carries.
pub(crate) const DESK_PATTERN_CHARS: usize = 256;

/// `D3DKMT_OPENADAPTERFROMGDIDISPLAYNAME`: a 32-character device name, then
/// the adapter handle, the adapter LUID and the video-present source id.
pub(crate) const D3DKMT_NAME_CHARS: usize = 32;
pub(crate) const D3DKMT_ADAPTER_OFFSET: u64 = (D3DKMT_NAME_CHARS * 2) as u64;
pub(crate) const D3DKMT_LUID_OFFSET: u64 = D3DKMT_ADAPTER_OFFSET + 4;
pub(crate) const D3DKMT_SOURCE_ID_OFFSET: u64 = D3DKMT_LUID_OFFSET + 8;
pub(crate) const D3DKMT_BYTES: usize = (D3DKMT_SOURCE_ID_OFFSET + 4) as usize;
/// The display-device name every adapter query is matched against.
const DISPLAY_PREFIX: &[u8] = b"\\\\.\\DISPLAY";

/// The one-based display index a `\\.\DISPLAYn` device name names. Anything
/// else names no adapter. # C: O(N_name)
pub(crate) fn display_index(name: &[u16]) -> Option<u32> {
    let name: Vec<u8> = name.iter().take_while(|unit| **unit != 0).map(|unit| u8::try_from(*unit).unwrap_or(0)).collect();
    let digits = name.strip_prefix(DISPLAY_PREFIX)?;
    if digits.is_empty() || !digits.iter().all(|byte| byte.is_ascii_digit()) { return None; }
    digits.iter().try_fold(0u32, |value, byte| value.checked_mul(10)?.checked_add(u32::from(byte - b'0')))
        .filter(|index| *index != 0)
}

/// The adapter record one display index answers: the adapter handle, its LUID
/// and the video-present source the display is driven from. The kernel owns
/// one adapter, so every display is a source on it and the handle is the
/// one-based index. # C: O(1)
pub(crate) fn adapter_record(index: u32, adapter_luid: u64) -> [u8; D3DKMT_BYTES] {
    let mut record = [0u8; D3DKMT_BYTES];
    let at = |record: &mut [u8; D3DKMT_BYTES], offset: u64, bytes: &[u8]| {
        record[offset as usize..offset as usize + bytes.len()].copy_from_slice(bytes);
    };
    at(&mut record, D3DKMT_ADAPTER_OFFSET, &index.to_le_bytes());
    at(&mut record, D3DKMT_LUID_OFFSET, &adapter_luid.to_le_bytes());
    at(&mut record, D3DKMT_SOURCE_ID_OFFSET, &(index - 1).to_le_bytes());
    record
}

#[cfg(target_os = "oxide-kernel")]
#[path = "one_param/kernel.rs"]
pub(crate) mod kernel;
#[cfg(test)]
#[path = "tests/one_param.rs"]
mod tests;
