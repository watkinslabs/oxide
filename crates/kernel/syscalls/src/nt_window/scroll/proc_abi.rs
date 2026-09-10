//! Scrollbar procedure and drawing callback ABI.
use ipc::win32_gdi::{Rect, ScrollLayout};
pub(crate) const WNDPROC_SELECTOR: u64 = 0x029a;
pub(crate) const DRAW_CALLBACK: u32 = 8;
pub(crate) const PAINT_COMPLETION: u64 = 0x80;
pub(crate) const REFRESH_COMPLETION: u64 = 0x81;
pub(crate) const WM_ENABLE: u32 = 0xa;
pub(crate) const DRAW_BYTES: usize = 104;
pub(crate) const SBS_VERT: u32 = 1;
pub(crate) const SBS_TOP_LEFT: u32 = 2;
pub(crate) const SBS_BOTTOM_RIGHT: u32 = 4;
pub(crate) const SBS_SIZEBOX: u32 = 8;
pub(crate) const SBS_SIZEGRIP: u32 = 16;
pub(crate) const WM_CREATE: u32 = 1;
pub(crate) const WM_ERASEBKGND: u32 = 0x14;
pub(crate) const WM_GETDLGCODE: u32 = 0x87;
pub(crate) const DLGC_WANTARROWS: u64 = 1;
pub(crate) const SC_SIZE: u64 = 0xf000;
pub(crate) const WMSZ_BOTTOMLEFT: u64 = 7;
pub(crate) const WMSZ_BOTTOMRIGHT: u64 = 8;
pub(crate) const SM_CXVSCROLL: i32 = 2;
pub(crate) const SM_CYHSCROLL: i32 = 3;
pub(crate) const SBM_GETPOS: u32 = 0xe1;
pub(crate) const SBM_GETRANGE: u32 = 0xe3;
pub(crate) const SBM_GETSCROLLINFO: u32 = 0xea;
pub(crate) const WM_HSCROLL:u32=0x114;
pub(crate) const WM_VSCROLL:u32=0x115;
pub(crate) const KEY_PREVIOUS_STATE:u64=1<<30;
const VK_PRIOR:u64=0x21;const VK_NEXT:u64=0x22;const VK_END:u64=0x23;const VK_HOME:u64=0x24;
const VK_LEFT:u64=0x25;const VK_UP:u64=0x26;const VK_RIGHT:u64=0x27;const VK_DOWN:u64=0x28;
const SB_LINEUP:u64=0;const SB_LINEDOWN:u64=1;const SB_PAGEUP:u64=2;const SB_PAGEDOWN:u64=3;const SB_TOP:u64=6;const SB_BOTTOM:u64=7;
/// Keyboard directions report logical line/page actions independently of orientation. # C: O(1)
pub(crate) fn key_scroll(key:u64)->Option<u64>{match key{
    VK_PRIOR=>Some(SB_PAGEUP),VK_NEXT=>Some(SB_PAGEDOWN),VK_HOME=>Some(SB_TOP),VK_END=>Some(SB_BOTTOM),
    VK_UP|VK_LEFT=>Some(SB_LINEUP),VK_DOWN|VK_RIGHT=>Some(SB_LINEDOWN),_=>None,
}}

/// The full callback record, including zeroed inactive tracking and tail padding.
/// # C: O(record bytes)
pub(crate) fn draw_record(hwnd: u64, dc: u64, rect: Rect, layout: ScrollLayout, flags: u32, vertical: bool, arrows: bool, interior: bool) -> [u8; DRAW_BYTES] {
    let mut bytes = [0u8; DRAW_BYTES];
    bytes[0..8].copy_from_slice(&hwnd.to_le_bytes()); bytes[8..16].copy_from_slice(&dc.to_le_bytes());
    for (offset, value) in [(16, ipc::win32_window::SB_CTL as u32), (56, arrows as u32), (60, interior as u32),
        (64, rect.left as u32), (68, rect.top as u32), (72, rect.right as u32), (76, rect.bottom as u32),
        (80, flags), (84, layout.arrow_size as u32), (88, layout.thumb_pos as u32),
        (92, layout.thumb_size as u32), (96, vertical as u32)] {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }
    bytes
}

/// Reserved scrollbar messages return zero; the remaining procedure cases are KI-0885.
pub(crate) const RESERVED_MESSAGES: &[u32] = &[0xe5, 0xe7, 0xe8, 0xec, 0xed, 0xee, 0xef];
pub(crate) const PENDING_MESSAGES: &[u32] = &[0x7, 0x8, 0x3d, 0xa0,
    0x118, 0x200, 0x201, 0x202, 0x203, 0x2a2, 0x2a3, 0xe0, 0xe2, 0xe4, 0xe6, 0xe9, 0xeb];

/// Creation alignment is in parent-client coordinates and requests no move without an alignment bit.
/// # C: O(1)
pub(crate) fn aligned_creation(mut rect: ipc::win32_window::WindowRect, style: u32, width: i32, height: i32)
    -> Option<ipc::win32_window::WindowRect> {
    if style & (SBS_TOP_LEFT | SBS_BOTTOM_RIGHT) == 0 { return None; }
    let start = style & SBS_TOP_LEFT != 0;
    if style & (SBS_SIZEBOX | SBS_SIZEGRIP) != 0 {
        if start { rect.right = rect.left.checked_add(width)?; rect.bottom = rect.top.checked_add(height)?; }
        else { rect.left = rect.right.checked_sub(width)?; rect.top = rect.bottom.checked_sub(height)?; }
    } else if style & SBS_VERT != 0 {
        if start { rect.right = rect.left.checked_add(width)?; } else { rect.left = rect.right.checked_sub(width)?; }
    } else if start { rect.bottom = rect.top.checked_add(height)?; }
    else { rect.top = rect.bottom.checked_sub(height)?; }
    Some(rect)
}

#[cfg(test)]
#[path = "tests/proc_abi.rs"]
mod tests;
