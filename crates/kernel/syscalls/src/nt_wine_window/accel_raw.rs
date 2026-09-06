//! Raw accelerator syscalls: table lifetime and keystroke translation.
use ipc::win32_accel::{self, Accel, ACCEL_BYTES};

pub(crate) const COPY_TABLE: u64 = 0x135a;
pub(crate) const CREATE_TABLE: u64 = 0x135c;
pub(crate) const DESTROY_TABLE: u64 = 0x137b;
pub(crate) const TRANSLATE: u64 = 0x15d7;
/// Stable MSG prefix: hwnd, message, wParam, lParam.
pub(crate) const MSG_PREFIX_BYTES: usize = 32;
pub(crate) const MAX_TABLE_ENTRIES: usize = 4096;
pub(crate) const VK_SHIFT: u32 = 0x10;
pub(crate) const VK_CONTROL: u32 = 0x11;
pub(crate) const VK_MENU: u32 = 0x12;
const KEY_DOWN: u64 = 0x8000;
pub(crate) const WM_COMMAND: u32 = 0x0111;
pub(crate) const WM_SYSCOMMAND: u32 = 0x0112;
pub(crate) const WM_INITMENU: u32 = 0x0116;
pub(crate) const WM_INITMENUPOPUP: u32 = 0x0117;
const COMMAND_FROM_ACCELERATOR: u64 = 0x10000;
const WS_CHILD: u32 = 0x4000_0000;
const WS_MINIMIZE: u32 = 0x2000_0000;
const WS_DISABLED: u32 = 0x0800_0000;
const MF_GRAYED: u32 = 1;
const MF_DISABLED: u32 = 2;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Msg { pub hwnd: u64, pub message: u32, pub wparam: u64, pub lparam: u64 }

impl Msg {
    pub(crate) fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < MSG_PREFIX_BYTES { return None; }
        let u64_at = |o: usize| u64::from_le_bytes(bytes[o..o + 8].try_into().unwrap());
        Some(Self { hwnd: u64_at(0), message: u32::from_le_bytes(bytes[8..12].try_into().unwrap()), wparam: u64_at(16), lparam: u64_at(24) })
    }
}

/// Packed ACCEL array → entries; a count below one is a parameter error. # C: O(count)
pub(crate) fn decode_table(bytes: &[u8], count: i64) -> Option<alloc::vec::Vec<Accel>> {
    let count = usize::try_from(count).ok().filter(|c| (1..=MAX_TABLE_ENTRIES).contains(c))?;
    bytes.chunks_exact(ACCEL_BYTES).take(count).map(Accel::decode).collect::<Option<alloc::vec::Vec<_>>>().filter(|v| v.len() == count)
}

/// FSHIFT/FCONTROL/FALT from the three modifier key states. # C: O(1)
pub(crate) fn modifiers(key_state: impl Fn(u32) -> u64) -> u8 {
    let mut mask = 0;
    if key_state(VK_CONTROL) & KEY_DOWN != 0 { mask |= win32_accel::FCONTROL; }
    if key_state(VK_MENU) & KEY_DOWN != 0 { mask |= win32_accel::FALT; }
    if key_state(VK_SHIFT) & KEY_DOWN != 0 { mask |= win32_accel::FSHIFT; }
    mask
}

/// Where a matched command lives relative to the target window's menu bar.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MenuPlacement { NotInMenu, InBar, InPopup { submenu: u32, position: u32 } }

/// Everything the send decision needs about the window and its menu.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Target { pub style: u32, pub captured: bool, pub menu: u32, pub placement: MenuPlacement, pub item_state: u32 }

/// Messages to send, in order, once a table entry matched. An empty list is
/// still a consumed keystroke (the reference returns TRUE with a reason code).
/// # C: O(1)
pub(crate) fn plan(cmd: u16, target: Target) -> alloc::vec::Vec<(u32, u64, u64)> {
    let mut sends = alloc::vec::Vec::new();
    let command = || (WM_COMMAND, COMMAND_FROM_ACCELERATOR | u64::from(cmd), 0);
    if target.placement == MenuPlacement::NotInMenu { sends.push(command()); return sends; }
    if target.captured || target.style & WS_DISABLED != 0 { return sends; }
    let menu = if target.style & WS_CHILD != 0 { 0 } else { u64::from(target.menu) };
    sends.push((WM_INITMENU, menu, 0));
    if let MenuPlacement::InPopup { submenu, position } = target.placement { sends.push((WM_INITMENUPOPUP, u64::from(submenu), u64::from(position))); }
    if target.style & WS_MINIMIZE != 0 || target.item_state & (MF_DISABLED | MF_GRAYED) != 0 { return sends; }
    sends.push(command());
    sends
}

#[cfg(target_os = "oxide-kernel")]
#[path = "accel_raw/kernel.rs"]
pub(crate) mod kernel;
#[cfg(test)]
#[path = "tests/accel_raw.rs"]
mod tests;
