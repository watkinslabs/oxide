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
// The messages a translated accelerator sends, and the styles and item states
// it reads, are the menu and window subsystems' own numbers: this path reads
// them from their owners rather than restating them.
pub(crate) use ipc::win32_menu::track::{WM_COMMAND, WM_INITMENUPOPUP, WM_SYSCOMMAND};
pub(crate) use ipc::win32_menu::track_loop::WM_INITMENU;
pub(crate) use ipc::win32_menu::{MF_DISABLED, MF_GRAYED};
pub(crate) use ipc::win32_window::styles::{WS_CHILD, WS_DISABLED, WS_MINIMIZE};
const COMMAND_FROM_ACCELERATOR: u64 = 0x10000;
/// The high word of `WM_INITMENUPOPUP`'s lParam, and of the system command's,
/// marks the menu the command came out of as the window's system menu.
const SYSTEM_MENU_MARK: u64 = 0x0001_0000;

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

/// Which of a window's two menus a matched command was found in. The system
/// menu is searched first and its commands reach the procedure as system
/// commands, so a window's own command ids can never shadow them.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MenuOwner { Client, System }

/// Where a matched command lives relative to the target window's menus.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MenuPlacement { NotInMenu, InBar(MenuOwner), InPopup { owner: MenuOwner, submenu: u32, position: u32 } }

impl MenuPlacement {
    /// The menu a found command sits in, and the submenu that has to be
    /// initialised before it is sent. # C: O(1)
    const fn found(self) -> Option<(MenuOwner, Option<(u32, u32)>)> {
        match self {
            Self::NotInMenu => None,
            Self::InBar(owner) => Some((owner, None)),
            Self::InPopup { owner, submenu, position } => Some((owner, Some((submenu, position)))),
        }
    }
}

/// Everything the send decision needs about the window and its menus.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Target { pub style: u32, pub captured: bool, pub menu: u32, pub sys_menu: u32,
    pub placement: MenuPlacement, pub item_state: u32 }

/// Find one command in one menu, one level of submenus deep, and report where
/// it sits and what state its item carries. # C: O(N_items * N_submenu_items)
pub(crate) fn locate(menus: &ipc::win32_menu::MenuManager, root: Option<u32>, cmd: u32, owner: MenuOwner) -> Option<(MenuPlacement, u32)> {
    let root_id = ipc::win32_menu::MenuId::from_raw(root?)?;
    if let Ok(item) = menus.item(root_id, cmd, 0) { return Some((MenuPlacement::InBar(owner), item.state)); }
    let count = menus.count(root_id).ok()?;
    for position in 0..count {
        let Ok(top) = menus.item(root_id, position as u32, ipc::win32_menu::MF_BYPOSITION) else { continue; };
        let Some(sub) = top.submenu.and_then(ipc::win32_menu::MenuId::from_raw) else { continue; };
        if let Ok(item) = menus.item(sub, cmd, 0) {
            return Some((MenuPlacement::InPopup { owner, submenu: sub.raw(), position: position as u32 }, item.state));
        }
    }
    None
}

/// Messages to send, in order, once a table entry matched. An empty list is
/// still a consumed keystroke (the reference returns TRUE with a reason code).
/// A command no menu carries goes straight to the procedure; one a menu
/// carries has that menu initialised first, and a command out of the system
/// menu reaches the procedure as a system command instead of an ordinary one.
/// A disabled window sends nothing; a captured mouse still initialises the
/// menu but withholds the command; the iconic rule guards the window's own
/// commands only. # C: O(1)
pub(crate) fn plan(cmd: u16, target: Target) -> alloc::vec::Vec<(u32, u64, u64)> {
    let mut sends = alloc::vec::Vec::new();
    let Some((owner, popup)) = target.placement.found() else {
        sends.push((WM_COMMAND, COMMAND_FROM_ACCELERATOR | u64::from(cmd), 0));
        return sends;
    };
    if target.style & WS_DISABLED != 0 { return sends; }
    let system = matches!(owner, MenuOwner::System);
    let menu = if system { u64::from(target.sys_menu) }
        else if target.style & WS_CHILD != 0 { 0 } else { u64::from(target.menu) };
    sends.push((WM_INITMENU, menu, 0));
    if let Some((submenu, position)) = popup {
        sends.push((WM_INITMENUPOPUP, u64::from(submenu), u64::from(position) | if system { SYSTEM_MENU_MARK } else { 0 }));
    }
    if target.captured { return sends; }
    if target.item_state & (MF_DISABLED | MF_GRAYED) != 0 { return sends; }
    if system { sends.push((WM_SYSCOMMAND, u64::from(cmd), SYSTEM_MENU_MARK)); return sends; }
    if target.style & WS_MINIMIZE != 0 { return sends; }
    sends.push((WM_COMMAND, COMMAND_FROM_ACCELERATOR | u64::from(cmd), 0));
    sends
}

#[cfg(target_os = "oxide-kernel")]
#[path = "accel_raw/kernel.rs"]
pub(crate) mod kernel;
#[cfg(test)]
#[path = "tests/accel_raw.rs"]
mod tests;
