//! The menu bar inside a window's nonclient area: the height it takes from the
//! client rectangle, the hit-test code its band answers, and the system
//! commands that carry a mouse press or an Alt/F10 key into menu tracking.

pub const HTNOWHERE: i16 = 0;
pub const HTCLIENT: i16 = 1;
pub const HTSYSMENU: i16 = 3;
pub const HTMENU: i16 = 5;

pub const WM_NCLBUTTONDOWN: u32 = 0x00a1;
pub const WM_SYSCOMMAND: u32 = 0x0112;
pub const WM_KEYDOWN: u32 = 0x0100;
pub const WM_KEYUP: u32 = 0x0101;
pub const WM_SYSKEYDOWN: u32 = 0x0104;
pub const WM_SYSKEYUP: u32 = 0x0105;
pub const WM_SYSCHAR: u32 = 0x0106;

pub const SC_MOUSEMENU: u32 = 0xf090;
pub const SC_KEYMENU: u32 = 0xf100;
/// `WM_SYSCOMMAND` reserves the low four bits of wParam for the hit test that
/// produced it.
pub const SC_MASK: u32 = 0xfff0;

pub const VK_SHIFT: u32 = 0x10;
pub const VK_ESCAPE: u32 = 0x1b;
pub const VK_MENU: u32 = 0x12;
pub const VK_LMENU: u32 = 0xa4;
pub const VK_RMENU: u32 = 0xa5;
pub const VK_F10: u32 = 0x79;
/// `SC_KEYMENU` carries the character that names a bar item; a bare Alt or F10
/// press names none, and the space that opens the window menu is its own.
pub const KEYMENU_NO_CHARACTER: u32 = 0;
pub const KEYMENU_SPACE: u32 = b' ' as u32;

/// Only a top-level or popup window carries a menu bar; a child window's menu
/// handle is its control id instead. # C: O(1)
pub const fn window_has_menu_bar(style: u32, ex_style: u32, menu: Option<u32>) -> bool {
    const WS_CHILD: u32 = 0x4000_0000;
    const WS_POPUP: u32 = 0x8000_0000;
    let _ = ex_style;
    style & (WS_CHILD | WS_POPUP) != WS_CHILD && menu.is_some()
}

/// The band a menu bar occupies between the top of the window's nonclient area
/// and the top of its client area. Absent when the window shows no bar or the
/// client already starts at the window's top. # C: O(1)
pub const fn menu_bar_band(window_top: i32, client_top: i32, has_menu: bool) -> Option<(i32, i32)> {
    if !has_menu || client_top <= window_top { return None; }
    Some((window_top, client_top))
}

/// The hit-test code a point takes over a window with a menu bar: the band
/// above the client area, across the client's own width, is the bar; anything
/// else the caller resolves itself. # C: O(1)
pub const fn menu_bar_hit_test(client_left: i32, client_top: i32, client_right: i32, has_menu: bool, x: i32, y: i32) -> Option<i16> {
    if !has_menu || y >= client_top || x < client_left || x >= client_right { return None; }
    Some(HTMENU)
}

/// The system command one nonclient press sends. A press on the bar opens it;
/// a press on the window-menu icon opens the window menu, and carries the hit
/// test that named it. # C: O(1)
pub const fn nc_button_sys_command(hit: i16) -> Option<u32> {
    match hit {
        HTMENU => Some(SC_MOUSEMENU),
        HTSYSMENU => Some(SC_MOUSEMENU + HTSYSMENU as u32),
        _ => None,
    }
}

/// What one system command asks menu tracking to do. # C: O(1)
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum MenuCommand {
    /// Track the bar from the pointer, on the hit test the press carried.
    Mouse { hit: i16 },
    /// Track the bar from the keyboard, opening the item this character names.
    Keyboard { character: u32 },
}

/// Decode one `WM_SYSCOMMAND`. The low bits of wParam are the hit test for a
/// mouse-opened menu and are not part of the command. # C: O(1)
pub const fn menu_sys_command(wparam: u32, lparam: u32) -> Option<MenuCommand> {
    match wparam & SC_MASK {
        SC_MOUSEMENU => Some(MenuCommand::Mouse { hit: (wparam & !SC_MASK) as i16 }),
        SC_KEYMENU => Some(MenuCommand::Keyboard { character: lparam }),
        _ => None,
    }
}

/// The Alt and F10 presses that open a menu bar are recognised on release, so
/// a key pressed while Alt is held cancels them. This is that per-thread
/// latch.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct KeyMenuLatch { menu_key: bool, f10_key: bool }

/// What one key message asks for after the latch has seen it.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum KeyMenuAction { SysCommand { command: u32, character: u32 }, ContextMenu, Beep }

impl KeyMenuLatch {
    /// Feed one key message through the latch. # C: O(1)
    pub fn key(&mut self, message: u32, vk: u32, character: u32, shift_down: bool, alt_down: bool) -> Option<KeyMenuAction> {
        let is_menu_key = matches!(vk, VK_MENU | VK_LMENU | VK_RMENU);
        match message {
            WM_KEYDOWN | WM_SYSKEYDOWN => {
                if alt_down {
                    self.menu_key = is_menu_key && !self.menu_key;
                    self.f10_key = false;
                    return None;
                }
                if vk == VK_F10 { self.f10_key = true; return shift_down.then_some(KeyMenuAction::ContextMenu); }
                if vk == VK_ESCAPE && shift_down {
                    return Some(KeyMenuAction::SysCommand { command: SC_KEYMENU, character: KEYMENU_SPACE });
                }
                None
            }
            WM_KEYUP | WM_SYSKEYUP => {
                let opens = (is_menu_key && self.menu_key) || (vk == VK_F10 && self.f10_key);
                self.menu_key = false;
                self.f10_key = false;
                opens.then_some(KeyMenuAction::SysCommand { command: SC_KEYMENU, character: KEYMENU_NO_CHARACTER })
            }
            WM_SYSCHAR => {
                self.menu_key = false;
                if !alt_down || character == 0 { return (character != VK_ESCAPE).then_some(KeyMenuAction::Beep); }
                if character == b'\t' as u32 || character == VK_ESCAPE { return None; }
                Some(KeyMenuAction::SysCommand { command: SC_KEYMENU, character })
            }
            _ => None,
        }
    }
}

#[cfg(test)]
#[path = "tests/nonclient_menu.rs"]
mod tests;
