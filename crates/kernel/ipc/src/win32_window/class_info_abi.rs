//! The x86-64 `WNDCLASSEXW` the class-information query fills in.
use super::ClassDescription;

/// Field offsets of `WNDCLASSEXW` on x86-64. The registration entry reads the
/// caller's structure at these same offsets, so the layout has one owner.
pub const BYTES: usize = 80;
pub const SIZE: usize = 0;
pub const STYLE: usize = 4;
pub const WNDPROC: usize = 8;
pub const CLS_EXTRA: usize = 16;
pub const WND_EXTRA: usize = 20;
pub const INSTANCE: usize = 24;
pub const ICON: usize = 32;
pub const CURSOR: usize = 40;
pub const BACKGROUND: usize = 48;
pub const MENU_NAME: usize = 56;
pub const CLASS_NAME: usize = 64;
pub const ICON_SM: usize = 72;

/// What one class-information reply reports beyond the class's own record.
pub struct ClassInfoReply { pub wndproc: u64, pub cb_wnd_extra: u32, pub instance: u64, pub class_name: u64, pub ansi: bool }

/// Encode one registered class as `WNDCLASSEXW`. Window creation loads the
/// class's menu from `lpszMenuName`, so a class registered with a menu name
/// and reported without one leaves every window of that class with no menu
/// bar. # C: O(1)
pub fn encode(class: &ClassDescription, reply: &ClassInfoReply) -> [u8; BYTES] {
    let mut bytes = [0u8; BYTES];
    let mut field = |offset: usize, value: &[u8]| bytes[offset..offset + value.len()].copy_from_slice(value);
    field(SIZE, &(BYTES as u32).to_le_bytes());
    field(STYLE, &class.style.to_le_bytes());
    field(WNDPROC, &reply.wndproc.to_le_bytes());
    field(CLS_EXTRA, &(class.cb_cls_extra as u32).to_le_bytes());
    field(WND_EXTRA, &reply.cb_wnd_extra.to_le_bytes());
    field(INSTANCE, &reply.instance.to_le_bytes());
    field(ICON, &class.icon.to_le_bytes());
    field(CURSOR, &class.cursor.to_le_bytes());
    field(BACKGROUND, &class.background.to_le_bytes());
    field(MENU_NAME, &menu_name(class, reply.ansi).to_le_bytes());
    field(CLASS_NAME, &reply.class_name.to_le_bytes());
    field(ICON_SM, &class.icon_sm.to_le_bytes());
    bytes
}

/// Every field of one caller-supplied `WNDCLASSEXW`. The registration entry
/// keeps all of them: a class whose icons, cursor or class-extra size were
/// dropped answers WM_SETCURSOR with no cursor, shows no icon, and reports
/// zeros to the class-information query.
pub struct ClassFields { pub style: u32, pub wndproc: u64, pub cb_cls_extra: i32, pub cb_wnd_extra: i32,
    pub instance: u64, pub icon: u64, pub cursor: u64, pub background: u64, pub menu_name: u64,
    pub class_name: u64, pub icon_sm: u64 }

/// Decode one caller-supplied `WNDCLASSEXW`. A structure whose `cbSize` is not
/// this layout's is a caller defect and decodes to nothing. # C: O(1)
pub fn decode(bytes: &[u8; BYTES]) -> Option<ClassFields> {
    let word = |offset: usize| u32::from_le_bytes([bytes[offset], bytes[offset + 1], bytes[offset + 2], bytes[offset + 3]]);
    let quad = |offset: usize| {
        let mut value = [0u8; 8];
        value.copy_from_slice(&bytes[offset..offset + 8]);
        u64::from_le_bytes(value)
    };
    if word(SIZE) as usize != BYTES { return None; }
    Some(ClassFields { style: word(STYLE), wndproc: quad(WNDPROC), cb_cls_extra: word(CLS_EXTRA) as i32,
        cb_wnd_extra: word(WND_EXTRA) as i32, instance: quad(INSTANCE), icon: quad(ICON), cursor: quad(CURSOR),
        background: quad(BACKGROUND), menu_name: quad(MENU_NAME), class_name: quad(CLASS_NAME), icon_sm: quad(ICON_SM) })
}

/// The menu-name pointer of the caller's own width. # C: O(1)
pub const fn menu_name(class: &ClassDescription, ansi: bool) -> u64 {
    if ansi { class.menu_name.ansi } else { class.menu_name.wide }
}

#[cfg(test)]
#[path = "tests/class_info_abi.rs"]
mod tests;
