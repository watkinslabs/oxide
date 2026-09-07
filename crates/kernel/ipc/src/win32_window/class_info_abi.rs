//! The x86-64 `WNDCLASSEXW` the class-information query fills in.
use super::ClassDescription;

/// Field offsets of `WNDCLASSEXW` on x86-64.
pub const BYTES: usize = 80;
const SIZE: usize = 0;
const STYLE: usize = 4;
const WNDPROC: usize = 8;
const CLS_EXTRA: usize = 16;
const WND_EXTRA: usize = 20;
const INSTANCE: usize = 24;
const ICON: usize = 32;
const CURSOR: usize = 40;
const BACKGROUND: usize = 48;
const MENU_NAME: usize = 56;
const CLASS_NAME: usize = 64;
const ICON_SM: usize = 72;

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

/// The menu-name pointer of the caller's own width. # C: O(1)
pub const fn menu_name(class: &ClassDescription, ansi: bool) -> u64 {
    if ansi { class.menu_name.ansi } else { class.menu_name.wide }
}

#[cfg(test)]
#[path = "tests/class_info_abi.rs"]
mod tests;
