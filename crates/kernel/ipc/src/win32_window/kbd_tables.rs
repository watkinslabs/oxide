//! US keyboard layout tables: scan-code to virtual key, virtual key to
//! characters per modifier combination, and the scan-code key names.

/// Scan-code flags carried alongside the virtual key in the scan table.
pub const KBDEXT: u16 = 0x0100;
pub const KBDMULTIVK: u16 = 0x0200;
pub const KBDSPECIAL: u16 = 0x0400;
pub const KBDNUMPAD: u16 = 0x0800;
/// Entry produces no key.
pub const VK_NONE: u16 = 0x00ff;
/// Entry produces no character in this modifier column.
pub const WCH_NONE: u16 = 0xf000;

/// Shift-state column selected by a modifier bit combination. Index is the
/// OR of the modifier bits; the value is the character column.
pub const MOD_NUMBER: [u8; 8] = [0, 1, 2, 3, 0, 1, 0, 0];
pub const MAX_MOD_BITS: u16 = 7;
pub const KBD_SHIFT: u16 = 1;
pub const KBD_CTRL: u16 = 2;
pub const KBD_ALT: u16 = 4;
/// Virtual keys whose down state contributes a modifier bit.
pub const VK_TO_BIT: [(u8, u16); 3] = [(0x10, KBD_SHIFT), (0x11, KBD_CTRL), (0x12, KBD_ALT)];

/// Entry attribute: the shift column also applies under caps lock.
pub const CAPLOK: u8 = 0x01;
/// Entry attribute: caps lock and shift differ; the next entry carries the
/// caps-lock-off mapping.
pub const SGCAPS: u8 = 0x02;

/// One virtual key's characters, one per modifier column.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VkToWchars { pub vkey: u8, pub attributes: u8, pub wch: [u16; 4], pub modifications: usize }

const fn two(vkey: u8, plain: u16, shifted: u16, attributes: u8) -> VkToWchars {
    VkToWchars { vkey, attributes, wch: [plain, shifted, 0, 0], modifications: 2 }
}
const fn three(vkey: u8, plain: u16, shifted: u16, control: u16) -> VkToWchars {
    VkToWchars { vkey, attributes: 0, wch: [plain, shifted, control, 0], modifications: 3 }
}
const fn four(vkey: u8, plain: u16, shifted: u16, control: u16, alt: u16) -> VkToWchars {
    VkToWchars { vkey, attributes: 0, wch: [plain, shifted, control, alt], modifications: 4 }
}
const fn one(vkey: u8, plain: u16) -> VkToWchars {
    VkToWchars { vkey, attributes: 0, wch: [plain, 0, 0, 0], modifications: 1 }
}
const fn letter(vkey: u8) -> VkToWchars { two(vkey, (vkey + 32) as u16, vkey as u16, CAPLOK) }

/// Character tables in the order the layout searches them: three-column
/// entries first, then four, then two, then one, matching the order a lookup
/// must see so a key present in several tables resolves to the widest.
pub const VK_TO_WCHARS: &[VkToWchars] = &[
    three(0xdb, b'[' as u16, b'{' as u16, 0x001b),
    three(0xdd, b']' as u16, b'}' as u16, 0x001d),
    three(0xdc, b'\\' as u16, b'|' as u16, 0x001c),
    three(0xe2, b'\\' as u16, b'|' as u16, 0x001c),
    three(0x08, 0x0008, 0x0008, 0x007f),
    three(0x1b, 0x001b, 0x001b, 0x001b),
    three(0x0d, 0x000d, 0x000d, 0x000a),
    three(0x20, b' ' as u16, b' ' as u16, b' ' as u16),
    three(0x03, 0x0003, 0x0003, 0x0003),
    four(b'2', b'2' as u16, b'@' as u16, WCH_NONE, 0x0000),
    four(b'6', b'6' as u16, b'^' as u16, WCH_NONE, 0x001e),
    four(0xbd, b'-' as u16, b'_' as u16, WCH_NONE, 0x001f),
    two(0xc0, b'`' as u16, b'~' as u16, 0),
    two(b'1', b'1' as u16, b'!' as u16, 0),
    two(b'3', b'3' as u16, b'#' as u16, 0),
    two(b'4', b'4' as u16, b'$' as u16, 0),
    two(b'5', b'5' as u16, b'%' as u16, 0),
    two(b'7', b'7' as u16, b'&' as u16, 0),
    two(b'8', b'8' as u16, b'*' as u16, 0),
    two(b'9', b'9' as u16, b'(' as u16, 0),
    two(b'0', b'0' as u16, b')' as u16, 0),
    two(0xbb, b'=' as u16, b'+' as u16, 0),
    letter(b'Q'), letter(b'W'), letter(b'E'), letter(b'R'), letter(b'T'), letter(b'Y'),
    letter(b'U'), letter(b'I'), letter(b'O'), letter(b'P'),
    letter(b'A'), letter(b'S'), letter(b'D'), letter(b'F'), letter(b'G'), letter(b'H'),
    letter(b'J'), letter(b'K'), letter(b'L'),
    two(0xba, b';' as u16, b':' as u16, 0),
    two(0xde, b'\'' as u16, b'"' as u16, 0),
    letter(b'Z'), letter(b'X'), letter(b'C'), letter(b'V'), letter(b'B'), letter(b'N'), letter(b'M'),
    two(0xbc, b',' as u16, b'<' as u16, 0),
    two(0xbe, b'.' as u16, b'>' as u16, 0),
    two(0xbf, b'/' as u16, b'?' as u16, 0),
    two(0x6e, b'.' as u16, b'.' as u16, 0),
    two(0x09, 0x0009, 0x0009, 0),
    two(0x6b, b'+' as u16, b'+' as u16, 0),
    two(0x6f, b'/' as u16, b'/' as u16, 0),
    two(0x6a, b'*' as u16, b'*' as u16, 0),
    two(0x6d, b'-' as u16, b'-' as u16, 0),
    one(0x60, b'0' as u16), one(0x61, b'1' as u16), one(0x62, b'2' as u16), one(0x63, b'3' as u16),
    one(0x64, b'4' as u16), one(0x65, b'5' as u16), one(0x66, b'6' as u16), one(0x67, b'7' as u16),
    one(0x68, b'8' as u16), one(0x69, b'9' as u16),
];

/// Scan code (0x00..) to virtual key with flags.
pub const VSC_TO_VK: &[u16] = &[
    VK_NONE, 0x1b, b'1' as u16, b'2' as u16, b'3' as u16, b'4' as u16, b'5' as u16, b'6' as u16,
    b'7' as u16, b'8' as u16, b'9' as u16, b'0' as u16, 0xbd, 0xbb, 0x08, 0x09,
    b'Q' as u16, b'W' as u16, b'E' as u16, b'R' as u16, b'T' as u16, b'Y' as u16, b'U' as u16, b'I' as u16,
    b'O' as u16, b'P' as u16, 0xdb, 0xdd, 0x0d, 0xa2, b'A' as u16, b'S' as u16,
    b'D' as u16, b'F' as u16, b'G' as u16, b'H' as u16, b'J' as u16, b'K' as u16, b'L' as u16, 0xba,
    0xde, 0xc0, 0xa0, 0xdc, b'Z' as u16, b'X' as u16, b'C' as u16, b'V' as u16,
    b'B' as u16, b'N' as u16, b'M' as u16, 0xbc, 0xbe, 0xbf, 0xa1 | KBDEXT, 0x6a | KBDMULTIVK,
    0xa4, 0x20, 0x14, 0x70, 0x71, 0x72, 0x73, 0x74,
    0x75, 0x76, 0x77, 0x78, 0x79, 0x90 | KBDEXT | KBDMULTIVK, 0x91 | KBDMULTIVK, 0x24 | KBDNUMPAD | KBDSPECIAL,
    0x26 | KBDNUMPAD | KBDSPECIAL, 0x21 | KBDNUMPAD | KBDSPECIAL, 0x6d, 0x25 | KBDNUMPAD | KBDSPECIAL,
    0x0c | KBDNUMPAD | KBDSPECIAL, 0x27 | KBDNUMPAD | KBDSPECIAL, 0x6b, 0x23 | KBDNUMPAD | KBDSPECIAL,
    0x28 | KBDNUMPAD | KBDSPECIAL, 0x22 | KBDNUMPAD | KBDSPECIAL, 0x2d | KBDNUMPAD | KBDSPECIAL,
    0x2e | KBDNUMPAD | KBDSPECIAL, 0x2c, VK_NONE, 0xe2, 0x7a,
    0x7b, 0x0c, 0xee, 0xf1, 0xea, 0xf9, 0xf5, 0xf3,
    VK_NONE, VK_NONE, 0xfb, 0x2f, 0x7c, 0x7d, 0x7e, 0x7f,
    0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0xed,
    VK_NONE, 0xe9, VK_NONE, 0xc1, VK_NONE, VK_NONE, 0x87, VK_NONE,
    VK_NONE, VK_NONE, VK_NONE, 0xeb, 0x09, VK_NONE, 0xc2,
];

/// Scan codes reached through the E0 prefix.
pub const VSC_TO_VK_E0: &[(u8, u16)] = &[
    (0x10, 0xb1 | KBDEXT), (0x19, 0xb0 | KBDEXT), (0x1d, 0xa3 | KBDEXT), (0x20, 0xad | KBDEXT),
    (0x21, 0xb7 | KBDEXT), (0x22, 0xb3 | KBDEXT), (0x24, 0xb2 | KBDEXT), (0x2e, 0xae | KBDEXT),
    (0x30, 0xaf | KBDEXT), (0x32, 0xac | KBDEXT), (0x35, 0x6f | KBDEXT), (0x37, 0x2c | KBDEXT),
    (0x38, 0xa5 | KBDEXT), (0x47, 0x24 | KBDEXT), (0x48, 0x26 | KBDEXT), (0x49, 0x21 | KBDEXT),
    (0x4b, 0x25 | KBDEXT), (0x4d, 0x27 | KBDEXT), (0x4f, 0x23 | KBDEXT), (0x50, 0x28 | KBDEXT),
    (0x51, 0x22 | KBDEXT), (0x52, 0x2d | KBDEXT), (0x53, 0x2e | KBDEXT), (0x5b, 0x5b | KBDEXT),
    (0x5c, 0x5c | KBDEXT), (0x5d, 0x5d | KBDEXT), (0x5f, 0x5f | KBDEXT), (0x65, 0xaa | KBDEXT),
    (0x66, 0xab | KBDEXT), (0x67, 0xa8 | KBDEXT), (0x68, 0xa9 | KBDEXT), (0x69, 0xa7 | KBDEXT),
    (0x6a, 0xa6 | KBDEXT), (0x6b, 0xb6 | KBDEXT), (0x6c, 0xb4 | KBDEXT), (0x6d, 0xb5 | KBDEXT),
    (0x1c, 0x0d | KBDEXT), (0x46, 0x03 | KBDEXT),
];

/// Scan codes reached through the E1 prefix.
pub const VSC_TO_VK_E1: &[(u8, u16)] = &[(0x1d, 0x13)];

/// Names of the non-extended scan codes.
pub const KEY_NAMES: &[(u8, &str)] = &[
    (0x01, "Esc"), (0x0e, "Backspace"), (0x0f, "Tab"), (0x1c, "Enter"), (0x1d, "Ctrl"),
    (0x2a, "Shift"), (0x36, "Right Shift"), (0x37, "Num *"), (0x38, "Alt"), (0x39, "Space"),
    (0x3a, "Caps Lock"), (0x3b, "F1"), (0x3c, "F2"), (0x3d, "F3"), (0x3e, "F4"), (0x3f, "F5"),
    (0x40, "F6"), (0x41, "F7"), (0x42, "F8"), (0x43, "F9"), (0x44, "F10"), (0x45, "Pause"),
    (0x46, "Scroll Lock"), (0x47, "Num 7"), (0x48, "Num 8"), (0x49, "Num 9"), (0x4a, "Num -"),
    (0x4b, "Num 4"), (0x4c, "Num 5"), (0x4d, "Num 6"), (0x4e, "Num +"), (0x4f, "Num 1"),
    (0x50, "Num 2"), (0x51, "Num 3"), (0x52, "Num 0"), (0x53, "Num Del"), (0x54, "Sys Req"),
    (0x57, "F11"), (0x58, "F12"), (0x7c, "F13"), (0x7d, "F14"), (0x7e, "F15"), (0x7f, "F16"),
    (0x80, "F17"), (0x81, "F18"), (0x82, "F19"), (0x83, "F20"), (0x84, "F21"), (0x85, "F22"),
    (0x86, "F23"), (0x87, "F24"),
];

/// Names of the extended scan codes.
pub const KEY_NAMES_EXT: &[(u8, &str)] = &[
    (0x1c, "Num Enter"), (0x1d, "Right Ctrl"), (0x35, "Num /"), (0x37, "Prnt Scrn"),
    (0x38, "Right Alt"), (0x45, "Num Lock"), (0x46, "Break"), (0x47, "Home"), (0x48, "Up"),
    (0x49, "Page Up"), (0x4b, "Left"), (0x4d, "Right"), (0x4f, "End"), (0x50, "Down"),
    (0x51, "Page Down"), (0x52, "Insert"), (0x53, "Delete"), (0x54, "<00>"), (0x56, "Help"),
    (0x5b, "Left Windows"), (0x5c, "Right Windows"), (0x5d, "Application"),
];
