//! Keyboard layout queries over the US layout tables: virtual key to scan
//! code and back, virtual key to character, character to virtual key, and the
//! scan-code key names.

use alloc::vec::Vec;
use super::kbd_tables::*;

pub const MAPVK_VK_TO_VSC: u32 = 0;
pub const MAPVK_VSC_TO_VK: u32 = 1;
pub const MAPVK_VK_TO_CHAR: u32 = 2;
pub const MAPVK_VSC_TO_VK_EX: u32 = 3;
pub const MAPVK_VK_TO_VSC_EX: u32 = 4;

const VK_SHIFT: u8 = 0x10;
const VK_CONTROL: u8 = 0x11;
const VK_MENU: u8 = 0x12;
const VK_LSHIFT: u8 = 0xa0;
const VK_RSHIFT: u8 = 0xa1;
const VK_LCONTROL: u8 = 0xa2;
const VK_RCONTROL: u8 = 0xa3;
const VK_LMENU: u8 = 0xa4;
const VK_RMENU: u8 = 0xa5;
const VK_CAPITAL: u8 = 0x14;
const VK_ESCAPE: u8 = 0x1b;
/// Table stride: entries 0x000..0x0ff are plain scan codes, 0x100.. are E0
/// prefixed, 0x200.. are E1 prefixed.
const SCAN_TABLE: usize = 0x300;
const PREFIX_E0: usize = 0x100;
const PREFIX_E1: usize = 0x200;
/// Extended-prefix bias between the packed scan code an extended key reports
/// and its table index.
const EXTENDED_BIAS: u32 = 0xdf00;

/// The scan-code to virtual-key table, flattened with its prefix pages.
/// # C: O(SCAN_TABLE)
pub fn scan_to_vkey_table() -> [u16; SCAN_TABLE] {
    let mut table = [0u16; SCAN_TABLE];
    for (scan, entry) in VSC_TO_VK.iter().enumerate() {
        if *entry == VK_NONE { continue; }
        table[scan] = *entry;
    }
    for (scan, entry) in VSC_TO_VK_E0 { if *entry & 0xff != VK_NONE { table[PREFIX_E0 + *scan as usize] = *entry; } }
    for (scan, entry) in VSC_TO_VK_E1 { if *entry & 0xff != VK_NONE { table[PREFIX_E1 + *scan as usize] = *entry; } }
    table
}

/// Left-hand virtual key a side-agnostic modifier and a numeric-pad key map
/// to before a scan-code lookup. # C: O(1)
const fn scan_lookup_key(code: u32) -> u32 {
    match code as u8 {
        VK_SHIFT => VK_LSHIFT as u32, VK_CONTROL => VK_LCONTROL as u32, VK_MENU => VK_LMENU as u32,
        0x60 => 0x2d, 0x61 => 0x23, 0x62 => 0x28, 0x63 => 0x22, 0x64 => 0x25,
        0x65 => 0x0c, 0x66 => 0x27, 0x67 => 0x24, 0x68 => 0x26, 0x69 => 0x21,
        0x6e => 0x2e,
        _ => code,
    }
}

/// Character each virtual key produces with no modifier, for the character
/// mapping direction. # C: O(N_char_entries)
pub fn vkey_to_char_table() -> [u16; 0x100] {
    let mut table = [0u16; 0x100];
    for entry in VK_TO_WCHARS { table[entry.vkey as usize] = entry.wch[0]; }
    table
}

/// Answer one mapping request. An unknown type answers zero, as does a
/// request naming a key the layout does not carry. # C: O(SCAN_TABLE)
pub fn map_virtual_key(code: u32, kind: u32) -> u32 {
    let table = scan_to_vkey_table();
    match kind {
        MAPVK_VK_TO_VSC | MAPVK_VK_TO_VSC_EX => {
            let wanted = scan_lookup_key(code) as u8;
            let Some(mut found) = table.iter().position(|entry| (*entry & 0xff) as u8 == wanted && *entry != 0) else { return 0; };
            if kind == MAPVK_VK_TO_VSC {
                if found >= PREFIX_E1 { return 0; }
                found &= 0xff;
            } else if found >= PREFIX_E0 { return found as u32 + EXTENDED_BIAS; }
            found as u32
        }
        MAPVK_VSC_TO_VK | MAPVK_VSC_TO_VK_EX => {
            let index = if code & 0xe000 != 0 { code.wrapping_sub(EXTENDED_BIAS) } else { code };
            let Some(entry) = table.get(index as usize) else { return 0; };
            let vkey = (*entry & 0xff) as u8;
            if kind == MAPVK_VSC_TO_VK_EX { return vkey as u32; }
            (match vkey {
                VK_LSHIFT | VK_RSHIFT => VK_SHIFT,
                VK_LCONTROL | VK_RCONTROL => VK_CONTROL,
                VK_LMENU | VK_RMENU => VK_MENU,
                other => other,
            }) as u32
        }
        MAPVK_VK_TO_CHAR => {
            if code >= 0x100 { return 0; }
            if (b'A' as u32..=b'Z' as u32).contains(&code) { return code; }
            vkey_to_char_table()[code as usize] as u32
        }
        _ => 0,
    }
}

/// Modifier column selected by the current key state. `caps` folds the caps
/// lock into the shift bit. # C: O(1)
fn mod_number(state: &[u8; 256], caps: bool) -> Option<usize> {
    let mut bits = 0u16;
    for (vkey, bit) in VK_TO_BIT { if state[vkey as usize] & 0x80 != 0 { bits |= bit; } }
    if caps { bits |= KBD_SHIFT; }
    if bits > MAX_MOD_BITS { return None; }
    Some(MOD_NUMBER[bits as usize] as usize)
}

/// Modifier bits that select one character column. # C: O(1)
fn mod_bits(column: usize) -> Option<u16> {
    (0..=MAX_MOD_BITS).find(|bits| MOD_NUMBER[*bits as usize] as usize == column)
}

/// Character one virtual key produces under the given key state, or `None`
/// when the combination produces none. # C: O(N_char_entries)
pub fn vkey_to_wchar(vkey: u32, state: &[u8; 256]) -> Option<u16> {
    let alt = state[VK_MENU as usize] & 0x80 != 0;
    let ctrl = state[VK_CONTROL as usize] & 0x80 != 0;
    let caps = state[VK_CAPITAL as usize] & 1 != 0;
    if ctrl && alt { return None; }
    if !ctrl && vkey == VK_ESCAPE as u32 { return Some(VK_ESCAPE as u16); }
    if ctrl && !alt && (b'A' as u32..=b'Z' as u32).contains(&vkey) { return Some((vkey - b'A' as u32 + 1) as u16); }
    let column = mod_number(state, false)?;
    let caps_column = if caps { mod_number(state, true)? } else { column };
    let mut index = 0;
    while index < VK_TO_WCHARS.len() {
        let entry = VK_TO_WCHARS[index];
        if entry.modifications <= column || entry.vkey as u32 != vkey { index += 1; continue; }
        // A caps-sensitive pair stores the caps-on mapping first; the entry
        // that follows carries the caps-off one.
        let entry = if entry.attributes & SGCAPS != 0 && !caps { VK_TO_WCHARS[index + 1] } else { entry };
        let column = if entry.attributes & CAPLOK != 0 && entry.modifications > caps_column { caps_column } else { column };
        let value = entry.wch[column];
        return (value != WCH_NONE).then_some(value);
    }
    None
}

/// Virtual key and modifier bits that produce one character. The high byte
/// carries the modifier bits, the low byte the virtual key. Answers `None`
/// when the layout produces no such character. # C: O(N_char_entries)
pub fn wchar_to_vkey(chr: u16) -> Option<u16> {
    if chr == 0x001b { return Some(VK_ESCAPE as u16); }
    for entry in VK_TO_WCHARS {
        for column in 0..entry.modifications {
            if entry.wch[column] == WCH_NONE || entry.wch[column] != chr { continue; }
            let bits = mod_bits(column)?;
            return Some((bits << 8) | entry.vkey as u16);
        }
    }
    // Control characters name the letter that produces them with control held.
    if (0x0001..=0x001a).contains(&chr) { return Some(0x0200 | (b'A' as u16 + chr - 1)); }
    if chr >= 0x0080 { return None; }
    Some(0)
}

/// Name of one key, given the packed lParam the key message carried.
/// # C: O(SCAN_TABLE)
pub fn key_name(lparam: u32) -> Option<Vec<u16>> {
    let mut code = ((lparam >> 16) & 0x1ff) as usize;
    let table = scan_to_vkey_table();
    // A "do not care about the side" request resolves a right-hand modifier
    // back to the scan code of its left-hand twin.
    if lparam & 0x0200_0000 != 0 {
        let vkey = (table[code] & 0xff) as u8;
        if matches!(vkey, VK_RSHIFT | VK_RCONTROL | VK_RMENU) {
            code = table.iter().position(|entry| (*entry & 0xff) as u8 == vkey - 1).unwrap_or(code);
        }
    }
    let names = if code < PREFIX_E0 { KEY_NAMES } else { KEY_NAMES_EXT };
    if let Some((_, name)) = names.iter().find(|(vsc, _)| *vsc as usize == code & 0xff) {
        return Some(name.chars().map(|unit| unit as u16).collect());
    }
    let vkey = map_virtual_key((code & 0xff) as u32, MAPVK_VSC_TO_VK);
    let character = map_virtual_key(vkey, MAPVK_VK_TO_CHAR) as u16;
    if character == 0 { return Some(Vec::new()); }
    Some(alloc::vec![character])
}

#[cfg(test)]
#[path = "tests/kbd_layout.rs"]
mod tests;
