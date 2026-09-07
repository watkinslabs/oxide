//! Keyboard layout ordinals: layout identity, key mapping and character
//! translation.

pub(crate) const ACTIVATE_KEYBOARD_LAYOUT: u64 = 0x1319;
pub(crate) const GET_KEYBOARD_LAYOUT: u64 = 0x1411;
pub(crate) const GET_KEYBOARD_LAYOUT_LIST: u64 = 0x1412;
pub(crate) const GET_KEYBOARD_LAYOUT_NAME: u64 = 0x1413;
pub(crate) const GET_KEY_NAME_TEXT: u64 = 0x140f;
pub(crate) const MAP_VIRTUAL_KEY_EX: u64 = 0x14b1;
pub(crate) const TO_UNICODE_EX: u64 = 0x15d1;
pub(crate) const VK_KEY_SCAN_EX: u64 = 0x15f4;

/// Key-state array the character translation reads.
pub(crate) const KEY_STATE_BYTES: usize = 256;
/// A translation whose key is released produces no character.
pub(crate) const SCAN_KEY_UP: u32 = 0x8000;
/// The character scan reports this when the layout produces no such character.
pub(crate) const NO_SUCH_CHARACTER: u64 = 0xffff;

/// Characters one name copy writes, given the caller's capacity. The
/// terminator always fits, so a one-character buffer answers an empty name.
/// # C: O(1)
pub(crate) fn name_copy_length(name: usize, capacity: i32) -> usize {
    if capacity <= 0 { return 0; }
    name.min(capacity as usize - 1)
}

/// A character translation writes at most one character plus a terminator, and
/// reports the character count. # C: O(1)
pub(crate) const fn translated_length(produced: bool) -> i32 { if produced { 1 } else { 0 } }

#[cfg(target_os = "oxide-kernel")]
#[path = "keyboard_raw/kernel.rs"]
pub(super) mod kernel;

#[cfg(test)]
#[path = "keyboard_raw/tests.rs"]
mod tests;
