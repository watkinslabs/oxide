//! The MENUITEMINFOW transaction one menu item is inserted, set or queried
//! with: the 64-bit image's field offsets, the mask bits naming which fields
//! are live, how the type word and the state word combine into the single
//! flag word an item keeps, and how each direction moves the item's text.
//!
//! A set or an insert carries its text as a NUL-terminated string at the
//! pointer field and never bounds it by the character count: that count
//! belongs to a query, and every caller that appends a resource item leaves
//! it zero. Reading `count` units on the way in therefore stores nothing.
use alloc::vec::Vec;

/// Size of the 64-bit image, and the value a caller's `cbSize` must carry.
pub const MENUITEMINFO_BYTES: usize = 80;

pub const MIIM_STATE: u32 = 0x0000_0001;
pub const MIIM_ID: u32 = 0x0000_0002;
pub const MIIM_SUBMENU: u32 = 0x0000_0004;
pub const MIIM_CHECKMARKS: u32 = 0x0000_0008;
pub const MIIM_TYPE: u32 = 0x0000_0010;
pub const MIIM_DATA: u32 = 0x0000_0020;
pub const MIIM_STRING: u32 = 0x0000_0040;
pub const MIIM_BITMAP: u32 = 0x0000_0080;
pub const MIIM_FTYPE: u32 = 0x0000_0100;

const MFT_BITMAP: u32 = 0x0000_0004;
const MFT_MENUBARBREAK: u32 = 0x0000_0020;
const MFT_MENUBREAK: u32 = 0x0000_0040;
const MFT_OWNERDRAW: u32 = 0x0000_0100;
const MFT_RADIOCHECK: u32 = 0x0000_0200;
const MFT_SEPARATOR: u32 = 0x0000_0800;
const MFT_RIGHTORDER: u32 = 0x0000_2000;
const MFT_RIGHTJUSTIFY: u32 = 0x0000_4000;
const MF_POPUP_BIT: u32 = 0x0000_0010;
const MF_SYSMENU_BIT: u32 = 0x0000_2000;
const MF_BYPOSITION_BIT: u32 = 0x0000_0400;
const MF_MOUSESELECT_BIT: u32 = 0x0000_8000;

/// Flag bits the type word owns.
pub const MENUITEMINFO_TYPE_MASK: u32 = MFT_BITMAP | MFT_OWNERDRAW | MFT_SEPARATOR | MFT_MENUBARBREAK
    | MFT_MENUBREAK | MFT_RADIOCHECK | MFT_RIGHTORDER | MFT_RIGHTJUSTIFY;
/// Every bit the type side of an item's flag word owns: what a write of its
/// state must leave alone.
pub const ITEM_TYPE_MASK: u32 = MENUITEMINFO_TYPE_MASK | MF_POPUP_BIT | MF_SYSMENU_BIT;
/// Flag bits the state word owns: everything outside the type side, less the
/// two selectors that never describe an item.
pub const MENUITEMINFO_STATE_MASK: u32 = !ITEM_TYPE_MASK & !(MF_BYPOSITION_BIT | MF_MOUSESELECT_BIT);

pub const OFFSET_SIZE: usize = 0;
pub const OFFSET_MASK: usize = 4;
pub const OFFSET_TYPE: usize = 8;
pub const OFFSET_STATE: usize = 12;
pub const OFFSET_ID: usize = 16;
pub const OFFSET_SUBMENU: usize = 24;
pub const OFFSET_CHECKED_BITMAP: usize = 32;
pub const OFFSET_UNCHECKED_BITMAP: usize = 40;
pub const OFFSET_ITEM_DATA: usize = 48;
pub const OFFSET_TEXT: usize = 56;
pub const OFFSET_COUNT: usize = 64;
pub const OFFSET_ITEM_BITMAP: usize = 72;

/// Longest item text one transaction moves in either direction.
pub const MENU_TEXT_UNITS_MAX: usize = 4096;

/// Where the text of one set or insert comes from.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum TextSource {
    /// The mask does not name the string, so the item keeps the text it has.
    Untouched,
    /// The string is named but the pointer is null: the item loses its text.
    Cleared,
    /// A NUL-terminated string begins at this address.
    At(u64),
}

/// Why one transaction cannot complete.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ItemInfoError { Fault, NoMemory }

/// One decoded MENUITEMINFOW image.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct ItemInfo { pub mask: u32, pub item_type: u32, pub state: u32, pub id: u32, pub submenu: Option<u32>, pub text: u64, pub count: u32 }

impl ItemInfo {
    /// Decode one image, rejecting any whose size field is not this ABI's.
    /// # C: O(1)
    pub fn decode(image: &[u8; MENUITEMINFO_BYTES]) -> Option<Self> {
        let word = |offset: usize| u32::from_le_bytes([image[offset], image[offset + 1], image[offset + 2], image[offset + 3]]);
        let pointer = |offset: usize| u64::from_le_bytes(image[offset..offset + 8].try_into().ok().unwrap_or([0; 8]));
        if word(OFFSET_SIZE) as usize != MENUITEMINFO_BYTES { return None; }
        let submenu = u32::try_from(pointer(OFFSET_SUBMENU)).ok().filter(|value| *value != 0);
        Some(Self { mask: word(OFFSET_MASK), item_type: word(OFFSET_TYPE), state: word(OFFSET_STATE),
            id: word(OFFSET_ID), submenu, text: pointer(OFFSET_TEXT), count: word(OFFSET_COUNT) })
    }

    /// The type bits this transaction replaces, when it names them. The older
    /// combined `MIIM_TYPE` never reaches here: a caller that sends it has the
    /// string and type bits split out of it first.
    /// # C: O(1)
    pub const fn type_value(self) -> Option<u32> {
        if self.mask & MIIM_FTYPE == 0 { return None; }
        Some(self.item_type & MENUITEMINFO_TYPE_MASK)
    }

    /// The state bits this transaction replaces, when it names them.
    /// # C: O(1)
    pub const fn state_value(self) -> Option<u32> {
        if self.mask & MIIM_STATE == 0 { return None; }
        Some(self.state & MENUITEMINFO_STATE_MASK)
    }

    /// The command identifier this transaction replaces. # C: O(1)
    pub const fn id_value(self) -> Option<u32> { if self.mask & MIIM_ID == 0 { None } else { Some(self.id) } }

    /// The submenu this transaction attaches or detaches. # C: O(1)
    pub const fn submenu_value(self) -> Option<Option<u32>> { if self.mask & MIIM_SUBMENU == 0 { None } else { Some(self.submenu) } }

    /// The flag word one newly inserted item begins with. # C: O(1)
    pub const fn insert_flags(self) -> u32 {
        let type_bits = match self.type_value() { Some(value) => value, None => 0 };
        let state_bits = match self.state_value() { Some(value) => value, None => 0 };
        type_bits | state_bits
    }

    /// Where this transaction's text comes from. # C: O(1)
    pub const fn text_source(self) -> TextSource {
        if self.mask & MIIM_STRING == 0 { return TextSource::Untouched; }
        if self.text == 0 { return TextSource::Cleared; }
        TextSource::At(self.text)
    }

    /// The text this transaction stores, read one unit at a time from the
    /// address the image names and stopped by the string's own terminator.
    /// Absent means the item keeps the text it already has. # C: O(text units)
    pub fn read_text<F: FnMut(u64) -> Option<u16>>(self, mut unit: F) -> Result<Option<Vec<u16>>, ItemInfoError> {
        let address = match self.text_source() {
            TextSource::Untouched => return Ok(None),
            TextSource::Cleared => return Ok(Some(Vec::new())),
            TextSource::At(address) => address,
        };
        let mut units = Vec::new();
        for offset in 0..MENU_TEXT_UNITS_MAX {
            let Some(address) = address.checked_add(offset as u64 * 2) else { return Err(ItemInfoError::Fault); };
            let Some(value) = unit(address) else { return Err(ItemInfoError::Fault); };
            if value == 0 { break; }
            units.try_reserve(1).map_err(|_| ItemInfoError::NoMemory)?;
            units.push(value);
        }
        Ok(Some(units))
    }
}

/// A query naming the older combined type field beside any field later split
/// out of it describes two answers for one word, and is refused rather than
/// answered from either.
/// # C: O(1)
pub const fn query_mask_conflict(mask: u32) -> bool {
    mask & MIIM_TYPE != 0 && mask & (MIIM_STRING | MIIM_FTYPE | MIIM_BITMAP) != 0
}

/// Whether a query writes the item's type word: either the combined field or
/// the one split out of it names it.
/// # C: O(1)
pub const fn query_writes_type(mask: u32) -> bool { mask & (MIIM_TYPE | MIIM_FTYPE) != 0 }

/// Whether a query writes the item's text: either the combined field or the
/// string field split out of it names it.
/// # C: O(1)
pub const fn query_writes_text(mask: u32) -> bool { mask & (MIIM_TYPE | MIIM_STRING) != 0 }

/// How far a query copies an item's text into the caller's buffer: one unit
/// of the buffer belongs to the terminator, and a query with no buffer copies
/// nothing. Both directions report the same number the copy produced.
/// # C: O(1)
pub const fn query_text_units(units: usize, count: u32, has_buffer: bool) -> usize {
    if !has_buffer || count == 0 { return units; }
    let room = count as usize - 1;
    if units < room { units } else { room }
}

#[cfg(test)]
#[path = "tests/item_info.rs"]
mod tests;
