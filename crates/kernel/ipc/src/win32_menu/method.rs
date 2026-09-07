//! Which transaction one thunked MENUITEMINFO call performs. The method word
//! is an index into a fixed list, so a wrong number silently answers a
//! different question: every slot below is pinned by a test naming the call
//! that reaches it.
//!
//! Slots 0 and 1 write an item; every later slot only reads one, and each
//! answers in its own currency — a boolean, an identifier, a state word or a
//! handle — so the miss value differs per slot too.

/// One thunked MENUITEMINFO transaction.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum MenuItemMethod {
    SetMenuItemInfo = 0,
    InsertMenuItem = 1,
    CheckMenuRadioItem = 2,
    GetMenuDefaultItem = 3,
    GetMenuItemId = 4,
    GetMenuItemInfoA = 5,
    GetMenuItemInfoW = 6,
    GetMenuState = 7,
    GetSubMenu = 8,
}

impl MenuItemMethod {
    /// Decode the method word one caller sent. # C: O(1)
    pub const fn from_raw(raw: u64) -> Option<Self> {
        match raw {
            0 => Some(Self::SetMenuItemInfo),
            1 => Some(Self::InsertMenuItem),
            2 => Some(Self::CheckMenuRadioItem),
            3 => Some(Self::GetMenuDefaultItem),
            4 => Some(Self::GetMenuItemId),
            5 => Some(Self::GetMenuItemInfoA),
            6 => Some(Self::GetMenuItemInfoW),
            7 => Some(Self::GetMenuState),
            8 => Some(Self::GetSubMenu),
            _ => None,
        }
    }

    /// The method word this transaction travels as. # C: O(1)
    pub const fn raw(self) -> u64 { self as u64 }

    /// Whether the caller's MENUITEMINFO block describes fields rather than
    /// carrying two loose arguments: the radio-range call reuses the block to
    /// pass its last item and its chosen item, and leaves every other field —
    /// the size word included — uninitialised.
    /// # C: O(1)
    pub const fn reads_item_block(self) -> bool {
        matches!(self, Self::SetMenuItemInfo | Self::InsertMenuItem | Self::GetMenuItemInfoA | Self::GetMenuItemInfoW)
    }

    /// Whether the query answers the item's text in the caller's code page
    /// rather than in wide units. # C: O(1)
    pub const fn is_ansi_query(self) -> bool { matches!(self, Self::GetMenuItemInfoA) }

    /// What an unhandled or failed transaction answers: a query for an
    /// identifier, a state word or a default item reports the miss as all-ones,
    /// while every other slot reports it as a false boolean.
    /// # C: O(1)
    pub const fn miss_value(self) -> u64 {
        match self {
            Self::GetMenuItemId | Self::GetMenuDefaultItem | Self::GetMenuState => u32::MAX as u64,
            _ => 0,
        }
    }
}

/// A default-item search that also considers disabled items.
pub const GMDI_USEDISABLED: u32 = 0x0000_0001;
/// A default-item search that descends into the submenu of a popup item.
pub const GMDI_GOINTOPOPUPS: u32 = 0x0000_0002;

/// The identifier a positional query answers: a popup item carries a submenu
/// handle where a command item carries its identifier, and has none to report.
/// # C: O(1)
pub const fn item_id_result(submenu: Option<u32>, id: u32) -> u32 {
    if submenu.is_some() { u32::MAX } else { id }
}

/// The state word a query answers. A popup item reports the size of its
/// submenu above its own low flag byte, and a popup whose submenu handle no
/// longer resolves reports the miss instead.
/// # C: O(1)
pub const fn item_state_result(flags: u32, submenu_count: Option<Option<usize>>) -> u32 {
    match submenu_count {
        None => flags,
        Some(None) => u32::MAX,
        Some(Some(count)) => ((count as u32) << STATE_COUNT_SHIFT) | (flags & STATE_FLAG_BYTE),
    }
}

/// Where a popup item's submenu size sits in the state word, and the flag
/// bits that stay below it.
const STATE_COUNT_SHIFT: u32 = 8;
const STATE_FLAG_BYTE: u32 = 0xff;

#[cfg(test)]
#[path = "tests/method.rs"]
mod tests;
