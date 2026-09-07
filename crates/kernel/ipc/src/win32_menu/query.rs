//! The read-only menu questions and the one radio-range write that the
//! thunked MENUITEMINFO call answers without touching a caller's item block.
//!
//! Each answers in its own currency, so each reports a miss differently: the
//! identifier, state and default-item queries answer all-ones, the submenu
//! query answers a null handle, and the radio range answers a boolean saying
//! whether the chosen item was reached.
use super::{MenuId, MenuManager, MF_BYPOSITION, MF_SEPARATOR, MENU_NOT_FOUND};
use super::item_info::ITEM_TYPE_MASK;
use super::method::{item_id_result, item_state_result, GMDI_GOINTOPOPUPS, GMDI_USEDISABLED};

/// Both bits a disabled item may carry: either alone disables it.
const MFS_DISABLED: u32 = super::MF_GRAYED | super::MF_DISABLED;
/// The bit a default item carries.
const MFS_DEFAULT: u32 = super::MF_DEFAULT;
/// The bit a checked item carries.
const MFS_CHECKED: u32 = super::MF_CHECKED;
/// The bit an item drawn as a radio button carries.
const MFT_RADIOCHECK: u32 = 0x0000_0200;

impl MenuManager {
    /// The identifier of one item, or all-ones when the item is missing or is
    /// a popup, which carries a submenu handle in place of an identifier.
    /// # C: O(N_menus + N_items)
    pub fn item_id(&self, menu: MenuId, position: u32, flags: u32) -> u32 {
        match self.item(menu, position, flags) {
            Ok(item) => item_id_result(item.submenu, item.id),
            Err(_) => MENU_NOT_FOUND,
        }
    }

    /// The flag word of one item, with a popup item reporting the size of its
    /// submenu above its own low flag byte.
    /// # C: O(N_menus + N_items)
    pub fn item_state(&self, menu: MenuId, id: u32, flags: u32) -> u32 {
        let Ok(item) = self.item(menu, id, flags) else { return MENU_NOT_FOUND; };
        let counts = item.submenu.map(|raw| MenuId::from_raw(raw).and_then(|submenu| self.count(submenu).ok()));
        item_state_result(item.state, counts)
    }

    /// The submenu attached to one item by position. A command item answers a
    /// null handle, as does a position no item occupies.
    /// # C: O(N_menus + N_items)
    pub fn sub_menu(&self, menu: MenuId, position: u32) -> u32 {
        self.item(menu, position, MF_BYPOSITION).ok().and_then(|item| item.submenu).unwrap_or(0)
    }

    /// The menu's default item, as a position when asked by position and as an
    /// identifier otherwise; all-ones when the menu has none.
    ///
    /// A disabled default item counts only when the search was asked to keep
    /// disabled items. A popup default item is descended into when the search
    /// was asked to enter popups, and the popup itself answers only when its
    /// submenu holds no default of its own.
    /// # C: O(N_items) over the searched menus
    pub fn default_item(&self, menu: MenuId, bypos: bool, flags: u32) -> u32 {
        let Ok(count) = self.count(menu) else { return MENU_NOT_FOUND; };
        let mut found = None;
        for position in 0..count {
            let Ok(item) = self.item(menu, position as u32, MF_BYPOSITION) else { continue; };
            if item.state & MFS_DEFAULT == 0 { continue; }
            found = Some((position, item));
            break;
        }
        let Some((position, item)) = found else { return MENU_NOT_FOUND; };
        if flags & GMDI_USEDISABLED == 0 && item.state & MFS_DISABLED != 0 { return MENU_NOT_FOUND; }
        if flags & GMDI_GOINTOPOPUPS != 0 {
            if let Some(submenu) = item.submenu.and_then(MenuId::from_raw) {
                let inner = self.default_item(submenu, bypos, flags);
                if inner != MENU_NOT_FOUND { return inner; }
            }
        }
        if bypos { position as u32 } else { item.id }
    }

    /// Check one item of a range as the range's radio selection: the chosen
    /// item gains the checked bit and is drawn as a radio button, and every
    /// other item of the range loses its checked bit while keeping the radio
    /// drawing it already had. A separator is skipped, and a missing member of
    /// the range is skipped rather than ending the walk. Answers whether the
    /// chosen item was reached.
    /// # C: O((last - first) * (N_menus + N_items))
    pub fn check_radio_item(&mut self, menu: MenuId, first: u32, last: u32, check: u32, flags: u32) -> bool {
        let mut done = false;
        let mut current = first;
        while current <= last {
            if let Ok(position) = self.position(menu, current, flags) {
                if let Ok(item) = self.item_mut_by_position(menu, position) {
                    if item.state & ITEM_TYPE_MASK != MF_SEPARATOR {
                        if current == check { item.state |= MFT_RADIOCHECK | MFS_CHECKED; done = true; }
                        else { item.state &= !MFS_CHECKED; }
                    }
                }
            }
            let Some(next) = current.checked_add(1) else { break; };
            current = next;
        }
        done
    }
}

#[cfg(test)]
#[path = "tests/query.rs"]
mod tests;
