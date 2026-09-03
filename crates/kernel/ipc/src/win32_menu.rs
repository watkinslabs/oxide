//! Canonical Win32 menu handles and item state for one NT GUI process.

use alloc::vec::Vec;

pub const MF_GRAYED: u32 = 0x0000_0001;
pub const MF_DISABLED: u32 = 0x0000_0002;
pub const MF_CHECKED: u32 = 0x0000_0008;
pub const MF_BYPOSITION: u32 = 0x0000_0400;
pub const MF_STATE_MASK: u32 = MF_GRAYED | MF_DISABLED | MF_CHECKED;
pub const MENU_NOT_FOUND: u32 = u32::MAX;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct MenuId(u32);

impl MenuId {
    pub fn raw(self) -> u32 { self.0 }
    pub fn from_raw(raw: u32) -> Option<Self> { (raw != 0).then_some(Self(raw)) }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MenuItem { pub id: u32, pub state: u32, pub text: Vec<u16>, pub submenu: Option<u32> }

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum MenuError { NoSuchMenu, NoSuchItem, InvalidPosition }

struct MenuRecord { items: Vec<MenuItem> }

/// Owns every HMENU in one NT process. Window associations remain in
/// `WindowManager`, while this owner retains menu lifetime and item state.
pub struct MenuManager { next: u32, menus: Vec<(MenuId, MenuRecord)> }

impl Default for MenuManager { fn default() -> Self { Self::new() } }

impl MenuManager {
    pub fn new() -> Self { Self { next: 1, menus: Vec::new() } }

    /// Allocate one process-local menu handle. # C: O(1) amortized
    pub fn create(&mut self) -> Result<MenuId, MenuError> {
        let id = MenuId(self.next);
        self.next = self.next.checked_add(1).ok_or(MenuError::NoSuchMenu)?;
        self.menus.push((id, MenuRecord { items: Vec::new() }));
        Ok(id)
    }

    /// Destroy a menu and all of its owned items. # C: O(N_menus)
    pub fn destroy(&mut self, id: MenuId) -> Result<(), MenuError> {
        let index = self.index(id).ok_or(MenuError::NoSuchMenu)?;
        self.menus.remove(index);
        Ok(())
    }

    pub fn contains(&self, id: MenuId) -> bool { self.index(id).is_some() }

    /// Add one item in resource order; callers may later replace its state.
    /// # C: O(N_menus + N_items)
    pub fn insert(&mut self, menu: MenuId, position: usize, item: MenuItem) -> Result<(), MenuError> {
        let record = self.record_mut(menu).ok_or(MenuError::NoSuchMenu)?;
        if position > record.items.len() { return Err(MenuError::InvalidPosition); }
        record.items.insert(position, item);
        Ok(())
    }

    pub fn count(&self, menu: MenuId) -> Result<usize, MenuError> { Ok(self.menus[self.index(menu).ok_or(MenuError::NoSuchMenu)?].1.items.len()) }
    pub fn item(&self, menu: MenuId, id: u32, flags: u32) -> Result<&MenuItem, MenuError> {
        let record = self.menus.get(self.index(menu).ok_or(MenuError::NoSuchMenu)?).ok_or(MenuError::NoSuchMenu)?;
        if flags & MF_BYPOSITION != 0 { record.1.items.get(id as usize).ok_or(MenuError::NoSuchItem) } else { record.1.items.iter().find(|item| item.id == id).ok_or(MenuError::NoSuchItem) }
    }
    pub fn position(&self, menu: MenuId, id: u32, flags: u32) -> Result<usize, MenuError> {
        let record = self.menus.get(self.index(menu).ok_or(MenuError::NoSuchMenu)?).ok_or(MenuError::NoSuchMenu)?;
        if flags & MF_BYPOSITION != 0 { ((id as usize) < record.1.items.len()).then_some(id as usize).ok_or(MenuError::NoSuchItem) } else { record.1.items.iter().position(|item| item.id == id).ok_or(MenuError::NoSuchItem) }
    }
    pub fn item_mut_by_position(&mut self, menu: MenuId, position: usize) -> Result<&mut MenuItem, MenuError> {
        self.record_mut(menu).ok_or(MenuError::NoSuchMenu)?.items.get_mut(position).ok_or(MenuError::NoSuchItem)
    }
    pub fn set_item(&mut self, menu: MenuId, position: usize, id: Option<u32>, state: Option<u32>, text: Option<Vec<u16>>, submenu: Option<Option<u32>>) -> Result<(), MenuError> {
        let item = self.item_mut_by_position(menu, position)?;
        if let Some(id) = id { item.id = id; }
        if let Some(state) = state { item.state = state & MF_STATE_MASK; }
        if let Some(text) = text { item.text = text; }
        if let Some(submenu) = submenu { item.submenu = submenu; }
        Ok(())
    }

    /// Return the prior checked bit and apply the requested checked bit.
    /// # C: O(N_menus + N_items)
    pub fn check(&mut self, menu: MenuId, id: u32, flags: u32) -> Result<u32, MenuError> {
        let item = self.item_mut(menu, id, flags)?;
        let previous = item.state & MF_CHECKED;
        item.state = (item.state & !MF_CHECKED) | (flags & MF_CHECKED);
        Ok(previous)
    }

    /// Return prior disabled/grayed state and apply the requested state.
    /// # C: O(N_menus + N_items)
    pub fn enable(&mut self, menu: MenuId, id: u32, flags: u32) -> Result<u32, MenuError> {
        let item = self.item_mut(menu, id, flags)?;
        let previous = item.state & (MF_GRAYED | MF_DISABLED);
        item.state = (item.state & !(MF_GRAYED | MF_DISABLED)) | (flags & (MF_GRAYED | MF_DISABLED));
        Ok(previous)
    }

    fn index(&self, id: MenuId) -> Option<usize> { self.menus.iter().position(|(candidate, _)| *candidate == id) }
    fn record_mut(&mut self, id: MenuId) -> Option<&mut MenuRecord> { self.menus.iter_mut().find(|(candidate, _)| *candidate == id).map(|(_, record)| record) }
    fn item_mut(&mut self, menu: MenuId, id: u32, flags: u32) -> Result<&mut MenuItem, MenuError> {
        let record = self.record_mut(menu).ok_or(MenuError::NoSuchMenu)?;
        let item = if flags & MF_BYPOSITION != 0 { record.items.get_mut(id as usize) } else { record.items.iter_mut().find(|item| item.id == id) };
        item.ok_or(MenuError::NoSuchItem)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn menu_state_returns_previous_bits_and_preserves_other_state() {
        let mut menus = MenuManager::new();
        let menu = menus.create().unwrap();
        menus.insert(menu, 0, MenuItem { id: 7, state: MF_DISABLED, text: Vec::new(), submenu: None }).unwrap();
        assert_eq!(menus.check(menu, 7, MF_CHECKED), Ok(0));
        assert_eq!(menus.check(menu, 7, 0), Ok(MF_CHECKED));
        assert_eq!(menus.enable(menu, 7, 0), Ok(MF_DISABLED));
        assert_eq!(menus.enable(menu, 7, MF_GRAYED), Ok(0));
    }

    #[test]
    fn position_and_command_lookup_are_distinct() {
        let mut menus = MenuManager::new();
        let menu = menus.create().unwrap();
        menus.insert(menu, 0, MenuItem { id: 11, state: 0, text: Vec::new(), submenu: None }).unwrap();
        menus.insert(menu, 1, MenuItem { id: 22, state: 0, text: Vec::new(), submenu: None }).unwrap();
        assert_eq!(menus.check(menu, 1, MF_BYPOSITION | MF_CHECKED), Ok(0));
        assert_eq!(menus.check(menu, 11, MF_CHECKED), Ok(0));
        assert_eq!(menus.check(menu, 1, MF_CHECKED), Err(MenuError::NoSuchItem));
    }

    #[test]
    fn destroyed_handles_cannot_be_reused_as_live_menus() {
        let mut menus = MenuManager::new();
        let menu = menus.create().unwrap();
        menus.destroy(menu).unwrap();
        assert_eq!(menus.insert(menu, 0, MenuItem { id: 1, state: 0, text: Vec::new(), submenu: None }), Err(MenuError::NoSuchMenu));
    }

    #[test]
    fn item_publication_preserves_order_and_updates_selected_fields() {
        let mut menus = MenuManager::new();
        let menu = menus.create().unwrap();
        menus.insert(menu, 0, MenuItem { id: 3, state: 0, text: Vec::new(), submenu: None }).unwrap();
        assert_eq!(menus.count(menu), Ok(1));
        menus.set_item(menu, 0, Some(9), Some(MF_CHECKED), Some(alloc::vec![65, 0]), Some(Some(2))).unwrap();
        assert_eq!(menus.item(menu, 0, MF_BYPOSITION).unwrap().id, 9);
        assert_eq!(menus.item(menu, 9, 0).unwrap().submenu, Some(2));
        assert_eq!(menus.set_item(menu, 4, Some(1), None, None, None), Err(MenuError::NoSuchItem));
    }
}
