//! Whole-menu properties and the per-item default and highlight states.
use super::{MenuError, MenuId, MenuItem, MenuManager, MenuRect};

pub const MIM_MAXHEIGHT: u32 = 0x0000_0001;
pub const MIM_BACKGROUND: u32 = 0x0000_0002;
pub const MIM_HELPID: u32 = 0x0000_0004;
pub const MIM_MENUDATA: u32 = 0x0000_0008;
pub const MIM_STYLE: u32 = 0x0000_0010;
pub const MIM_APPLYTOSUBMENUS: u32 = 0x8000_0000;
pub const MENUINFO_BYTES: u32 = 40;

pub const MF_POPUP: u32 = 0x0000_0010;
pub const MF_HILITE: u32 = 0x0000_0080;
pub const MF_SEPARATOR: u32 = 0x0000_0800;
pub const MF_DEFAULT: u32 = 0x0000_1000;
pub const MF_SYSMENU: u32 = 0x0000_2000;

/// `SetMenuDefaultItem` clears every default when it names this item.
pub const NO_DEFAULT_ITEM: u32 = u32::MAX;

/// Whole-menu properties a menu carries beside its items.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct MenuInfo { pub max_height: u32, pub background: u64, pub context_help_id: u32, pub data: u64, pub style: u32 }

impl MenuManager {
    /// Read the properties the mask names, leaving the rest as supplied.
    /// # C: O(N_menus)
    pub fn info(&self, menu: MenuId, mask: u32, into: &mut MenuInfo) -> Result<(), MenuError> {
        let stored = self.menu_info(menu)?;
        if mask & MIM_MAXHEIGHT != 0 { into.max_height = stored.max_height; }
        if mask & MIM_BACKGROUND != 0 { into.background = stored.background; }
        if mask & MIM_HELPID != 0 { into.context_help_id = stored.context_help_id; }
        if mask & MIM_MENUDATA != 0 { into.data = stored.data; }
        if mask & MIM_STYLE != 0 { into.style = stored.style; }
        Ok(())
    }

    /// Store the properties the mask names, optionally through every submenu.
    /// # C: O(N_menus * N_items)
    pub fn set_info(&mut self, menu: MenuId, mask: u32, from: MenuInfo) -> Result<(), MenuError> {
        {
            let stored = self.menu_info_mut(menu)?;
            if mask & MIM_MAXHEIGHT != 0 { stored.max_height = from.max_height; }
            if mask & MIM_BACKGROUND != 0 { stored.background = from.background; }
            if mask & MIM_HELPID != 0 { stored.context_help_id = from.context_help_id; }
            if mask & MIM_MENUDATA != 0 { stored.data = from.data; }
            if mask & MIM_STYLE != 0 { stored.style = from.style; }
        }
        if mask & MIM_APPLYTOSUBMENUS == 0 { return Ok(()); }
        for submenu in self.submenus(menu)? { let _ = self.set_info(submenu, mask, from); }
        Ok(())
    }

    /// Store one menu's context help id. # C: O(N_menus)
    pub fn set_context_help_id(&mut self, menu: MenuId, id: u32) -> Result<(), MenuError> {
        self.menu_info_mut(menu)?.context_help_id = id;
        Ok(())
    }

    /// Mark one item the default and clear every other. Naming no item clears
    /// them all and still succeeds. # C: O(N_items)
    pub fn set_default_item(&mut self, menu: MenuId, item: u32, by_position: bool) -> Result<bool, MenuError> {
        let count = self.count(menu)?;
        for position in 0..count { self.item_mut_by_position(menu, position)?.state &= !MF_DEFAULT; }
        if item == NO_DEFAULT_ITEM { return Ok(true); }
        if by_position {
            if item as usize >= count { return Ok(false); }
            self.item_mut_by_position(menu, item as usize)?.state |= MF_DEFAULT;
            return Ok(true);
        }
        let mut found = false;
        for position in 0..count {
            let entry = self.item_mut_by_position(menu, position)?;
            if entry.id == item { entry.state |= MF_DEFAULT; found = true; }
        }
        Ok(found)
    }

    /// Highlight one item and clear any other highlight, reporting whether the
    /// highlight moved. # C: O(N_items)
    pub fn hilite(&mut self, menu: MenuId, position: usize, hilite: bool) -> Result<bool, MenuError> {
        let count = self.count(menu)?;
        if position >= count { return Err(MenuError::NoSuchItem); }
        let mut moved = false;
        for candidate in 0..count {
            let wanted = hilite && candidate == position;
            let entry = self.item_mut_by_position(menu, candidate)?;
            let had = entry.state & MF_HILITE != 0;
            if had != wanted { moved = true; }
            entry.state = if wanted { entry.state | MF_HILITE } else { entry.state & !MF_HILITE };
        }
        Ok(moved)
    }

    /// Position of the bar item under a point, or none. # C: O(N_items)
    pub fn item_from_point(&self, menu: MenuId, point: (i32, i32), origin: MenuRect,
        char_width: i32, char_height: i32, bar_height: i32) -> Result<Option<usize>, MenuError> {
        for position in 0..self.count(menu)? {
            let rect = self.bar_item_rect(menu, position, origin, char_width, char_height, bar_height)?;
            if point.0 >= rect.left && point.0 < rect.right && point.1 >= rect.top && point.1 < rect.bottom {
                return Ok(Some(position));
            }
        }
        Ok(None)
    }

    /// Append the standard window-menu commands to one popup. # C: O(N_items)
    pub fn fill_system_menu(&mut self, menu: MenuId, commands: &[(u32, &[u16])]) -> Result<(), MenuError> {
        for (id, text) in commands {
            let position = self.count(menu)?;
            let state = if *id == 0 { MF_SEPARATOR } else { 0 };
            let mut owned = alloc::vec::Vec::new();
            owned.try_reserve(text.len()).map_err(|_| MenuError::NoSuchMenu)?;
            owned.extend_from_slice(text);
            self.insert(menu, position, MenuItem { id: *id, state, text: owned, submenu: None })?;
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "tests/info.rs"]
mod tests;
