//! What the tracking loop does with the virtual keys it acts on itself.
//!
//! The arms that move along a menu bar are the interesting ones: closing the
//! open popup, moving the bar highlight and opening the popup of what it lands
//! on are one decision, and the menu the loop follows changes with it.
use alloc::vec::Vec;
use super::{TrackLoop, VK_DOWN, VK_END, VK_ESCAPE, VK_F10, VK_HOME, VK_LEFT, VK_MENU, VK_RETURN, VK_RIGHT, VK_UP};
use crate::win32_menu::popup::NO_SELECTED_ITEM;
use crate::win32_menu::track::{is_popup_menu, parent_menu, TrackEffect, EXEC_POPUP_SHOWN, ITEM_NEXT, ITEM_PREV};
use crate::win32_menu::{MenuId, MenuManager};

/// The character the return key carries. The reference never acts on the key
/// itself: it translates the key into this character and the character arm
/// executes the highlighted item.
const RETURN_CHAR: u16 = '\r' as u16;

impl TrackLoop {
    /// Virtual keys the tracking loop acts on itself. # C: O(N_menus * N_items)
    pub(super) fn key_down(&mut self, menus: &mut MenuManager, vk: u32, effects: &mut Vec<TrackEffect>) {
        let current = self.tracker.current_menu;
        match vk {
            VK_MENU | VK_F10 => self.tracker.exit = true,
            VK_ESCAPE => self.key_escape(menus, effects),
            VK_HOME | VK_END => {
                self.tracker.select_item(menus, effects, current, NO_SELECTED_ITEM, false, 0);
                self.tracker.move_selection(menus, effects, current, if vk == VK_HOME { ITEM_NEXT } else { ITEM_PREV });
            }
            VK_UP | VK_DOWN => {
                if is_popup_menu(menus, current) { self.tracker.move_selection(menus, effects, current, if vk == VK_UP { ITEM_PREV } else { ITEM_NEXT }); }
                else { effects.push(TrackEffect::ShowSubPopup { menu: current, select_first: true }); }
            }
            VK_LEFT => self.key_left(menus, effects),
            VK_RIGHT => self.key_right(menus, effects),
            VK_RETURN => {
                let chosen = self.tracker.char_key(menus, RETURN_CHAR, effects);
                if self.tracker.exit && chosen != EXEC_POPUP_SHOWN { self.executed = chosen; }
            }
            _ => {}
        }
    }

    /// Escape closes the innermost open popup and tracking goes on; with
    /// nothing below the top menu open it ends tracking.
    /// # C: O(N_menus * N_items)
    fn key_escape(&mut self, menus: &mut MenuManager, effects: &mut Vec<TrackEffect>) {
        let (current, top) = (self.tracker.current_menu, self.tracker.top_menu);
        if current == top || !is_popup_menu(menus, current) { self.tracker.exit = true; return; }
        let prev = parent_menu(menus, top, current).unwrap_or(top);
        effects.push(TrackEffect::HideSubPopups { menu: prev });
        self.tracker.current_menu = prev;
    }

    /// Left closes the innermost open popup; landing back on a bar it moves
    /// the bar highlight one item left and opens what it lands on, since a
    /// popup was open before. # C: O(N_menus * N_items)
    fn key_left(&mut self, menus: &mut MenuManager, effects: &mut Vec<TrackEffect>) {
        let (current, top) = (self.tracker.current_menu, self.tracker.top_menu);
        let prev = if current == top { top } else { parent_menu(menus, top, current).unwrap_or(top) };
        let was_open = prev != current;
        effects.push(TrackEffect::HideSubPopups { menu: prev });
        self.tracker.current_menu = prev;
        if prev != top || is_popup_menu(menus, top) { return; }
        self.tracker.move_selection(menus, effects, top, ITEM_PREV);
        if was_open { effects.push(TrackEffect::ShowSubPopup { menu: top, select_first: true }); }
    }

    /// Right opens the submenu of the highlighted item when there is one;
    /// otherwise, on a bar, it closes what is open, moves the bar highlight
    /// one item right and opens that item's popup. # C: O(N_menus * N_items)
    fn key_right(&mut self, menus: &mut MenuManager, effects: &mut Vec<TrackEffect>) {
        let (current, top) = (self.tracker.current_menu, self.tracker.top_menu);
        let top_is_popup = is_popup_menu(menus, top);
        if (top_is_popup || current != top) && has_submenu_focused(menus, current) {
            effects.push(TrackEffect::ShowSubPopup { menu: current, select_first: true });
            return;
        }
        if top_is_popup { return; }
        let was_open = current != top;
        if was_open { effects.push(TrackEffect::HideSubPopups { menu: top }); self.tracker.current_menu = top; }
        self.tracker.move_selection(menus, effects, top, ITEM_NEXT);
        if was_open { effects.push(TrackEffect::ShowSubPopup { menu: top, select_first: true }); }
    }
}

/// Whether the highlighted item of one menu carries a submenu. # C: O(N_items)
fn has_submenu_focused(menus: &MenuManager, menu: u32) -> bool {
    MenuId::from_raw(menu).is_some_and(|id| {
        let focused = menus.focused_item(id);
        focused != NO_SELECTED_ITEM && menus.is_submenu_item(id, focused)
    })
}

#[cfg(test)]
#[path = "tests/track_keys.rs"]
mod tests;
