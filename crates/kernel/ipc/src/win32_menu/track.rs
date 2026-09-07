//! The modal menu-tracking state machine: what one pointer or key event does
//! to the tracked menus, and what the tracking loop must do about it. Every
//! decision here is geometry-free; the loop supplies the hit test and applies
//! the effects against the live windows.
use alloc::vec::Vec;
use super::popup::{PopupHit, NO_SELECTED_ITEM, TF_RCVD_BTN_UP, TPM_RETURNCMD, TPM_RIGHTBUTTON};
use super::{MenuError, MenuId, MenuManager, MF_BYPOSITION, MF_DISABLED, MF_GRAYED, MF_HILITE, MF_POPUP, MF_SEPARATOR, MF_SYSMENU};

/// A popup item whose submenu is open under the pointer.
pub const MF_MOUSESELECT: u32 = 0x0000_8000;
/// Whole-menu style: the owner is told by position, not by command id.
pub const MNS_NOTIFYBYPOS: u32 = 0x0800_0000;

/// `exec_focused_item` executed nothing.
pub const EXEC_NOTHING: i32 = -1;
/// `exec_focused_item` opened a submenu instead of executing a command.
pub const EXEC_POPUP_SHOWN: i32 = -2;

pub const WM_CANCELMODE: u32 = 0x001f;
pub const WM_INITMENUPOPUP: u32 = 0x0117;
pub const WM_UNINITMENUPOPUP: u32 = 0x0125;
pub const WM_COMMAND: u32 = 0x0111;
pub const WM_SYSCOMMAND: u32 = 0x0112;
pub const WM_MENUSELECT: u32 = 0x011f;
pub const WM_MENUCOMMAND: u32 = 0x0126;

/// Selection movement, in item positions.
pub const ITEM_PREV: i32 = -1;
pub const ITEM_NEXT: i32 = 1;

/// What the tracking loop must do to the live windows for one decision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TrackEffect {
    /// Repaint one menu after its highlight moved.
    Repaint { menu: u32 },
    /// Send `WM_MENUSELECT` to the owner.
    MenuSelect { wparam: u64, lparam: i64 },
    /// Close the submenu open under `menu`'s focused item, innermost first.
    HideSubPopups { menu: u32 },
    /// Open the submenu of `menu`'s focused item; the new tracked menu.
    ShowSubPopup { menu: u32, select_first: bool },
    /// Post one message to the owner window.
    Post { message: u32, wparam: u64, lparam: i64 },
    /// The chosen item is disabled or absent.
    Beep,
}

/// One pointer event, already resolved to the menu and item it names.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct PointerEvent { pub pt: (i32, i32), pub menu: Option<u32>, pub hit: PopupHit, pub menu_is_bar: bool, pub right_button: bool }

/// The tracked menu chain and the flags one `TrackPopupMenuEx` or menu-bar
/// tracking session runs under.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Tracker { pub flags: u32, pub track_flags: u32, pub owner: u32, pub top_menu: u32, pub current_menu: u32, pub pt: (i32, i32), pub exit: bool }

impl MenuManager {
    /// Position of the highlighted item, or the absent-item report. # C: O(N_items)
    pub fn focused_item(&self, menu: MenuId) -> u32 {
        let Ok(count) = self.count(menu) else { return NO_SELECTED_ITEM; };
        for position in 0..count {
            if self.item(menu, position as u32, MF_BYPOSITION).is_ok_and(|item| item.state & MF_HILITE != 0) { return position as u32; }
        }
        NO_SELECTED_ITEM
    }

    /// Highlight exactly this position, clearing the previous highlight and
    /// the mouse-select bit it carried. A separator never highlights.
    /// # C: O(N_items)
    pub fn set_focused_item(&mut self, menu: MenuId, index: u32) -> Result<(), MenuError> {
        let count = self.count(menu)?;
        for position in 0..count {
            let entry = self.item_mut_by_position(menu, position)?;
            if position as u32 == index && entry.state & MF_SEPARATOR == 0 { entry.state |= MF_HILITE; }
            else { entry.state &= !(MF_HILITE | MF_MOUSESELECT); }
        }
        Ok(())
    }

    /// Whether an item at this position carries a submenu. # C: O(N_items)
    pub fn is_submenu_item(&self, menu: MenuId, position: u32) -> bool {
        self.item(menu, position, MF_BYPOSITION).is_ok_and(|item| item.submenu.is_some())
    }

    /// The `WM_MENUSELECT` word for one item: its position when it opens a
    /// submenu, its command id otherwise, beside its combined flags.
    /// # C: O(N_items)
    pub fn menu_select_word(&self, menu: MenuId, position: u32) -> Option<u64> {
        let item = self.item(menu, position, MF_BYPOSITION).ok()?;
        let popup = if item.submenu.is_some() { MF_POPUP } else { 0 };
        let sysmenu = self.item(menu, 0, MF_BYPOSITION).ok().map_or(0, |first| first.state & MF_SYSMENU);
        let low = if item.submenu.is_some() { position } else { item.id };
        Some((low as u64 & 0xffff) | (((item.state | popup | sysmenu) as u64 & 0xffff) << 16))
    }

    /// Position of the first item whose text carries `&key`, the close report
    /// when none does. # C: O(N_items * len)
    pub fn item_by_key(&self, menu: MenuId, key: u16) -> Option<u32> {
        let count = self.count(menu).ok()?;
        let wanted = fold_case(key);
        for position in 0..count {
            let item = self.item(menu, position as u32, MF_BYPOSITION).ok()?;
            let mut index = 0;
            while index + 1 < item.text.len() {
                if item.text[index] == '&' as u16 {
                    if item.text[index + 1] == '&' as u16 { index += 2; continue; }
                    if fold_case(item.text[index + 1]) == wanted { return Some(position as u32); }
                }
                index += 1;
            }
        }
        None
    }
}

/// ASCII case folding, the only folding a mnemonic comparison needs. # C: O(1)
fn fold_case(unit: u16) -> u16 { if (b'a' as u16..=b'z' as u16).contains(&unit) { unit - 32 } else { unit } }

impl Tracker {
    /// # C: O(1)
    pub fn new(flags: u32, owner: u32, menu: u32, pt: (i32, i32)) -> Self {
        Self { flags, track_flags: 0, owner, top_menu: menu, current_menu: menu, pt, exit: false }
    }

    /// Move the highlight to one item, repainting the menu and telling the
    /// owner which item is selected. Naming no item clears the highlight and,
    /// when a top menu is given, reports its item instead. # C: O(N_items)
    pub fn select_item(&self, menus: &mut MenuManager, effects: &mut Vec<TrackEffect>, menu: u32, index: u32, send_select: bool, topmenu: u32) {
        let Some(id) = MenuId::from_raw(menu) else { return; };
        if menus.count(id).unwrap_or(0) == 0 { return; }
        if menus.focused_item(id) == index { return; }
        let _ = menus.set_focused_item(id, index);
        effects.push(TrackEffect::Repaint { menu });
        if !send_select { return; }
        if index != NO_SELECTED_ITEM {
            if let Some(wparam) = menus.menu_select_word(id, index) {
                effects.push(TrackEffect::MenuSelect { wparam, lparam: menu as i64 });
            }
            return;
        }
        let Some(top) = MenuId::from_raw(topmenu) else { return; };
        let Some(position) = submenu_position(menus, top, menu) else { return; };
        if let Some(wparam) = menus.menu_select_word(top, position) {
            effects.push(TrackEffect::MenuSelect { wparam, lparam: topmenu as i64 });
        }
    }

    /// Move the highlight by one step, skipping separators and wrapping to the
    /// first or last item when nothing is highlighted. # C: O(N_items)
    pub fn move_selection(&self, menus: &mut MenuManager, effects: &mut Vec<TrackEffect>, menu: u32, offset: i32) {
        let Some(id) = MenuId::from_raw(menu) else { return; };
        let count = menus.count(id).unwrap_or(0) as i32;
        if count == 0 { return; }
        let focused = menus.focused_item(id);
        if focused != NO_SELECTED_ITEM {
            if count == 1 { return; }
            let mut position = focused as i32 + offset;
            while position >= 0 && position < count {
                if !is_separator(menus, id, position as u32) { self.select_item(menus, effects, menu, position as u32, true, 0); return; }
                position += offset;
            }
        }
        let mut position = if offset > 0 { 0 } else { count - 1 };
        while position >= 0 && position < count {
            if !is_separator(menus, id, position as u32) { self.select_item(menus, effects, menu, position as u32, true, 0); return; }
            position += offset;
        }
    }

    /// Execute the highlighted item: open its submenu, refuse a disabled item,
    /// or report its command id, posting it to the owner unless the caller
    /// asked for the id instead. # C: O(N_items)
    pub fn exec_focused_item(&mut self, menus: &mut MenuManager, effects: &mut Vec<TrackEffect>, menu: u32) -> i32 {
        let Some(id) = MenuId::from_raw(menu) else { return EXEC_NOTHING; };
        let focused = menus.focused_item(id);
        if focused == NO_SELECTED_ITEM { return EXEC_NOTHING; }
        let Ok(item) = menus.item(id, focused, MF_BYPOSITION) else { return EXEC_NOTHING; };
        let (command, state, submenu) = (item.id, item.state, item.submenu);
        if submenu.is_some() {
            effects.push(TrackEffect::ShowSubPopup { menu, select_first: true });
            return EXEC_POPUP_SHOWN;
        }
        if state & (MF_GRAYED | MF_DISABLED | MF_SEPARATOR) != 0 { return EXEC_NOTHING; }
        if self.flags & TPM_RETURNCMD == 0 {
            let sysmenu = menus.item(id, 0, MF_BYPOSITION).is_ok_and(|first| first.state & MF_SYSMENU != 0);
            let point = ((self.pt.0 as u16 as u64) | ((self.pt.1 as u16 as u64) << 16)) as i64;
            if sysmenu { effects.push(TrackEffect::Post { message: WM_SYSCOMMAND, wparam: command as u64, lparam: point }); }
            else if by_position(menus, id, self.top_menu) { effects.push(TrackEffect::Post { message: WM_MENUCOMMAND, wparam: focused as u64, lparam: menu as i64 }); }
            else { effects.push(TrackEffect::Post { message: WM_COMMAND, wparam: command as u64, lparam: 0 }); }
        }
        command as i32
    }

    /// Move tracking to another menu in the chain, closing what the previous
    /// one had open. # C: O(N_items)
    pub fn switch_tracking(&mut self, menus: &mut MenuManager, effects: &mut Vec<TrackEffect>, pt_menu: u32, index: u32) {
        let both_bars = !is_popup_menu(menus, pt_menu) && !is_popup_menu(menus, self.top_menu);
        if self.top_menu != pt_menu && both_bars {
            effects.push(TrackEffect::HideSubPopups { menu: self.top_menu });
            self.select_item(menus, effects, self.top_menu, NO_SELECTED_ITEM, false, 0);
            self.top_menu = pt_menu;
        } else {
            effects.push(TrackEffect::HideSubPopups { menu: pt_menu });
        }
        self.select_item(menus, effects, pt_menu, index, true, 0);
    }

    /// A button going down over a menu: select what it names, open a submenu,
    /// and report whether tracking continues. # C: O(N_items)
    pub fn button_down(&mut self, menus: &mut MenuManager, event: &PointerEvent, effects: &mut Vec<TrackEffect>) -> bool {
        if event.right_button && self.flags & TPM_RIGHTBUTTON == 0 { return true; }
        let Some(menu) = event.menu else { return false; };
        let Some(id) = MenuId::from_raw(menu) else { return false; };
        self.pt = event.pt;
        let position = match event.hit { PopupHit::Item(position) => position, _ => NO_SELECTED_ITEM };
        if position != NO_SELECTED_ITEM {
            if menus.focused_item(id) != position { self.switch_tracking(menus, effects, menu, position); }
            let popped = menus.item(id, position, MF_BYPOSITION).is_ok_and(|item| item.state & MF_MOUSESELECT != 0);
            if !popped && menus.is_submenu_item(id, position) { effects.push(TrackEffect::ShowSubPopup { menu, select_first: false }); }
        }
        matches!(event.hit, PopupHit::Item(_)) || (is_popup_menu(menus, menu) && event.hit != PopupHit::Nowhere)
    }

    /// A button coming up over a menu: execute the item it names, or report
    /// that tracking continues. # C: O(N_items)
    pub fn button_up(&mut self, menus: &mut MenuManager, event: &PointerEvent, effects: &mut Vec<TrackEffect>) -> i32 {
        if event.right_button && self.flags & TPM_RIGHTBUTTON == 0 { return EXEC_NOTHING; }
        let Some(menu) = event.menu else { return EXEC_NOTHING; };
        let Some(id) = MenuId::from_raw(menu) else { return EXEC_NOTHING; };
        self.pt = event.pt;
        let position = match event.hit { PopupHit::Item(position) => position, _ => NO_SELECTED_ITEM };
        if position != NO_SELECTED_ITEM && menus.focused_item(id) == position {
            if !menus.is_submenu_item(id, position) {
                let executed = self.exec_focused_item(menus, effects, menu);
                return if executed == EXEC_NOTHING || executed == EXEC_POPUP_SHOWN { EXEC_NOTHING } else { executed };
            }
            if self.top_menu == menu && self.track_flags & TF_RCVD_BTN_UP != 0 { return 0; }
        }
        if event.menu_is_bar {
            if position == NO_SELECTED_ITEM { return 0; }
            self.track_flags |= TF_RCVD_BTN_UP;
        }
        EXEC_NOTHING
    }

    /// The pointer moving: the highlight follows it, opening the submenu of
    /// whatever it lands on. # C: O(N_items)
    pub fn mouse_move(&mut self, menus: &mut MenuManager, event: &PointerEvent, effects: &mut Vec<TrackEffect>) -> bool {
        self.pt = event.pt;
        let position = match (event.menu, event.hit) { (Some(_), PopupHit::Item(position)) => position, _ => NO_SELECTED_ITEM };
        if position == NO_SELECTED_ITEM {
            let current = self.current_menu;
            let top = self.top_menu;
            self.select_item(menus, effects, current, NO_SELECTED_ITEM, true, top);
            return true;
        }
        let menu = event.menu.unwrap_or(0);
        let Some(id) = MenuId::from_raw(menu) else { return true; };
        if menus.focused_item(id) != position {
            self.switch_tracking(menus, effects, menu, position);
            effects.push(TrackEffect::ShowSubPopup { menu, select_first: false });
        }
        true
    }

    /// A character typed while tracking: return or space executes the
    /// highlighted item, any other character selects and executes the item
    /// whose mnemonic it names. # C: O(N_items * len)
    pub fn char_key(&mut self, menus: &mut MenuManager, ch: u16, effects: &mut Vec<TrackEffect>) -> i32 {
        let menu = self.current_menu;
        if ch == '\r' as u16 || ch == ' ' as u16 {
            let executed = self.exec_focused_item(menus, effects, menu);
            self.exit = executed != EXEC_POPUP_SHOWN;
            return executed;
        }
        if ch < 32 { return EXEC_NOTHING; }
        let Some(id) = MenuId::from_raw(menu) else { return EXEC_NOTHING; };
        let Some(position) = menus.item_by_key(id, ch) else { effects.push(TrackEffect::Beep); return EXEC_NOTHING; };
        self.select_item(menus, effects, menu, position, true, 0);
        let executed = self.exec_focused_item(menus, effects, menu);
        self.exit = executed != EXEC_POPUP_SHOWN;
        executed
    }
}

/// Whether one menu is a popup rather than a bar. # C: O(N_menus)
pub fn is_popup_menu(menus: &MenuManager, menu: u32) -> bool {
    MenuId::from_raw(menu).and_then(|id| menus.is_popup(id).ok()).unwrap_or(false)
}

/// The menu whose item carries `target` as its submenu, searched from `top`
/// down the submenu links. The top menu itself has no parent. A menu reached
/// twice is not walked twice, so a malformed cycle terminates.
/// # C: O(N_menus * N_items)
pub fn parent_menu(menus: &MenuManager, top: u32, target: u32) -> Option<u32> {
    if top == target { return None; }
    let mut pending = alloc::vec![top];
    let mut seen: Vec<u32> = Vec::new();
    while let Some(menu) = pending.pop() {
        if seen.contains(&menu) { continue; }
        seen.push(menu);
        let Some(id) = MenuId::from_raw(menu) else { continue; };
        let Ok(count) = menus.count(id) else { continue; };
        for position in 0..count {
            let Some(submenu) = menus.item(id, position as u32, MF_BYPOSITION).ok().and_then(|item| item.submenu) else { continue; };
            if submenu == target { return Some(menu); }
            pending.push(submenu);
        }
    }
    None
}

fn is_separator(menus: &MenuManager, menu: MenuId, position: u32) -> bool {
    menus.item(menu, position, MF_BYPOSITION).is_ok_and(|item| item.state & MF_SEPARATOR != 0)
}

/// Whether either the executing menu or the top menu asks for position
/// notification. # C: O(N_menus)
fn by_position(menus: &MenuManager, menu: MenuId, top: u32) -> bool {
    let mut info = super::MenuInfo::default();
    let own = menus.info(menu, super::MIM_STYLE, &mut info).is_ok() && info.style & MNS_NOTIFYBYPOS != 0;
    let mut top_info = super::MenuInfo::default();
    let top_style = MenuId::from_raw(top).is_some_and(|top| menus.info(top, super::MIM_STYLE, &mut top_info).is_ok()) && top_info.style & MNS_NOTIFYBYPOS != 0;
    own || top_style
}

/// Position of the item of `menu` whose submenu is `submenu`. # C: O(N_items)
pub fn submenu_position(menus: &MenuManager, menu: MenuId, submenu: u32) -> Option<u32> {
    let count = menus.count(menu).ok()?;
    for position in 0..count {
        if menus.item(menu, position as u32, MF_BYPOSITION).ok()?.submenu == Some(submenu) { return Some(position as u32); }
    }
    None
}

#[cfg(test)]
#[path = "tests/track.rs"]
mod tests;
