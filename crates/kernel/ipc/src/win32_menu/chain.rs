//! The tracked chain of menus resolved against geometry: which menu a screen
//! point falls on, which item's submenu is about to open, and which submenus
//! are open under an item. The driver owns the windows; every decision about
//! them is here, where it can be tested without one.
use alloc::vec::Vec;
use super::bar_hit::{bar_hit_test, BarMetrics};
use super::popup::{hit_test, PopupHit, PopupLayout, NO_SELECTED_ITEM};
#[cfg(test)]
use super::popup::PopupMetrics;
use super::track::MF_MOUSESELECT;
use super::{MenuId, MenuManager, MenuRect, MF_BYPOSITION};

/// One menu of the chain that has a window of its own: where that window sits
/// on screen, and the layout its items were measured with.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OpenMenu { pub menu: u32, pub rect: MenuRect, pub layout: PopupLayout }

/// The top menu drawn as a bar on its owner's window rather than in a popup
/// window: the owner's rectangle, and the cell metrics the bar was measured
/// and drawn with.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct BarChain { pub menu: u32, pub bounds: MenuRect, pub metrics: BarMetrics }

/// Which menu of the tracked chain a screen point falls on, and where in it.
/// The innermost popup wins, as the chain is walked from the open submenu
/// outwards; only once no open popup claims the point does the top menu get
/// its turn, as a bar drawn on the owner's own window. # C: O(N_open * N_items)
pub fn menu_from_point(menus: &MenuManager, open: &[OpenMenu], bar: Option<BarChain>, point: (i32, i32)) -> (Option<u32>, PopupHit) {
    for entry in open {
        let hit = hit_test(&entry.layout, entry.rect, point);
        if hit != PopupHit::Nowhere { return (Some(entry.menu), hit); }
    }
    let Some(bar) = bar else { return (None, PopupHit::Nowhere); };
    let Some(menu) = MenuId::from_raw(bar.menu) else { return (None, PopupHit::Nowhere); };
    if menus.is_popup(menu).unwrap_or(true) { return (None, PopupHit::Nowhere); }
    let hit = bar_hit_test(menus, menu, bar.bounds, point, bar.metrics);
    if hit == PopupHit::Nowhere { (None, hit) } else { (Some(bar.menu), hit) }
}

/// The item of one menu whose submenu the loop is about to open. # C: O(N_items)
pub fn submenu_target(menus: &MenuManager, menu: u32) -> Option<(u32, u32)> {
    let id = MenuId::from_raw(menu)?;
    let focused = menus.focused_item(id);
    if focused == NO_SELECTED_ITEM { return None; }
    Some((focused, menus.item(id, focused, MF_BYPOSITION).ok()?.submenu?))
}

/// The submenus open under one menu's focused item, innermost first, with
/// their highlight and mouse-select state cleared as they are collected. The
/// walk stops after `depth` menus, which is how many windows the chain has.
/// # C: O(depth * N_items)
pub fn sub_popup_chain(menus: &mut MenuManager, depth: usize, menu: u32) -> Vec<u32> {
    let mut chain = Vec::new();
    let mut current = menu;
    for _ in 0..depth {
        let Some(id) = MenuId::from_raw(current) else { break; };
        let focused = menus.focused_item(id);
        if focused == NO_SELECTED_ITEM { break; }
        let Ok(item) = menus.item(id, focused, MF_BYPOSITION) else { break; };
        if item.state & MF_MOUSESELECT == 0 { break; }
        let Some(submenu) = item.submenu else { break; };
        if let Ok(item) = menus.item_mut_by_position(id, focused as usize) { item.state &= !MF_MOUSESELECT; }
        if let Some(submenu_id) = MenuId::from_raw(submenu) { let _ = menus.set_focused_item(submenu_id, NO_SELECTED_ITEM); }
        chain.push(submenu);
        current = submenu;
    }
    chain.reverse();
    chain
}

/// Mark one item as the one whose submenu is open under the pointer, which is
/// what the chain walk reads back. # C: O(N_items)
pub fn mark_mouse_select(menus: &mut MenuManager, menu: u32, position: u32) {
    let Some(id) = MenuId::from_raw(menu) else { return; };
    if let Ok(item) = menus.item_mut_by_position(id, position as usize) { item.state |= MF_MOUSESELECT; }
}

/// Where a submenu opens: at the right edge of the item that owns it, in the
/// screen space its parent's window is placed in. Reports the origin and the
/// anchor size a popup that will not fit is pushed past. # C: O(1)
pub fn sub_popup_origin(parent: MenuRect, item: MenuRect) -> ((i32, i32), (i32, i32)) {
    ((parent.left.saturating_add(item.right), parent.top.saturating_add(item.top)),
        (item.right.saturating_sub(item.left), item.bottom.saturating_sub(item.top)))
}

#[cfg(test)]
#[path = "tests/chain.rs"]
mod tests;
