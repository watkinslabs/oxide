use super::*;
use crate::win32_menu::MenuItem;
use crate::win32_menu::popup::{TPM_RETURNCMD, TPM_RIGHTBUTTON};

fn text(value: &str) -> alloc::vec::Vec<u16> { value.encode_utf16().collect() }

/// One bar carrying a single popup, and the popup's own items.
fn chain() -> (MenuManager, u32, u32) {
    let mut menus = MenuManager::new();
    let bar = menus.create().unwrap();
    let popup = menus.create_popup().unwrap();
    menus.insert(bar, 0, MenuItem { id: 0, state: 0, text: text("&File"), submenu: Some(popup.raw()) }).unwrap();
    menus.insert(popup, 0, MenuItem { id: 100, state: 0, text: text("&New"), submenu: None }).unwrap();
    menus.insert(popup, 1, MenuItem { id: 101, state: MF_GRAYED, text: text("&Open"), submenu: None }).unwrap();
    menus.insert(popup, 2, MenuItem { id: 0, state: MF_SEPARATOR, text: text(""), submenu: None }).unwrap();
    menus.insert(popup, 3, MenuItem { id: 102, state: 0, text: text("E&xit"), submenu: None }).unwrap();
    (menus, bar.raw(), popup.raw())
}

fn event(position: u32, menu: u32) -> PointerEvent {
    PointerEvent { pt: (10, 20), menu: Some(menu), hit: PopupHit::Item(position), menu_is_bar: false, right_button: false }
}

#[test]
fn the_highlight_moves_and_the_owner_is_told_which_item_is_selected() {
    let (mut menus, _, popup) = chain();
    let tracker = Tracker::new(0, 7, popup, (0, 0));
    let mut effects = alloc::vec::Vec::new();
    tracker.select_item(&mut menus, &mut effects, popup, 3, true, 0);
    assert_eq!(menus.focused_item(MenuId::from_raw(popup).unwrap()), 3);
    assert_eq!(effects[0], TrackEffect::Repaint { menu: popup });
    assert_eq!(effects[1], TrackEffect::MenuSelect { wparam: 102 | ((MF_HILITE as u64) << 16), lparam: popup as i64 });
    // Selecting the same item again decides nothing.
    effects.clear();
    tracker.select_item(&mut menus, &mut effects, popup, 3, true, 0);
    assert!(effects.is_empty());
}

#[test]
fn clearing_the_selection_reports_the_top_menu_item_the_popup_belongs_to() {
    let (mut menus, bar, popup) = chain();
    let tracker = Tracker::new(0, 7, bar, (0, 0));
    let mut effects = alloc::vec::Vec::new();
    tracker.select_item(&mut menus, &mut effects, popup, 0, true, 0);
    effects.clear();
    tracker.select_item(&mut menus, &mut effects, popup, NO_SELECTED_ITEM, true, bar);
    assert_eq!(menus.focused_item(MenuId::from_raw(popup).unwrap()), NO_SELECTED_ITEM);
    assert_eq!(effects.last(), Some(&TrackEffect::MenuSelect { wparam: (MF_POPUP as u64) << 16, lparam: bar as i64 }));
}

#[test]
fn selection_movement_skips_separators_and_wraps_from_nothing() {
    let (mut menus, _, popup) = chain();
    let tracker = Tracker::new(0, 7, popup, (0, 0));
    let mut effects = alloc::vec::Vec::new();
    let id = MenuId::from_raw(popup).unwrap();
    tracker.move_selection(&mut menus, &mut effects, popup, ITEM_NEXT);
    assert_eq!(menus.focused_item(id), 0);
    tracker.move_selection(&mut menus, &mut effects, popup, ITEM_NEXT);
    assert_eq!(menus.focused_item(id), 1);
    tracker.move_selection(&mut menus, &mut effects, popup, ITEM_NEXT);
    assert_eq!(menus.focused_item(id), 3);
    tracker.move_selection(&mut menus, &mut effects, popup, ITEM_PREV);
    assert_eq!(menus.focused_item(id), 1);
}

#[test]
fn a_separator_never_takes_the_highlight() {
    let (mut menus, _, popup) = chain();
    let id = MenuId::from_raw(popup).unwrap();
    menus.set_focused_item(id, 2).unwrap();
    assert_eq!(menus.focused_item(id), NO_SELECTED_ITEM);
}

#[test]
fn executing_a_command_posts_it_to_the_owner_and_reports_its_id() {
    let (mut menus, bar, popup) = chain();
    let mut tracker = Tracker::new(0, 7, popup, (5, 6));
    tracker.top_menu = bar;
    let mut effects = alloc::vec::Vec::new();
    tracker.select_item(&mut menus, &mut effects, popup, 3, false, 0);
    effects.clear();
    assert_eq!(tracker.exec_focused_item(&mut menus, &mut effects, popup), 102);
    assert_eq!(effects, alloc::vec![TrackEffect::Post { message: WM_COMMAND, wparam: 102, lparam: 0 }]);
}

#[test]
fn a_return_command_request_reports_the_id_and_posts_nothing() {
    let (mut menus, _, popup) = chain();
    let mut tracker = Tracker::new(TPM_RETURNCMD, 7, popup, (0, 0));
    let mut effects = alloc::vec::Vec::new();
    tracker.select_item(&mut menus, &mut effects, popup, 3, false, 0);
    effects.clear();
    assert_eq!(tracker.exec_focused_item(&mut menus, &mut effects, popup), 102);
    assert!(effects.is_empty());
}

#[test]
fn a_disabled_item_and_an_unselected_menu_execute_nothing() {
    let (mut menus, _, popup) = chain();
    let mut tracker = Tracker::new(0, 7, popup, (0, 0));
    let mut effects = alloc::vec::Vec::new();
    assert_eq!(tracker.exec_focused_item(&mut menus, &mut effects, popup), EXEC_NOTHING);
    tracker.select_item(&mut menus, &mut effects, popup, 1, false, 0);
    effects.clear();
    assert_eq!(tracker.exec_focused_item(&mut menus, &mut effects, popup), EXEC_NOTHING);
    assert!(effects.is_empty());
}

#[test]
fn executing_a_submenu_item_opens_it_rather_than_choosing_a_command() {
    let (mut menus, bar, _) = chain();
    let mut tracker = Tracker::new(0, 7, bar, (0, 0));
    let mut effects = alloc::vec::Vec::new();
    tracker.select_item(&mut menus, &mut effects, bar, 0, false, 0);
    effects.clear();
    assert_eq!(tracker.exec_focused_item(&mut menus, &mut effects, bar), EXEC_POPUP_SHOWN);
    assert_eq!(effects, alloc::vec![TrackEffect::ShowSubPopup { menu: bar, select_first: true }]);
}

#[test]
fn a_system_menu_command_is_posted_as_a_system_command_with_the_point() {
    let mut menus = MenuManager::new();
    let sys = menus.create_popup().unwrap();
    menus.insert(sys, 0, MenuItem { id: 0xf060, state: MF_SYSMENU, text: text("&Close"), submenu: None }).unwrap();
    let mut tracker = Tracker::new(0, 7, sys.raw(), (5, 6));
    let mut effects = alloc::vec::Vec::new();
    tracker.select_item(&mut menus, &mut effects, sys.raw(), 0, false, 0);
    effects.clear();
    assert_eq!(tracker.exec_focused_item(&mut menus, &mut effects, sys.raw()), 0xf060);
    assert_eq!(effects, alloc::vec![TrackEffect::Post { message: WM_SYSCOMMAND, wparam: 0xf060, lparam: 5 | (6 << 16) }]);
}

#[test]
fn a_by_position_menu_notifies_the_owner_by_position() {
    let (mut menus, _, popup) = chain();
    let id = MenuId::from_raw(popup).unwrap();
    menus.set_info(id, crate::win32_menu::MIM_STYLE, crate::win32_menu::MenuInfo { style: MNS_NOTIFYBYPOS, ..Default::default() }).unwrap();
    let mut tracker = Tracker::new(0, 7, popup, (0, 0));
    let mut effects = alloc::vec::Vec::new();
    tracker.select_item(&mut menus, &mut effects, popup, 3, false, 0);
    effects.clear();
    tracker.exec_focused_item(&mut menus, &mut effects, popup);
    assert_eq!(effects, alloc::vec![TrackEffect::Post { message: WM_MENUCOMMAND, wparam: 3, lparam: popup as i64 }]);
}

#[test]
fn a_button_down_on_an_item_selects_it_and_keeps_tracking() {
    let (mut menus, _, popup) = chain();
    let mut tracker = Tracker::new(0, 7, popup, (0, 0));
    let mut effects = alloc::vec::Vec::new();
    assert!(tracker.button_down(&mut menus, &event(3, popup), &mut effects));
    assert_eq!(menus.focused_item(MenuId::from_raw(popup).unwrap()), 3);
    assert!(effects.contains(&TrackEffect::HideSubPopups { menu: popup }));
}

#[test]
fn a_button_down_on_a_bar_item_opens_its_submenu() {
    let (mut menus, bar, _) = chain();
    let mut tracker = Tracker::new(0, 7, bar, (0, 0));
    let mut effects = alloc::vec::Vec::new();
    assert!(tracker.button_down(&mut menus, &event(0, bar), &mut effects));
    assert!(effects.contains(&TrackEffect::ShowSubPopup { menu: bar, select_first: false }));
}

#[test]
fn a_button_down_outside_every_menu_ends_tracking() {
    let (mut menus, _, popup) = chain();
    let mut tracker = Tracker::new(0, 7, popup, (0, 0));
    let mut effects = alloc::vec::Vec::new();
    let outside = PointerEvent { pt: (0, 0), menu: None, hit: PopupHit::Nowhere, menu_is_bar: false, right_button: false };
    assert!(!tracker.button_down(&mut menus, &outside, &mut effects));
}

#[test]
fn a_right_button_is_ignored_unless_the_caller_asked_for_it() {
    let (mut menus, _, popup) = chain();
    let mut tracker = Tracker::new(0, 7, popup, (0, 0));
    let mut effects = alloc::vec::Vec::new();
    let right = PointerEvent { right_button: true, ..event(3, popup) };
    assert!(tracker.button_down(&mut menus, &right, &mut effects));
    assert!(effects.is_empty());
    let mut accepting = Tracker::new(TPM_RIGHTBUTTON, 7, popup, (0, 0));
    assert!(accepting.button_down(&mut menus, &right, &mut effects));
    assert!(!effects.is_empty());
}

#[test]
fn a_button_up_on_the_selected_command_executes_it() {
    let (mut menus, _, popup) = chain();
    let mut tracker = Tracker::new(0, 7, popup, (0, 0));
    let mut effects = alloc::vec::Vec::new();
    tracker.select_item(&mut menus, &mut effects, popup, 3, false, 0);
    effects.clear();
    assert_eq!(tracker.button_up(&mut menus, &event(3, popup), &mut effects), 102);
}

#[test]
fn a_button_up_on_an_unselected_item_keeps_tracking() {
    let (mut menus, _, popup) = chain();
    let mut tracker = Tracker::new(0, 7, popup, (0, 0));
    let mut effects = alloc::vec::Vec::new();
    assert_eq!(tracker.button_up(&mut menus, &event(3, popup), &mut effects), EXEC_NOTHING);
}

#[test]
fn a_second_button_up_on_an_open_bar_item_ends_tracking_with_nothing_chosen() {
    let (mut menus, bar, _) = chain();
    let mut tracker = Tracker::new(0, 7, bar, (0, 0));
    let mut effects = alloc::vec::Vec::new();
    tracker.select_item(&mut menus, &mut effects, bar, 0, false, 0);
    let on_bar = PointerEvent { menu_is_bar: true, ..event(0, bar) };
    assert_eq!(tracker.button_up(&mut menus, &on_bar, &mut effects), EXEC_NOTHING);
    assert_eq!(tracker.track_flags & TF_RCVD_BTN_UP, TF_RCVD_BTN_UP);
    assert_eq!(tracker.button_up(&mut menus, &on_bar, &mut effects), 0);
}

#[test]
fn the_pointer_leaving_every_item_clears_the_selection() {
    let (mut menus, _, popup) = chain();
    let mut tracker = Tracker::new(0, 7, popup, (0, 0));
    let mut effects = alloc::vec::Vec::new();
    tracker.select_item(&mut menus, &mut effects, popup, 0, false, 0);
    effects.clear();
    let nowhere = PointerEvent { pt: (1, 2), menu: None, hit: PopupHit::Nowhere, menu_is_bar: false, right_button: false };
    assert!(tracker.mouse_move(&mut menus, &nowhere, &mut effects));
    assert_eq!(menus.focused_item(MenuId::from_raw(popup).unwrap()), NO_SELECTED_ITEM);
    assert_eq!(tracker.pt, (1, 2));
}

#[test]
fn the_pointer_moving_onto_an_item_selects_it_and_opens_its_submenu() {
    let (mut menus, bar, _) = chain();
    let mut tracker = Tracker::new(0, 7, bar, (0, 0));
    let mut effects = alloc::vec::Vec::new();
    assert!(tracker.mouse_move(&mut menus, &event(0, bar), &mut effects));
    assert_eq!(menus.focused_item(MenuId::from_raw(bar).unwrap()), 0);
    assert!(effects.contains(&TrackEffect::ShowSubPopup { menu: bar, select_first: false }));
}

#[test]
fn return_executes_the_selected_item_and_a_mnemonic_picks_one() {
    let (mut menus, _, popup) = chain();
    let mut tracker = Tracker::new(TPM_RETURNCMD, 7, popup, (0, 0));
    let mut effects = alloc::vec::Vec::new();
    tracker.select_item(&mut menus, &mut effects, popup, 0, false, 0);
    assert_eq!(tracker.char_key(&mut menus, '\r' as u16, &mut effects), 100);
    assert!(tracker.exit);
    let mut second = Tracker::new(TPM_RETURNCMD, 7, popup, (0, 0));
    assert_eq!(second.char_key(&mut menus, 'x' as u16, &mut effects), 102);
}

#[test]
fn an_unknown_mnemonic_warns_and_chooses_nothing() {
    let (mut menus, _, popup) = chain();
    let mut tracker = Tracker::new(0, 7, popup, (0, 0));
    let mut effects = alloc::vec::Vec::new();
    assert_eq!(tracker.char_key(&mut menus, 'z' as u16, &mut effects), EXEC_NOTHING);
    assert_eq!(effects, alloc::vec![TrackEffect::Beep]);
}

#[test]
fn a_control_character_decides_nothing() {
    let (mut menus, _, popup) = chain();
    let mut tracker = Tracker::new(0, 7, popup, (0, 0));
    let mut effects = alloc::vec::Vec::new();
    assert_eq!(tracker.char_key(&mut menus, 3, &mut effects), EXEC_NOTHING);
    assert!(effects.is_empty());
}

#[test]
fn a_doubled_ampersand_is_not_a_mnemonic() {
    let mut menus = MenuManager::new();
    let menu = menus.create_popup().unwrap();
    menus.insert(menu, 0, MenuItem { id: 1, state: 0, text: text("A&&B&C"), submenu: None }).unwrap();
    assert_eq!(menus.item_by_key(menu, 'c' as u16), Some(0));
    assert_eq!(menus.item_by_key(menu, 'b' as u16), None);
}

#[test]
fn switching_between_two_bars_moves_the_top_menu_and_closes_the_old_one() {
    let (mut menus, bar, popup) = chain();
    let second = menus.create().unwrap();
    menus.insert(second, 0, MenuItem { id: 5, state: 0, text: text("&Help"), submenu: None }).unwrap();
    let mut tracker = Tracker::new(0, 7, bar, (0, 0));
    let mut effects = alloc::vec::Vec::new();
    tracker.switch_tracking(&mut menus, &mut effects, second.raw(), 0);
    assert_eq!(tracker.top_menu, second.raw());
    assert_eq!(effects[0], TrackEffect::HideSubPopups { menu: bar });
    // A popup in the chain hides only itself and leaves the top menu alone.
    effects.clear();
    tracker.switch_tracking(&mut menus, &mut effects, popup, 0);
    assert_eq!(tracker.top_menu, second.raw());
    assert_eq!(effects[0], TrackEffect::HideSubPopups { menu: popup });
}

#[test]
fn the_submenu_position_lookup_names_the_owning_item() {
    let (menus, bar, popup) = chain();
    assert_eq!(submenu_position(&menus, MenuId::from_raw(bar).unwrap(), popup), Some(0));
    assert_eq!(submenu_position(&menus, MenuId::from_raw(bar).unwrap(), 999), None);
}
