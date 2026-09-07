//! The single-word menu questions and the radio-range write.
use super::super::*;
use super::super::method::{GMDI_GOINTOPOPUPS, GMDI_USEDISABLED};

fn item(id: u32, state: u32) -> MenuItem { MenuItem { id, state, text: alloc::vec::Vec::new(), submenu: None } }

fn menu_of(states: &[(u32, u32)]) -> (MenuManager, MenuId) {
    let mut menus = MenuManager::new();
    let menu = menus.create().unwrap();
    for (position, (id, state)) in states.iter().enumerate() { menus.insert(menu, position, item(*id, *state)).unwrap(); }
    (menus, menu)
}

#[test]
fn a_command_item_answers_its_identifier_and_a_popup_answers_none() {
    let (mut menus, menu) = menu_of(&[(11, 0), (12, 0)]);
    let submenu = menus.create_popup().unwrap();
    menus.item_mut_by_position(menu, 1).unwrap().submenu = Some(submenu.raw());
    assert_eq!(menus.item_id(menu, 0, MF_BYPOSITION), 11);
    assert_eq!(menus.item_id(menu, 1, MF_BYPOSITION), u32::MAX);
    assert_eq!(menus.item_id(menu, 7, MF_BYPOSITION), MENU_NOT_FOUND);
}

#[test]
fn a_popup_items_state_reports_the_size_of_its_submenu() {
    let (mut menus, menu) = menu_of(&[(11, MF_CHECKED), (12, MF_POPUP)]);
    let submenu = menus.create_popup().unwrap();
    menus.insert(submenu, 0, item(21, 0)).unwrap();
    menus.insert(submenu, 1, item(22, 0)).unwrap();
    menus.item_mut_by_position(menu, 1).unwrap().submenu = Some(submenu.raw());
    assert_eq!(menus.item_state(menu, 0, MF_BYPOSITION), MF_CHECKED);
    assert_eq!(menus.item_state(menu, 1, MF_BYPOSITION), (2 << 8) | MF_POPUP);
    assert_eq!(menus.item_state(menu, 5, MF_BYPOSITION), MENU_NOT_FOUND);
}

#[test]
fn the_submenu_query_answers_a_handle_only_for_a_popup_item() {
    let (mut menus, menu) = menu_of(&[(11, 0), (12, MF_POPUP)]);
    let submenu = menus.create_popup().unwrap();
    menus.item_mut_by_position(menu, 1).unwrap().submenu = Some(submenu.raw());
    assert_eq!(menus.sub_menu(menu, 1), submenu.raw());
    assert_eq!(menus.sub_menu(menu, 0), 0);
    assert_eq!(menus.sub_menu(menu, 9), 0);
}

#[test]
fn the_default_item_answers_a_position_or_an_identifier_as_asked() {
    let (menus, menu) = menu_of(&[(11, 0), (12, MF_DEFAULT), (13, 0)]);
    assert_eq!(menus.default_item(menu, true, 0), 1);
    assert_eq!(menus.default_item(menu, false, 0), 12);
    let (menus, menu) = menu_of(&[(11, 0)]);
    assert_eq!(menus.default_item(menu, true, 0), MENU_NOT_FOUND);
}

#[test]
fn a_disabled_default_item_answers_only_when_the_search_keeps_disabled_items() {
    let (menus, menu) = menu_of(&[(11, 0), (12, MF_DEFAULT | MF_GRAYED)]);
    assert_eq!(menus.default_item(menu, true, 0), MENU_NOT_FOUND);
    assert_eq!(menus.default_item(menu, true, GMDI_USEDISABLED), 1);
    let (menus, menu) = menu_of(&[(11, MF_DEFAULT | MF_DISABLED)]);
    assert_eq!(menus.default_item(menu, false, 0), MENU_NOT_FOUND);
    assert_eq!(menus.default_item(menu, false, GMDI_USEDISABLED), 11);
}

#[test]
fn the_default_search_enters_a_popup_only_when_asked_and_falls_back_to_the_popup() {
    let (mut menus, menu) = menu_of(&[(11, 0), (12, MF_POPUP | MF_DEFAULT)]);
    let submenu = menus.create_popup().unwrap();
    menus.insert(submenu, 0, item(21, 0)).unwrap();
    menus.insert(submenu, 1, item(22, MF_DEFAULT)).unwrap();
    menus.item_mut_by_position(menu, 1).unwrap().submenu = Some(submenu.raw());
    assert_eq!(menus.default_item(menu, false, 0), 12);
    assert_eq!(menus.default_item(menu, false, GMDI_GOINTOPOPUPS), 22);
    assert_eq!(menus.default_item(menu, true, GMDI_GOINTOPOPUPS), 1);
    // A submenu with no default of its own leaves the popup item itself as the answer.
    menus.item_mut_by_position(submenu, 1).unwrap().state &= !MF_DEFAULT;
    assert_eq!(menus.default_item(menu, false, GMDI_GOINTOPOPUPS), 12);
}

#[test]
fn the_radio_range_checks_one_item_and_clears_the_others() {
    let (mut menus, menu) = menu_of(&[(10, MF_CHECKED), (11, MF_CHECKED), (12, MF_CHECKED)]);
    assert!(menus.check_radio_item(menu, 10, 12, 11, 0));
    assert_eq!(menus.item(menu, 0, MF_BYPOSITION).unwrap().state, 0);
    assert_eq!(menus.item(menu, 1, MF_BYPOSITION).unwrap().state, MFT_RADIOCHECK_TEST | MF_CHECKED);
    assert_eq!(menus.item(menu, 2, MF_BYPOSITION).unwrap().state, 0);
}

/// The bit an item drawn as a radio button carries.
const MFT_RADIOCHECK_TEST: u32 = 0x0000_0200;

#[test]
fn the_radio_range_walks_positions_when_asked_by_position() {
    let (mut menus, menu) = menu_of(&[(90, 0), (91, 0), (92, 0)]);
    assert!(menus.check_radio_item(menu, 0, 2, 2, MF_BYPOSITION));
    assert_eq!(menus.item(menu, 2, MF_BYPOSITION).unwrap().state, MFT_RADIOCHECK_TEST | MF_CHECKED);
    assert_eq!(menus.item(menu, 0, MF_BYPOSITION).unwrap().state, 0);
}

#[test]
fn a_separator_in_the_range_is_left_alone_and_a_missing_member_does_not_end_the_walk() {
    let (mut menus, menu) = menu_of(&[(10, MF_SEPARATOR | MF_CHECKED), (12, 0)]);
    assert!(menus.check_radio_item(menu, 10, 12, 12, 0));
    assert_eq!(menus.item(menu, 0, MF_BYPOSITION).unwrap().state, MF_SEPARATOR | MF_CHECKED);
    assert_eq!(menus.item(menu, 1, MF_BYPOSITION).unwrap().state, MFT_RADIOCHECK_TEST | MF_CHECKED);
}

#[test]
fn a_range_that_never_reaches_the_chosen_item_answers_false() {
    let (mut menus, menu) = menu_of(&[(10, 0), (11, 0)]);
    assert!(!menus.check_radio_item(menu, 10, 11, 12, 0));
    assert_eq!(menus.item(menu, 0, MF_BYPOSITION).unwrap().state, 0);
    // A range ending at the last representable identifier still terminates.
    assert!(!menus.check_radio_item(menu, u32::MAX - 1, u32::MAX, u32::MAX, 0));
}
