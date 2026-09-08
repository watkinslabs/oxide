//! Whole-menu properties, default item and highlight.
use super::super::*;

fn menu_with(items: usize) -> (MenuManager, MenuId) {
    let mut menus = MenuManager::new();
    let menu = menus.create().unwrap();
    for index in 0..items {
        menus.insert(menu, index, MenuItem { id: 100 + index as u32, state: 0, text: alloc::vec![b'a' as u16], submenu: None }).unwrap();
    }
    (menus, menu)
}

#[test]
fn only_the_named_properties_are_stored_and_read_back() {
    let (mut menus, menu) = menu_with(0);
    let all = MenuInfo { max_height: 7, background: 0x11, context_help_id: 9, data: 0x22, style: MIM_STYLE };
    menus.set_info(menu, MIM_HELPID, all).unwrap();
    let mut read = MenuInfo::default();
    menus.info(menu, MIM_HELPID | MIM_MAXHEIGHT | MIM_BACKGROUND | MIM_MENUDATA | MIM_STYLE, &mut read).unwrap();
    assert_eq!(read, MenuInfo { context_help_id: 9, ..MenuInfo::default() });
}

#[test]
fn a_read_leaves_properties_the_mask_does_not_name_untouched() {
    let (mut menus, menu) = menu_with(0);
    menus.set_info(menu, MIM_MAXHEIGHT | MIM_MENUDATA, MenuInfo { max_height: 5, data: 0x33, ..MenuInfo::default() }).unwrap();
    let mut read = MenuInfo { max_height: 99, background: 0x44, context_help_id: 1, data: 0x55, style: 2 };
    menus.info(menu, MIM_MAXHEIGHT, &mut read).unwrap();
    assert_eq!(read, MenuInfo { max_height: 5, background: 0x44, context_help_id: 1, data: 0x55, style: 2 });
}

#[test]
fn applying_to_submenus_reaches_every_child() {
    let mut menus = MenuManager::new();
    let child = menus.create_popup().unwrap();
    let parent = menus.create().unwrap();
    menus.insert(parent, 0, MenuItem { id: 1, state: 0, text: Vec::new(), submenu: Some(child.raw()) }).unwrap();
    menus.set_info(parent, MIM_HELPID | MIM_APPLYTOSUBMENUS, MenuInfo { context_help_id: 12, ..MenuInfo::default() }).unwrap();
    let mut read = MenuInfo::default();
    menus.info(child, MIM_HELPID, &mut read).unwrap();
    assert_eq!(read.context_help_id, 12);
}

#[test]
fn the_context_help_id_is_stored_on_its_own() {
    let (mut menus, menu) = menu_with(0);
    menus.set_context_help_id(menu, 77).unwrap();
    let mut read = MenuInfo::default();
    menus.info(menu, MIM_HELPID, &mut read).unwrap();
    assert_eq!(read.context_help_id, 77);
    assert_eq!(menus.set_context_help_id(MenuId::from_raw(0xdead).unwrap(), 1), Err(MenuError::NoSuchMenu));
}

#[test]
fn one_default_item_replaces_any_other() {
    let (mut menus, menu) = menu_with(3);
    assert!(menus.set_default_item(menu, 1, true).unwrap());
    assert_eq!(menus.item(menu, 1, MF_BYPOSITION).unwrap().state & MF_DEFAULT, MF_DEFAULT);
    assert!(menus.set_default_item(menu, 102, false).unwrap());
    assert_eq!(menus.item(menu, 1, MF_BYPOSITION).unwrap().state & MF_DEFAULT, 0);
    assert_eq!(menus.item(menu, 2, MF_BYPOSITION).unwrap().state & MF_DEFAULT, MF_DEFAULT);
}

#[test]
fn naming_no_item_clears_every_default_and_still_succeeds() {
    let (mut menus, menu) = menu_with(2);
    menus.set_default_item(menu, 0, true).unwrap();
    assert!(menus.set_default_item(menu, NO_DEFAULT_ITEM, false).unwrap());
    for position in 0..2 { assert_eq!(menus.item(menu, position, MF_BYPOSITION).unwrap().state & MF_DEFAULT, 0); }
}

#[test]
fn a_default_item_that_names_nothing_reports_no_change_but_still_clears() {
    let (mut menus, menu) = menu_with(2);
    menus.set_default_item(menu, 0, true).unwrap();
    assert!(!menus.set_default_item(menu, 9, true).unwrap());
    assert!(!menus.set_default_item(menu, 999, false).unwrap());
    assert_eq!(menus.item(menu, 0, MF_BYPOSITION).unwrap().state & MF_DEFAULT, 0);
}

#[test]
fn a_highlight_moves_to_one_item_at_a_time() {
    let (mut menus, menu) = menu_with(3);
    assert!(menus.hilite(menu, 1, true).unwrap());
    assert_eq!(menus.item(menu, 1, MF_BYPOSITION).unwrap().state & MF_HILITE, MF_HILITE);
    assert!(!menus.hilite(menu, 1, true).unwrap());
    assert!(menus.hilite(menu, 2, true).unwrap());
    assert_eq!(menus.item(menu, 1, MF_BYPOSITION).unwrap().state & MF_HILITE, 0);
    assert!(menus.hilite(menu, 2, false).unwrap());
    assert_eq!(menus.item(menu, 2, MF_BYPOSITION).unwrap().state & MF_HILITE, 0);
    assert_eq!(menus.hilite(menu, 9, true), Err(MenuError::NoSuchItem));
}

#[test]
fn a_point_selects_the_bar_item_it_falls_inside() {
    let (menus, menu) = menu_with(3);
    let origin = MenuRect { left: 0, top: 0, right: 300, bottom: 20 };
    let first = menus.bar_item_rect(menu, 0, origin, &crate::win32_gdi::MenuMetrics::uniform(8, 16, 18)).unwrap();
    let second = menus.bar_item_rect(menu, 1, origin, &crate::win32_gdi::MenuMetrics::uniform(8, 16, 18)).unwrap();
    assert_eq!(menus.item_from_point(menu, (first.left, first.top), origin, &crate::win32_gdi::MenuMetrics::uniform(8, 16, 18)).unwrap(), Some(0));
    assert_eq!(menus.item_from_point(menu, (second.left, second.top), origin, &crate::win32_gdi::MenuMetrics::uniform(8, 16, 18)).unwrap(), Some(1));
    assert_eq!(menus.item_from_point(menu, (first.left - 1, first.top), origin, &crate::win32_gdi::MenuMetrics::uniform(8, 16, 18)).unwrap(), None);
    assert_eq!(menus.item_from_point(menu, (first.left, first.bottom), origin, &crate::win32_gdi::MenuMetrics::uniform(8, 16, 18)).unwrap(), None);
}

#[test]
fn a_system_menu_takes_the_standard_commands_in_order() {
    let mut menus = MenuManager::new();
    let menu = menus.create_popup().unwrap();
    menus.fill_system_menu(menu, &[(0xf120, &[b'R' as u16]), (0, &[]), (0xf060, &[b'C' as u16])]).unwrap();
    assert_eq!(menus.count(menu).unwrap(), 3);
    assert_eq!(menus.item(menu, 0, MF_BYPOSITION).unwrap().id, 0xf120);
    assert_eq!(menus.item(menu, 1, MF_BYPOSITION).unwrap().state, MF_SEPARATOR);
    assert_eq!(menus.item(menu, 2, MF_BYPOSITION).unwrap().id, 0xf060);
}
