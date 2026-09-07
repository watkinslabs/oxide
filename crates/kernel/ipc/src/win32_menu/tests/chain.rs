use super::*;
use crate::win32_menu::{MenuItem, MF_BYPOSITION};
use alloc::vec;

const METRICS: BarMetrics = BarMetrics { char_width: 8, char_height: 16, bar_height: 19 };

fn text(value: &str) -> Vec<u16> { value.encode_utf16().collect() }

/// A bar carrying one popup, on a window at (100, 100).
fn fixture() -> (MenuManager, u32, u32, MenuRect) {
    let mut menus = MenuManager::new();
    let bar = menus.create().unwrap();
    let popup = menus.create_popup().unwrap();
    menus.insert(bar, 0, MenuItem { id: 0, state: 0, text: text("&File"), submenu: Some(popup.raw()) }).unwrap();
    menus.insert(popup, 0, MenuItem { id: 100, state: 0, text: text("&New"), submenu: None }).unwrap();
    (menus, bar.raw(), popup.raw(), MenuRect { left: 100, top: 100, right: 700, bottom: 500 })
}

#[test]
fn a_point_on_a_bar_item_names_that_item_of_the_top_menu() {
    let (menus, bar, _, window) = fixture();
    let item = menus.bar_item_rect(MenuId::from_raw(bar).unwrap(), 0, window, 8, 16, 19).unwrap();
    let point = ((item.left + item.right) / 2, (item.top + item.bottom) / 2);
    let chain = BarChain { menu: bar, bounds: window, metrics: METRICS };
    assert_eq!(menu_from_point(&menus, &[], Some(chain), point), (Some(bar), PopupHit::Item(0)));
    // Below the band the bar owns nothing.
    assert_eq!(menu_from_point(&menus, &[], Some(chain), (point.0, window.top + 200)), (None, PopupHit::Nowhere));
}

#[test]
fn an_open_popup_outranks_the_bar_underneath_it() {
    let (menus, bar, popup, window) = fixture();
    let layout = menus.popup_layout(MenuId::from_raw(popup).unwrap(), PopupMetrics { char_width: 8, char_height: 16 }, i32::MAX).unwrap();
    let rect = MenuRect { left: window.left, top: window.top, right: window.left + layout.width, bottom: window.top + layout.height };
    let item = layout.items[0];
    let point = (rect.left + (item.left + item.right) / 2, rect.top + (item.top + item.bottom) / 2);
    let open = vec![OpenMenu { menu: popup, rect, layout }];
    let chain = BarChain { menu: bar, bounds: window, metrics: METRICS };
    assert_eq!(menu_from_point(&menus, &open, Some(chain), point), (Some(popup), PopupHit::Item(0)));
}

#[test]
fn the_open_chain_unwinds_innermost_first_and_only_under_a_mouse_selected_item() {
    let (mut menus, bar, popup, _) = fixture();
    assert_eq!(sub_popup_chain(&mut menus, 4, bar), Vec::new(), "nothing is open under an unselected bar");
    menus.set_focused_item(MenuId::from_raw(bar).unwrap(), 0).unwrap();
    assert_eq!(sub_popup_chain(&mut menus, 4, bar), Vec::new(), "a selected item with no open popup opens nothing");
    mark_mouse_select(&mut menus, bar, 0);
    assert_eq!(sub_popup_chain(&mut menus, 4, bar), vec![popup]);
    assert_eq!(menus.item(MenuId::from_raw(bar).unwrap(), 0, MF_BYPOSITION).unwrap().state & MF_MOUSESELECT, 0,
        "the walk clears the mark it consumed");
}

#[test]
fn the_submenu_target_is_the_focused_item_that_owns_one() {
    let (mut menus, bar, popup, _) = fixture();
    assert_eq!(submenu_target(&menus, bar), None);
    menus.set_focused_item(MenuId::from_raw(bar).unwrap(), 0).unwrap();
    assert_eq!(submenu_target(&menus, bar), Some((0, popup)));
    assert_eq!(submenu_target(&menus, popup), None, "an item with no submenu is no target");
}

/// A popup's submenu opens beside the item; a bar's drops below it, and a bar
/// keeps its items in the owner's own space, so nothing is added to them.
#[test]
fn a_submenu_opens_beside_a_popup_item_and_below_a_bar_item() {
    let window = MenuRect { left: 40, top: 60, right: 140, bottom: 200 };
    let item = MenuRect { left: 3, top: 19, right: 97, bottom: 35 };
    assert_eq!(submenu_origin(ParentMenu::Popup { window }, item), ((137, 79), (94, 16)));
    let bar_item = MenuRect { left: 148, top: 147, right: 196, bottom: 165 };
    assert_eq!(submenu_origin(ParentMenu::Bar, bar_item), ((148, 165), (48, 18)));
}
