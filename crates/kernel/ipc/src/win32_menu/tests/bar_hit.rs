use super::*;
use crate::win32_menu::{MenuItem, MF_SEPARATOR};

const CHAR_WIDTH: i32 = 8;
const CHAR_HEIGHT: i32 = 16;
const BAR_HEIGHT: i32 = 19;

fn metrics() -> MenuMetrics { MenuMetrics::uniform(CHAR_WIDTH, CHAR_HEIGHT, BAR_HEIGHT) }

/// A window at (100, 50) carrying a three-item bar.
fn bar() -> (MenuManager, MenuId, MenuRect) {
    let mut menus = MenuManager::new();
    let menu = menus.create().unwrap();
    for (position, text) in ["&File", "&Edit", "&Help"].iter().enumerate() {
        let units: alloc::vec::Vec<u16> = text.encode_utf16().collect();
        menus.insert(menu, position, MenuItem { id: position as u32 + 1, state: 0, text: units, submenu: None }).unwrap();
    }
    (menus, menu, MenuRect { left: 100, top: 50, right: 500, bottom: 400 })
}

#[test]
fn a_point_over_a_bar_item_names_that_item() {
    let (menus, menu, window) = bar();
    for position in 0..3u32 {
        let rect = menus.bar_item_rect(menu, position as usize, window, &metrics()).unwrap();
        let point = ((rect.left + rect.right) / 2, (rect.top + rect.bottom) / 2);
        assert_eq!(bar_hit_test(&menus, menu, window, point, &metrics()), PopupHit::Item(position));
    }
}

#[test]
fn the_first_item_starts_at_the_left_edge_of_the_window() {
    let (menus, menu, window) = bar();
    assert_eq!(bar_hit_test(&menus, menu, window, (window.left, window.top + 2), &metrics()), PopupHit::Item(0));
}

#[test]
fn the_band_right_of_the_last_item_is_the_bars_own_background() {
    let (menus, menu, window) = bar();
    let last = menus.bar_item_rect(menu, 2, window, &metrics()).unwrap();
    assert_eq!(bar_hit_test(&menus, menu, window, (last.right + 1, last.top + 1), &metrics()), PopupHit::Border);
    assert_eq!(bar_hit_test(&menus, menu, window, (window.right - 1, last.top + 1), &metrics()), PopupHit::Border);
}

#[test]
fn a_point_below_the_band_or_outside_the_window_names_nothing() {
    let (menus, menu, window) = bar();
    let bar_rect = menus.bar_rect(menu, window, &metrics()).unwrap();
    assert_eq!(bar_hit_test(&menus, menu, window, (window.left + 10, bar_rect.bottom), &metrics()), PopupHit::Nowhere);
    assert_eq!(bar_hit_test(&menus, menu, window, (window.left - 1, window.top + 2), &metrics()), PopupHit::Nowhere);
    assert_eq!(bar_hit_test(&menus, menu, window, (window.right, window.top + 2), &metrics()), PopupHit::Nowhere);
    assert_eq!(bar_hit_test(&menus, menu, window, (window.left + 10, window.top - 1), &metrics()), PopupHit::Nowhere);
}

#[test]
fn an_empty_bar_claims_no_point() {
    let mut menus = MenuManager::new();
    let menu = menus.create().unwrap();
    let window = MenuRect { left: 0, top: 0, right: 200, bottom: 200 };
    assert_eq!(bar_hit_test(&menus, menu, window, (0, 0), &metrics()), PopupHit::Nowhere);
    let _ = menus.insert(menu, 0, MenuItem { id: 1, state: MF_SEPARATOR, text: alloc::vec::Vec::new(), submenu: None });
}

#[test]
fn the_hit_test_names_the_item_the_drawing_plan_highlights() {
    let (menus, menu, window) = bar();
    let origin = MenuRect { left: 0, top: 0, right: window.right - window.left, bottom: window.bottom - window.top };
    // The bar is drawn in window coordinates and hit-tested in screen ones;
    // the two must place item 1 in the same place.
    let drawn = menus.bar_item_rect(menu, 1, origin, &metrics()).unwrap();
    let point = (window.left + (drawn.left + drawn.right) / 2, window.top + (drawn.top + drawn.bottom) / 2);
    assert_eq!(bar_hit_test(&menus, menu, window, point, &metrics()), PopupHit::Item(1));
}
