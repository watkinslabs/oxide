use super::*;
use crate::win32_window::{WindowId, WindowManager};

fn icons(big: u64, small: u64, small2: u64) -> WindowIcons { WindowIcons { big, small, small2 } }

#[test]
fn a_request_kind_outside_the_two_settable_icons_is_refused() {
    assert_eq!(set_icon(WindowIcons::default(), ICON_SMALL2, 5), None);
    assert_eq!(get_icon(icons(1, 2, 3), 9), 0);
}

#[test]
fn installing_a_large_icon_with_no_small_one_asks_for_a_derived_small_icon() {
    let (previous, next, effect) = set_icon(WindowIcons::default(), ICON_BIG, 7).unwrap();
    assert_eq!(previous, 0);
    assert_eq!(next.big, 7);
    assert_eq!(effect, IconSideEffect::DeriveSmall(7));
}

#[test]
fn replacing_a_large_icon_releases_the_icon_derived_from_the_old_one() {
    let (previous, next, effect) = set_icon(icons(7, 0, 8), ICON_BIG, 9).unwrap();
    assert_eq!(previous, 7);
    assert_eq!(next.small2, 0);
    assert_eq!(effect, IconSideEffect::ReleaseDerived(8));
}

#[test]
fn clearing_the_small_icon_derives_one_from_the_large_icon_again() {
    let (previous, next, effect) = set_icon(icons(7, 4, 0), ICON_SMALL, 0).unwrap();
    assert_eq!(previous, 4);
    assert_eq!(next.small, 0);
    assert_eq!(effect, IconSideEffect::DeriveSmall(7));
}

#[test]
fn setting_a_small_icon_releases_the_derived_one() {
    let (_, next, effect) = set_icon(icons(7, 0, 8), ICON_SMALL, 5).unwrap();
    assert_eq!((next.small, next.small2), (5, 0));
    assert_eq!(effect, IconSideEffect::ReleaseDerived(8));
}

#[test]
fn the_small_request_prefers_the_set_icon_and_falls_back_to_the_derived_one() {
    assert_eq!(get_icon(icons(1, 2, 3), ICON_SMALL), 2);
    assert_eq!(get_icon(icons(1, 0, 3), ICON_SMALL), 0);
    assert_eq!(get_icon(icons(1, 0, 3), ICON_SMALL2), 3);
    assert_eq!(get_icon(icons(1, 2, 3), ICON_SMALL2), 2);
    assert_eq!(get_icon(icons(1, 2, 3), ICON_BIG), 1);
}

#[test]
fn the_table_is_keyed_by_window_and_an_unknown_window_is_refused() {
    let mut manager = WindowManager::new();
    let window = manager.create(1, None, 0).unwrap();
    assert_eq!(manager.set_window_icon(window, ICON_BIG, 12), Some((0, IconSideEffect::DeriveSmall(12))));
    assert_eq!(manager.window_icon(window, ICON_BIG), 12);
    manager.set_derived_window_icon(window, 13);
    assert_eq!(manager.window_icon(window, ICON_SMALL2), 13);
    let stray = WindowId::from_raw(0x777).unwrap();
    assert_eq!(manager.set_window_icon(stray, ICON_BIG, 1), None);
    assert_eq!(manager.window_icons(stray), WindowIcons::default());
}
