//! The drawing contract: which colour every item state paints in, what the
//! borders and separators fill, and where an item's text starts.
use super::*;
use crate::win32_menu::popup::PopupMetrics;
use crate::win32_menu::{MenuItem, MF_CHECKED, MF_DISABLED};
use alloc::vec;

fn text(units: &[u8]) -> Vec<u16> { units.iter().map(|unit| *unit as u16).chain(core::iter::once(0)).collect() }

fn menu_with(items: &[(u32, u32, &[u8], Option<u32>)]) -> (MenuManager, MenuId) {
    let mut menus = MenuManager::new();
    let menu = menus.create().unwrap();
    for (position, (id, state, label, submenu)) in items.iter().enumerate() {
        menus.insert(menu, position, MenuItem { id: *id, state: *state, text: text(label), submenu: *submenu }).unwrap();
    }
    (menus, menu)
}

fn fills(ops: &[MenuDrawOp]) -> Vec<(MenuRect, SystemColor)> {
    ops.iter().filter_map(|op| match op { MenuDrawOp::Fill { rect, color } => Some((*rect, *color)), _ => None }).collect()
}

fn texts(ops: &[MenuDrawOp]) -> Vec<(u32, MenuRect, SystemColor, bool)> {
    ops.iter().filter_map(|op| match op { MenuDrawOp::Text { rect, position, color, centered, .. } => Some((*position, *rect, *color, *centered)), _ => None }).collect()
}

#[test]
fn a_raised_edge_draws_light_outside_and_button_highlight_inside_on_the_top_left() {
    let mut ops = Vec::new();
    rect_edge(MenuRect { left: 0, top: 0, right: 10, bottom: 10 }, EDGE_RAISED, BF_RECT, 1, &mut ops);
    let drawn = fills(&ops);
    assert_eq!(drawn[0], (MenuRect { left: 0, top: 0, right: 10, bottom: 1 }, SystemColor::Light));
    assert_eq!(drawn[1], (MenuRect { left: 0, top: 0, right: 1, bottom: 10 }, SystemColor::Light));
    assert_eq!(drawn[2], (MenuRect { left: 0, top: 9, right: 10, bottom: 10 }, SystemColor::DarkShadow));
    assert_eq!(drawn[3], (MenuRect { left: 9, top: 0, right: 10, bottom: 10 }, SystemColor::DarkShadow));
    assert_eq!(drawn[4], (MenuRect { left: 1, top: 1, right: 9, bottom: 2 }, SystemColor::ButtonHighlight));
    assert_eq!(drawn[7], (MenuRect { left: 8, top: 1, right: 9, bottom: 9 }, SystemColor::ButtonShadow));
    assert_eq!(drawn.len(), 8);
}

#[test]
fn a_sunken_outer_edge_has_no_inner_fills_and_reverses_the_raised_pair() {
    let mut ops = Vec::new();
    rect_edge(MenuRect { left: 2, top: 4, right: 12, bottom: 20 }, BDR_SUNKENOUTER, BF_RECT, 1, &mut ops);
    let drawn = fills(&ops);
    assert_eq!(drawn.len(), 4);
    assert_eq!(drawn[0].1, SystemColor::ButtonShadow);
    assert_eq!(drawn[2].1, SystemColor::ButtonHighlight);
}

#[test]
fn a_popup_paints_its_menu_background_then_a_raised_border_before_any_item() {
    let (menus, menu) = menu_with(&[(1, 0, b"New", None)]);
    let layout = menus.popup_layout(menu, PopupMetrics { char_width: 8, char_height: 16 }, i32::MAX).unwrap();
    let ops = menus.popup_draw_plan(menu, &layout).unwrap();
    assert_eq!(fills(&ops)[0], (MenuRect { left: 0, top: 0, right: layout.width, bottom: layout.height }, SystemColor::Menu));
    assert!(matches!(ops[1], MenuDrawOp::Fill { color: SystemColor::Light, .. }));
    let drawn = texts(&ops);
    assert_eq!(drawn.len(), 1);
    assert_eq!(drawn[0].0, 0);
    assert!(!drawn[0].3);
}

#[test]
fn a_popup_item_reserves_the_check_column_and_the_arrow_column_around_its_text() {
    let (menus, menu) = menu_with(&[(1, 0, b"Open", None)]);
    let layout = menus.popup_layout(menu, PopupMetrics { char_width: 8, char_height: 16 }, i32::MAX).unwrap();
    let ops = menus.popup_draw_plan(menu, &layout).unwrap();
    let item = layout.items[0];
    let drawn = texts(&ops)[0];
    assert_eq!(drawn.1.left, item.left + TEXT_GAP + crate::win32_menu::popup::CHECK_WIDTH);
    assert_eq!(drawn.1.right, item.right - crate::win32_menu::popup::ARROW_WIDTH);
}

#[test]
fn a_highlighted_popup_item_fills_the_selection_colour_and_takes_the_selection_text() {
    let (mut menus, menu) = menu_with(&[(1, 0, b"A", None), (2, 0, b"B", None)]);
    menus.hilite(menu, 1, true).unwrap();
    let layout = menus.popup_layout(menu, PopupMetrics { char_width: 8, char_height: 16 }, i32::MAX).unwrap();
    let ops = menus.popup_draw_plan(menu, &layout).unwrap();
    let drawn = texts(&ops);
    assert_eq!(drawn[0].2, SystemColor::MenuText);
    assert_eq!(drawn[1].2, SystemColor::HighlightText);
    assert!(fills(&ops).contains(&(layout.items[1], SystemColor::Highlight)));
    assert!(fills(&ops).contains(&(layout.items[0], SystemColor::Menu)));
}

#[test]
fn a_grayed_item_keeps_the_gray_text_colour_even_while_it_is_highlighted() {
    assert_eq!(item_text_color(MF_GRAYED, false), SystemColor::GrayText);
    assert_eq!(item_text_color(MF_GRAYED | MF_HILITE, false), SystemColor::GrayText);
    assert_eq!(item_text_color(MF_HILITE, false), SystemColor::HighlightText);
    assert_eq!(item_text_color(MF_HILITE, true), SystemColor::MenuText);
    assert_eq!(item_text_color(MF_DISABLED, false), SystemColor::MenuText);
}

#[test]
fn a_separator_draws_one_etched_rule_and_no_text() {
    let (menus, menu) = menu_with(&[(0, MF_SEPARATOR, b"", None), (1, 0, b"X", None)]);
    let layout = menus.popup_layout(menu, PopupMetrics { char_width: 8, char_height: 16 }, i32::MAX).unwrap();
    let ops = menus.popup_draw_plan(menu, &layout).unwrap();
    let drawn = texts(&ops);
    assert_eq!(drawn.len(), 1);
    assert_eq!(drawn[0].0, 1);
    let rule = layout.items[0];
    let middle = (rule.top + rule.bottom) / 2;
    assert!(fills(&ops).contains(&(MenuRect { left: rule.left + 1, top: middle, right: rule.right - 1, bottom: middle + SEPARATOR_RULE }, SystemColor::ButtonShadow)));
}

#[test]
fn a_checked_item_draws_a_tick_and_a_submenu_item_draws_an_arrow() {
    let (menus, menu) = menu_with(&[(1, MF_CHECKED, b"Wrap", None), (2, 0, b"More", Some(9))]);
    let layout = menus.popup_layout(menu, PopupMetrics { char_width: 8, char_height: 16 }, i32::MAX).unwrap();
    let ops = menus.popup_draw_plan(menu, &layout).unwrap();
    let glyphs: Vec<_> = ops.iter().filter_map(|op| match op { MenuDrawOp::Glyph { count, points, .. } => Some((*count, *points)), _ => None }).collect();
    assert_eq!(glyphs.len(), 2);
    assert_eq!(glyphs[0].0, GLYPH_POINTS);
    assert_eq!(glyphs[1].0, 3);
    assert!(glyphs[0].1.iter().all(|point| point.0 >= layout.items[0].left && point.0 < layout.items[0].left + crate::win32_menu::popup::CHECK_WIDTH));
    assert!(glyphs[1].1.iter().all(|point| point.0 < layout.items[1].right));
}

#[test]
fn an_unchecked_item_without_a_submenu_draws_no_glyph() {
    let (menus, menu) = menu_with(&[(1, 0, b"Plain", None)]);
    let layout = menus.popup_layout(menu, PopupMetrics { char_width: 8, char_height: 16 }, i32::MAX).unwrap();
    let ops = menus.popup_draw_plan(menu, &layout).unwrap();
    assert!(!ops.iter().any(|op| matches!(op, MenuDrawOp::Glyph { .. })));
}

#[test]
fn a_bar_fills_its_own_height_and_closes_with_a_face_coloured_line() {
    let (menus, menu) = menu_with(&[(1, 0, b"File", None), (2, 0, b"Edit", None)]);
    let origin = MenuRect { left: 0, top: 0, right: 400, bottom: 300 };
    let ops = menus.bar_draw_plan(menu, origin, 8, 16, 19).unwrap();
    let bar = menus.bar_rect(menu, origin, 8, 16, 19).unwrap();
    let drawn = fills(&ops);
    assert_eq!(drawn[0], (MenuRect { left: 0, top: 0, right: 400, bottom: bar.bottom }, SystemColor::Menu));
    assert_eq!(drawn[1], (MenuRect { left: 0, top: bar.bottom, right: 400, bottom: bar.bottom + 1 }, SystemColor::Face));
}

#[test]
fn every_bar_item_paints_one_centred_text_run_inside_its_own_rectangle() {
    let (menus, menu) = menu_with(&[(1, 0, b"File", None), (2, 0, b"Edit", None), (3, 0, b"Help", None)]);
    let origin = MenuRect { left: 0, top: 0, right: 400, bottom: 300 };
    let ops = menus.bar_draw_plan(menu, origin, 8, 16, 19).unwrap();
    let drawn = texts(&ops);
    assert_eq!(drawn.len(), 3);
    for (index, entry) in drawn.iter().enumerate() {
        let rect = menus.bar_item_rect(menu, index, origin, 8, 16, 19).unwrap();
        assert_eq!(entry.0, index as u32);
        assert_eq!(entry.1.left, rect.left + 8);
        assert_eq!(entry.1.right, rect.right - 8);
        assert!(entry.3);
    }
}

#[test]
fn a_highlighted_bar_item_marks_itself_with_a_sunken_edge_rather_than_a_fill() {
    let (mut menus, menu) = menu_with(&[(1, 0, b"File", None), (2, 0, b"Edit", None)]);
    menus.hilite(menu, 0, true).unwrap();
    let origin = MenuRect { left: 0, top: 0, right: 400, bottom: 300 };
    let ops = menus.bar_draw_plan(menu, origin, 8, 16, 19).unwrap();
    let rect = menus.bar_item_rect(menu, 0, origin, 8, 16, 19).unwrap();
    assert!(!fills(&ops).contains(&(rect, SystemColor::Menu)));
    assert!(fills(&ops).iter().any(|(drawn, color)| *color == SystemColor::ButtonShadow && drawn.left == rect.left));
    assert!(fills(&ops).contains(&(menus.bar_item_rect(menu, 1, origin, 8, 16, 19).unwrap(), SystemColor::Menu)));
}

#[test]
fn a_bar_separator_paints_nothing_at_all() {
    let (menus, menu) = menu_with(&[(1, 0, b"File", None), (0, MF_SEPARATOR, b"", None)]);
    let origin = MenuRect { left: 0, top: 0, right: 400, bottom: 300 };
    let ops = menus.bar_draw_plan(menu, origin, 8, 16, 19).unwrap();
    assert_eq!(texts(&ops).len(), 1);
    assert_eq!(vec![0], texts(&ops).iter().map(|entry| entry.0).collect::<Vec<_>>());
}
