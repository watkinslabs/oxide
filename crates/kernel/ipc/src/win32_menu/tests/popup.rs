use super::*;
use crate::win32_menu::{MenuItem, MF_GRAYED};

fn metrics() -> MenuMetrics { MenuMetrics::uniform(CELL, CELL_HEIGHT, BAR_HEIGHT) }

/// One advance, one cell height and one band, so a run's extent is its length
/// times the cell and every rule below reads as the reference states it.
const CELL: i32 = 8;
const CELL_HEIGHT: i32 = 16;
const BAR_HEIGHT: i32 = 19;
/// The check column, the gap and the one character size a row reserves before
/// its text.
fn lead() -> i32 { check_width(CELL_HEIGHT) + 4 + CELL }
/// The rule a row's height follows: the taller of the face's cell plus two and
/// its character height plus four.
const ROW: i32 = CELL_HEIGHT + 4;
/// Half a band, which is what a separator row claims.
fn rule_row() -> i32 { separator_height(BAR_HEIGHT) }
/// What a row adds behind its name: the arrow column and the text margin.
const TRAIL: i32 = ARROW_WIDTH + 2;

fn menu_of(texts: &[(&str, u32)]) -> (MenuManager, MenuId) {
    let mut menus = MenuManager::new();
    let menu = menus.create_popup().unwrap();
    for (position, (text, state)) in texts.iter().enumerate() {
        let units: alloc::vec::Vec<u16> = text.encode_utf16().collect();
        menus.insert(menu, position, MenuItem { id: position as u32 + 1, state: *state, text: units, submenu: None }).unwrap();
    }
    (menus, menu)
}

#[test]
fn a_popup_is_as_wide_as_its_widest_item_and_stacks_its_rows() {
    let (menus, menu) = menu_of(&[("New", 0), ("Save As", 0), ("", MF_SEPARATOR), ("Exit", MF_GRAYED)]);
    let layout = menus.popup_layout(menu, &metrics(), i32::MAX).unwrap();
    assert_eq!(layout.width, lead() + 7 * CELL + TRAIL + POPUP_BORDER * 2);
    assert_eq!(layout.height, POPUP_BORDER * 2 + ROW * 3 + rule_row());
    assert_eq!(layout.items.len(), 4);
    assert_eq!(layout.items[0].top, POPUP_BORDER);
    assert_eq!(layout.items[1].top, POPUP_BORDER + ROW);
    assert_eq!(layout.items[2].bottom - layout.items[2].top, rule_row());
    assert_eq!(layout.items[3].top, POPUP_BORDER + ROW * 2 + rule_row());
    assert!(layout.items.iter().all(|rect| rect.right == layout.width - POPUP_BORDER));
}

#[test]
fn an_empty_popup_is_only_its_border() {
    let (menus, menu) = menu_of(&[]);
    let layout = menus.popup_layout(menu, &metrics(), i32::MAX).unwrap();
    assert_eq!((layout.width, layout.height, layout.items.len()), (POPUP_BORDER * 2, POPUP_BORDER * 2, 0));
}

#[test]
fn the_maximum_height_clips_a_tall_popup() {
    let (menus, menu) = menu_of(&[("a", 0), ("b", 0), ("c", 0), ("d", 0)]);
    assert_eq!(menus.popup_layout(menu, &metrics(), 40).unwrap().height, 40);
}

const WORK: MenuRect = MenuRect { left: 0, top: 0, right: 800, bottom: 600 };

#[test]
fn the_default_alignment_places_the_popup_at_the_point() {
    assert_eq!(popup_origin(0, 100, 200, 60, 80, WORK, 0, 0), (100, 200));
}

#[test]
fn each_alignment_flag_moves_the_popup_off_the_point() {
    assert_eq!(popup_origin(TPM_RIGHTALIGN, 100, 200, 60, 80, WORK, 0, 0).0, 40);
    assert_eq!(popup_origin(TPM_CENTERALIGN, 100, 200, 60, 80, WORK, 0, 0).0, 70);
    assert_eq!(popup_origin(TPM_BOTTOMALIGN, 100, 200, 60, 80, WORK, 0, 0).1, 120);
    assert_eq!(popup_origin(TPM_VCENTERALIGN, 100, 200, 60, 80, WORK, 0, 0).1, 160);
}

#[test]
fn a_right_to_left_layout_mirrors_the_horizontal_alignment() {
    assert_eq!(popup_origin(TPM_LAYOUTRTL, 100, 200, 60, 80, WORK, 0, 0).0, 40);
    assert_eq!(popup_origin(TPM_LAYOUTRTL | TPM_RIGHTALIGN, 100, 200, 60, 80, WORK, 0, 0).0, 100);
}

#[test]
fn a_popup_that_would_leave_the_work_area_is_pulled_back_onto_it() {
    assert_eq!(popup_origin(0, 780, 590, 60, 80, WORK, 0, 0), (740, 520));
    assert_eq!(popup_origin(0, -30, -40, 60, 80, WORK, 0, 0), (0, 0));
}

#[test]
fn an_anchor_flips_the_popup_past_the_item_it_belongs_to() {
    // The anchor pushes the popup left of the item, then the work area clamps it.
    assert_eq!(popup_origin(0, 790, 100, 60, 80, WORK, 20, 0).0, 740);
    assert_eq!(popup_origin(0, 100, 560, 60, 80, WORK, 0, 10), (100, 470));
}

#[test]
fn the_hit_test_names_the_item_under_a_screen_point() {
    let (menus, menu) = menu_of(&[("New", 0), ("Open", 0)]);
    let layout = menus.popup_layout(menu, &metrics(), i32::MAX).unwrap();
    let window = MenuRect { left: 100, top: 50, right: 100 + layout.width, bottom: 50 + layout.height };
    assert_eq!(hit_test(&layout, window, (110, 50 + POPUP_BORDER)), PopupHit::Item(0));
    assert_eq!(hit_test(&layout, window, (110, 50 + POPUP_BORDER + ROW)), PopupHit::Item(1));
    assert_eq!(hit_test(&layout, window, (110, 51)), PopupHit::Border);
    assert_eq!(hit_test(&layout, window, (99, 60)), PopupHit::Nowhere);
    assert_eq!(hit_test(&layout, window, (110, 50 + layout.height)), PopupHit::Nowhere);
}

#[test]
fn text_length_stops_at_the_terminator() {
    assert_eq!(crate::win32_menu::mnemonic::stored_len(&[65, 66, 0, 67]), 2);
    assert_eq!(crate::win32_menu::mnemonic::stored_len(&[65, 66]), 2);
    assert_eq!(crate::win32_menu::mnemonic::stored_len(&[]), 0);
}

#[test]
fn a_label_splits_at_its_tab_and_the_two_halves_are_measured_apart() {
    let (menus, menu) = menu_of(&[("Save\tCtrl+S", 0)]);
    let layout = menus.popup_layout(menu, &metrics(), i32::MAX).unwrap();
    // "Save" is the name column, "Ctrl+S" the accelerator column, and one
    // cell separates them.
    assert_eq!(layout.tab, lead() + 4 * CELL);
    assert_eq!(layout.width, lead() + 4 * CELL + TRAIL + CELL + 6 * CELL + POPUP_BORDER * 2);
}

#[test]
fn the_tab_column_is_the_widest_name_of_the_menu_and_the_width_holds_the_widest_accelerator() {
    let (menus, menu) = menu_of(&[("New\tCtrl+N", 0), ("Page Setup...\tF5", 0), ("Print\tCtrl+Shift+P", 0)]);
    let layout = menus.popup_layout(menu, &metrics(), i32::MAX).unwrap();
    assert_eq!(layout.tab, lead() + "Page Setup...".len() as i32 * CELL);
    assert_eq!(layout.width, layout.tab + TRAIL + CELL + "Ctrl+Shift+P".len() as i32 * CELL + POPUP_BORDER * 2);
}

#[test]
fn a_menu_with_no_tab_in_any_label_reserves_no_accelerator_column() {
    let (menus, menu) = menu_of(&[("Undo", 0), ("Select All", 0)]);
    let layout = menus.popup_layout(menu, &metrics(), i32::MAX).unwrap();
    assert_eq!(layout.tab, lead() + 10 * CELL);
    assert_eq!(layout.width, lead() + 10 * CELL + TRAIL + POPUP_BORDER * 2);
}

#[test]
fn a_flush_right_label_is_measured_the_same_way_a_tab_is() {
    let (menus, menu) = menu_of(&[("Help\u{8}F1", 0)]);
    let layout = menus.popup_layout(menu, &metrics(), i32::MAX).unwrap();
    assert_eq!(layout.tab, lead() + 4 * CELL);
    assert_eq!(layout.width, layout.tab + TRAIL + CELL + 2 * CELL + POPUP_BORDER * 2);
}
