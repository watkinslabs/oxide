//! The menu bar of a real five-item window, drawn through the same plan the
//! nonclient painter walks: every text run must be a record the kernel-owned
//! launch accepts, and its glyphs must start inside the band.
use super::*;
use alloc::vec::Vec;
use ipc::win32_gdi::{TextAttributes, TextState, MENU_BAR_HEIGHT, MENU_CHAR_HEIGHT, MENU_CHAR_WIDTH};
use ipc::win32_menu::draw::MenuDrawOp;
use ipc::win32_menu::{MenuItem, MenuManager, MenuRect};

/// Glyph height a device context with the stock font reports.
const GLYPH_HEIGHT: i32 = MENU_CHAR_HEIGHT;
/// Device-context handle the band is drawn into.
const BAND_DC: u64 = 0x21;
/// `MenuText` on the default scheme.
const MENU_TEXT: u32 = 0;
/// Notepad's own bar.
const LABELS: [&[u8]; 5] = [b"File", b"Edit", b"Format", b"View", b"Help"];
/// Frame width the band spans in the acceptance window.
const FRAME_WIDTH: i32 = 582 - 261;

fn units(label: &[u8]) -> Vec<u16> { label.iter().map(|unit| *unit as u16).chain(core::iter::once(0)).collect() }

fn notepad_bar() -> (MenuManager, ipc::win32_menu::MenuId) {
    let mut menus = MenuManager::new();
    let menu = menus.create().unwrap();
    for (position, label) in LABELS.iter().enumerate() {
        menus.insert(menu, position, MenuItem { id: position as u32 + 1, state: 0, text: units(label), submenu: None }).unwrap();
    }
    (menus, menu)
}

fn stock_state() -> TextState {
    TextState { font: None, attributes: TextAttributes::default(), width: FRAME_WIDTH, height: 768,
        break_extra: 0, break_rem: 0 }
}

/// Every text run of the bar plan, as the nonclient painter issues them.
fn runs() -> Vec<(MenuRect, usize, TextRequest)> {
    let (menus, menu) = notepad_bar();
    let origin = MenuRect { left: 0, top: 0, right: FRAME_WIDTH, bottom: 768 };
    let plan = menus.bar_draw_plan(menu, origin, MENU_CHAR_WIDTH, MENU_CHAR_HEIGHT, MENU_BAR_HEIGHT).unwrap();
    let state = stock_state();
    plan.iter().filter_map(|op| match op {
        MenuDrawOp::Text { rect, position, .. } => {
            let count = LABELS[*position as usize].len();
            Some((*rect, count, request(BAND_DC, *rect, count, true, MENU_TEXT, &state, GLYPH_HEIGHT)))
        }
        _ => None,
    }).collect()
}

#[test]
fn the_bar_plan_issues_one_run_for_every_item() {
    assert_eq!(runs().len(), LABELS.len());
}

#[test]
fn a_menu_run_is_a_record_the_kernel_owned_launch_can_size() {
    for (_, count, request) in runs() {
        assert_eq!(request.count as usize, count);
        assert_eq!(request.kernel_payload_bytes(),
            Some((core::mem::size_of::<TextRequest>() + count * 2 + 3) & !3usize));
    }
}

#[test]
fn a_menu_run_carries_no_unit_pointer_until_its_payload_is_placed() {
    // The user-facing check rejects exactly this record, because the units of
    // a kernel-owned run live in the callback payload the launch places.
    for (_, _, request) in runs() {
        assert_eq!(request.text, 0);
        assert!(!request.valid());
        assert_eq!(request.payload_bytes(), None);
    }
}

#[test]
fn every_run_starts_inside_the_item_it_belongs_to() {
    for (rect, count, request) in runs() {
        assert!(request.x >= rect.left, "run starts left of its item");
        assert!(request.x + run_width(count) <= rect.right, "run runs past its item");
        assert!(request.y >= rect.top, "run starts above its item");
        assert!(request.y + GLYPH_HEIGHT <= rect.bottom, "run runs below its item");
    }
}

#[test]
fn the_band_holds_every_run_of_the_bar() {
    let (menus, menu) = notepad_bar();
    let origin = MenuRect { left: 0, top: 0, right: FRAME_WIDTH, bottom: 768 };
    let band = menus.bar_rect(menu, origin, MENU_CHAR_WIDTH, MENU_CHAR_HEIGHT, MENU_BAR_HEIGHT).unwrap();
    for (_, count, request) in runs() {
        assert!(request.x >= band.left && request.x + run_width(count) <= band.right);
        assert!(request.y >= band.top && request.y + GLYPH_HEIGHT <= band.bottom);
    }
}

#[test]
fn a_popup_run_starts_at_the_left_edge_and_a_bar_run_is_centred() {
    let rect = MenuRect { left: 10, top: 4, right: 10 + MENU_CHAR_WIDTH * 6, bottom: 4 + 18 };
    assert_eq!(origin(rect, 4, false, GLYPH_HEIGHT).0, 10);
    assert_eq!(origin(rect, 4, true, GLYPH_HEIGHT).0, 10 + MENU_CHAR_WIDTH);
    assert_eq!(origin(rect, 4, true, GLYPH_HEIGHT).1, 4 + 1);
}
