//! The menu bar of a real five-item window, drawn through the same plan the
//! nonclient painter walks: every text run must be a record the kernel-owned
//! launch accepts, and its glyphs must start inside the band.
use super::*;
use alloc::vec::Vec;
use ipc::win32_gdi::{TextAttributes, TextState};
use ipc::win32_menu::draw::{MenuDrawOp, MenuTextAlign};
use ipc::win32_menu::mnemonic::label_halves;
use ipc::win32_menu::{MenuItem, MenuManager, MenuRect};

/// The cells the nonclient profile's menu font measures this bar with. The
/// device context every run is placed against selects that same face, so its
/// reported advance is the one the layout used.
fn cells() -> ipc::win32_gdi::MenuMetrics { ipc::win32_gdi::menu_bar_metrics() }
/// Glyph height and ascent that face reports.
fn glyph_height() -> i32 { cells().char_height }
fn ascent() -> i32 { ipc::win32_gdi::font_text_metrics(ipc::win32_gdi::menu_font()).ascent }
/// Device-context handle the band is drawn into.
const BAND_DC: u64 = 0x21;
/// `MenuText` on the default scheme.
const MENU_TEXT: u32 = 0;
/// Notepad's own bar, as its resource stores it.
const STORED: [&[u8]; 5] = [b"&File", b"&Edit", b"F&ormat", b"&View", b"&Help"];
/// The same bar as it is drawn, once the prefix rules have run.
const LABELS: [&[u8]; 5] = [b"File", b"Edit", b"Format", b"View", b"Help"];
/// Frame width the band spans in the acceptance window.
const FRAME_WIDTH: i32 = 582 - 261;

fn units(label: &[u8]) -> Vec<u16> { label.iter().map(|unit| *unit as u16).chain(core::iter::once(0)).collect() }

fn notepad_bar() -> (MenuManager, ipc::win32_menu::MenuId) { notepad_bar_from(&LABELS) }

fn notepad_bar_from(labels: &[&[u8]; 5]) -> (MenuManager, ipc::win32_menu::MenuId) {
    let mut menus = MenuManager::new();
    let menu = menus.create().unwrap();
    for (position, label) in labels.iter().enumerate() {
        menus.insert(menu, position, MenuItem { id: position as u32 + 1, state: 0, text: units(label), submenu: None }).unwrap();
    }
    (menus, menu)
}

fn stock_state() -> TextState {
    TextState { font: None, attributes: TextAttributes::default(), width: FRAME_WIDTH, height: 768,
        break_extra: 0, break_rem: 0 }
}

/// Every text run of the bar plan, as the nonclient painter issues them.
fn runs() -> Vec<(MenuRect, Vec<u16>, TextRequest)> {
    let (menus, menu) = notepad_bar();
    let origin = MenuRect { left: 0, top: 0, right: FRAME_WIDTH, bottom: 768 };
    let plan = menus.bar_draw_plan(menu, origin, &cells()).unwrap();
    let state = stock_state();
    plan.iter().filter_map(|op| match op {
        MenuDrawOp::Text { rect, position, .. } => {
            let drawn: Vec<u16> = LABELS[*position as usize].iter().map(|unit| *unit as u16).collect();
            let request = request(BAND_DC, *rect, &drawn, MenuTextAlign::Center, &cells().cells, MENU_TEXT, &state, glyph_height());
            Some((*rect, drawn, request))
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
    for (_, drawn, request) in runs() {
        assert_eq!(request.count as usize, drawn.len());
        assert_eq!(request.kernel_payload_bytes(),
            Some((core::mem::size_of::<TextRequest>() + drawn.len() * 2 + 3) & !3usize));
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
    for (rect, drawn, request) in runs() {
        assert!(request.x >= rect.left, "run starts left of its item");
        assert!(request.x + run_width(&drawn, &cells().cells) <= rect.right, "run runs past its item");
        assert!(request.y >= rect.top, "run starts above its item");
        assert!(request.y + glyph_height() <= rect.bottom, "run runs below its item");
    }
}

#[test]
fn the_band_holds_every_run_of_the_bar() {
    let (menus, menu) = notepad_bar();
    let origin = MenuRect { left: 0, top: 0, right: FRAME_WIDTH, bottom: 768 };
    let band = menus.bar_rect(menu, origin, &cells()).unwrap();
    for (_, drawn, request) in runs() {
        assert!(request.x >= band.left && request.x + run_width(&drawn, &cells().cells) <= band.right);
        assert!(request.y >= band.top && request.y + glyph_height() <= band.bottom);
    }
}

#[test]
fn every_notepad_label_draws_without_its_prefix_and_rules_the_marked_character() {
    let (menus, menu) = notepad_bar_from(&STORED);
    let origin = MenuRect { left: 0, top: 0, right: FRAME_WIDTH, bottom: 768 };
    let plan = menus.bar_draw_plan(menu, origin, &cells()).unwrap();
    let marked: [usize; 5] = [0, 0, 1, 0, 0];
    let mut seen = 0;
    for op in &plan {
        let MenuDrawOp::Text { rect, position, align, .. } = op else { continue; };
        let item = menus.item(menu, *position, ipc::win32_menu::MF_BYPOSITION).unwrap();
        let drawn = label_halves(&item.text).name;
        let expected = LABELS[*position as usize];
        assert_eq!(drawn.units, expected.iter().map(|unit| *unit as u16).collect::<Vec<u16>>());
        assert_eq!(drawn.mnemonic, Some(marked[*position as usize]));
        // The run is measured from the drawn units, so it still fits the cell
        // the prefix-free measurement produced.
        let face = cells().cells;
        let request = request(BAND_DC, *rect, &drawn.units, *align, &face, MENU_TEXT, &stock_state(), glyph_height());
        assert_eq!(request.count as usize, expected.len());
        assert!(request.x >= rect.left && request.x + run_width(&drawn.units, &face) <= rect.right);
        // The rule sits under the marked character's own advance, below the
        // baseline, inside the item.
        let mark = marked[*position as usize];
        let rule = underline(*rect, &drawn.units, mark, *align, &face, glyph_height(), ascent());
        assert_eq!(rule.left, request.x + run_width(&drawn.units[..mark], &face));
        assert_eq!(rule.right, rule.left + run_width(&drawn.units[mark..mark + 1], &face) - 1);
        assert_eq!(rule.bottom - rule.top, UNDERLINE_RULE);
        assert!(rule.top > request.y && rule.bottom <= rect.bottom, "the rule sits under the glyphs and inside the item");
        seen += 1;
    }
    assert_eq!(seen, LABELS.len());
}

#[test]
fn a_popup_run_starts_at_the_left_edge_and_a_bar_run_is_centred() {
    let face = cells().cells;
    let (advance, height) = (cells().char_width, glyph_height());
    let four: Vec<u16> = alloc::vec![b'n' as u16; 4];
    let rect = MenuRect { left: 10, top: 4, right: 10 + run_width(&four, &face) + advance * 2, bottom: 4 + 18 };
    assert_eq!(origin(rect, &four, MenuTextAlign::Left, &face, height).0, 10);
    // Two character sizes are free, so the centred run gives one to each side.
    assert_eq!(origin(rect, &four, MenuTextAlign::Center, &face, height).0, 10 + advance);
    // The glyphs sit on the face's own cell, centred in the item's rows.
    assert_eq!(origin(rect, &four, MenuTextAlign::Center, &face, height).1, 4 + (18 - height) / 2);
}

#[test]
fn a_flush_right_run_ends_at_the_right_edge_and_never_starts_left_of_the_rectangle() {
    let face = cells().cells;
    let height = glyph_height();
    let four: Vec<u16> = alloc::vec![b'n' as u16; 4];
    let nine: Vec<u16> = alloc::vec![b'n' as u16; 9];
    let rect = MenuRect { left: 10, top: 4, right: 10 + run_width(&four, &face) + 8, bottom: 4 + 18 };
    assert_eq!(origin(rect, &four, MenuTextAlign::Right, &face, height).0, rect.right - run_width(&four, &face));
    // A run wider than its rectangle is clamped to the left edge rather than
    // drawn outside the item.
    assert_eq!(origin(rect, &nine, MenuTextAlign::Right, &face, height).0, rect.left);
}
