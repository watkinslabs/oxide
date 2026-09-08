//! The five items of the reference text editor's bar, measured with the real
//! extent of each label under the menu face rather than a character count on
//! one advance.
use crate::win32_gdi::{menu_bar_metrics, MenuCells, MenuMetrics, CELL_COUNT, CELL_FIRST, CELL_SCALE, CELL_TABLE_BYTES};
use crate::win32_menu::popup::{check_width, ARROW_WIDTH, POPUP_BORDER};
use crate::win32_menu::{mnemonic::display_text, MenuId, MenuItem, MenuManager, MenuRect};
use alloc::vec::Vec;

/// Notepad's bar as its resource stores it, prefixes included.
const NOTEPAD_BAR: [&[u8]; 5] = [b"&File", b"&Edit", b"F&ormat", b"&View", b"&Help"];

/// The band Notepad's bar claims on the shipped menu face.
const NOTEPAD_BAND: i32 = 19;

/// Width the acceptance window's frame gives the band.
const FRAME_WIDTH: i32 = 582 - 261;

fn units(label: &[u8]) -> Vec<u16> { label.iter().map(|unit| *unit as u16).chain(core::iter::once(0)).collect() }

fn notepad_bar() -> (MenuManager, MenuId) {
    let mut menus = MenuManager::new();
    let menu = menus.create().unwrap();
    for (position, label) in NOTEPAD_BAR.iter().enumerate() {
        menus.insert(menu, position, MenuItem { id: position as u32 + 1, state: 0, text: units(label), submenu: None }).unwrap();
    }
    (menus, menu)
}

/// A face whose glyphs are not one width: every character keeps the advance
/// the closure gives it, quoted in sub-pixel units.
fn face(advance: impl Fn(u8) -> f32, height: i32, bar_height: i32) -> MenuMetrics {
    let mut words = [0u8; CELL_TABLE_BYTES];
    for index in 0..CELL_COUNT {
        let unit = (CELL_FIRST as usize + index) as u8;
        let scaled = (advance(unit) * CELL_SCALE as f32).round() as u16;
        words[index * 2..index * 2 + 2].copy_from_slice(&scaled.to_le_bytes());
    }
    MenuMetrics::measured(MenuCells::from_words(&words, height).unwrap(), bar_height)
}

/// The proportional shape a real GUI face has: narrow letters are much
/// narrower than the average, wide ones much wider.
fn proportional() -> MenuMetrics {
    face(|unit| match unit {
        b'i' | b'l' | b'j' | b'.' | b',' | b'\'' => 2.5,
        b'f' | b't' | b'r' => 3.5,
        b'W' | b'M' | b'm' => 9.5,
        _ => 6.0,
    }, 11, NOTEPAD_BAND)
}

/// The rule the reference lays a bar item out by: the extent of the drawn
/// label, padded by twice the face's character size. Nothing here is a
/// character count.
#[test]
fn a_bar_item_is_its_label_s_extent_padded_by_two_character_sizes() {
    let (menus, menu) = notepad_bar();
    let metrics = proportional();
    let origin = MenuRect { left: 0, top: 0, right: FRAME_WIDTH, bottom: 768 };
    let mut left = 0;
    for (position, label) in NOTEPAD_BAR.iter().enumerate() {
        let rect = menus.bar_item_rect(menu, position, origin, &metrics).unwrap();
        let drawn = display_text(&units(label));
        assert_eq!(drawn.units.len(), label.len() - 1, "the prefix costs no column");
        let extent = metrics.cells.extent(&drawn.units);
        assert_eq!(rect.right - rect.left, extent + 2 * metrics.char_width);
        assert_eq!(rect.left, left, "items run left to right without a gap");
        left = rect.right;
    }
}

/// The defect this measurement replaces: a label whose glyphs are wider than
/// the face's average overruns a box measured as a character count on that
/// average, and the item behind it is drawn over. The box the extent produces
/// holds every run with a full character size of clearance on each side.
#[test]
fn every_item_box_contains_its_own_run_with_the_reference_s_padding() {
    let metrics = proportional();
    let origin = MenuRect { left: 0, top: 0, right: FRAME_WIDTH, bottom: 768 };
    // The same bar measured the way a character count on one advance measures
    // it, which is what the layout did before the face was measured.
    let counted = MenuMetrics::uniform(metrics.char_width, metrics.char_height, metrics.bar_height);
    let labels: [&[u8]; 6] = [b"&File", b"&Edit", b"F&ormat", b"&View", b"&Help", b"&Window Mommm"];
    let mut menus = MenuManager::new();
    let menu = menus.create().unwrap();
    for (position, label) in labels.iter().enumerate() {
        menus.insert(menu, position, MenuItem { id: position as u32 + 1, state: 0, text: units(label), submenu: None }).unwrap();
    }
    let mut overran = false;
    for (position, label) in labels.iter().enumerate() {
        let run = metrics.cells.extent(&display_text(&units(label)).units);
        let measured = menus.bar_item_rect(menu, position, origin, &metrics).unwrap();
        assert!(measured.right - measured.left - run >= 2 * metrics.char_width,
            "the run sits inside its box with one character size on each side");
        let counted_rect = menus.bar_item_rect(menu, position, origin, &counted).unwrap();
        if counted_rect.right - counted_rect.left < run + 2 * counted.char_width { overran = true; }
    }
    assert!(overran, "a count on one advance cannot hold a run of wide glyphs: the case this test guards");
}

/// The band the bar claims comes from that same measurement, and the height
/// one item takes never leaves the band.
#[test]
fn the_band_is_one_row_of_border_over_the_tallest_item() {
    let (menus, menu) = notepad_bar();
    let metrics = proportional();
    let origin = MenuRect { left: 0, top: 0, right: FRAME_WIDTH, bottom: 768 };
    let bar = menus.bar_rect(menu, origin, &metrics).unwrap();
    assert_eq!(bar.bottom - origin.top, metrics.bar_height);
    for position in 0..NOTEPAD_BAR.len() {
        let rect = menus.bar_item_rect(menu, position, origin, &metrics).unwrap();
        assert_eq!(rect.top, origin.top + crate::win32_menu::BAR_TOP_BORDER);
        assert_eq!(rect.bottom - rect.top, metrics.char_height.max(metrics.bar_height - crate::win32_menu::BAR_TOP_BORDER));
        assert!(rect.bottom <= bar.bottom && rect.top >= bar.top);
    }
    let last = menus.bar_item_rect(menu, NOTEPAD_BAR.len() - 1, origin, &metrics).unwrap();
    assert_eq!(bar.right, last.right);
}

/// A taller face raises the band, because the row it needs no longer fits the
/// height the profile reserves.
#[test]
fn a_taller_face_raises_the_band_it_is_drawn_in() {
    let (menus, menu) = notepad_bar();
    let tall = face(|_| 12.0, 30, 33);
    let origin = MenuRect { left: 0, top: 0, right: FRAME_WIDTH, bottom: 768 };
    let bar = menus.bar_rect(menu, origin, &tall).unwrap();
    assert!(bar.bottom - bar.top > NOTEPAD_BAND);
}

/// A popup row reserves the check column, the gap and one character size
/// before its text, and the arrow column behind it, so its width is the
/// widest label's extent inside those columns.
#[test]
fn a_popup_row_reserves_the_columns_the_reference_reserves() {
    let (mut menus, _) = notepad_bar();
    let popup = menus.create_popup().unwrap();
    let items: [&[u8]; 3] = [b"&New", b"Save &As...", b"&Print"];
    for (position, label) in items.iter().enumerate() {
        menus.insert(popup, position, MenuItem { id: position as u32 + 10, state: 0, text: units(label), submenu: None }).unwrap();
    }
    let metrics = proportional();
    let layout = menus.popup_layout(popup, &metrics, 768).unwrap();
    let widest = items.iter().map(|label| metrics.cells.extent(&display_text(&units(label)).units)).max().unwrap();
    let lead = check_width(metrics.char_height) + 4 + metrics.char_width;
    assert_eq!(layout.text, lead);
    assert_eq!(layout.tab, lead + widest);
    assert_eq!(layout.width, lead + widest + ARROW_WIDTH + 2 + POPUP_BORDER * 2);
    // Every row is as tall as the face's character height plus the four rows
    // the reference floors a row at.
    assert_eq!(layout.height, POPUP_BORDER * 2 + items.len() as i32 * (metrics.char_height + 4));
}

/// An accelerator half is set off from the name by one character size, and
/// every accelerator in the menu starts in one column.
#[test]
fn the_accelerator_column_is_one_character_size_behind_the_widest_name() {
    let mut menus = MenuManager::new();
    let popup = menus.create_popup().unwrap();
    for (position, label) in [b"&New\tCtrl+N".as_slice(), b"Page Set&up...\tF5".as_slice()].iter().enumerate() {
        menus.insert(popup, position, MenuItem { id: position as u32 + 1, state: 0, text: units(label), submenu: None }).unwrap();
    }
    let metrics = proportional();
    let layout = menus.popup_layout(popup, &metrics, 768).unwrap();
    let lead = check_width(metrics.char_height) + 4 + metrics.char_width;
    let widest_name = metrics.cells.extent(&display_text(&units(b"Page Set&up...")).units);
    let widest_accel = metrics.cells.extent(&display_text(&units(b"Ctrl+N")).units)
        .max(metrics.cells.extent(&display_text(&units(b"F5")).units));
    assert_eq!(layout.tab, lead + widest_name);
    assert_eq!(layout.width, layout.tab + ARROW_WIDTH + 2 + metrics.char_width + widest_accel + POPUP_BORDER * 2);
}

/// A bar and the popups under it are measured with one face, so an item and
/// the menu that opens from it cannot be laid out on different numbers.
#[test]
fn a_popup_and_a_bar_are_measured_on_one_face() {
    let _face = crate::win32_gdi::face_test_lock().lock();
    let metrics = menu_bar_metrics();
    assert_eq!(metrics.cells.char_size(), (metrics.char_width, metrics.char_height));
}
