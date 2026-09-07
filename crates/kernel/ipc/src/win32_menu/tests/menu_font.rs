//! The five items of the reference text editor's bar, measured on the face
//! the bar is drawn in rather than on a fixed cell.
use crate::win32_gdi::{font_text_metrics, menu_bar_metrics, menu_font};
use crate::win32_menu::popup::{PopupMetrics, ARROW_WIDTH, CHECK_WIDTH, POPUP_BORDER};
use crate::win32_menu::{mnemonic::display_len, MenuId, MenuItem, MenuManager, MenuRect};
use alloc::vec::Vec;

/// Notepad's bar as its resource stores it, prefixes included.
const NOTEPAD_BAR: [&[u8]; 5] = [b"&File", b"&Edit", b"F&ormat", b"&View", b"&Help"];

/// The cells the shipped menu face gives Notepad's own five items, and the
/// band they sit in: the geometry the acceptance window shows.
const NOTEPAD_CELLS: [i32; 5] = [30, 30, 40, 30, 30];
const NOTEPAD_BAND: i32 = 19;

/// Width the acceptance window's frame gives the band.
const FRAME_WIDTH: i32 = 582 - 261;

/// Columns a bar item adds around its label, one on each side.
const PAD_COLUMNS: i32 = 2;

fn units(label: &[u8]) -> Vec<u16> { label.iter().map(|unit| *unit as u16).chain(core::iter::once(0)).collect() }

fn notepad_bar() -> (MenuManager, MenuId) {
    let mut menus = MenuManager::new();
    let menu = menus.create().unwrap();
    for (position, label) in NOTEPAD_BAR.iter().enumerate() {
        menus.insert(menu, position, MenuItem { id: position as u32 + 1, state: 0, text: units(label), submenu: None }).unwrap();
    }
    (menus, menu)
}

/// Every label is measured as its drawn text on the menu face's advance: the
/// prefix that marks the mnemonic costs no column, and the cell is never the
/// stock face's own.
#[test]
fn the_five_notepad_labels_measure_on_the_menu_face() {
    let (menus, menu) = notepad_bar();
    let cells = menu_bar_metrics();
    let face = font_text_metrics(menu_font());
    assert_eq!(cells.char_width, face.character_width);
    let origin = MenuRect { left: 0, top: 0, right: FRAME_WIDTH, bottom: 768 };
    let mut left = 0;
    for (position, label) in NOTEPAD_BAR.iter().enumerate() {
        let rect = menus.bar_item_rect(menu, position, origin, cells.char_width, cells.char_height, cells.bar_height).unwrap();
        let drawn = display_len(&units(label)) as i32;
        assert_eq!(drawn, label.len() as i32 - 1, "the prefix costs no column");
        assert_eq!(rect.right - rect.left, (drawn + PAD_COLUMNS) * face.character_width);
        assert_eq!(rect.right - rect.left, NOTEPAD_CELLS[position], "the shipped menu face's own cell");
        assert_eq!(rect.left, left, "items run left to right without a gap");
        left = rect.right;
    }
}

/// The band the bar claims comes from that same measurement, and the height
/// one item takes never leaves the band.
#[test]
fn the_band_comes_from_the_measured_items() {
    let (menus, menu) = notepad_bar();
    let cells = menu_bar_metrics();
    let origin = MenuRect { left: 0, top: 0, right: FRAME_WIDTH, bottom: 768 };
    let bar = menus.bar_rect(menu, origin, cells.char_width, cells.char_height, cells.bar_height).unwrap();
    assert_eq!(bar.bottom - origin.top, cells.bar_height);
    assert_eq!(cells.bar_height, NOTEPAD_BAND);
    for position in 0..NOTEPAD_BAR.len() {
        let rect = menus.bar_item_rect(menu, position, origin, cells.char_width, cells.char_height, cells.bar_height).unwrap();
        assert!(rect.bottom <= bar.bottom && rect.top >= bar.top);
    }
    let last = menus.bar_item_rect(menu, NOTEPAD_BAR.len() - 1, origin, cells.char_width, cells.char_height, cells.bar_height).unwrap();
    assert_eq!(bar.right, last.right);
}

/// A popup is as wide as its widest item measured on the same face, plus the
/// two reserved columns and its border.
#[test]
fn the_popup_is_as_wide_as_its_widest_item_on_the_menu_face() {
    let (mut menus, _) = notepad_bar();
    let popup = menus.create_popup().unwrap();
    let items: [&[u8]; 3] = [b"&New", b"Save &As...", b"&Print"];
    for (position, label) in items.iter().enumerate() {
        menus.insert(popup, position, MenuItem { id: position as u32 + 10, state: 0, text: units(label), submenu: None }).unwrap();
    }
    let cells = menu_bar_metrics();
    let layout = menus.popup_layout(popup, PopupMetrics::menu(), 768).unwrap();
    let widest = items.iter().map(|label| display_len(&units(label)) as i32).max().unwrap();
    assert_eq!(layout.width, CHECK_WIDTH + widest * cells.char_width + ARROW_WIDTH + POPUP_BORDER * 2);
    assert_eq!(layout.height, POPUP_BORDER * 2 + items.len() as i32 * cells.char_height);
}

/// The cells a popup is measured with are the bar's, so an item and the bar
/// entry that opens it are one face.
#[test]
fn a_popup_and_a_bar_are_measured_on_one_face() {
    let cells = menu_bar_metrics();
    assert_eq!(PopupMetrics::menu(), PopupMetrics { char_width: cells.char_width, char_height: cells.char_height });
}
