//! The face a menu is measured with, and the cells that measurement produces.
use super::*;
use crate::win32_gdi::{nonclient_defaults, GdiManager};
use crate::win32_gdi::nonclient::NONCLIENT_BYTES;

/// Byte offset of `lfMenuFont` inside the nonclient profile, and the offsets
/// of the two fields a measurement reads out of a logical font.
const MENU_FONT_AT: usize = 224;
const LF_HEIGHT: usize = 0;
const LF_WEIGHT: usize = 16;

fn field(bytes: &[u8], at: usize) -> i32 { i32::from_le_bytes(bytes[at..at + 4].try_into().unwrap()) }

/// One owner: the face the menu measurement uses is the very `lfMenuFont` a
/// caller reads out of the profile, not a second description beside it.
#[test]
fn the_menu_face_is_the_profile_s_own_menu_font() {
    let profile = nonclient_defaults(NONCLIENT_BYTES as u32).unwrap();
    let font = menu_font().unwrap();
    assert_eq!(font.height, field(&profile, MENU_FONT_AT + LF_HEIGHT));
    assert_eq!(font.weight, field(&profile, MENU_FONT_AT + LF_WEIGHT));
}

/// A logical width of zero asks the face to choose its own aspect ratio. Read
/// as a literal pixel advance it measures every label at one column, which is
/// what the profile's menu font carries.
#[test]
fn a_face_that_names_no_width_is_measured_at_half_its_cell() {
    let font = menu_font().unwrap();
    assert_eq!(font.width, 0, "the profile's menu font leaves its width to the face");
    let metrics = font_text_metrics(Some(font));
    assert_eq!(metrics.height, font.height.abs());
    assert_eq!(metrics.character_width, font.height.abs() / 2);
    assert_ne!(metrics.character_width, 1, "a width of zero is not a one-pixel advance");
}

/// A width the caller asked for is still the advance.
#[test]
fn a_named_width_is_the_advance() {
    let metrics = font_text_metrics(Some(Font { height: 20, width: 10, weight: 400, italic: false }));
    assert_eq!((metrics.height, metrics.character_width), (20, 10));
}

/// The band a bar claims comes from the measurement: the profile's own menu
/// height while the face fits inside it, and the face's cell once it does not.
#[test]
fn the_band_follows_the_face_it_is_measured_with() {
    let short = menu_metrics(Some(Font { height: -11, width: 0, weight: 400, italic: false }));
    assert_eq!(short, MenuMetrics { char_width: 5, char_height: 11, bar_height: MENU_HEIGHT + 1 });
    let tall = menu_metrics(Some(Font { height: -30, width: 0, weight: 400, italic: false }));
    assert_eq!(tall, MenuMetrics { char_width: 15, char_height: 30, bar_height: 33 });
    assert!(tall.bar_height > short.bar_height, "a taller face claims a taller band");
}

/// The cells the bar is measured with are the ones the selected face reports
/// through the device-context query, so a caller measuring the same label
/// through `GetTextExtentPoint32W` gets the layout's own numbers.
#[test]
fn the_measurement_and_the_selected_face_s_extent_are_one_owner() {
    let mut gdi = GdiManager::new();
    let dc = gdi.create_dc(800, 600).unwrap();
    let face = gdi.menu_face().unwrap();
    gdi.select_font(dc, face).unwrap();
    let cells = menu_bar_metrics();
    assert_eq!(gdi.text_metrics(dc).unwrap().character_width, cells.char_width);
    assert_eq!(gdi.text_metrics(dc).unwrap().height, cells.char_height);
    assert_eq!(gdi.text_extent(dc, 6).unwrap().width, cells.char_width * 6);
}

/// The face is created once and handed back to every later paint, and a
/// deleted one is replaced rather than returned.
#[test]
fn the_menu_face_is_created_once_per_process() {
    let mut gdi = GdiManager::new();
    let first = gdi.menu_face().unwrap();
    assert_eq!(gdi.menu_face().unwrap(), first);
    gdi.delete_object(first).unwrap();
    assert_ne!(gdi.menu_face().unwrap(), first);
}
