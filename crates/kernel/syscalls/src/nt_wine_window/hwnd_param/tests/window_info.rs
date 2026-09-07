//! The `WINDOWINFO` layout and the two border widths derived from it.
use super::*;

#[test]
fn the_record_places_every_field_at_its_offset() {
    let info = WindowInfo {
        window: Rect { left: 100, top: 50, right: 400, bottom: 300 },
        client: Rect { left: 104, top: 74, right: 396, bottom: 296 },
        style: 0x82c8_00c4, ex_style: 0x0000_0101, active: true, class_atom: 0xc012,
    };
    let bytes = info.encode();
    assert_eq!(&bytes[0..4], &(WINDOWINFO_BYTES as u32).to_le_bytes());
    assert_eq!(Rect::decode(&bytes[4..20]), info.window);
    assert_eq!(Rect::decode(&bytes[20..36]), info.client);
    assert_eq!(&bytes[36..40], &0x82c8_00c4u32.to_le_bytes());
    assert_eq!(&bytes[40..44], &0x0000_0101u32.to_le_bytes());
    assert_eq!(&bytes[44..48], &WS_ACTIVECAPTION.to_le_bytes());
    assert_eq!(&bytes[56..58], &0xc012u16.to_le_bytes());
    assert_eq!(&bytes[58..60], &CREATOR_VERSION.to_le_bytes());
}

#[test]
fn the_border_widths_are_the_two_rectangles_horizontal_and_bottom_insets() {
    let info = WindowInfo {
        window: Rect { left: 100, top: 50, right: 400, bottom: 300 },
        client: Rect { left: 104, top: 74, right: 396, bottom: 296 },
        style: 0, ex_style: 0, active: false, class_atom: 0,
    };
    let bytes = info.encode();
    // The x border is the client's left inset; the y border is the bottom one,
    // not the top, so a caption does not count as a border.
    assert_eq!(i32::from_le_bytes(bytes[48..52].try_into().unwrap()), 4);
    assert_eq!(i32::from_le_bytes(bytes[52..56].try_into().unwrap()), 4);
    // An inactive window carries no window-status bit.
    assert_eq!(&bytes[44..48], &0u32.to_le_bytes());
}

#[test]
fn a_client_rectangle_outside_its_window_still_encodes_a_signed_border() {
    let info = WindowInfo {
        window: Rect { left: 10, top: 10, right: 20, bottom: 20 },
        client: Rect { left: 0, top: 0, right: 30, bottom: 30 },
        style: 0, ex_style: 0, active: false, class_atom: 0,
    };
    let bytes = info.encode();
    assert_eq!(i32::from_le_bytes(bytes[48..52].try_into().unwrap()), -10);
    assert_eq!(i32::from_le_bytes(bytes[52..56].try_into().unwrap()), -10);
}
