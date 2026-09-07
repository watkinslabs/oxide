use super::*;

#[test]
fn the_ordinals_match_the_generated_win32u_table() {
    assert_eq!([SHOW_CURSOR, DESTROY_CURSOR, SET_CURSOR_ICON_DATA, FIND_EXISTING_CURSOR_ICON,
        GET_ICON_INFO, GET_ICON_SIZE, GET_CURSOR_FRAME_INFO, INTERNAL_GET_WINDOW_ICON],
        [0x15b8, 0x137f, 0x1548, 0x13c5, 0x1403, 0x1404, 0x13e8, 0x1488]);
}

#[test]
fn the_client_record_offsets_pack_the_sixty_four_bit_layout() {
    assert_eq!([FRAME_WIDTH, FRAME_HEIGHT, FRAME_COLOR, FRAME_ALPHA, FRAME_MASK, FRAME_HOTSPOT_X, FRAME_HOTSPOT_Y],
        [0, 4, 8, 16, 24, 32, 36]);
    assert_eq!(FRAME_BYTES, 40);
    assert_eq!([DESC_FLAGS, DESC_NUM_STEPS, DESC_NUM_FRAMES, DESC_DELAY, DESC_FRAMES, DESC_FRAME_SEQ, DESC_FRAME_RATES, DESC_RSRC],
        [0, 4, 8, 12, 16, 24, 32, 40]);
    assert_eq!([STRING_LENGTH, STRING_MAXIMUM, STRING_BUFFER], [0, 2, 8]);
}

#[test]
fn an_icon_record_carries_the_hotspot_and_both_bitmaps() {
    let info = IconInfo { is_icon: true, hotspot_x: 3, hotspot_y: 5, color: 0xaa, mask: 0xbb };
    let bytes = encode_icon_info(info);
    assert_eq!(u32::from_le_bytes(bytes[0..4].try_into().unwrap()), 1);
    assert_eq!(u32::from_le_bytes(bytes[4..8].try_into().unwrap()), 3);
    assert_eq!(u32::from_le_bytes(bytes[8..12].try_into().unwrap()), 5);
    assert_eq!(u64::from_le_bytes(bytes[16..24].try_into().unwrap()), 0xbb);
    assert_eq!(u64::from_le_bytes(bytes[24..32].try_into().unwrap()), 0xaa);
    let cursor = encode_icon_info(IconInfo { is_icon: false, ..info });
    assert_eq!(u32::from_le_bytes(cursor[0..4].try_into().unwrap()), 0);
}

#[test]
fn a_small_resource_buffer_names_an_integer_resource() {
    assert_eq!(integer_resource(0x7f00), Some(0x7f00));
    assert_eq!(integer_resource(0), Some(0));
    assert_eq!(integer_resource(0x1_0000), None);
}
