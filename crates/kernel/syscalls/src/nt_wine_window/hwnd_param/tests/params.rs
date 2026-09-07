//! Parameter-record layouts. Each is checked at the byte offsets the client
//! writes, because a field read from the wrong offset reads a neighbouring
//! field or a padding hole and answers a plausible wrong number rather than
//! failing: the rectangle record's dpi word sits where a flag would, and
//! reading a flag there once made three separate rectangle queries one query.
use super::*;

#[test]
fn the_rectangle_record_is_a_pointer_then_a_dpi_word_then_padding() {
    assert_eq!(WINDOW_RECTS_BYTES, 16);
    let params = WindowRects { rect: 0x1122_3344_5566_7788, dpi: 144 };
    assert_eq!(WindowRects::decode(params.encode()), params);
    let bytes = params.encode();
    assert_eq!(&bytes[0..8], &0x1122_3344_5566_7788u64.to_le_bytes());
    assert_eq!(&bytes[8..12], &144u32.to_le_bytes());
    // The last four bytes are padding the client does not write, so nothing
    // may be read from them: whatever is there decodes to the same record.
    let mut dirty = bytes;
    dirty[12..16].copy_from_slice(&0xdead_beefu32.to_le_bytes());
    assert_eq!(WindowRects::decode(dirty), params);
}

#[test]
fn the_map_points_record_places_its_count_and_dpi_after_two_pointers() {
    assert_eq!(MAP_POINTS_BYTES, 24);
    let params = MapPoints { hwnd_to: 0x0000_0000_0001_0002, points: 0x7fff_1234_5678, count: 2, dpi: 96 };
    assert_eq!(MapPoints::decode(params.encode()), params);
    let bytes = params.encode();
    assert_eq!(&bytes[16..20], &2u32.to_le_bytes());
    assert_eq!(&bytes[20..24], &96u32.to_le_bytes());
}

#[test]
fn the_private_data_records_differ_only_by_the_value_they_carry() {
    assert_eq!(GET_PRIVATE_BYTES, 8);
    assert_eq!(SET_PRIVATE_BYTES, 16);
    let read = PrivateData { offset: 8, size: 8, value: 0 };
    let mut bytes = [0u8; GET_PRIVATE_BYTES];
    bytes.copy_from_slice(&read.encode_set()[0..GET_PRIVATE_BYTES]);
    assert_eq!(PrivateData::decode_get(bytes), read);
    let write = PrivateData { offset: 4, size: 4, value: 0x7fff_0000_0001 };
    assert_eq!(PrivateData::decode_set(write.encode_set()), write);
}

#[test]
fn the_exposure_record_marks_a_whole_surface_before_its_rectangle() {
    assert_eq!(EXPOSE_BYTES, 24);
    let whole = Expose { flags: 0x0085, whole: true, rect: Rect::default() };
    assert_eq!(Expose::decode(whole.encode()), whole);
    let partial = Expose { flags: 1, whole: false, rect: Rect { left: 1, top: 2, right: 3, bottom: 4 } };
    let bytes = partial.encode();
    assert_eq!(Expose::decode(bytes), partial);
    // The rectangle begins one flags word and one boolean in, which is where
    // the redraw owner is handed it.
    assert_eq!(Rect::decode(&bytes[8..24]), partial.rect);
}

#[test]
fn the_raw_position_record_leads_with_its_rectangle() {
    assert_eq!(RAW_WINDOW_POS_BYTES, 24);
    let params = RawWindowPos { rect: Rect { left: 10, top: 20, right: 110, bottom: 220 }, flags: 0x0010, internal: true };
    assert_eq!(RawWindowPos::decode(params.encode()), params);
    assert_eq!(Rect::decode(&params.encode()[0..16]), params.rect);
}

#[test]
fn the_hardware_input_record_pads_its_flags_word_out_to_the_pointer() {
    assert_eq!(HARDWARE_INPUT_BYTES, 24);
    let params = HardwareInput { flags: 2, input: 0x7fff_dead_0000, lparam: 0x1234 };
    assert_eq!(HardwareInput::decode(params.encode()), params);
    let bytes = params.encode();
    // Bytes four through eight are the alignment hole before the pointer.
    assert_eq!(&bytes[4..8], &[0, 0, 0, 0]);
    assert_eq!(&bytes[8..16], &0x7fff_dead_0000u64.to_le_bytes());
}

#[test]
fn a_rectangle_is_four_signed_edges_in_order() {
    assert_eq!(RECT_BYTES, 16);
    assert_eq!(POINT_BYTES, 8);
    let rect = Rect { left: -1, top: -2, right: 3, bottom: 4 };
    assert_eq!(Rect::decode(&rect.encode()), rect);
    assert_eq!(&rect.encode()[0..4], &(-1i32).to_le_bytes());
    assert_eq!(&rect.encode()[12..16], &4i32.to_le_bytes());
}
