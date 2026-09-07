//! Depth-wise pixel encode and decode; the packing every stored depth uses.
use super::*;

#[test]
fn sub_byte_depths_address_pixels_from_the_high_bits_of_each_byte() {
    let bits = [0b1010_0000u8, 0x00, 0x00, 0x00];
    assert_eq!(raw_pixel(&bits, 4, 1, 0, 0), Some(1));
    assert_eq!(raw_pixel(&bits, 4, 1, 1, 0), Some(0));
    assert_eq!(raw_pixel(&bits, 4, 1, 2, 0), Some(1));
    let nibbles = [0x3fu8, 0x00, 0x00, 0x00];
    assert_eq!(raw_pixel(&nibbles, 4, 4, 0, 0), Some(3));
    assert_eq!(raw_pixel(&nibbles, 4, 4, 1, 0), Some(0xf));
}

#[test]
fn writes_at_sub_byte_depths_leave_the_neighbouring_pixel_alone() {
    let mut bits = [0x00u8; 4];
    assert_eq!(put_raw_pixel(&mut bits, 4, 4, 1, 0, 0xa), Some(()));
    assert_eq!(bits[0], 0x0a);
    assert_eq!(put_raw_pixel(&mut bits, 4, 4, 0, 0, 0x5), Some(()));
    assert_eq!(bits[0], 0x5a);
    let mut mono = [0xffu8; 4];
    assert_eq!(put_raw_pixel(&mut mono, 4, 1, 3, 0, 0), Some(()));
    assert_eq!(mono[0], 0b1110_1111);
}

#[test]
fn packed_depths_round_trip_through_their_byte_order() {
    let mut bits = [0u8; 16];
    put_raw_pixel(&mut bits, 16, 24, 1, 0, 0x0012_3456).unwrap();
    assert_eq!(&bits[3..6], &[0x56, 0x34, 0x12]);
    assert_eq!(raw_pixel(&bits, 16, 24, 1, 0), Some(0x0012_3456));
    put_raw_pixel(&mut bits, 16, 32, 2, 0, 0x89ab_cdef).unwrap();
    assert_eq!(raw_pixel(&bits, 16, 32, 2, 0), Some(0x89ab_cdef));
    put_raw_pixel(&mut bits, 16, 16, 0, 0, 0x1234).unwrap();
    assert_eq!(raw_pixel(&bits, 16, 16, 0, 0), Some(0x1234));
}

#[test]
fn five_bit_channels_replicate_their_high_bits_so_a_full_field_stays_saturated() {
    assert_eq!(masked_to_xrgb(0x7fff, DEFAULT_555), 0x00ff_ffff);
    assert_eq!(masked_to_xrgb(0x0000, DEFAULT_555), 0x0000_0000);
    assert_eq!(masked_to_xrgb(0x7c00, DEFAULT_555), 0x00ff_0000);
    assert_eq!(masked_to_xrgb(0x001f, DEFAULT_555), 0x0000_00ff);
    // One unit of red is five bits wide: 0b00001 expands to 0b00001_000 | 0b00001.
    assert_eq!(masked_to_xrgb(0x0400, DEFAULT_555), 0x0008_0000);
}

#[test]
fn channel_encoding_is_the_inverse_of_decoding_for_every_representable_value() {
    for raw in 0..0x8000u32 {
        assert_eq!(xrgb_to_masked(masked_to_xrgb(raw, DEFAULT_555), DEFAULT_555), raw);
    }
    assert_eq!(xrgb_to_masked(0x0012_3456, DEFAULT_888), 0x0012_3456);
    assert_eq!(masked_to_xrgb(0x0012_3456, DEFAULT_888), 0x0012_3456);
}

#[test]
fn nearest_table_entry_takes_the_least_squared_distance() {
    let table = [Rgb { red: 0, green: 0, blue: 0 }, Rgb { red: 0xff, green: 0, blue: 0 }, Rgb { red: 0, green: 0xff, blue: 0 }];
    assert_eq!(nearest_index(&table, 0x00ff_0000), 1);
    assert_eq!(nearest_index(&table, 0x0000_ff00), 2);
    assert_eq!(nearest_index(&table, 0x0010_1010), 0);
    assert_eq!(nearest_index(&[], 0), 0);
}

#[test]
fn indexed_depths_are_exactly_the_ones_with_a_default_table() {
    for bpp in [1, 4, 8] { assert!(is_indexed(bpp)); assert!(default_table(bpp).is_some()); }
    for bpp in [16, 24, 32] { assert!(!is_indexed(bpp)); assert!(default_table(bpp).is_none()); }
    assert_eq!(default_table(8).unwrap().len(), 256);
    assert_eq!(default_table(4).unwrap()[1], Rgb { red: 0x80, green: 0, blue: 0 });
}

#[test]
fn out_of_range_positions_and_unknown_depths_answer_nothing() {
    let mut bits = [0u8; 4];
    assert_eq!(raw_pixel(&bits, 4, 8, -1, 0), None);
    assert_eq!(raw_pixel(&bits, 4, 8, 0, -1), None);
    assert_eq!(raw_pixel(&bits, 4, 8, 9, 0), None);
    assert_eq!(raw_pixel(&bits, 4, 2, 0, 0), None);
    assert_eq!(put_raw_pixel(&mut bits, 4, 8, 99, 0, 1), None);
    assert_eq!(put_raw_pixel(&mut bits, 4, 2, 0, 0, 1), None);
}
