//! Default colour-table provenance: the entries the reference tabulates.
use super::*;

#[test]
fn monochrome_and_sixteen_colour_tables_match_their_tabulated_entries() {
    assert_eq!(default_color_table_len(1), Some(2));
    assert_eq!(default_color_entry(1, 0), Some((0x00, 0x00, 0x00)));
    assert_eq!(default_color_entry(1, 1), Some((0xff, 0xff, 0xff)));
    assert_eq!(default_color_entry(1, 2), None);
    assert_eq!(default_color_table_len(4), Some(16));
    assert_eq!(default_color_entry(4, 1), Some((0x80, 0x00, 0x00)));
    assert_eq!(default_color_entry(4, 4), Some((0x00, 0x00, 0x80)));
    assert_eq!(default_color_entry(4, 8), Some((0xc0, 0xc0, 0xc0)));
    assert_eq!(default_color_entry(4, 15), Some((0xff, 0xff, 0xff)));
}

#[test]
fn eight_bit_table_keeps_both_system_blocks_and_the_colour_cube_between_them() {
    assert_eq!(default_color_table_len(8), Some(256));
    assert_eq!(default_color_entry(8, 0), Some((0x00, 0x00, 0x00)));
    assert_eq!(default_color_entry(8, 7), Some((0xc0, 0xc0, 0xc0)));
    assert_eq!(default_color_entry(8, 8), Some((0xc0, 0xdc, 0xc0)));
    assert_eq!(default_color_entry(8, 9), Some((0xa6, 0xca, 0xf0)));
    // First cube entry: blue level 0, green level 1, red level 2.
    assert_eq!(default_color_entry(8, 10), Some((0x40, 0x20, 0x00)));
    assert_eq!(default_color_entry(8, 15), Some((0xe0, 0x20, 0x00)));
    assert_eq!(default_color_entry(8, 16), Some((0x00, 0x40, 0x00)));
    assert_eq!(default_color_entry(8, 64), Some((0x00, 0x00, 0x40)));
    // Last cube entry precedes the tail block.
    assert_eq!(default_color_entry(8, 245), Some((0xa0, 0xc0, 0xc0)));
    assert_eq!(default_color_entry(8, 246), Some((0xff, 0xfb, 0xf0)));
    assert_eq!(default_color_entry(8, 247), Some((0xa0, 0xa0, 0xa4)));
    assert_eq!(default_color_entry(8, 255), Some((0xff, 0xff, 0xff)));
    assert_eq!(default_color_entry(8, 256), None);
}

#[test]
fn depths_without_a_colour_table_have_none() {
    for bpp in [0, 2, 3, 5, 16, 24, 32] { assert_eq!(default_color_table_len(bpp), None); }
    assert_eq!(default_color_entry(16, 0), None);
}
