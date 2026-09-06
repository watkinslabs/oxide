use super::*;

#[test]
fn a_clean_register_is_the_value_itself() {
    for raw in [0u64, 1, 0x80, 0x100, 0xffff_ffff] {
        assert_eq!(ulong(raw), raw as usize, "raw={raw:#x}");
    }
}

#[test]
fn a_pointer_left_in_the_upper_half_is_not_part_of_the_length() {
    // Measured shape: a 128-byte source arrived as 0x00007f92_00000080, whose
    // upper half is the top of an unrelated pointer. Taking the whole register
    // measured the conversion as needing 2687 units instead of 128.
    assert_eq!(ulong(0x0000_7f92_0000_0080), 0x80);
    assert_eq!(ulong(0x0000_7ffe_0000_0080), 0x80);
}

#[test]
fn upper_bits_never_change_the_result() {
    for upper in [0u64, 1, 0x7fff, 0xffff_ffff] {
        assert_eq!(ulong((upper << 32) | 0x0000_0100), 0x100, "upper={upper:#x}");
    }
}

#[test]
fn a_zero_length_stays_zero_whatever_rides_above_it() {
    assert_eq!(ulong(0xdead_beef_0000_0000), 0);
}
