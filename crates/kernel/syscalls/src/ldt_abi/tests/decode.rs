use crate::ldt_abi::{UserDesc, USER_DESC_BYTES};

#[test]
fn each_flag_occupies_its_own_wire_bit() {
    // One bit at a time, so a shifted field shows up as the wrong flag rather
    // than as a plausible combination.
    let bit = |n: u32| {
        let mut raw = [0u8; USER_DESC_BYTES as usize];
        raw[12..16].copy_from_slice(&(1u32 << n).to_le_bytes());
        UserDesc::decode(&raw)
    };
    assert!(bit(0).seg_32bit);
    assert_eq!(bit(1).contents, 1);
    assert_eq!(bit(2).contents, 2);
    assert!(bit(3).read_exec_only);
    assert!(bit(4).limit_in_pages);
    assert!(bit(5).seg_not_present);
    assert!(bit(6).useable);
    assert!(bit(7).lm);
}

#[test]
fn the_three_word_fields_are_little_endian_in_order() {
    let mut raw = [0u8; USER_DESC_BYTES as usize];
    raw[0..4].copy_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
    raw[4..8].copy_from_slice(&0x1234_5678u32.to_le_bytes());
    raw[8..12].copy_from_slice(&0x000A_BCDEu32.to_le_bytes());
    let d = UserDesc::decode(&raw);
    assert_eq!(d.entry_number, 0xDEAD_BEEF);
    assert_eq!(d.base_addr, 0x1234_5678);
    assert_eq!(d.limit, 0x000A_BCDE);
}

#[test]
fn decode_and_encode_round_trip() {
    let d = UserDesc {
        entry_number: 5, base_addr: 0xCAFE_0000, limit: 0x000F_FFFF,
        seg_32bit: true, contents: 2, read_exec_only: true, limit_in_pages: true,
        seg_not_present: false, useable: true, lm: true,
    };
    assert_eq!(UserDesc::decode(&d.encode()), d);
}

#[test]
fn the_flag_word_holds_no_bits_above_the_defined_eight() {
    let d = UserDesc {
        seg_32bit: true, contents: 3, read_exec_only: true, limit_in_pages: true,
        seg_not_present: true, useable: true, lm: true, ..UserDesc::default()
    };
    let raw = d.encode();
    let flags = u32::from_le_bytes([raw[12], raw[13], raw[14], raw[15]]);
    assert_eq!(flags, 0xFF, "all eight defined bits, nothing above them");
}

#[test]
fn unknown_high_bits_from_userspace_are_ignored() {
    // A 32-bit caller leaves the `lm` bit and everything above it
    // uninitialised. Nothing above bit 7 may reach any decision.
    let mut raw = [0u8; USER_DESC_BYTES as usize];
    raw[12..16].copy_from_slice(&0xFFFF_FF00u32.to_le_bytes());
    let d = UserDesc::decode(&raw);
    assert_eq!(d, UserDesc::default());
}

#[test]
fn user_desc_is_sixteen_bytes() {
    assert_eq!(USER_DESC_BYTES, 16);
}
