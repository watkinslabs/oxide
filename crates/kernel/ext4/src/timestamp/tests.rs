use super::*;

/// Round-trip one instant through the `(base, extra)` pair.
fn round_trip(ts: Timespec64) -> Timespec64 {
    decode_extra_time(encode_base(ts), encode_extra_time(ts))
}

/// A 256-byte inode slot with `i_extra_isize = 32` — what mke2fs writes, so
/// every extended field is present.
fn slot_256() -> std::vec::Vec<u8> {
    let mut b = std::vec![0u8; 256];
    b[I_EXTRA_ISIZE..I_EXTRA_ISIZE + 2]
        .copy_from_slice(&(EXT4_INODE_EXTRA_ISIZE_DEFAULT as u16).to_le_bytes());
    b
}

#[test]
fn pre_1970_round_trips_and_stays_negative() {
    // 1906-08-16 — the case a zero-extending decode reads back as year 2100+.
    let ts = Timespec64::new(-2_000_000_000, 123_456_789);
    let (base, extra) = (encode_base(ts), encode_extra_time(ts));
    // Epoch bits 0,0 with the base msb set: the ext4.h table's first row.
    assert_eq!(extra & EXT4_EPOCH_MASK, 0, "pre-epoch times use epoch bits 0,0");
    assert!(base & 0x8000_0000 != 0, "the base word's high bit is set");
    let back = decode_extra_time(base, extra);
    assert_eq!(back, ts);
    assert!(back.sec < 0, "decoded seconds stay NEGATIVE, not year 2106");
    assert!(back.sec > -2_147_483_649, "and inside EXT4_TIMESTAMP_MIN");
}

#[test]
fn epoch_bit_bands_from_the_ext4_h_table_round_trip() {
    // ext4 on-disk "extra epoch bits" table: one probe per band, at both
    // ends where the band is a boundary.
    let bands: [(i64, u32); 10] = [
        (-0x8000_0000,      0), // 1901-12-13, epoch 0,0 msb 1
        (-1,                0), // 1969-12-31, epoch 0,0 msb 1
        (0,                 0), // 1970-01-01, epoch 0,0 msb 0
        (0x7fff_ffff,       0), // 2038-01-19, epoch 0,0 msb 0
        (0x8000_0000,       1), // 2038-01-19, epoch 0,1 msb 1
        (0xffff_ffff,       1), // 2106-02-07, epoch 0,1 msb 1
        (0x1_0000_0000,     1), // 2106-02-07, epoch 0,1 msb 0
        (0x1_7fff_ffff,     1), // 2174-02-25, epoch 0,1 msb 0
        (0x3_0000_0000,     3), // 2378-04-22, epoch 1,1 msb 0
        (0x3_7fff_ffff,     3), // 2446-05-10, epoch 1,1 msb 0
    ];
    for (sec, want_epoch) in bands {
        let ts = Timespec64::new(sec, 999_999_999);
        let extra = encode_extra_time(ts);
        assert_eq!(extra & EXT4_EPOCH_MASK, want_epoch, "epoch bits for sec {sec:#x}");
        assert_eq!(round_trip(ts), ts, "round-trip for sec {sec:#x}");
    }
}

#[test]
fn every_intermediate_band_round_trips_too() {
    // The four bands the probe list above only touches at one end, plus the
    // 2242/2310 rows, so all eight table rows are covered.
    for sec in [0x1_8000_0000i64, 0x1_ffff_ffff, 0x2_0000_0000, 0x2_7fff_ffff,
                0x2_8000_0000, 0x2_ffff_ffff] {
        let ts = Timespec64::new(sec, 1);
        assert_eq!(round_trip(ts), ts, "round-trip for sec {sec:#x}");
    }
}

#[test]
fn extra_max_is_the_last_representable_second() {
    let max = Timespec64::new(EXT4_EXTRA_TIMESTAMP_MAX, 999_999_999);
    assert_eq!(EXT4_EXTRA_TIMESTAMP_MAX, 0x3_7fff_ffff);
    assert_eq!(round_trip(max), max);
    assert_eq!(EXT4_TIMESTAMP_MIN, i32::MIN as i64);
    let min = Timespec64::from_secs(EXT4_TIMESTAMP_MIN);
    assert_eq!(round_trip(min), min);
}

#[test]
fn nsec_never_encodes_out_of_the_30_bit_field() {
    // 999_999_999 << 2 = 3_999_999_996 < 2^32: the shift cannot collide with
    // the epoch bits or overflow the word.
    let ts = Timespec64::new(0, 999_999_999);
    let extra = encode_extra_time(ts);
    assert_eq!(extra >> EXT4_EPOCH_BITS, 999_999_999);
    assert_eq!(extra & EXT4_EPOCH_MASK, 0);
}

#[test]
fn corrupt_nsec_field_normalizes_instead_of_breaking_the_invariant() {
    // The nsec field holds 30 bits (max 1_073_741_823) — above NSEC_PER_SEC.
    let extra = 1_073_741_823u32 << EXT4_EPOCH_BITS;
    let ts = decode_extra_time(0, extra);
    assert!(ts.nsec < 1_000_000_000);
    assert_eq!(ts, Timespec64 { sec: 1, nsec: 73_741_823 });
}

#[test]
fn no_extra_field_clamps_on_write_and_sign_extends_on_read() {
    // EXT4_INODE_SET_XTIME_VAL else-branch: clamp_t(int32_t, tv_sec, ...).
    let far_future = Timespec64::new(0x3_7fff_ffff, 500);
    assert_eq!(encode_base_clamped(far_future), i32::MAX as u32);
    let far_past = Timespec64::from_secs(-4_000_000_000);
    assert_eq!(encode_base_clamped(far_past), i32::MIN as u32);
    let inside = Timespec64::new(-2_000_000_000, 500);
    assert_eq!(encode_base_clamped(inside), (-2_000_000_000i32) as u32);
    // EXT4_INODE_GET_XTIME_VAL fallback: (signed)le32_to_cpu(xtime), nsec 0.
    assert_eq!(decode_base_only(i32::MIN as u32), Timespec64::from_secs(EXT4_TIMESTAMP_MIN));
    assert_eq!(decode_base_only(i32::MAX as u32),
               Timespec64::from_secs(EXT4_NON_EXTRA_TIMESTAMP_MAX));
    assert_eq!(decode_base_only((-2_000_000_000i32) as u32),
               Timespec64::from_secs(-2_000_000_000));
}

#[test]
fn slot_write_read_round_trip_uses_the_extra_field_when_present() {
    let mut b = slot_256();
    let ts = Timespec64::new(-2_000_000_000, 7);
    set_xtime(&mut b, 256, I_MTIME, I_MTIME_EXTRA, ts);
    assert_eq!(get_xtime(&b, 256, I_MTIME, I_MTIME_EXTRA), ts);
    // And the far-future end, which a clamped write would have destroyed.
    let far = Timespec64::new(EXT4_EXTRA_TIMESTAMP_MAX, 999_999_999);
    set_xtime(&mut b, 256, I_ATIME, I_ATIME_EXTRA, far);
    assert_eq!(get_xtime(&b, 256, I_ATIME, I_ATIME_EXTRA), far);
}

#[test]
fn a_128_byte_inode_has_no_extra_field_so_writes_clamp() {
    let mut b = std::vec![0u8; 128];
    assert!(!fits_in_inode(&b, 128, I_MTIME_EXTRA + TIME_FIELD_LEN));
    let far = Timespec64::new(EXT4_EXTRA_TIMESTAMP_MAX, 999_999_999);
    set_xtime(&mut b, 128, I_MTIME, I_MTIME_EXTRA, far);
    assert_eq!(get_xtime(&b, 128, I_MTIME, I_MTIME_EXTRA),
               Timespec64::from_secs(EXT4_NON_EXTRA_TIMESTAMP_MAX));
    let old = Timespec64::new(-2_000_000_000, 7);
    set_xtime(&mut b, 128, I_MTIME, I_MTIME_EXTRA, old);
    // Sub-second precision is lost (no extra word), the sign is not.
    assert_eq!(get_xtime(&b, 128, I_MTIME, I_MTIME_EXTRA),
               Timespec64::from_secs(-2_000_000_000));
    assert_eq!(get_crtime(&b, 128), None, "a 128-byte inode stores no birth time");
}

#[test]
fn high_bit_base_with_zero_extra_decodes_negative() {
    // THE bug this module fixes: an on-disk inode whose i_mtime has the high
    // bit set and whose i_mtime_extra is 0 is a PRE-1970 time. Zero-extending
    // the base word reads it back as year 2106.
    let mut b = slot_256();
    let raw_base = (-2_000_000_000i32) as u32;
    b[I_MTIME..I_MTIME + TIME_FIELD_LEN].copy_from_slice(&raw_base.to_le_bytes());
    assert!(raw_base & 0x8000_0000 != 0);
    let ts = get_xtime(&b, 256, I_MTIME, I_MTIME_EXTRA);
    assert_eq!(ts.sec, -2_000_000_000);
    assert!(ts.sec < 0, "decodes NEGATIVE, not 0x8000_0000+ seconds");
    assert_ne!(ts.sec, raw_base as i64, "not the zero-extended reading");
}

#[test]
fn crtime_presence_follows_fits_in_inode_not_the_epoch_second() {
    let mut b = slot_256();
    // An inode created exactly at the epoch still HAS a birth time.
    set_crtime(&mut b, 256, Timespec64::ZERO);
    assert_eq!(get_crtime(&b, 256), Some(Timespec64::ZERO));
    // i_extra_isize too small to cover i_crtime (ends at 0x94 = 148 > 128+16)
    // yet still large enough for the [acm]time extras (i_atime_extra ends at
    // 0x90 = 144 <= 144) — the presence test is per FIELD, not per inode size.
    b[I_EXTRA_ISIZE..I_EXTRA_ISIZE + 2].copy_from_slice(&16u16.to_le_bytes());
    assert_eq!(get_crtime(&b, 256), None);
    assert!(fits_in_inode(&b, 256, I_ATIME_EXTRA + TIME_FIELD_LEN));
    assert!(!fits_in_inode(&b, 256, I_CRTIME + TIME_FIELD_LEN));
}

#[test]
fn zero_extra_isize_claims_the_default_extra_region() {
    // ext4_iget: "the extra space is currently unused, use it".
    let mut b = std::vec![0u8; 256];
    assert_eq!(inode_extra_isize(&b, 256), EXT4_INODE_EXTRA_ISIZE_DEFAULT);
    assert!(fits_in_inode(&b, 256, I_CRTIME_EXTRA + TIME_FIELD_LEN));
    // A corrupt oversized value cannot admit an out-of-slot read.
    b[I_EXTRA_ISIZE..I_EXTRA_ISIZE + 2].copy_from_slice(&4096u16.to_le_bytes());
    assert_eq!(inode_extra_isize(&b, 256), 256 - EXT4_GOOD_OLD_INODE_SIZE);
    // A 128-byte inode has no extra region at all.
    assert_eq!(inode_extra_isize(&b, 128), 0);
}

#[test]
fn superblock_time_range_matches_ext4_fill_super() {
    // 256-byte inode: nanosecond granularity out to year 2446.
    assert_eq!(time_range_for_inode_size(256),
               (1, EXT4_TIMESTAMP_MIN, EXT4_EXTRA_TIMESTAMP_MAX));
    // 128-byte inode: whole seconds, capped at 2038.
    assert_eq!(time_range_for_inode_size(128),
               (1_000_000_000, EXT4_TIMESTAMP_MIN, EXT4_NON_EXTRA_TIMESTAMP_MAX));
    // The cutover is `i_atime_extra` fitting, exactly as Linux tests it.
    assert_eq!(time_range_for_inode_size(I_ATIME_EXTRA + TIME_FIELD_LEN).0, 1);
    assert_eq!(time_range_for_inode_size(I_ATIME_EXTRA + TIME_FIELD_LEN - 1).0, 1_000_000_000);
    // Pre-1970 is IN range for ext4 — 1901-12-13, not clamped away.
    assert_eq!(EXT4_TIMESTAMP_MIN, -2_147_483_648);
}
