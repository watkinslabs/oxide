use super::*;

fn key(seed: u8) -> Key {
    let mut raw = [0u8; KEY_LEN];
    for (at, byte) in raw.iter_mut().enumerate() { *byte = seed.wrapping_add(at as u8); }
    Key::new(raw)
}

#[test]
fn a_key_pair_is_carried_as_the_active_key_followed_by_the_backup() {
    let ctx = KeyCtx::new(key(1), None);
    assert_eq!(ctx.bytes().len(), KEY_LEN);
    assert_eq!(&ctx.bytes()[..], key(1).as_bytes());
    let pair = KeyCtx::new(key(1), Some(key(0x40)));
    assert_eq!(pair.bytes().len(), KEY_BUF_LEN);
    assert_eq!(&pair.bytes()[..KEY_LEN], key(1).as_bytes());
    assert_eq!(&pair.bytes()[KEY_LEN..], key(0x40).as_bytes());
}

#[test]
fn only_one_key_or_a_pair_names_a_key_write() {
    assert_eq!(KeyCtx::from_bytes(&[0u8; KEY_LEN]).map(|c| c.backup), Some(None));
    assert!(KeyCtx::from_bytes(&[0u8; KEY_BUF_LEN]).is_some_and(|c| c.backup.is_some()));
    for len in [0, 1, KEY_LEN - 1, KEY_LEN + 1, KEY_BUF_LEN - 1, KEY_BUF_LEN + 1] {
        assert!(KeyCtx::from_bytes(&alloc::vec![0u8; len]).is_none(), "len {len}");
    }
}

#[test]
fn bytes_round_trip_through_the_byte_form() {
    let pair = KeyCtx::new(key(9), Some(key(0x80)));
    assert_eq!(KeyCtx::from_bytes(&pair.bytes()), Some(pair));
    let single = KeyCtx::new(key(9), None);
    assert_eq!(KeyCtx::from_bytes(&single.bytes()), Some(single));
}

#[test]
fn a_group_is_the_little_endian_reading_of_four_key_bytes() {
    // 01 02 03 04 reads as 0x04030201, so an administrator comparing the file
    // against the bytes a `TCP_FASTOPEN_KEY` write supplied sees them in that
    // order and no other.
    let mut raw = [0u8; KEY_LEN];
    raw[..4].copy_from_slice(&[0x01, 0x02, 0x03, 0x04]);
    raw[4..8].copy_from_slice(&[0xff, 0x00, 0x00, 0x00]);
    let text = format_hex(Some(&KeyCtx::new(Key::new(raw), None)));
    assert_eq!(text, b"04030201-000000ff-00000000-00000000".to_vec());
}

#[test]
fn an_owner_with_no_key_still_reads_as_one_all_zero_key() {
    assert_eq!(format_hex(None), b"00000000-00000000-00000000-00000000".to_vec());
    // And it is one key, not a pair: no comma.
    assert!(!format_hex(None).contains(&b','));
}

#[test]
fn a_backup_key_is_printed_after_a_comma() {
    let text = format_hex(Some(&KeyCtx::new(Key::new([0u8; KEY_LEN]), Some(key(0)))));
    let (first, second) = text.split_at(text.iter().position(|b| *b == b',').unwrap());
    assert_eq!(first, b"00000000-00000000-00000000-00000000");
    assert_eq!(second[0], b',');
    assert_eq!(&second[1..], b"03020100-07060504-0b0a0908-0f0e0d0c");
}

#[test]
fn the_text_form_round_trips_both_shapes() {
    for ctx in [KeyCtx::new(key(3), None), KeyCtx::new(key(3), Some(key(0x70)))] {
        assert_eq!(parse_hex(&format_hex(Some(&ctx))), Some(ctx));
    }
}

#[test]
fn a_write_tolerates_the_trailing_newline_the_leaf_prints() {
    let ctx = KeyCtx::new(key(5), None);
    let mut text = format_hex(Some(&ctx));
    text.push(b'\n');
    assert_eq!(parse_hex(&text), Some(ctx));
    // And whitespace around the backup key after the comma.
    let mut pair = format_hex(Some(&KeyCtx::new(key(5), Some(key(6)))));
    pair.push(b'\n');
    assert_eq!(parse_hex(&pair), Some(KeyCtx::new(key(5), Some(key(6)))));
}

#[test]
fn short_groups_are_accepted_and_zero_extended() {
    // The printed form is padded, but a write need not be: `1-2-3-4` names the
    // same key as the padded spelling of it.
    let padded = parse_hex(b"00000001-00000002-00000003-00000004").unwrap();
    assert_eq!(parse_hex(b"1-2-3-4"), Some(padded));
    assert_eq!(padded.primary.as_bytes()[..4], [0x01, 0, 0, 0]);
}

#[test]
fn a_write_that_names_no_four_groups_is_refused() {
    for text in [&b""[..], b"1-2-3", b"1-2-3-", b"-1-2-3-4", b"1_2-3-4",
                 b"zz-2-3-4", b"1-2-3-4-5-6-7-8,", b"1-2-3-4,1-2-3"]
    {
        assert!(parse_hex(text).is_none(), "{}", core::str::from_utf8(text).unwrap());
    }
}

#[test]
fn text_after_the_fourth_group_does_not_change_the_key() {
    // A fifth group is not part of a key, so the value read back is the same
    // one a well-formed write would have named.
    let ctx = parse_hex(b"1-2-3-4-5").unwrap();
    assert_eq!(ctx, parse_hex(b"1-2-3-4").unwrap());
    assert_eq!(ctx.backup, None);
}
