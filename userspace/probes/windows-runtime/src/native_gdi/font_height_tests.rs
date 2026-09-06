use super::*;

fn fixture() -> Vec<u8> {
    let mut bytes = vec![0u8; 160];
    bytes[4..6].copy_from_slice(&3u16.to_be_bytes());
    for (index, tag, offset, len) in [(0, b"head", 64u32, 20u32),
        (1, b"OS/2", 84, 78), (2, b"hhea", 162, 8)] {
        bytes.resize(bytes.len().max((offset + len) as usize), 0);
        let entry = &mut bytes[12 + index * 16..28 + index * 16];
        entry[..4].copy_from_slice(tag);
        entry[8..12].copy_from_slice(&offset.to_be_bytes()); entry[12..].copy_from_slice(&len.to_be_bytes());
    }
    bytes[82..84].copy_from_slice(&1000u16.to_be_bytes());
    bytes[158..160].copy_from_slice(&900u16.to_be_bytes());
    bytes[160..162].copy_from_slice(&300u16.to_be_bytes());
    bytes[166..168].copy_from_slice(&900i16.to_be_bytes());
    bytes[168..170].copy_from_slice(&(-300i16).to_be_bytes());
    bytes
}

#[test]
fn cell_height_rounding_default_and_negative_em_are_distinct() {
    let bytes = fixture();
    assert_eq!(pixel_size(&bytes, 16), Some(13.0));
    assert_eq!(pixel_size(&bytes, 0), Some(13.0));
    assert_eq!(pixel_size(&bytes, -16), Some(16.0));
    assert_eq!(pixel_size(&bytes, 10), Some(8.0));
    assert_eq!(pixel_size(&bytes, i32::MIN), None);
    assert_eq!(pixel_size(&bytes, MAX_HEIGHT + 1), None);
}

#[test]
fn signed_descent_and_zero_os2_sum_use_bounded_metadata() {
    let mut bytes = fixture();
    bytes[160..162].copy_from_slice(&(-300i16).to_be_bytes());
    assert_eq!(pixel_size(&bytes, 16), Some(13.0));
    bytes[158..162].fill(0);
    assert_eq!(pixel_size(&bytes, 16), Some(13.0));
    for end in 0..170 { assert!(pixel_size(&bytes[..end], 16).is_none()); }
    bytes[20..24].copy_from_slice(&u32::MAX.to_be_bytes());
    assert_eq!(pixel_size(&bytes, 16), None);
}
