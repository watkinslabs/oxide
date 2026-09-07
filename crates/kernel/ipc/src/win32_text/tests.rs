use super::utf16_to_ansi;

#[test]
fn ascii_text_converts_one_byte_per_unit() {
    let units: alloc::vec::Vec<u16> = "&File".encode_utf16().collect();
    assert_eq!(utf16_to_ansi(&units), b"&File".to_vec());
}

#[test]
fn each_scalar_range_takes_its_own_encoded_length() {
    assert_eq!(utf16_to_ansi(&[0x00e9]).len(), 2);
    assert_eq!(utf16_to_ansi(&[0x20ac]).len(), 3);
    assert_eq!(utf16_to_ansi(&[0x0000]), alloc::vec![0]);
}

#[test]
fn a_complete_surrogate_pair_becomes_one_supplementary_scalar() {
    let units: alloc::vec::Vec<u16> = "\u{1f600}".encode_utf16().collect();
    assert_eq!(units.len(), 2);
    assert_eq!(utf16_to_ansi(&units), "\u{1f600}".as_bytes().to_vec());
}

#[test]
fn a_lone_surrogate_encodes_as_its_own_value_rather_than_vanishing() {
    let converted = utf16_to_ansi(&[0xd83d, 0x0041]);
    assert_eq!(converted.len(), 4);
    assert_eq!(converted[3], b'A');
    assert_eq!(utf16_to_ansi(&[0xd83d]).len(), 3);
}
