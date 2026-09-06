use super::*;
fn integer(bytes: &[u8], offset: usize) -> i32 { i32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap()) }

#[test]
fn default_profile_serializes_all_five_canonical_stock_fonts() {
    let bytes = nonclient_defaults(504).unwrap();
    let stock = stock_object(17).unwrap();
    let StockDescription::Font(stock) = stock.description else { unreachable!() };
    assert_eq!(integer(&bytes, 0), 504);
    for (i, offset) in [24, 124, 224, 316, 408].into_iter().enumerate() {
        assert_eq!(integer(&bytes, offset), stock.logical.height);
        assert_eq!(integer(&bytes, offset + 4), stock.logical.width);
        assert_eq!(integer(&bytes, offset + 16), if i == 0 { 700 } else { 400 });
        assert_eq!(bytes[offset + 23], 1);
        assert_eq!(bytes[offset + 27], stock.pitch_and_family);
        for (j, unit) in stock.face.encode_utf16().enumerate() {
            assert_eq!(u16::from_le_bytes(bytes[offset + 28 + j * 2..offset + 30 + j * 2].try_into().unwrap()), unit);
        }
    }
    for (offset, value) in [(4, 1), (8, 16), (12, 16), (16, 18), (20, 18), (116, 15), (120, 15), (216, 18), (220, 18), (500, 0)] {
        assert_eq!(integer(&bytes, offset), value);
    }
    assert_eq!(system_metric_default(2), Some(integer(&bytes, 8)));
    assert_eq!(system_metric_default(9), Some(integer(&bytes, 12)));
    assert_eq!(system_metric_default(31), None);
}

#[test]
fn legacy_and_modern_profiles_only_differ_in_caller_size() {
    let old = nonclient_defaults(500).unwrap();
    let new = nonclient_defaults(504).unwrap();
    assert_eq!(integer(&old, 0), 500);
    assert_eq!(&old[4..], &new[4..]);
    for size in [0, 499, 501, 503, 505, u32::MAX] { assert!(nonclient_defaults(size).is_err()); }
}
