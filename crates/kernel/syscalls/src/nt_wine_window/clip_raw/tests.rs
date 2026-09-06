use super::*;

#[test]
fn clip_ordinals_decode_all_signed_coordinates_and_pointer() {
    assert_eq!(decode(0x1238, &[7, u32::MAX as u64, 3, 4, 0xfffffffe]), Some(Operation::Intersect { dc: 7, left: -1, top: 3, right: 4, bottom: -2 }));
    assert_eq!(decode(0x11db, &[7, 0x10000]), Some(Operation::GetBox { dc: 7, output: 0x10000 }));
    assert_eq!(decode(0x1238, &[7; 4]), None);
    assert_eq!(decode(0x11db, &[7]), None);
    assert_eq!(decode(0x1239, &[7; 5]), None);
}
