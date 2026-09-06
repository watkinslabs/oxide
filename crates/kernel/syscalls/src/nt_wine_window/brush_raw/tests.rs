use super::*;

#[test]
fn actual_ordinal_argument_counts_and_signed_extents() {
    assert_eq!(decode(CREATE_SOLID_BRUSH, &[0xdeadbeef_00112233, 7]), Some(Operation::CreateSolid { color: 0x112233 }));
    assert_eq!(decode(SELECT_BRUSH, &[0x10040, 0x100041]), Some(Operation::Select { dc: 0x10040, brush: 0x100041 }));
    assert_eq!(decode(PAT_BLT, &[0x10040, 2, 3, 0xffff_fffe, 0xffff_ffff, 0xf00021]), Some(Operation::PatBlt {
        dc: 0x10040, x: 2, y: 3, width: -2, height: -1, rop: 0xf00021,
    }));
    assert_eq!(decode(CREATE_SOLID_BRUSH, &[1]), None);
    assert_eq!(decode(SELECT_BRUSH, &[1]), None);
    assert_eq!(decode(PAT_BLT, &[1; 5]), None);
    assert_eq!(decode(0x1250, &[1; 6]), None);
}
