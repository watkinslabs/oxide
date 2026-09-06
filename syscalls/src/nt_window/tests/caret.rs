use super::*;

#[test]
fn caret_position_preserves_signed_wire_coordinates() {
    let position = CaretPos { x: -7, y: 19 };
    assert_eq!(CaretPos::decode(position.encode()), position);
    assert_eq!(CREATE_CARET_ORDINAL, 0x1360);
    assert_eq!(SET_CARET_POS_ORDINAL, 0x153c);
}
