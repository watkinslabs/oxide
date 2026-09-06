use super::*;

#[test]
fn each_client_write_is_observed_and_setter_changes_only_owned_field() {
    let mut bytes = abi::encode_dc_attr(0x10040, 2, 2, abi::DcText::default()).unwrap();
    for color in [0x00112233u32, 0x00abcdef] {
        let before = bytes;
        let old = snapshot(&bytes).unwrap().0;
        let (previous, encoded) = replacement(&bytes, color).unwrap();
        assert_eq!(previous, old);
        bytes[abi::dc::BRUSH_COLOR..abi::dc::BRUSH_COLOR + 4].copy_from_slice(&encoded);
        assert_eq!(snapshot(&bytes), Ok((color, ((color & 0xff) << 16) | (color & 0xff00) | ((color >> 16) & 0xff))));
        assert_eq!(&bytes[..abi::dc::BRUSH_COLOR], &before[..abi::dc::BRUSH_COLOR]);
        assert_eq!(&bytes[abi::dc::BRUSH_COLOR + 4..], &before[abi::dc::BRUSH_COLOR + 4..]);
    }
}

#[test]
fn unsupported_color_encoding_does_not_emit_a_write() {
    let bytes = abi::encode_dc_attr(0x10040, 1, 1, abi::DcText::default()).unwrap();
    assert!(replacement(&bytes, 0x01000001).is_err());
    let mut invalid = bytes;
    invalid[abi::dc::BRUSH_COLOR + 3] = 1;
    assert!(snapshot(&invalid).is_err());
    assert!(replacement(&invalid, 0).is_err());
}
