use super::*;
use super::super::{encode_dc_attr,decode_text,DcText,TYPE_DC,dc};
#[test]
fn zero_metadata_roundtrips_through_production_codec(){
    for(width,height)in[(0,0),(0,4),(4,0),(4,4)]{
        let bytes=encode_dc_attr(TYPE_DC|64,width,height,DcText::default()).unwrap();
        assert_eq!(decode_text(&bytes,TYPE_DC|64),Ok(DcText::default()));
        assert_eq!(i32::from_le_bytes(bytes[dc::VIS_RECT+8..dc::VIS_RECT+12].try_into().unwrap()),width);
        assert_eq!(i32::from_le_bytes(bytes[dc::VIS_RECT+12..dc::VIS_RECT+16].try_into().unwrap()),height);
    }
}
#[test]
fn empty_metadata_keeps_transform_and_mode_error_order(){
    let dc_handle=TYPE_DC|64;let mut bytes=encode_dc_attr(dc_handle,0,0,DcText::default()).unwrap();
    bytes[dc::MAP_MODE..dc::MAP_MODE+4].copy_from_slice(&2u32.to_le_bytes());
    assert_eq!(decode_text(&bytes,dc_handle),Err(Error::UnsupportedTransform));
    bytes[dc::MAP_MODE..dc::MAP_MODE+4].copy_from_slice(&1u32.to_le_bytes());
    bytes[dc::BACKGROUND_MODE..dc::BACKGROUND_MODE+2].copy_from_slice(&0u16.to_le_bytes());
    assert_eq!(decode_text(&bytes,dc_handle),Err(Error::BackgroundMode));
    bytes[dc::DISABLED..dc::DISABLED+4].copy_from_slice(&1u32.to_le_bytes());
    assert_eq!(decode_text(&bytes,dc_handle),Err(Error::Disabled));
    assert_eq!(decode_text(&bytes,dc_handle+1),Err(Error::Handle));
}
#[test]
fn reversed_overflow_and_negative_dimensions_still_fail(){
    assert_eq!(visible_rect(-4,-3,-4,-3),Ok(()));
    for rect in[(1,0,0,0),(0,1,0,0),(i32::MIN,0,i32::MAX,0),(0,i32::MIN,0,i32::MAX)]{
        assert_eq!(visible_rect(rect.0,rect.1,rect.2,rect.3),Err(Error::Dimensions));
    }
    for(w,h)in[(-1,0),(0,-1),(i32::MIN,4)]{assert_eq!(dimensions(w,h),Err(Error::Dimensions));}
}
