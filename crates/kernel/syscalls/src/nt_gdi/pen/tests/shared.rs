use super::*;
#[test]
fn shared_stroke_snapshot_uses_real_colorref_position_and_rop_fields(){
    let dc=0x10040;
    let mut bytes=abi::encode_dc_attr(dc,8,8,abi::DcText{foreground:0,background:0x123456,
        alignment:0,background_mode:1,current_position:(-7,9)}).unwrap();
    bytes[abi::dc::PEN_COLOR..abi::dc::PEN_COLOR+4].copy_from_slice(&0x00123456u32.to_le_bytes());
    bytes[abi::dc::ROP_MODE..abi::dc::ROP_MODE+2].copy_from_slice(&7u16.to_le_bytes());
    bytes[abi::dc::ARC_DIRECTION..abi::dc::ARC_DIRECTION+4].copy_from_slice(&2u32.to_le_bytes());
    let state=decode(&bytes,dc).unwrap();assert_eq!(state.position,(-7,9));assert_eq!(state.pen_color,0x563412);
    assert_eq!(state.background,0x123456);assert_eq!(state.rop,7);assert!(state.clockwise);assert!(!state.opaque);
    bytes[abi::dc::ROP_MODE..abi::dc::ROP_MODE+2].copy_from_slice(&17u16.to_le_bytes());assert!(decode(&bytes,dc).is_err());
    bytes[abi::dc::ROP_MODE..abi::dc::ROP_MODE+2].copy_from_slice(&13u16.to_le_bytes());
    bytes[abi::dc::ARC_DIRECTION..abi::dc::ARC_DIRECTION+4].copy_from_slice(&0u32.to_le_bytes());assert!(decode(&bytes,dc).is_err());
    assert!(decode(&bytes[..100],dc).is_err());
}
#[test]
fn typed_pen_client_projection_preserves_extended_type_and_has_no_object_pointer(){
    let mut g=ipc::win32_gdi::GdiManager::new();let dc=g.create_dc(2,2).unwrap();
    let p=g.create_pen(0,1,0).unwrap();g.select_pen(dc,p).unwrap();g.delete_object(p).unwrap();
    assert!(g.live_handles().contains(&p));
    let entry=abi::HandleEntry::for_handle(p,42,0).unwrap();let bytes=entry.encode().unwrap();
    let decoded=abi::HandleEntry::decode(&bytes).unwrap();assert_eq!(decoded.kind,0x10);assert_eq!(decoded.extended_type(),0x30);
    assert_eq!(decoded.user_pointer,0);assert_eq!(&bytes[..8],&[0;8]);assert!(!decoded.stock());
    for index in [6,7,8,19]{let h=g.stock_object(index).unwrap().handle;
        let entry=abi::HandleEntry::for_handle(h,42,0).unwrap();assert_eq!(entry.extended_type(),0x30);assert!(entry.stock());}
}
