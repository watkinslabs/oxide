use super::{raw,shared};
use ipc::win32_gdi::{GdiManager,Rect};
use syscall::nt_gdi_client as abi;

#[test]
fn raw_line_and_rectangle_consume_selected_owner_objects_and_fresh_client_bytes(){
    let mut g=GdiManager::new();let dc=g.create_dc(5,5).unwrap();
    let pen=g.stock_object(19).unwrap().handle;g.select_pen(dc,pen).unwrap();
    let brush=g.stock_object(18).unwrap().handle;g.select_brush(dc,brush).unwrap();
    let mut bytes=abi::encode_dc_attr(dc,5,5,abi::DcText{foreground:0,background:0,alignment:0,
        background_mode:1,current_position:(1,2)}).unwrap();
    bytes[abi::dc::PEN_COLOR..abi::dc::PEN_COLOR+4].copy_from_slice(&0x00332211u32.to_le_bytes());
    bytes[abi::dc::BRUSH_COLOR..abi::dc::BRUSH_COLOR+4].copy_from_slice(&0x00665544u32.to_le_bytes());
    let result=raw::route(raw::LINE_TO,&[u64::from(dc),4,2],|call|{
        let raw::PenCall::Line{dc,x,y}=call else{unreachable!()};
        let state=shared::decode(&bytes,dc as u32).unwrap();
        g.pen_line_to(dc as u32,(x,y),Some(state)).unwrap();1
    });
    assert_eq!(result,Some(1));assert_eq!(&g.pixels(dc).unwrap()[10..15],&[0,0x112233,0x112233,0x112233,0]);
    let null=g.create_pen(5,0,0).unwrap();g.select_pen(dc,null).unwrap();
    assert_eq!(raw::route(raw::RECTANGLE,&[u64::from(dc),0,0,4,4],|call|{
        let raw::PenCall::Rectangle{dc,rect}=call else{unreachable!()};
        g.pen_rectangle(dc as u32,rect,Some(shared::decode(&bytes,dc as u32).unwrap())).unwrap();1
    }),Some(1));
    for y in 0..5{for x in 0..5{assert_eq!(g.pixels(dc).unwrap()[y*5+x],if x<4&&y<4{0x445566}else{0});}}
    let before=g.pixels(dc).unwrap().to_vec();
    bytes[abi::dc::ROP_MODE..abi::dc::ROP_MODE+2].copy_from_slice(&0u16.to_le_bytes());
    assert!(shared::decode(&bytes,dc).is_err());assert_eq!(g.pixels(dc).unwrap(),before);
    assert!(g.pen_rectangle(u32::MAX,Rect{left:0,top:0,right:4,bottom:4},None).is_err());
}
