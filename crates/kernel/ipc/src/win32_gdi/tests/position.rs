use super::*;
fn r(x:i32,y:i32,w:i32,h:i32)->WindowRect{WindowRect{left:x,top:y,right:x+w,bottom:y+h}}
#[test]fn resize_copies_parent_coordinate_valid_pair_and_preserves_dc_attributes(){
    let mut g=GdiManager::new();let dc=g.acquire_window_dc(7,4,3).unwrap();
    for y in 0..3{for x in 0..4{g.fill_rect(dc,Rect{left:x,top:y,right:x+1,bottom:y+1},(y*4+x+1)as u32).unwrap();}}
    g.set_text_attribute(dc,TextAttribute::Foreground,0x123456).unwrap();let old=g.text_state(dc).unwrap();
    g.preserve_window_position(7,r(10,20,4,3),r(30,40,5,4),Some([r(32,41,2,2),r(11,20,2,2)]),0).unwrap();
    assert_eq!(g.window_dc(7),Some(dc));assert_eq!(g.text_state(dc).unwrap().attributes,old.attributes);
    assert_eq!(g.pixels(dc).unwrap(),&[0,0,0,0,0,0,0,2,3,0,0,0,6,7,0,0,0,0,0,0]);
    assert_eq!(g.pending_output(7,dc).unwrap().damage,Rect{left:0,top:0,right:5,bottom:4});
}
#[test]fn same_extent_overlapping_copy_uses_original_pixels_and_invalid_request_is_atomic(){
    let mut g=GdiManager::new();let dc=g.acquire_window_dc(7,4,1).unwrap();
    for x in 0..4{g.fill_rect(dc,Rect{left:x,top:0,right:x+1,bottom:1},(x+1)as u32).unwrap();}
    g.preserve_window_position(7,r(0,0,4,1),r(0,0,4,1),Some([r(1,0,3,1),r(0,0,3,1)]),0).unwrap();
    assert_eq!(g.pixels(dc).unwrap(),&[0,1,2,3]);let before=g.pending_output(7,dc);
    assert!(g.preserve_window_position(7,r(0,0,4,1),r(0,0,5,1),Some([r(0,0,3,1),r(3,0,3,1)]),0).is_err());
    assert_eq!(g.pixels(dc).unwrap(),&[0,1,2,3]);assert_eq!(g.pending_output(7,dc),before);
}
#[test]fn no_backing_does_not_create_identity_and_zero_geometry_remains_empty(){
    let mut g=GdiManager::new();g.preserve_window_position(7,r(0,0,1,1),r(0,0,3,3),None,0).unwrap();assert_eq!(g.window_dc(7),None);
    let dc=g.acquire_window_dc(7,2,2).unwrap();g.preserve_window_position(7,r(0,0,2,2),r(0,0,0,2),None,0).unwrap();
    assert_eq!(g.surface(dc).map(|(w,h,p)|(w,h,p.len())),Some((0,2,0)));
}
