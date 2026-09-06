use super::*;
use ipc::win32_gdi::{GdiManager,NULL_REGION,SIMPLE_REGION};

#[test]
fn rectangular_replacement_preserves_identity_snapshot_and_returns_bool_not_complexity(){
    let mut g=GdiManager::new();let h=g.create_rect_region(Rect{left:0,top:0,right:10,bottom:10}).unwrap();
    let snapshot=g.region_snapshot(h).unwrap();let handles=g.live_handles();
    assert_eq!(route(SET_RECT_RGN,&[u64::from(h),9,8,2,1],|handle,rect|g.set_rect_region(handle as u32,rect).is_ok()),Some(1));
    assert_eq!(g.region_box(h),Ok((SIMPLE_REGION,Rect{left:2,top:1,right:9,bottom:8})));
    assert_eq!(g.live_handles(),handles);assert_eq!(snapshot.bounds().unwrap().right,10);
    assert_eq!(route(SET_RECT_RGN,&[u64::from(h),3,4,3,9],|handle,rect|g.set_rect_region(handle as u32,rect).is_ok()),Some(1));
    assert_eq!(g.region_box(h),Ok((NULL_REGION,Rect{left:0,top:0,right:0,bottom:0})));
}
#[test]
fn scalar_truncation_keeps_signed_extremes_but_never_truncates_handles(){
    let mut called=false;
    assert_eq!(route(SET_RECT_RGN,&[0x100040040,0x123ffffffff,0x12380000000,0x1237fffffff,0x12300000000],|h,r|{
        called=true;assert_eq!(h,0x100040040);assert_eq!(r,Rect{left:-1,top:i32::MIN,right:i32::MAX,bottom:0});false
    }),Some(0));assert!(called);
    let mut g=GdiManager::new();let h=g.create_rect_region(Rect{left:0,top:0,right:1,bottom:1}).unwrap();
    g.set_rect_region(h,Rect{left:i32::MAX,top:i32::MAX,right:i32::MIN,bottom:i32::MIN}).unwrap();
    assert_eq!(g.region_box(h).unwrap().1,Rect{left:i32::MIN,top:i32::MIN,right:i32::MAX,bottom:i32::MAX});
}
#[test]
fn malformed_unknown_and_wrong_object_calls_do_not_mutate_regions(){
    assert_eq!(route(0,&[],|_,_|panic!("unknown admitted")),None);
    for count in 0..5{assert_eq!(route(SET_RECT_RGN,&[0;5][..count],|_,_|panic!("short admitted")),Some(0));}
    let mut g=GdiManager::new();let rect=Rect{left:0,top:0,right:8,bottom:8};
    let h=g.create_rect_region(rect).unwrap();let dc=g.create_dc(1,1).unwrap();let pen=g.create_pen(0,1,0).unwrap();
    let handles=g.live_handles();
    for invalid in [0,1,dc,pen,h^0x800000]{assert!(g.set_rect_region(invalid,rect).is_err());}
    assert_eq!(g.region_box(h).unwrap().1,rect);assert_eq!(g.live_handles(),handles);
    g.delete_object(h).unwrap();assert!(g.set_rect_region(h,rect).is_err());
}
