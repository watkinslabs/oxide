use super::*;
use crate::win32_gdi::{DcLeaseRequest,LeaseOwner,DCX_CACHE};
use crate::win32_window::{PaintRegion,WindowRect};
fn lease(g:&mut GdiManager,backing:u32)->u32{
    g.acquire_dc_lease(DcLeaseRequest{hwnd:9,backing_hwnd:7,backing,origin:(1,1),screen_origin:(0,0),
        width:2,height:2,visible:PaintRegion::from_rect(WindowRect{left:0,top:0,right:2,bottom:2}).unwrap(),
        flags:DCX_CACHE,owner:LeaseOwner::Cached,clip_handle:0}).unwrap()
}
#[test]
fn lease_pixels_mark_parent_backing_once_per_operation_and_release_does_not_clear(){
    let mut g=GdiManager::new();let dc=g.acquire_window_dc(7,4,4).unwrap();let alias=lease(&mut g,dc);
    assert!(g.pending_outputs().unwrap().is_empty());
    g.fill_rect(alias,Rect{left:0,top:0,right:2,bottom:2},0x123456).unwrap();
    let token=g.pending_output(7,dc).unwrap();assert_eq!(token.generation,1);
    assert_eq!(token.damage,Rect{left:1,top:1,right:3,bottom:3});
    assert!(g.pending_output(9,alias).is_none());
    g.release_dc_lease(alias).unwrap();assert_eq!(g.pending_outputs().unwrap(),[token]);
    assert!(g.acknowledge_output(token));assert!(g.pending_outputs().unwrap().is_empty());
}
#[test]
fn queries_clipped_and_unchanged_writes_do_not_create_output(){
    let mut g=GdiManager::new();let dc=g.acquire_window_dc(7,4,4).unwrap();let alias=lease(&mut g,dc);
    assert!(g.text_metrics(alias).is_ok());
    g.fill_rect(alias,Rect{left:0,top:0,right:2,bottom:2},0).unwrap();
    g.fill_rect(alias,Rect{left:4,top:4,right:8,bottom:8},0xabcdef).unwrap();
    g.blend_pixels(alias,0,0,1,1,&[0x00ffffff]).unwrap();
    g.release_dc_lease(alias).unwrap();assert!(g.pending_outputs().unwrap().is_empty());
}
#[test]
fn stale_ack_and_failed_submission_preserve_newer_output(){
    let mut g=GdiManager::new();let dc=g.acquire_window_dc(7,4,4).unwrap();
    g.write_dc_pixel(dc,0,0,1).unwrap();let old=g.pending_output(7,dc).unwrap();
    assert_eq!(g.pending_output(7,dc),Some(old)); // failed transport makes no ACK
    g.write_dc_pixel(dc,3,3,2).unwrap();assert!(!g.acknowledge_output(old));
    let new=g.pending_output(7,dc).unwrap();assert_eq!(new.generation,old.generation+1);
    assert_eq!(new.damage,Rect{left:0,top:0,right:4,bottom:4});
    assert!(g.acknowledge_output(new));assert!(!g.acknowledge_output(new));
}
#[test]
fn resize_and_destroy_invalidate_captured_generation(){
    let mut g=GdiManager::new();let dc=g.acquire_window_dc(7,4,4).unwrap();
    g.write_dc_pixel(dc,0,0,1).unwrap();let old=g.pending_output(7,dc).unwrap();
    g.resize_dc(dc,2,2).unwrap();assert!(!g.acknowledge_output(old));
    let new=g.pending_output(7,dc).unwrap();assert_eq!(new.damage,Rect{left:0,top:0,right:2,bottom:2});
    g.destroy_window_dc(7).unwrap();assert!(!g.acknowledge_output(new));assert!(g.pending_outputs().unwrap().is_empty());
}
#[test]
fn empty_surface_and_saturated_generation_never_clear_new_output(){
    let mut output=PendingOutput{generation:u64::MAX,damage:None,in_flight:None};
    output.record(Some(Rect{left:0,top:0,right:1,bottom:1}));assert_eq!(output.generation,u64::MAX);
    let mut g=GdiManager::new();let dc=g.acquire_window_dc(7,1,1).unwrap();
    g.dcs.iter_mut().find(|(id,_)|*id==dc).unwrap().1.pending_output=output;
    assert!(!g.acknowledge_output(g.pending_output(7,dc).unwrap()));
    g.resize_dc(dc,0,0).unwrap();assert!(g.pending_output(7,dc).is_none());
}

#[test]
fn storage_surface_rejects_active_and_inactive_aliases_but_backing_is_explicit(){
    let mut g=GdiManager::new();let backing=g.acquire_window_dc(7,4,4).unwrap();let dc=lease(&mut g,backing);
    assert!(g.dc_storage_surface(dc).is_none());
    assert!(g.surface(dc).is_none());assert!(g.pixels(dc).is_none());
    assert_eq!(g.dc_backing_surface(dc).map(|(w,h,p)|(w,h,p.len())),Some((4,4,16)));
    g.release_dc_lease(dc).unwrap();
    assert!(g.dc_storage_surface(dc).is_none());assert!(g.dc_backing_surface(dc).is_none());
    assert!(g.surface(dc).is_none());assert!(g.pixels(dc).is_none());
    assert_eq!(g.dc_storage_surface(backing).map(|(w,h,p)|(w,h,p.len())),Some((4,4,16)));
}

#[test]
fn paint_retention_marks_only_changed_client_pixels_in_backing_coordinates(){
    let mut g=GdiManager::new();let backing=g.acquire_window_dc(7,4,4).unwrap();let paint=g.create_dc(2,2).unwrap();
    g.write_dc_pixel(paint,1,0,0x123456).unwrap();assert!(g.pending_outputs().unwrap().is_empty());
    let region=PaintRegion::from_rect(WindowRect{left:0,top:0,right:2,bottom:2}).unwrap();
    let layout=crate::win32_gdi::PaintBacking{width:4,height:4,client:Rect{left:1,top:1,right:3,bottom:3}};
    g.retain_paint_region(7,paint,&region,layout).unwrap();
    let token=g.pending_output(7,backing).unwrap();assert_eq!(token.damage,Rect{left:2,top:1,right:3,bottom:2});
    assert_eq!(token.generation,1);g.retain_paint_region(7,paint,&region,layout).unwrap();
    assert_eq!(g.pending_output(7,backing),Some(token));
}

#[test]
fn in_flight_reservation_serializes_backing_without_losing_newer_writes(){
    let mut g=GdiManager::new();let dc=g.acquire_window_dc(7,4,4).unwrap();
    g.write_dc_pixel(dc,0,0,1).unwrap();let first=g.pending_output(7,dc).unwrap();
    assert!(g.reserve_output(first));assert!(!g.reserve_output(first));
    g.write_dc_pixel(dc,1,1,2).unwrap();let second=g.pending_output(7,dc).unwrap();
    assert!(!g.reserve_output(second));assert!(!g.finish_output(second,true));
    assert!(!g.finish_output(first,true));assert_eq!(g.pending_output(7,dc),Some(second));
    assert!(g.reserve_output(second));assert!(!g.finish_output(second,false));
    assert_eq!(g.pending_output(7,dc),Some(second));assert!(g.reserve_output(second));
    assert!(g.finish_output(second,true));assert!(g.pending_outputs().unwrap().is_empty());
}

#[test]
fn exact_zero_window_backing_acquires_font_query_lease_without_output(){
    for(width,height)in[(0,0),(0,4),(4,0)]{
        let mut g=GdiManager::new();let backing=g.acquire_window_dc(7,width,height).unwrap();
        let dc=g.acquire_dc_lease(DcLeaseRequest{hwnd:7,backing_hwnd:7,backing,origin:(0,0),screen_origin:(0,0),
            width,height,visible:PaintRegion::default(),flags:DCX_CACHE,owner:LeaseOwner::Cached,clip_handle:0}).unwrap();
        assert!(g.text_metrics(dc).is_ok());assert_eq!((g.text_state(dc).unwrap().width,g.text_state(dc).unwrap().height),(width,height));
        assert!(g.dc_backing_surface(dc).unwrap().2.is_empty());
        g.fill_rect(dc,Rect{left:0,top:0,right:4,bottom:4},0x123456).unwrap();
        g.release_dc_lease(dc).unwrap();assert!(g.pending_outputs().unwrap().is_empty());
    }
}

#[test]
fn explicit_black_frame_requests_output_without_raster_changes(){
    let mut g=GdiManager::new();let dc=g.acquire_window_dc(7,4,4).unwrap();
    assert!(g.pending_outputs().unwrap().is_empty());let token=g.request_output(7,dc).unwrap();
    assert_eq!(token.damage,Rect{left:0,top:0,right:4,bottom:4});assert_eq!(token.generation,1);
    assert!(g.pixels(dc).unwrap().iter().all(|pixel|*pixel==0));assert!(g.reserve_output(token));
    let next=g.request_output(7,dc).unwrap();assert_eq!(next.generation,2);
    assert!(!g.reserve_output(next));assert!(!g.finish_output(token,true));
    assert_eq!(g.pending_output(7,dc),Some(next));assert!(g.reserve_output(next));
    assert!(g.finish_output(next,true));assert!(g.pending_outputs().unwrap().is_empty());
}

#[test]
fn invalid_explicit_requests_do_not_mutate_output(){
    let mut g=GdiManager::new();let dc=g.acquire_window_dc(7,4,4).unwrap();let alias=lease(&mut g,dc);
    assert_eq!(g.request_output(9,dc),Err(GdiError::NoSuchObject));
    assert_eq!(g.request_output(7,alias),Err(GdiError::NoSuchObject));
    let empty=g.acquire_window_dc(8,0,0).unwrap();
    assert_eq!(g.request_output(8,empty),Err(GdiError::InvalidDimensions));
    assert!(g.pending_outputs().unwrap().is_empty());
}
