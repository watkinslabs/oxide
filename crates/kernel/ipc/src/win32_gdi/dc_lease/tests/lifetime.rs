use super::*;
fn lease(g:&mut GdiManager,hwnd:u32,backing:u32,owned:bool)->(u32,u32){
    let region=g.create_rect_region(Rect{left:0,top:0,right:2,bottom:2}).unwrap();
    let dc=g.acquire_dc_lease(DcLeaseRequest{hwnd,backing_hwnd:7,backing,origin:(1,1),screen_origin:(0,0),width:2,height:2,
        visible:PaintRegion::from_rect(WindowRect{left:0,top:0,right:2,bottom:2}).unwrap(),
        flags:DCX_INTERSECTRGN|if owned{0}else{DCX_CACHE},owner:if owned{LeaseOwner::Window(hwnd)}else{LeaseOwner::Cached},clip_handle:region}).unwrap();
    (dc,region)
}
#[test]
fn lease_resize_rejects_even_same_size_without_touching_backing_or_attributes(){
    let mut g=GdiManager::new();let backing=g.acquire_window_dc(7,4,4).unwrap();let(dc,_)=lease(&mut g,7,backing,false);
    let before=g.text_state(dc).unwrap();
    for(w,h)in[(2,2),(3,3),(1,1)]{assert_eq!(g.resize_dc(dc,w,h),Err(GdiError::InvalidDimensions));}
    assert_eq!(g.text_state(dc).unwrap(),before);assert_eq!(g.surface(backing).map(|(w,h,_)|(w,h)),Some((4,4)));
}
#[test]
fn cached_deletion_releases_region_and_pen_without_deleting_backing(){
    let mut g=GdiManager::new();let backing=g.acquire_window_dc(7,4,4).unwrap();let(dc,region)=lease(&mut g,7,backing,false);
    let pen=g.create_pen(0,1,0).unwrap();g.select_pen(dc,pen).unwrap();g.delete_pen(pen).unwrap();
    g.write_dc_pixel(dc,0,0,0x123456).unwrap();g.delete_dc_object(dc).unwrap();
    assert!(!g.contains_object(dc));assert!(!g.contains_object(region));assert!(!g.contains_object(pen));
    assert_eq!(g.pixels(backing).unwrap()[5],0x123456);
}
#[test]
fn owned_deletion_succeeds_without_removal_but_backing_revokes_aliases(){
    let mut g=GdiManager::new();let backing=g.acquire_window_dc(7,4,4).unwrap();
    let(owned,region)=lease(&mut g,8,backing,true);let(cached,_)=lease(&mut g,9,backing,false);
    let before=g.text_state(owned).unwrap();
    assert_eq!(g.delete_object(owned),Ok(()));
    assert!(g.contains_object(owned));assert!(g.contains_object(region));
    assert_eq!(g.text_state(owned).unwrap(),before);
    g.write_dc_pixel(owned,0,0,0x654321).unwrap();assert_eq!(g.pixels(backing).unwrap()[5],0x654321);
    g.release_dc_lease(cached).unwrap();g.delete_object(backing).unwrap();
    for handle in[owned,cached,region,backing]{assert!(!g.contains_object(handle));}
    assert_eq!(g.window_dc(7),None);assert!(g.raster_dc(owned).is_err());
}
#[test]
fn child_revocation_preserves_parent_backing_and_other_child_lease(){
    let mut g=GdiManager::new();let backing=g.acquire_window_dc(7,4,4).unwrap();
    let(first,r1)=lease(&mut g,8,backing,true);let(second,r2)=lease(&mut g,9,backing,false);
    g.revoke_window_leases(8);
    assert!(!g.contains_object(first));assert!(!g.contains_object(r1));assert!(g.contains_object(second));assert!(g.contains_object(r2));
    assert_eq!(g.window_dc(7),Some(backing));g.write_dc_pixel(second,0,0,0x123456).unwrap();
    assert_eq!(g.pixels(backing).unwrap()[5],0x123456);
}
