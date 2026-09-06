use super::*;
fn rect(left:i32,top:i32,right:i32,bottom:i32)->Rect { Rect { left,top,right,bottom } }
fn region(left:i32,top:i32,right:i32,bottom:i32)->PaintRegion {
    PaintRegion::from_rect(WindowRect {left,top,right,bottom}).unwrap()
}

#[test]
fn region_handles_share_typed_allocator_projection_and_generic_deletion() {
    let mut g = GdiManager::new(); let dc = g.create_dc(2,2).unwrap();
    let handle = g.create_rect_region(rect(5,6,-1,-2)).unwrap();
    assert_eq!(handle & !0xffff,TYPE_REGION); assert!((handle & 0xffff)>=64);
    assert_ne!(handle & 0xffff,dc & 0xffff); assert_ne!(handle,1);
    assert!(g.contains_object(handle)); assert!(g.live_handles().contains(&handle));
    assert_eq!(g.region_box(handle),Ok((SIMPLE_REGION,rect(-1,-2,5,6))));
    let copy = g.region_snapshot(handle).unwrap();
    g.delete_object(handle).unwrap();
    assert!(!g.contains_object(handle)); assert!(!g.live_handles().contains(&handle));
    assert_eq!(g.region_snapshot(handle),Err(GdiError::NoSuchObject));
    assert_eq!(copy.bounds(),Some(WindowRect {left:-1,top:-2,right:5,bottom:6}));
    let next = g.create_region(copy).unwrap(); assert_ne!(next,handle);
    for bad in [1,0,dc,handle,(next&0xffff)|super::super::TYPE_FONT] {
        assert_eq!(g.region_snapshot(bad),Err(GdiError::NoSuchObject));
        assert_eq!(g.delete_region(bad),Err(GdiError::NoSuchObject));
    }
}

#[test]
fn empty_holes_adjacent_coverage_and_extreme_coordinates_have_real_complexity() {
    let mut g=GdiManager::new(); let h=g.create_rect_region(rect(3,4,3,9)).unwrap();
    assert_eq!(g.region_box(h),Ok((NULL_REGION,rect(0,0,0,0))));
    let mut ring=region(0,0,10,10); ring.subtract(&region(2,2,8,8)).unwrap();
    g.replace_region(h,ring).unwrap(); assert_eq!(g.region_box(h),Ok((COMPLEX_REGION,rect(0,0,10,10))));
    assert!(g.region_snapshot(h).unwrap().clipped(WindowRect {left:2,top:2,right:8,bottom:8}).unwrap().is_empty());
    let mut joined=region(0,0,5,10); joined.union(&region(5,0,10,10)).unwrap();
    g.replace_region(h,joined).unwrap(); assert_eq!(g.region_box(h),Ok((SIMPLE_REGION,rect(0,0,10,10))));
    let huge=g.create_rect_region(rect(i32::MAX,i32::MAX,i32::MIN,i32::MIN)).unwrap();
    assert_eq!(g.region_box(huge),Ok((SIMPLE_REGION,rect(i32::MIN,i32::MIN,i32::MAX,i32::MAX))));
}

#[test]
fn region_snapshot_and_dc_paint_coverage_survive_owner_replacement_and_deletion() {
    let mut g=GdiManager::new(); let dc=g.create_dc(6,2).unwrap();
    let mut islands=region(0,0,2,2); islands.union(&region(4,0,6,2)).unwrap();
    let h=g.create_region(islands).unwrap(); g.set_paint_region(dc,g.region_snapshot(h).unwrap()).unwrap();
    g.replace_region(h,PaintRegion::default()).unwrap(); g.delete_object(h).unwrap();
    g.fill_rect(dc,rect(0,0,6,2),0xffffff).unwrap();
    assert_eq!(g.pixels(dc).unwrap(),&[0xffffff,0xffffff,0,0,0xffffff,0xffffff,0xffffff,0xffffff,0,0,0xffffff,0xffffff]);
}

#[test]
fn failed_handle_allocation_does_not_publish_region_or_change_existing_objects() {
    let mut g=GdiManager::new(); let h=g.create_rect_region(rect(0,0,1,1)).unwrap();
    let handles=g.live_handles(); g.next=super::super::SLOT_LIMIT;
    assert_eq!(g.create_region(PaintRegion::default()),Err(GdiError::HandleLimit));
    assert_eq!(g.live_handles(),handles); assert_eq!(g.region_box(h),Ok((SIMPLE_REGION,rect(0,0,1,1))));
}

#[test]
fn boolean_regions_preserve_exact_geometry_aliases_and_invalid_call_rollback() {
    for mode in [RGN_AND,RGN_OR,RGN_XOR,RGN_DIFF,RGN_COPY] {
        let mut g=GdiManager::new();
        let a=g.create_rect_region(rect(0,0,4,4)).unwrap(); let b=g.create_rect_region(rect(2,2,6,6)).unwrap();
        let handles=g.live_handles();
        assert!(g.combine_region(a,a,b,mode).is_ok());
        let result=g.region_snapshot(a).unwrap();
        for y in 0..6 { for x in 0..6 {
            let left=x<4 && y<4; let right=x>=2 && y>=2;
            let expected=match mode {RGN_AND=>left&&right,RGN_OR=>left||right,RGN_XOR=>left!=right,RGN_DIFF=>left&&!right,_=>left};
            let present=!result.clipped(WindowRect {left:x,top:y,right:x+1,bottom:y+1}).unwrap().is_empty();
            assert_eq!(present,expected,"mode {mode} pixel {x},{y}");
        } }
        assert_eq!(g.live_handles(),handles);
        assert_eq!(g.combine_region(a,a,1,RGN_COPY),Ok(g.region_box(a).unwrap().0));
        let before=g.region_snapshot(a).unwrap();
        for (dst,src1,src2,mode) in [(a,a,b,0),(a,a,1,RGN_AND),(a,1,b,RGN_COPY),(1,a,b,RGN_OR)] {
            assert!(g.combine_region(dst,src1,src2,mode).is_err()); assert_eq!(g.region_snapshot(a).unwrap(),before);
        }
        assert_eq!(g.combine_region(a,a,a,RGN_XOR),Ok(NULL_REGION));
    }
}
