use super::*;
fn request(backing: u32) -> DcLeaseRequest {
    DcLeaseRequest { hwnd: 7, backing_hwnd: 7, backing, origin: (2, 3), screen_origin: (0, 0), width: 4, height: 4,
        visible: PaintRegion::from_rect(WindowRect { left: 0, top: 0, right: 4, bottom: 4 }).unwrap(),
        flags: DCX_CACHE, owner: LeaseOwner::Cached, clip_handle: 0 }
}

#[test]
fn cached_leases_have_independent_attributes_and_share_only_actual_window_pixels() {
    let mut g = GdiManager::new(); let backing = g.acquire_window_dc(7, 9, 10).unwrap();
    let first = g.acquire_dc_lease(request(backing)).unwrap();
    let second = g.acquire_dc_lease(request(backing)).unwrap();
    assert_ne!(first, second); assert_ne!(first, backing);
    assert!(g.dcs.iter().find(|(id,_)| *id == first).unwrap().1.pixels.is_empty());
    g.write_dc_pixel(first, 1, 1, 0xabcdef).unwrap();
    assert_eq!(g.pixels(backing).unwrap()[4 * 9 + 3], 0xabcdef);
    g.set_text_attribute(first, super::super::TextAttribute::Foreground, 0x123456).unwrap();
    assert_eq!(g.text_state(second).unwrap().attributes.foreground, 0);
    g.release_dc_lease(first).unwrap();
    assert!(g.write_dc_pixel(first, 1, 1, 0).is_err());
    assert!(g.release_dc_lease(first).is_err());
    assert_eq!(g.acquire_dc_lease(request(backing)), Ok(first));
    assert_eq!(g.text_state(first).unwrap().attributes.foreground, 0);
    assert_eq!(g.pixels(backing).unwrap()[4 * 9 + 3], 0xabcdef);
}

#[test]
fn intersect_and_exclude_use_real_region_and_cached_release_consumes_handle() {
    for intersected in [false, true] {
        let mut g = GdiManager::new(); let backing = g.acquire_window_dc(7, 9, 10).unwrap();
        let region = g.create_rect_region(Rect { left: 1, top: 1, right: 2, bottom: 2 }).unwrap();
        let mut r = request(backing); r.clip_handle = region;
        r.flags |= if intersected { DCX_INTERSECTRGN } else { DCX_EXCLUDERGN };
        let dc = g.acquire_dc_lease(r).unwrap();
        for y in 0..4 { for x in 0..4 { g.write_dc_pixel(dc, x, y, 0xffffff).unwrap(); } }
        for y in 0..4 { for x in 0..4 {
            assert_eq!(g.pixels(backing).unwrap()[(y+3)*9+x+2], if ((x==1)&&(y==1)) == intersected {0xffffff} else {0});
        } }
        g.release_dc_lease(dc).unwrap(); assert!(!g.contains_object(region));
    }
}

#[test]
fn ignored_region_is_not_consumed_and_null_intersection_is_empty() {
    let mut g = GdiManager::new(); let backing = g.acquire_window_dc(7, 9, 10).unwrap();
    let mut r = request(backing); r.clip_handle = u32::MAX;
    let dc = g.acquire_dc_lease(r).unwrap(); g.release_dc_lease(dc).unwrap();
    let mut r = request(backing); r.flags |= DCX_INTERSECTRGN;
    let dc = g.acquire_dc_lease(r).unwrap(); g.write_dc_pixel(dc, 1, 1, 0xffffff).unwrap();
    assert!(g.pixels(backing).unwrap().iter().all(|p| *p == 0));
}

#[test]
fn style_flags_follow_cache_window_and_parent_precedence() {
    assert_eq!(dc_lease_flags(DCX_WINDOW|DCX_CLIPCHILDREN,0,0,0,false)&(DCX_CACHE|DCX_CLIPCHILDREN),DCX_CACHE);
    assert_eq!(dc_lease_flags(DCX_PARENTCLIP,0,0,0,true)&(DCX_PARENTCLIP|DCX_CLIPSIBLINGS),DCX_CLIPSIBLINGS);
    assert_eq!(dc_lease_flags(DCX_USESTYLE,WS_CLIPCHILDREN,CS_PARENTDC,0,false)&(DCX_PARENTCLIP|DCX_CLIPCHILDREN),DCX_CLIPCHILDREN);
}

#[test]
fn owned_dc_preserves_attributes_and_negative_parent_clip_coordinates_map_backing() {
    let mut g = GdiManager::new(); let backing = g.acquire_window_dc(7, 9, 10).unwrap();
    let mut r = request(backing); r.flags = 0; r.owner = LeaseOwner::Window(7);
    r.visible = PaintRegion::from_rect(WindowRect { left: -2, top: -3, right: 4, bottom: 4 }).unwrap();
    let dc = g.acquire_dc_lease(r).unwrap();
    g.write_dc_pixel(dc, -2, -3, 0x123456).unwrap();
    assert_eq!(g.pixels(backing).unwrap()[0], 0x123456);
    g.set_text_attribute(dc, super::super::TextAttribute::Foreground, 0xabcdef).unwrap();
    g.release_dc_lease(dc).unwrap();
    let mut r = request(backing); r.flags = 0; r.owner = LeaseOwner::Window(7);
    assert_eq!(g.acquire_dc_lease(r), Ok(dc));
    assert_eq!(g.text_state(dc).unwrap().attributes.foreground, 0xabcdef);
}

#[test]
fn screen_region_translates_once_but_original_identity_is_consumed_on_release() {
    for origin in [(100, 200), (-100, -200), (i32::MIN, i32::MIN)] {
        let mut g = GdiManager::new(); let backing = g.acquire_window_dc(7, 9, 10).unwrap();
        let region = g.create_rect_region(Rect { left: origin.0 + 1, top: origin.1 + 1,
            right: origin.0 + 2, bottom: origin.1 + 2 }).unwrap();
        let original = g.region_snapshot(region).unwrap();
        let mut r = request(backing); r.screen_origin = origin; r.flags |= DCX_INTERSECTRGN; r.clip_handle = region;
        let dc = g.acquire_dc_lease(r).unwrap();
        g.write_dc_pixel(dc, 1, 1, 0xabcdef).unwrap();
        g.write_dc_pixel(dc, 0, 0, 0xffffff).unwrap();
        assert_eq!(g.pixels(backing).unwrap()[4*9+3], 0xabcdef);
        assert_eq!(g.pixels(backing).unwrap()[3*9+2], 0);
        assert_eq!(g.region_snapshot(region).unwrap(), original);
        g.release_dc_lease(dc).unwrap();
        assert!(!g.contains_object(region));
    }
}

#[test]
fn parent_backing_identity_and_screen_overflow_reject_without_consumption() {
    let mut g = GdiManager::new(); let backing = g.acquire_window_dc(9, 9, 10).unwrap();
    let mut r = request(backing);
    assert_eq!(g.acquire_dc_lease(r), Err(GdiError::NoSuchObject));
    r = request(backing); r.backing_hwnd = 9;
    let dc = g.acquire_dc_lease(r).unwrap();
    g.write_dc_pixel(dc, 1, 1, 0xabcdef).unwrap();
    assert_eq!(g.pixels(backing).unwrap()[4*9+3], 0xabcdef);
    g.release_dc_lease(dc).unwrap();
    let region = g.create_rect_region(Rect { left: i32::MIN, top: 0, right: i32::MIN + 1, bottom: 1 }).unwrap();
    let before = g.live_handles();
    let mut r = request(backing); r.backing_hwnd = 9; r.screen_origin = (1, 0);
    r.clip_handle = region; r.flags |= DCX_INTERSECTRGN;
    assert_eq!(g.acquire_dc_lease(r), Err(GdiError::InvalidDimensions));
    assert_eq!(g.live_handles(), before);
    assert!(g.region_snapshot(region).is_ok());
}

#[test]
fn release_returns_reset_projection_before_disabling_cached_raster() {
    let mut g = GdiManager::new(); let backing = g.acquire_window_dc(7, 9, 10).unwrap();
    let dc = g.acquire_dc_lease(request(backing)).unwrap();
    g.set_text_attribute(dc, super::super::TextAttribute::Foreground, 0xabcdef).unwrap();
    let projection = g.release_dc_lease_state(dc).unwrap();
    assert_eq!(projection.attributes.foreground, 0);
    assert_eq!((projection.width, projection.height), (4, 4));
    assert!(g.dc_pixel_target(dc, 0, 0).is_err());
}

#[test]
fn all_raster_work_functions_use_lease_origin_and_exact_visible_holes() {
    for kind in 0..5 {
        let mut g = GdiManager::new(); let backing = g.acquire_window_dc(7, 9, 10).unwrap();
        let mut r = request(backing);
        r.visible = PaintRegion::from_rects(&[WindowRect {left:0,top:0,right:1,bottom:4},WindowRect {left:3,top:0,right:4,bottom:4}]).unwrap();
        let dc = g.acquire_dc_lease(r).unwrap();
        match kind {
            0 => g.fill_rect(dc,Rect {left:0,top:0,right:4,bottom:4},0xffffff).unwrap(),
            1 => g.blit_pixels(dc,0,0,4,4,4,&[0xffffff;16]).unwrap(),
            2 => g.blend_pixels(dc,0,0,4,4,&[0xffffffff;16]).unwrap(),
            3 => g.pat_blt(dc,0,0,4,4,0x00f00021).unwrap(),
            _ => {let src=g.create_dc(4,4).unwrap();g.raster_fill_rect(src,Rect{left:0,top:0,right:4,bottom:4},0xffffff).unwrap();
                g.bitblt(dc,0,0,src,0,0,4,4).unwrap();}
        }
        for y in 0..10 {for x in 0..9 {
            assert_eq!(g.dc_backing_surface(dc).unwrap().2[y*9+x],if (3..7).contains(&y)&&(x==2||x==5){0xffffff}else{0},"consumer {kind}");
        }}
    }
}

#[test]
fn inactive_cached_identity_cannot_query_mutate_or_draw_but_projection_reset_succeeds() {
    let mut g=GdiManager::new();let backing=g.acquire_window_dc(7,9,10).unwrap();
    let dc=g.acquire_dc_lease(request(backing)).unwrap();
    let projection=g.release_dc_lease_state(dc).unwrap();
    assert_eq!(projection.attributes,TextAttributes::default());
    assert!(g.contains_object(dc));
    assert!(g.text_state(dc).is_err());
    assert!(g.set_text_attribute(dc,super::super::TextAttribute::Foreground,1).is_err());
    assert!(g.set_text_position(dc,(1,2)).is_err());
    assert!(g.intersect_clip_rect(dc,Rect{left:0,top:0,right:1,bottom:1}).is_err());
    assert!(g.set_paint_region(dc,PaintRegion::default()).is_err());
    assert!(g.get_app_clip_box(dc).is_err());assert!(g.visibility_region(dc).is_err());
    assert!(g.fill_rect(dc,Rect{left:0,top:0,right:1,bottom:1},1).is_err());
    assert!(g.blend_pixels(dc,0,0,1,1,&[0xffffffff]).is_err());
    assert!(g.pat_blt(dc,0,0,1,1,0x00f00021).is_err());
    assert!(g.dc_backing_surface(dc).is_none());
    assert!(g.pixels(backing).unwrap().iter().all(|pixel|*pixel==0));
}

#[test]
fn visibility_and_clip_query_keep_lease_holes_and_logical_coordinates() {
    let mut g=GdiManager::new();let backing=g.acquire_window_dc(7,9,10).unwrap();
    let mut r=request(backing);r.visible=PaintRegion::from_rects(&[
        WindowRect{left:0,top:0,right:1,bottom:4},WindowRect{left:3,top:0,right:4,bottom:4}]).unwrap();
    let dc=g.acquire_dc_lease(r).unwrap();
    assert_eq!(g.get_app_clip_box(dc),Ok((super::super::COMPLEX_REGION,Rect{left:0,top:0,right:4,bottom:4})));
    assert!(!super::super::rect_visible_in_clip(g.visibility_region(dc).unwrap(),Rect{left:1,top:0,right:3,bottom:4}));
    assert!(super::super::rect_visible_in_clip(g.visibility_region(dc).unwrap(),Rect{left:3,top:0,right:4,bottom:4}));
}

#[test]
fn cached_release_resets_pen_and_collects_only_final_deleted_selection() {
    let mut g=GdiManager::new();let backing=g.acquire_window_dc(7,9,10).unwrap();
    let first=g.acquire_dc_lease(request(backing)).unwrap();let second=g.acquire_dc_lease(request(backing)).unwrap();
    let pen=g.create_pen(0,1,0xabcdef).unwrap();g.select_pen(first,pen).unwrap();g.select_pen(second,pen).unwrap();
    g.dcs.iter_mut().find(|(id,_)|*id==first).unwrap().1.dc_pen_color=0xabcdef;
    g.delete_pen(pen).unwrap();g.release_dc_lease(first).unwrap();
    let state=&g.dcs.iter().find(|(id,_)|*id==first).unwrap().1;
    assert_eq!((state.pen,state.dc_pen_color),(super::super::DEFAULT_DC_PEN_HANDLE,0));
    assert!(g.pen_description(pen,0).is_ok());
    g.release_dc_lease(second).unwrap();assert!(g.pen_description(pen,0).is_err());
}

#[test]
fn noreset_cached_release_preserves_pen_selection_and_color() {
    let mut g=GdiManager::new();let backing=g.acquire_window_dc(7,9,10).unwrap();
    let mut r=request(backing);r.flags|=DCX_NORESETATTRS;
    let dc=g.acquire_dc_lease(r).unwrap();let pen=g.create_pen(0,1,0xabcdef).unwrap();
    g.select_pen(dc,pen).unwrap();g.dcs.iter_mut().find(|(id,_)|*id==dc).unwrap().1.dc_pen_color=0x123456;
    g.delete_pen(pen).unwrap();g.release_dc_lease(dc).unwrap();
    let state=&g.dcs.iter().find(|(id,_)|*id==dc).unwrap().1;
    assert_eq!((state.pen,state.dc_pen_color),(pen,0x123456));assert!(g.pen_description(pen,0).is_ok());
}

#[test]
fn two_alias_bitblt_snapshots_source_before_overlap_and_ignores_source_clip() {
    let mut g=GdiManager::new();let backing=g.acquire_window_dc(7,9,10).unwrap();
    let source=g.acquire_dc_lease(request(backing)).unwrap();let dst=g.acquire_dc_lease(request(backing)).unwrap();
    g.raster_blit_pixels(source,0,0,4,1,4,&[1,2,3,4]).unwrap();
    g.set_paint_region(source,PaintRegion::default()).unwrap();
    g.raster_bitblt(dst,1,0,source,0,0,3,1).unwrap();
    assert_eq!(&g.dc_backing_surface(dst).unwrap().2[3*9+2..3*9+6],&[1,1,2,3]);
}
