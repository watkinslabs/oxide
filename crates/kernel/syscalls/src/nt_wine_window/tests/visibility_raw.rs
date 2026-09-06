use super::*;
use ipc::win32_gdi::{GdiManager, rect_visible_in_clip};
use ipc::win32_window::WindowRect;
fn rect(left: i32, top: i32, right: i32, bottom: i32) -> Rect { Rect { left, top, right, bottom } }
fn region(rect: Rect) -> PaintRegion {
    PaintRegion::from_rect(WindowRect { left: rect.left, top: rect.top, right: rect.right, bottom: rect.bottom }).unwrap()
}
fn bytes(rect: Rect) -> [u8;16] {
    let mut out = [0;16];
    for (i,value) in [rect.left,rect.top,rect.right,rect.bottom].into_iter().enumerate() {
        out[i*4..i*4+4].copy_from_slice(&value.to_le_bytes());
    }
    out
}
fn query(gdi: &GdiManager, dc: u64, rect: Rect) -> Option<u64> {
    route(RECT_VISIBLE, &[dc,0x1000], |dc| gdi.visibility_region(u32::try_from(dc).ok()?).ok(),
        |_| Some(bytes(rect)), rect_visible_in_clip)
}

#[test]
fn status_part_query_uses_actual_application_paint_surface_intersection_without_mutation() {
    let mut gdi = GdiManager::new(); let dc = gdi.create_dc(8,8).unwrap();
    gdi.intersect_clip_rect(dc, rect(2,2,7,7)).unwrap();
    gdi.set_paint_clip(dc, rect(0,3,8,6)).unwrap();
    let state = gdi.text_state(dc).unwrap(); let clip = gdi.get_app_clip_box(dc).unwrap();
    let handles = gdi.live_handles(); let font = gdi.selected_object(dc, ipc::win32_gdi::TYPE_FONT);
    let pixels = gdi.pixels(dc).unwrap().to_vec();
    for (r,expected) in [(rect(0,0,8,8),1), (rect(6,5,3,4),1), (rect(0,0,2,8),0),
        (rect(2,2,7,3),0), (rect(3,4,3,5),0)] { assert_eq!(query(&gdi,dc as u64,r),Some(expected)); }
    assert_eq!(gdi.get_app_clip_box(dc).unwrap(),clip);
    assert_eq!(gdi.pixels(dc).unwrap(),pixels);
    assert_eq!(gdi.text_state(dc).unwrap().attributes,state.attributes);
    assert_eq!(gdi.live_handles(),handles);
    assert_eq!(gdi.selected_object(dc,ipc::win32_gdi::TYPE_FONT),font);
    assert_eq!(query(&gdi,(1u64<<32)|dc as u64,rect(0,0,8,8)),Some(0));
    gdi.delete_object(dc).unwrap();
    assert_eq!(query(&gdi,dc as u64,rect(0,0,8,8)),Some(0));
}

#[test]
fn resized_surface_reveals_retained_clip_without_allocating_a_dc() {
    let mut gdi = GdiManager::new(); let dc = gdi.create_dc(2,2).unwrap();
    gdi.intersect_clip_rect(dc,rect(3,3,8,8)).unwrap();
    assert_eq!(query(&gdi,dc as u64,rect(3,3,4,4)),Some(0));
    gdi.resize_dc(dc,6,6).unwrap();
    assert_eq!(query(&gdi,dc as u64,rect(3,3,4,4)),Some(1));
}

#[test]
fn raw_admission_copy_bounds_and_invalid_dc_failure_precede_geometry() {
    assert_eq!(route(0,&[], |_|panic!("unknown DC lookup"), |_|panic!("unknown copy"), |_,_|panic!("unknown geometry")),None);
    assert_eq!(route(RECT_VISIBLE,&[1], |_|panic!("short lookup"), |_|None, |_,_|true),Some(0));
    assert_eq!(route(RECT_VISIBLE,&[99,0x1234], |_|None, |_|panic!("invalid DC copied"), |_,_|true),Some(0));
    for pointer in [0,u64::MAX-15] {
        assert_eq!(route(RECT_VISIBLE,&[1,pointer], |_|Some(region(rect(0,0,4,4))), |_|panic!("invalid pointer copied"), |_,_|true),Some(0));
    }
    assert_eq!(route(RECT_VISIBLE,&[1,0x1234], |_|Some(region(rect(0,0,4,4))), |_|None, |_,_|panic!("failed copy evaluated")),Some(0));
    let pointer = 0x1234_0000_5678;
    assert_eq!(route(RECT_VISIBLE,&[1,pointer], |_|Some(region(rect(0,0,4,4))), |p| {
        assert_eq!(p,pointer); Some(bytes(rect(-1,-2,2,2)))
    }, rect_visible_in_clip),Some(1));
}

#[test]
fn exact_visibility_preserves_holes_and_matches_canonical_raster_coverage() {
    let mut gdi = GdiManager::new(); let dc = gdi.create_dc(8,8).unwrap();
    let mut paint = region(rect(0,0,8,8)); paint.subtract(&region(rect(2,2,6,6))).unwrap();
    gdi.set_paint_region(dc,paint).unwrap();
    gdi.intersect_clip_rect(dc,rect(1,1,7,7)).unwrap();
    assert_eq!(query(&gdi,dc as u64,rect(2,2,6,6)),Some(0));
    assert_eq!(query(&gdi,dc as u64,rect(6,6,2,2)),Some(0));
    assert_eq!(query(&gdi,dc as u64,rect(1,1,3,3)),Some(1));
    assert_eq!(query(&gdi,dc as u64,rect(0,0,1,8)),Some(0));
    gdi.fill_rect(dc,rect(0,0,8,8),0xffffff).unwrap();
    for y in 0..8 { for x in 0..8 {
        let expected = u64::from(gdi.pixels(dc).unwrap()[(y*8+x) as usize] != 0);
        assert_eq!(query(&gdi,dc as u64,rect(x,y,x+1,y+1)),Some(expected),"pixel {x},{y}");
    } }
    let snapshot = gdi.visibility_region(dc).unwrap();
    gdi.set_paint_region(dc,PaintRegion::default()).unwrap();
    gdi.delete_object(dc).unwrap();
    assert!(rect_visible_in_clip(snapshot.try_copy().unwrap(),rect(1,1,2,2)));
    assert!(!rect_visible_in_clip(snapshot,rect(2,2,6,6)));
}
