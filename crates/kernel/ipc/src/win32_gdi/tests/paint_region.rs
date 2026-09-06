use super::*;

fn rect(left: i32, top: i32, right: i32, bottom: i32) -> Rect { Rect { left, top, right, bottom } }
fn region(rects: &[Rect]) -> PaintRegion {
    let values: alloc::vec::Vec<_> = rects.iter().map(|r| WindowRect { left: r.left, top: r.top, right: r.right, bottom: r.bottom }).collect();
    PaintRegion::from_rects(&values).unwrap()
}
fn islands() -> PaintRegion { region(&[rect(0, 0, 2, 3), rect(4, 0, 6, 3)]) }

#[test]
fn five_raster_consumers_preserve_holes_and_intersect_application_bounds() {
    for consumer in 0..5 {
        let mut g = GdiManager::new(); let dc = g.create_dc(6, 3).unwrap();
        g.fill_rect(dc, rect(0, 0, 6, 3), 0x123456).unwrap();
        g.set_paint_region(dc, islands()).unwrap();
        g.intersect_clip_rect(dc, rect(1, 1, 5, 3)).unwrap();
        match consumer {
            0 => g.fill_rect(dc, rect(0, 0, 6, 3), 0xffffff).unwrap(),
            1 => { let brush = g.create_solid_brush(0xffffff).unwrap(); g.select_brush(dc, brush).unwrap();
                g.pat_blt(dc, 0, 0, 6, 3, 0x00f00021).unwrap(); }
            2 => g.blit_pixels(dc, 0, 0, 6, 3, 6, &[0xffffff; 18]).unwrap(),
            3 => g.blend_pixels(dc, 0, 0, 6, 3, &[0xffffffff; 18]).unwrap(),
            _ => { let src = g.create_dc(6, 3).unwrap(); g.fill_rect(src, rect(0, 0, 6, 3), 0xffffff).unwrap();
                g.set_paint_region(src, PaintRegion::default()).unwrap();
                g.bitblt(dc, 0, 0, src, 0, 0, 6, 3).unwrap(); }
        }
        for y in 0..3 { for x in 0..6 {
            assert_eq!(g.pixels(dc).unwrap()[y * 6 + x], if y >= 1 && (x == 1 || x == 4) { 0xffffff } else { 0x123456 }, "consumer {consumer} ({x},{y})");
        } }
    }
}

#[test]
fn exact_complexity_collapses_only_when_effective_coverage_is_rectangular() {
    let mut g = GdiManager::new(); let dc = g.create_dc(6, 3).unwrap();
    g.set_paint_region(dc, islands()).unwrap();
    assert_eq!(g.get_app_clip_box(dc), Ok((COMPLEX_REGION, rect(0, 0, 6, 3))));
    g.intersect_clip_rect(dc, rect(0, 0, 2, 3)).unwrap();
    assert_eq!(g.get_app_clip_box(dc), Ok((SIMPLE_REGION, rect(0, 0, 2, 3))));
    g.set_paint_region(dc, region(&[rect(4, 0, 6, 3)])).unwrap();
    assert_eq!(g.get_app_clip_box(dc), Ok((NULL_REGION, EMPTY)));
    let other = g.create_dc(6, 3).unwrap();
    g.set_paint_region(other, region(&[rect(0, 0, 3, 3), rect(3, 0, 6, 3)])).unwrap();
    assert_eq!(g.get_app_clip_box(other), Ok((SIMPLE_REGION, rect(0, 0, 6, 3))));
}

#[test]
fn empty_region_blocks_every_pixel_and_resize_keeps_exact_islands() {
    let mut g = GdiManager::new(); let dc = g.create_dc(3, 3).unwrap();
    g.set_paint_region(dc, islands()).unwrap();
    g.resize_dc(dc, 6, 3).unwrap();
    assert_eq!(g.get_app_clip_box(dc), Ok((COMPLEX_REGION, rect(0, 0, 6, 3))));
    g.set_paint_region(dc, PaintRegion::default()).unwrap();
    g.fill_rect(dc, rect(0, 0, 6, 3), 0xffffff).unwrap();
    assert!(g.pixels(dc).unwrap().iter().all(|pixel| *pixel == 0));
    assert_eq!(g.get_app_clip_box(dc), Ok((NULL_REGION, EMPTY)));
    assert_eq!(g.set_paint_region(0, islands()), Err(GdiError::NoSuchObject));
}
