use super::*;

const PATCOPY: u32 = 0x00f0_0021;
const DSTINVERT: u32 = 0x0055_0009;
const SRCCOPY: u32 = 0x00cc_0020;

#[test]
fn shared_brush_color_is_consumed_each_draw_without_mirroring_private_state() {
    let mut gdi = GdiManager::new();
    let dc = gdi.create_dc(1, 1).unwrap();
    let stock = gdi.stock_object(18).unwrap().handle;
    gdi.select_brush(dc, stock).unwrap();
    for color in [0x123456, 0xabcdef] {
        gdi.pat_blt_shared_color(dc, 0, 0, 1, 1, PATCOPY, color).unwrap();
        assert_eq!(gdi.pixels(dc).unwrap(), &[color]);
    }
    assert_eq!(gdi.set_dc_brush_color(dc, 0), Ok(0xffffff));
    let solid = gdi.create_solid_brush(0x112233).unwrap();
    gdi.select_brush(dc, solid).unwrap();
    gdi.pat_blt_shared_color(dc, 0, 0, 1, 1, PATCOPY, 0xff0000).unwrap();
    assert_eq!(gdi.pixels(dc).unwrap(), &[0x112233]);
}

#[test]
fn every_source_dependent_table_rejects_without_mutation_even_when_empty() {
    let mut gdi = GdiManager::new();
    let dc = gdi.create_dc(1, 1).unwrap();
    gdi.fill_rect(dc, super::super::Rect { left: 0, top: 0, right: 1, bottom: 1 }, 0x123456).unwrap();
    let mut rejected = 0;
    for table in 0u32..=255 {
        if ((table >> 2) & 0x33) == (table & 0x33) { continue; }
        for size in [0, 1] {
            assert!(gdi.pat_blt(dc, 0, 0, size, size, table << 16).is_err(), "ROP {table:02x}");
            assert_eq!(gdi.pixels(dc).unwrap(), &[0x123456]);
        }
        rejected += 1;
    }
    assert_eq!(rejected, 240);
}

#[test]
fn final_deselection_collects_deleted_brush_and_resize_retains_selection() {
    let mut gdi = GdiManager::new();
    let dc = gdi.acquire_window_dc(7, 1, 1).unwrap();
    let brush = gdi.create_solid_brush(0x112233).unwrap();
    let old = gdi.select_brush(dc, brush).unwrap();
    assert_eq!(gdi.acquire_window_dc(7, 3, 2), Ok(dc));
    gdi.delete_object(brush).unwrap();
    gdi.pat_blt(dc, 0, 0, 3, 2, PATCOPY).unwrap();
    assert_eq!(gdi.pixels(dc).unwrap(), &[0x112233; 6]);
    assert_eq!(gdi.select_brush(dc, old), Ok(brush));
    assert_eq!(gdi.delete_object(brush), Err(GdiError::NoSuchObject));
    assert_eq!(gdi.select_brush(dc, brush), Err(GdiError::NoSuchObject));
}

#[test]
fn selected_brush_lifetime_and_default_restore_share_owner() {
    let mut gdi = GdiManager::new();
    let a = gdi.create_dc(2, 2).unwrap();
    let b = gdi.create_dc(2, 2).unwrap();
    let brush = gdi.create_solid_brush(0x123456).unwrap();
    let white = gdi.stock_object(0).unwrap().handle;
    assert_eq!(brush & !super::super::SLOT_MASK, TYPE_BRUSH);
    assert_eq!(gdi.select_brush(a, brush), Ok(white));
    assert_eq!(gdi.select_brush(b, brush), Ok(white));
    gdi.delete_object(brush).unwrap();
    gdi.pat_blt(a, 0, 0, 2, 2, PATCOPY).unwrap();
    assert_eq!(gdi.pixels(a).unwrap(), &[0x123456; 4]);
    assert_eq!(gdi.select_brush(a, white), Ok(brush));
    assert!(gdi.brush_style(brush, 0).is_ok());
    gdi.delete_object(b).unwrap();
    assert_eq!(gdi.brush_style(brush, 0), Err(GdiError::NoSuchObject));
    assert_eq!(gdi.select_brush(a, brush), Err(GdiError::NoSuchObject));
    gdi.pat_blt(a, 0, 0, 2, 2, PATCOPY).unwrap();
    assert_eq!(gdi.pixels(a).unwrap(), &[0xffffff; 4]);
    assert_ne!(gdi.create_solid_brush(0).unwrap(), brush);
}

#[test]
fn all_source_independent_truth_tables_drive_production_pixels() {
    let mut gdi = GdiManager::new();
    let dc = gdi.create_dc(1, 1).unwrap();
    for table in 0u32..=255 {
        if ((table >> 2) & 0x33) != (table & 0x33) { continue; }
        for pattern in [0, 0xffffff, 0x123456] { for dest in [0, 0xffffff, 0xabcdef] {
            let brush = gdi.create_solid_brush(pattern).unwrap();
            let old = gdi.select_brush(dc, brush).unwrap();
            gdi.fill_rect(dc, super::super::Rect { left: 0, top: 0, right: 1, bottom: 1 }, dest).unwrap();
            gdi.pat_blt(dc, 0, 0, 1, 1, table << 16).unwrap();
            let mut expected = 0;
            for bit in 0..24 {
                let index = (((pattern >> bit) & 1) << 2) | ((dest >> bit) & 1);
                expected |= ((table >> index) & 1) << bit;
            }
            assert_eq!(gdi.pixels(dc).unwrap()[0], expected, "ROP {table:02x}");
            gdi.select_brush(dc, old).unwrap(); gdi.delete_object(brush).unwrap();
        } }
    }
}

#[test]
fn signed_clipping_includes_origin_and_excludes_reverse_endpoint() {
    let mut gdi = GdiManager::new();
    let dc = gdi.create_dc(4, 3).unwrap();
    gdi.pat_blt(dc, 2, 1, -2, -2, PATCOPY).unwrap();
    assert_eq!(gdi.pixels(dc).unwrap(), &[0, 0xffffff, 0xffffff, 0, 0, 0xffffff, 0xffffff, 0, 0, 0, 0, 0]);
    let before = gdi.pixels(dc).unwrap().to_vec();
    assert!(gdi.pat_blt(dc, 0, 0, 3, 3, SRCCOPY).is_err());
    assert_eq!(gdi.pixels(dc).unwrap(), before);
    assert_eq!(gdi.pat_blt(0, 0, 0, 0, 0, PATCOPY), Err(GdiError::NoSuchObject));
    gdi.pat_blt(dc, i32::MAX, i32::MIN, i32::MAX, i32::MIN, PATCOPY).unwrap();
    assert_eq!(gdi.pixels(dc).unwrap(), before);
}

#[test]
fn hollow_brush_skips_pattern_but_not_destination_operations() {
    let mut gdi = GdiManager::new();
    let dc = gdi.create_dc(1, 1).unwrap();
    let hollow = gdi.stock_object(5).unwrap().handle;
    gdi.select_brush(dc, hollow).unwrap();
    gdi.pat_blt(dc, 0, 0, 1, 1, PATCOPY).unwrap();
    assert_eq!(gdi.pixels(dc).unwrap(), &[0]);
    gdi.pat_blt(dc, 0, 0, 1, 1, DSTINVERT).unwrap();
    assert_eq!(gdi.pixels(dc).unwrap(), &[0xffffff]);
    gdi.delete_object(hollow).unwrap();
    assert!(gdi.brush_style(hollow, 0).is_ok());
}

#[test]
fn stock_dc_brush_color_is_per_dc_and_forged_types_fail() {
    let mut gdi = GdiManager::new();
    let a = gdi.create_dc(1, 1).unwrap(); let b = gdi.create_dc(1, 1).unwrap();
    let brush = gdi.stock_object(18).unwrap().handle;
    gdi.select_brush(a, brush).unwrap(); gdi.select_brush(b, brush).unwrap();
    assert_eq!(gdi.set_dc_brush_color(a, 0x123456), Ok(0xffffff));
    gdi.pat_blt(a, 0, 0, 1, 1, PATCOPY).unwrap(); gdi.pat_blt(b, 0, 0, 1, 1, PATCOPY).unwrap();
    assert_eq!(gdi.pixels(a).unwrap(), &[0x123456]); assert_eq!(gdi.pixels(b).unwrap(), &[0xffffff]);
    let font = gdi.stock_object(13).unwrap().handle;
    assert_eq!(gdi.select_brush(a, font), Err(GdiError::NoSuchObject));
    assert_eq!(gdi.select_brush(a, brush ^ super::super::TYPE_FONT), Err(GdiError::NoSuchObject));
    assert_eq!(gdi.select_brush(a, a), Err(GdiError::NoSuchObject));
}
