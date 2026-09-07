//! Blits between device contexts, through the owner.
use super::*;

const PATCOPY: u32 = 0x00f0_0021;
const SRCINVERT: u32 = 0x0066_0046;

fn colors() -> SharedDcColors { SharedDcColors { brush: 0, text: 0, background: 0x00ff_ffff, background_mode: 2 } }

fn seeded(gdi: &mut GdiManager, width: i32, height: i32, pixels: &[u32]) -> u32 {
    let dc = gdi.create_dc(width, height).unwrap();
    gdi.blit_pixels(dc, 0, 0, width, height, width, pixels).unwrap();
    dc
}

#[test]
fn a_copy_moves_source_pixels_and_a_pattern_only_code_never_reads_the_source() {
    let mut gdi = GdiManager::new();
    let src = seeded(&mut gdi, 2, 2, &[1, 2, 3, 4]);
    let dst = gdi.create_dc(2, 2).unwrap();
    gdi.bit_blt(dst, 0, 0, 2, 2, src, 0, 0, SRCCOPY, colors()).unwrap();
    assert_eq!(gdi.pixels(dst).unwrap(), &[1, 2, 3, 4]);
    // A pattern-only code paints the selected brush and ignores the source.
    let brush = gdi.create_solid_brush(0x0000_00ff).unwrap();
    gdi.select_brush(dst, brush).unwrap();
    gdi.bit_blt(dst, 0, 0, 2, 2, src, 0, 0, PATCOPY, colors()).unwrap();
    assert_eq!(gdi.pixels(dst).unwrap(), &[0xff; 4]);
}

#[test]
fn a_three_operand_code_combines_pattern_source_and_destination() {
    let mut gdi = GdiManager::new();
    let src = seeded(&mut gdi, 1, 1, &[0x00ff_0000]);
    let dst = seeded(&mut gdi, 1, 1, &[0x0000_ff00]);
    gdi.bit_blt(dst, 0, 0, 1, 1, src, 0, 0, SRCINVERT, colors()).unwrap();
    assert_eq!(gdi.pixels(dst).unwrap(), &[0x00ff_ff00]);
}

#[test]
fn a_blit_onto_the_same_context_reads_its_pre_operation_pixels() {
    let mut gdi = GdiManager::new();
    let dc = seeded(&mut gdi, 4, 1, &[1, 2, 3, 4]);
    gdi.bit_blt(dc, 1, 0, 3, 1, dc, 0, 0, SRCCOPY, colors()).unwrap();
    assert_eq!(gdi.pixels(dc).unwrap(), &[1, 1, 2, 3]);
}

#[test]
fn a_stretched_copy_scales_the_source_across_the_destination() {
    let mut gdi = GdiManager::new();
    let src = seeded(&mut gdi, 2, 1, &[0x0000_00ff, 0x00ff_0000]);
    let dst = gdi.create_dc(4, 1).unwrap();
    gdi.stretch_blt(dst, BltCoords { x: 0, y: 0, width: 4, height: 1 }, src,
        BltCoords { x: 0, y: 0, width: 2, height: 1 }, SRCCOPY, colors(), COLORONCOLOR).unwrap();
    assert_eq!(gdi.pixels(dst).unwrap(), &[0xff, 0xff, 0x00ff_0000, 0x00ff_0000]);
    // Shrinking with the light-preserving mode unions the covered pixels.
    let small = gdi.create_dc(1, 1).unwrap();
    gdi.stretch_blt(small, BltCoords { x: 0, y: 0, width: 1, height: 1 }, src,
        BltCoords { x: 0, y: 0, width: 2, height: 1 }, SRCCOPY, colors(), WHITEONBLACK).unwrap();
    assert_eq!(gdi.pixels(small).unwrap(), &[0x00ff_00ff]);
}

#[test]
fn an_empty_extent_is_refused_and_writes_nothing() {
    let mut gdi = GdiManager::new();
    let src = seeded(&mut gdi, 2, 2, &[1, 2, 3, 4]);
    let dst = gdi.create_dc(2, 2).unwrap();
    assert_eq!(gdi.stretch_blt(dst, BltCoords { x: 0, y: 0, width: 0, height: 2 }, src,
        BltCoords { x: 0, y: 0, width: 2, height: 2 }, SRCCOPY, colors(), COLORONCOLOR), Err(GdiError::InvalidDimensions));
    assert_eq!(gdi.bit_blt(dst, 0, 0, 2, 2, 99, 0, 0, SRCCOPY, colors()), Err(GdiError::NoSuchObject));
    assert_eq!(gdi.pixels(dst).unwrap(), &[0; 4]);
}

#[test]
fn the_transparent_colour_leaves_the_destination_and_a_mirror_is_refused() {
    let mut gdi = GdiManager::new();
    let src = seeded(&mut gdi, 2, 1, &[0x0000_00ff, 0x00ff_0000]);
    let dst = seeded(&mut gdi, 2, 1, &[0x0011_1111, 0x0022_2222]);
    let (whole, source) = (BltCoords { x: 0, y: 0, width: 2, height: 1 }, BltCoords { x: 0, y: 0, width: 2, height: 1 });
    gdi.transparent_blt(dst, whole, src, source, 0x0000_00ff).unwrap();
    assert_eq!(gdi.pixels(dst).unwrap(), &[0x0011_1111, 0x00ff_0000]);
    let mirrored = BltCoords { x: 0, y: 0, width: -2, height: 1 };
    assert_eq!(gdi.transparent_blt(dst, mirrored, src, source, 0), Err(GdiError::InvalidDimensions));
}

#[test]
fn alpha_refuses_negative_extents_an_oversized_source_and_an_overlapping_self_blit() {
    let mut gdi = GdiManager::new();
    let dc = seeded(&mut gdi, 4, 1, &[1, 2, 3, 4]);
    let blend = BlendFunction { op: AC_SRC_OVER, flags: 0, source_constant_alpha: 255, alpha_format: 0 };
    let whole = BltCoords { x: 0, y: 0, width: 2, height: 1 };
    assert_eq!(gdi.alpha_blend(dc, BltCoords { x: 0, y: 0, width: -1, height: 1 }, dc, whole, blend), Err(GdiError::InvalidDimensions));
    assert_eq!(gdi.alpha_blend(dc, whole, dc, BltCoords { x: 3, y: 0, width: 4, height: 1 }, blend), Err(GdiError::InvalidDimensions));
    assert_eq!(gdi.alpha_blend(dc, whole, dc, whole, blend), Err(GdiError::InvalidDimensions));
    assert_eq!(gdi.pixels(dc).unwrap(), &[1, 2, 3, 4]);
}

#[test]
fn a_half_transparent_source_mixes_into_the_destination() {
    let mut gdi = GdiManager::new();
    let src = seeded(&mut gdi, 1, 1, &[0x00ff_ffff]);
    let dst = seeded(&mut gdi, 1, 1, &[0x0000_0000]);
    let blend = BlendFunction { op: AC_SRC_OVER, flags: 0, source_constant_alpha: 128, alpha_format: 0 };
    let whole = BltCoords { x: 0, y: 0, width: 1, height: 1 };
    gdi.alpha_blend(dst, whole, src, whole, blend).unwrap();
    assert_eq!(gdi.pixels(dst).unwrap(), &[0x0080_8080]);
}

#[test]
fn a_gradient_paints_its_shape_and_refuses_an_unnamed_vertex() {
    let mut gdi = GdiManager::new();
    let dc = gdi.create_dc(4, 1).unwrap();
    let vertices = [TriVertex { x: 0, y: 0, red: 0, green: 0, blue: 0, alpha: 0 },
        TriVertex { x: 4, y: 1, red: 0xff00, green: 0, blue: 0, alpha: 0 }];
    gdi.gradient_fill(dc, &vertices, &[0, 1], GRADIENT_FILL_RECT_H).unwrap();
    assert_eq!(gdi.pixels(dc).unwrap(), &[0, 0x003f_0000, 0x007f_0000, 0x00bf_0000]);
    assert_eq!(gdi.gradient_fill(dc, &vertices, &[0, 5], GRADIENT_FILL_RECT_H), Err(GdiError::InvalidDimensions));
}

#[test]
fn blits_reach_the_bitmap_a_memory_context_selected() {
    let mut gdi = GdiManager::new();
    let src = seeded(&mut gdi, 2, 1, &[0x00ff_0000, 0x0000_00ff]);
    let dst = gdi.create_dc(1, 1).unwrap();
    let bitmap = gdi.create_bitmap(2, 1, 1, 32, None).unwrap();
    gdi.select_bitmap(dst, bitmap).unwrap();
    gdi.bit_blt(dst, 0, 0, 2, 1, src, 0, 0, SRCCOPY, colors()).unwrap();
    assert_eq!(gdi.bitmap(bitmap).unwrap().pixel(0, 0), Some(0x00ff_0000));
    assert_eq!(gdi.bitmap(bitmap).unwrap().pixel(1, 0), Some(0x0000_00ff));
    // The bitmap is now the only pixel store the context has.
    assert!(gdi.pixels(dst).is_none());
    let back = gdi.create_dc(2, 1).unwrap();
    gdi.bit_blt(back, 0, 0, 2, 1, dst, 0, 0, SRCCOPY, colors()).unwrap();
    assert_eq!(gdi.pixels(back).unwrap(), &[0x00ff_0000, 0x0000_00ff]);
}
