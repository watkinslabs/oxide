//! Masked and parallelogram copies.
use super::super::{GdiManager, GdiError, SharedDcColors, SRCCOPY};

fn colors() -> SharedDcColors { SharedDcColors { brush: 0, text: 0, background: 0x00ff_ffff, background_mode: 2 } }

/// A one-by-eight monochrome mask whose leftmost two cells are set.
fn mask(gdi: &mut GdiManager) -> u32 { gdi.create_bitmap(4, 1, 1, 1, Some(&[0b1100_0000, 0])).unwrap() }

#[test]
fn a_set_mask_bit_takes_the_foreground_code_and_a_clear_one_the_background() {
    let mut gdi = GdiManager::new();
    let src = gdi.create_dc(4, 1).unwrap();
    gdi.blit_pixels(src, 0, 0, 4, 1, 4, &[0x00ff_0000; 4]).unwrap();
    let dst = gdi.create_dc(4, 1).unwrap();
    gdi.blit_pixels(dst, 0, 0, 4, 1, 4, &[0x0000_00ff; 4]).unwrap();
    let handle = mask(&mut gdi);
    // Foreground copies the source; the background byte here leaves the
    // destination alone, which is the code whose truth table is 0xaa.
    gdi.mask_blt(dst, 0, 0, 4, 1, src, 0, 0, Some(handle), 0, 0, 0xaacc_0000, colors()).unwrap();
    assert_eq!(gdi.pixels(dst).unwrap(), &[0x00ff_0000, 0x00ff_0000, 0x0000_00ff, 0x0000_00ff]);
}

#[test]
fn no_mask_at_all_applies_the_foreground_code_over_the_whole_rectangle() {
    let mut gdi = GdiManager::new();
    let src = gdi.create_dc(2, 1).unwrap();
    gdi.blit_pixels(src, 0, 0, 2, 1, 2, &[7, 8]).unwrap();
    let dst = gdi.create_dc(2, 1).unwrap();
    gdi.mask_blt(dst, 0, 0, 2, 1, src, 0, 0, None, 0, 0, SRCCOPY, colors()).unwrap();
    assert_eq!(gdi.pixels(dst).unwrap(), &[7, 8]);
}

#[test]
fn the_mask_origin_shifts_which_cells_select_the_foreground() {
    let mut gdi = GdiManager::new();
    let src = gdi.create_dc(4, 1).unwrap();
    gdi.blit_pixels(src, 0, 0, 4, 1, 4, &[0x00ff_0000; 4]).unwrap();
    let dst = gdi.create_dc(4, 1).unwrap();
    let handle = mask(&mut gdi);
    gdi.mask_blt(dst, 0, 0, 4, 1, src, 0, 0, Some(handle), 1, 0, 0xaacc_0000, colors()).unwrap();
    assert_eq!(gdi.pixels(dst).unwrap(), &[0x00ff_0000, 0, 0, 0]);
    assert_eq!(gdi.mask_blt(dst, 0, 0, 0, 1, src, 0, 0, Some(handle), 0, 0, SRCCOPY, colors()), Err(GdiError::InvalidDimensions));
}

#[test]
fn a_degenerate_or_non_parallel_target_is_refused_before_any_pixel_moves() {
    let mut gdi = GdiManager::new();
    let src = gdi.create_dc(2, 2).unwrap();
    gdi.blit_pixels(src, 0, 0, 2, 2, 2, &[1, 2, 3, 4]).unwrap();
    let dst = gdi.create_dc(4, 4).unwrap();
    // A zero-extent source triangle has no transform.
    assert_eq!(gdi.plg_blt(dst, [(0, 0), (2, 0), (0, 2)], src, 0, 0, 0, 2, None, 0, 0, colors()), Err(GdiError::InvalidDimensions));
    // A rotated or sheared parallelogram needs a world transform.
    assert_eq!(gdi.plg_blt(dst, [(0, 0), (2, 1), (0, 2)], src, 0, 0, 2, 2, None, 0, 0, colors()), Err(GdiError::InvalidDimensions));
    assert_eq!(gdi.pixels(dst).unwrap(), &[0; 16]);
    gdi.plg_blt(dst, [(1, 1), (3, 1), (1, 3)], src, 0, 0, 2, 2, None, 0, 0, colors()).unwrap();
    assert_eq!(gdi.get_pixel(dst, 1, 1), Ok(1));
    assert_eq!(gdi.get_pixel(dst, 2, 2), Ok(4));
}
