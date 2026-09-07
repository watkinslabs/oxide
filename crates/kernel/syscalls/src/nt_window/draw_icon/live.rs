//! Live icon and cursor drawing against the canonical GDI and cursor owners.
use super::super::*;
use crate::nt_wine_window::draw_icon_raw as raw;
use ipc::win32_gdi::{BltCoords, COLORONCOLOR};

const FALSE: u64 = 0;
const TRUE: u64 = 1;
/// Every surface this raster device carries is one plane of direct colour.
const PLANES: u32 = 1;

/// Route the icon-drawing ordinal. # C: O(1) plus the draw's own cost
pub(crate) fn route(ordinal: u64, args: &[u64]) -> Option<u64> {
    if ordinal != raw::DRAW_ICON_EX { return None; }
    let arg = |index: usize| args.get(index).copied().unwrap_or(0);
    Some(draw_icon_ex(arg(0), arg(1) as i32, arg(2) as i32, arg(3), arg(4) as i32, arg(5) as i32,
        arg(6) as u32, arg(7), arg(8) as u32))
}

/// One non-display metric, from the canonical owner every metric query reads.
/// # C: O(1)
fn metric(index: i32) -> i32 { ipc::win32_gdi::system_metric_default(index).unwrap_or(0) }

/// A memory device context matching the caller's own extent, which is what a
/// context created compatible with it carries. # C: O(processes + DCs)
fn compatible_dc(hdc: u64) -> Option<u32> {
    let state = crate::nt_gdi::text_snapshot_for_current(hdc).ok()?;
    crate::nt_gdi::create_paint_dc_for_current(state.width, state.height).ok()
}

/// Draw one frame of an icon or cursor object. A frame the object does not
/// carry, and a device context that admits no memory context, both refuse.
/// # C: O(processes + DCs + drawn pixels)
fn draw_icon_ex(hdc: u64, x0: i32, y0: i32, icon: u64, width: i32, height: i32,
    step: u32, brush: u64, flags: u32) -> u64 {
    let Some(frame) = user_input::icon_frame_for_current(icon, step) else { return FALSE; };
    let Some(mem_dc) = compatible_dc(hdc) else { return FALSE; };
    let width = raw::draw_extent(width, flags, frame.width, metric(raw::SM_CXICON));
    let height = raw::draw_extent(height, flags, frame.height, metric(raw::SM_CYICON));
    let Ok((colors, _)) = crate::nt_gdi::colors_for(hdc) else {
        let _ = crate::nt_gdi::delete_paint_dc_current(mem_dc);
        return FALSE;
    };
    let colors = raw::icon_colors(colors);
    let offscreen = raw::is_brush(brush).then(|| offscreen_target(hdc, brush, width, height, colors)).flatten();
    let Ok(dest) = u32::try_from(offscreen.map_or(hdc, |(dc, _)| dc as u64)) else {
        let _ = crate::nt_gdi::delete_paint_dc_current(mem_dc);
        return FALSE;
    };
    let (x, y) = raw::offscreen_origin(offscreen.is_some(), x0, y0);
    run_passes(dest, x, y, width, height, mem_dc, frame, flags, colors);
    if let Some((dc, bitmap)) = offscreen {
        let _ = crate::nt_gdi::with_gdi(|state| state.bit_blt(hdc as u32, x0, y0, width, height, dc, 0, 0,
            ipc::win32_gdi::SRCCOPY, colors));
        let _ = crate::nt_gdi::delete_paint_dc_current(dc);
        let _ = crate::nt_gdi::delete_paint_dc_current(bitmap);
    }
    let _ = crate::nt_gdi::delete_paint_dc_current(mem_dc);
    TRUE
}

/// Build the offscreen context a brush argument asks for and fill it with that
/// brush. The fill covers a square of the destination width.
/// # C: O(processes + DCs + width squared)
fn offscreen_target(hdc: u64, brush: u64, width: i32, height: i32,
    colors: ipc::win32_gdi::SharedDcColors) -> Option<(u32, u32)> {
    let dc = compatible_dc(hdc)?;
    let Ok(hdc32) = u32::try_from(hdc) else { let _ = crate::nt_gdi::delete_paint_dc_current(dc); return None; };
    let bitmap = match crate::nt_gdi::create_compatible_bitmap_for_current(hdc32, width, height,
        PLANES, ipc::win32_gdi::SURFACE_BITS_PER_PIXEL) {
        Ok(bitmap) => bitmap,
        Err(_) => { let _ = crate::nt_gdi::delete_paint_dc_current(dc); return None; }
    };
    let _ = crate::nt_gdi::select_bitmap_for_current(dc as u64, bitmap as u64);
    let previous = crate::nt_gdi::select_brush_for_current(dc as u64, brush).ok();
    let (fill_width, fill_height) = raw::brush_fill_extent(width);
    let _ = crate::nt_gdi::with_gdi(|state| state.pat_blt_shared_colors(dc, 0, 0, fill_width, fill_height,
        ipc::win32_gdi::PATCOPY, colors));
    if let Some(previous) = previous.filter(|previous| *previous != 0) {
        let _ = crate::nt_gdi::select_brush_for_current(dc as u64, previous as u64);
    }
    let _ = height;
    Some((dc, bitmap))
}

/// Run the alpha, mask and image passes the request asks for. A blend that
/// cannot run leaves the mask and image passes to do the work.
/// # C: O(drawn pixels)
fn run_passes(dest: u32, x: i32, y: i32, width: i32, height: i32, mem_dc: u32,
    frame: ipc::win32_window::CursorFrame, flags: u32, colors: ipc::win32_gdi::SharedDcColors) {
    let plan = raw::icon_plan(flags, frame.alpha != 0, frame.color != 0);
    let dst = BltCoords { x, y, width, height };
    let src = |top: i32| BltCoords { x: 0, y: top, width: frame.width, height: frame.height };
    if plan.alpha {
        let _ = crate::nt_gdi::select_bitmap_for_current(mem_dc as u64, frame.alpha);
        if crate::nt_gdi::with_gdi(|state| state.alpha_blend(dest, dst, mem_dc, src(0), raw::icon_blend())).is_ok() { return; }
    }
    if let Some(code) = plan.mask {
        let _ = crate::nt_gdi::select_bitmap_for_current(mem_dc as u64, frame.mask);
        let _ = crate::nt_gdi::with_gdi(|state| state.stretch_blt(dest, dst, mem_dc, src(0), code, colors, COLORONCOLOR));
    }
    if let Some((source, code)) = plan.image {
        let (bitmap, top) = match source {
            raw::ImageSource::Color => (frame.color, 0),
            raw::ImageSource::MaskLowerHalf => (frame.mask, frame.height),
        };
        let _ = crate::nt_gdi::select_bitmap_for_current(mem_dc as u64, bitmap);
        let _ = crate::nt_gdi::with_gdi(|state| state.stretch_blt(dest, dst, mem_dc, src(top), code, colors, COLORONCOLOR));
    }
}
