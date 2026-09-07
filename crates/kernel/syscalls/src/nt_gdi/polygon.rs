//! Filled glyph runs the kernel draws itself: the menu check mark and the
//! submenu arrow, each one closed polygon in a single colour.
use super::*;
use ipc::win32_gdi::{Point, POLY_POLYGON};

/// A one-pixel solid pen closes the polygon outline in the fill colour.
const PS_SOLID: i32 = 0;

/// Fill one closed point run in `color`, restoring the device context's own
/// brush and pen afterwards. # C: O(N_points + area)
pub(crate) fn fill_polygon_for_current(dc: u64, points: &[(i32, i32)], color: u32) -> Result<(), u64> {
    let mut run = Vec::new();
    run.try_reserve(points.len()).map_err(|_| STATUS_INVALID_PARAMETER)?;
    for (x, y) in points { run.push(Point { x: *x, y: *y }); }
    let colorref = syscall::nt_gdi_client::xrgb_to_colorref(color).map_err(|_| STATUS_INVALID_PARAMETER)?;
    let brush = brush::create_solid_brush_for_current(color)?;
    let pen = pen::create_pen_for_current(PS_SOLID, 1, colorref);
    let previous_brush = brush::select_brush_for_current(dc, u64::from(brush))?;
    let previous_pen = if pen != 0 { pen::select_pen_for_current(dc, pen) } else { 0 };
    let counts = [run.len() as u32];
    let result = brush::with_owner(|state| state.poly_poly_draw(dc as u32, &run, &counts, POLY_POLYGON));
    let _ = brush::select_brush_for_current(dc, u64::from(previous_brush));
    if previous_pen != 0 { let _ = pen::select_pen_for_current(dc, previous_pen); }
    result
}
