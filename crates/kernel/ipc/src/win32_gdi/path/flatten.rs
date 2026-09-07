//! Bezier removal and path-to-region conversion; 31fk§8.
use super::{bezier, record::{GdiPath, PT_BEZIERTO, PT_CLOSEFIGURE, PT_LINETO, PT_MOVETO}, Vec, GdiError};
use crate::win32_gdi::region::scan::{self, Point};
use crate::win32_window::PaintRegion;

/// Replace every Bezier run with the polyline that approximates it. # C: O(N_points + output points)
pub fn flatten(path: &GdiPath) -> Result<GdiPath, GdiError> {
    let (points, flags) = (path.points(), path.flags());
    let mut out = GdiPath::open(path.position());
    let mut index = 0usize;
    while index < points.len() {
        match flags[index] & !PT_CLOSEFIGURE {
            PT_MOVETO | PT_LINETO => { out.push_raw(points[index], flags[index])?; index += 1; },
            PT_BEZIERTO => {
                if index == 0 || index + 2 >= points.len() { return Err(GdiError::InvalidDimensions); }
                let closed = flags[index + 2] & PT_CLOSEFIGURE != 0;
                let curve = bezier::flatten(&points[index - 1..index + 3])?;
                for point in curve.iter().skip(1) { out.push_raw(*point, PT_LINETO)?; }
                if closed { out.close_figure(); }
                index += 3;
            },
            _ => { index += 1; },
        }
    }
    Ok(out)
}

/// Point counts per figure, split at every recorded move. # C: O(N_points)
fn figure_counts(flags: &[u8]) -> Result<Vec<usize>, GdiError> {
    let mut counts: Vec<usize> = Vec::new();
    let mut start = 0usize;
    for index in 1..flags.len() {
        if flags[index] & !PT_CLOSEFIGURE != PT_MOVETO { continue; }
        counts.try_reserve(1).map_err(|_| GdiError::HandleLimit)?;
        counts.push(index - start); start = index;
    }
    if flags.len() > start + 1 {
        counts.try_reserve(1).map_err(|_| GdiError::HandleLimit)?;
        counts.push(flags.len() - start);
    }
    Ok(counts)
}

/// Convert a flattened path to region coverage under the DC polygon fill mode. # C: O(scan conversion)
pub fn to_region(path: &GdiPath, mode: i32) -> Result<PaintRegion, GdiError> {
    if path.is_empty() { return Err(GdiError::NoSuchObject); }
    let counts = figure_counts(path.flags())?;
    if counts.is_empty() { return Err(GdiError::NoSuchObject); }
    let points: &[Point] = path.points();
    scan::poly_polygon_region(points, &counts, mode)
}

#[cfg(test)]
#[path = "../tests/path_flatten.rs"]
mod tests;
