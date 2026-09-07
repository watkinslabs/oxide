//! Kernel binding: point and type runs cross the boundary, then the canonical
//! rasteriser draws them.
use super::{Bounds, Call, MAX_ARGUMENTS, MAX_POINTS, argument_count};
use crate::nt_gdi::dc_state::with_state;
use ipc::win32_gdi::{Point, Rect};

/// Two little-endian LONG fields.
const POINT_BYTES: u64 = 8;
/// One little-endian ULONG field.
const COUNT_BYTES: u64 = 4;

/// # C: canonical rasteriser operation plus bounded usercopy
pub(crate) fn route(ordinal: u64, args: &[u64]) -> Option<u64> {
    let count = argument_count(ordinal)?;
    let Some(full) = crate::nt_wine_window::raw_gather::gather(args, count) else { return Some(0); };
    super::route(ordinal, &full[..count.min(MAX_ARGUMENTS)], execute)
}

fn rect(bounds: Bounds) -> Rect { Rect { left: bounds.left, top: bounds.top, right: bounds.right, bottom: bounds.bottom } }

fn execute(call: Call) -> u64 {
    match call {
        Call::AngleArc { dc, x, y, radius, start_bits, sweep_bits } => u64::from(with_state(|state|
            state.angle_arc(dc, Point { x, y }, radius, f32::from_bits(start_bits), f32::from_bits(sweep_bits))).is_ok()),
        Call::ArcInternal { dc, kind, bounds, start, end } => u64::from(with_state(|state|
            state.arc_internal(dc, kind, rect(bounds), Point { x: start.0, y: start.1 }, Point { x: end.0, y: end.1 })).is_ok()),
        Call::Ellipse { dc, bounds } => u64::from(with_state(|state| state.ellipse(dc, rect(bounds))).is_ok()),
        Call::RoundRect { dc, bounds, ellipse } => u64::from(with_state(|state|
            state.round_rect(dc, rect(bounds), ellipse.0, ellipse.1)).is_ok()),
        Call::PolyDraw { dc, points, types, count } => {
            let Some(points) = read_points(points, count) else { return 0; };
            let Some(types) = read_types(types, count) else { return 0; };
            u64::from(with_state(|state| state.poly_draw(dc, &points, &types)).is_ok())
        }
        Call::PolyPolyDraw { dc, points, counts, runs, function } => {
            let Some(counts) = read_counts(counts, runs) else { return 0; };
            let total: u64 = counts.iter().map(|count| u64::from(*count)).sum();
            if total > MAX_POINTS { return 0; }
            let Ok(total) = u32::try_from(total) else { return 0; };
            let Some(points) = read_points(points, total) else { return 0; };
            u64::from(with_state(|state| state.poly_poly_draw(dc, &points, &counts, function)).is_ok())
        }
    }
}

fn read_points(address: u64, count: u32) -> Option<alloc::vec::Vec<Point>> {
    let mut points = alloc::vec::Vec::new();
    if count == 0 { return Some(points); }
    if address == 0 || u64::from(count) > MAX_POINTS { return None; }
    points.try_reserve_exact(count as usize).ok()?;
    for index in 0..u64::from(count) {
        let base = address.checked_add(index * POINT_BYTES)?;
        points.push(Point { x: uaccess::get_user_u32(base).ok()? as i32,
            y: uaccess::get_user_u32(base.checked_add(4)?).ok()? as i32 });
    }
    Some(points)
}

fn read_types(address: u64, count: u32) -> Option<alloc::vec::Vec<u8>> {
    let mut types = alloc::vec::Vec::new();
    if count == 0 { return Some(types); }
    if address == 0 { return None; }
    types.try_reserve_exact(count as usize).ok()?;
    types.resize(count as usize, 0);
    uaccess::copy_from_user(&mut types, address).ok()?;
    Some(types)
}

fn read_counts(address: u64, runs: u32) -> Option<alloc::vec::Vec<u32>> {
    let mut counts = alloc::vec::Vec::new();
    if runs == 0 { return Some(counts); }
    if address == 0 || u64::from(runs) > MAX_POINTS { return None; }
    counts.try_reserve_exact(runs as usize).ok()?;
    for index in 0..u64::from(runs) {
        counts.push(uaccess::get_user_u32(address.checked_add(index * COUNT_BYTES)?).ok()?);
    }
    Some(counts)
}
