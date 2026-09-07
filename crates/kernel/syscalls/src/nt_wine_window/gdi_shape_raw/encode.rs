//! Bounded output images and return-value policy for path and region queries; 31d§1.
use alloc::vec::Vec;
use ipc::win32_gdi::Rect;
use ipc::win32_gdi::region::scan::Point;

/// Layout mirroring and monitor-DPI selectors ride above the region code.
pub(crate) const RGN_MIRROR_RTL: u32 = 0x8000_0000;
pub(crate) const RGN_MONITOR_DPI: u32 = 0x4000_0000;
/// A path query answers with a signed count; failure is the negative one.
pub(crate) const PATH_FAILURE: i32 = -1;
pub(crate) const POINT_BYTES: usize = 8;
const RECT_BYTES: usize = 16;

/// The region selector without the layout and DPI request bits. # C: O(1)
pub(crate) fn region_code(code: i32) -> i32 { (code as u32 & !(RGN_MIRROR_RTL | RGN_MONITOR_DPI)) as i32 }

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PathPlan { Refuse, Count(i32), Copy(usize) }

/// A zero size asks for the count; a smaller one is refused before any copy. # C: O(1)
pub(crate) fn path_plan(size: i32, count: usize) -> PathPlan {
    let Ok(count_i32) = i32::try_from(count) else { return PathPlan::Refuse; };
    if size == 0 { return PathPlan::Count(count_i32); }
    if size < count_i32 { return PathPlan::Refuse; }
    PathPlan::Copy(count)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DataPlan { Size(u32), Refuse, Copy(u32) }

/// A null buffer asks for the size; a buffer too small reports zero. # C: O(1)
pub(crate) fn data_plan(buffer: u64, count: u32, needed: usize) -> DataPlan {
    let Ok(needed) = u32::try_from(needed) else { return DataPlan::Refuse; };
    if buffer == 0 { return DataPlan::Size(needed); }
    if count < needed { return DataPlan::Refuse; }
    DataPlan::Copy(needed)
}

/// Little-endian POINT array image of recorded path points. # C: O(N_points)
pub(crate) fn point_bytes(points: &[Point]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    out.try_reserve(points.len().checked_mul(POINT_BYTES)?).ok()?;
    for point in points {
        out.extend_from_slice(&point.x.to_le_bytes());
        out.extend_from_slice(&point.y.to_le_bytes());
    }
    Some(out)
}

/// Signed RECT read back from a user image. # C: O(1)
pub(crate) fn rect_from_bytes(bytes: [u8; RECT_BYTES]) -> Rect {
    let word = |index: usize| i32::from_le_bytes([bytes[index * 4], bytes[index * 4 + 1], bytes[index * 4 + 2], bytes[index * 4 + 3]]);
    Rect { left: word(0), top: word(1), right: word(2), bottom: word(3) }
}

#[cfg(test)]
#[path = "../tests/gdi_shape_encode.rs"]
mod tests;
