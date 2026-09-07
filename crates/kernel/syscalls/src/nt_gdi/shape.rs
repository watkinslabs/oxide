//! Path, region-shape and region-clip work functions over the canonical GDI owner.
use super::*;
use ipc::win32_gdi::{GdiError, GdiManager, Rect};
use ipc::win32_window::PaintRegion;

/// Run one operation against the calling process GDI owner under the lifetime gate. # C: O(processes) plus the operation
pub(crate) fn with_owner<T>(operation: impl FnOnce(&mut GdiManager) -> Result<T, GdiError>) -> Result<T, u64> {
    let _gate = lifecycle::ClientGate::acquire_current().map_err(|_| STATUS_INVALID_HANDLE)?;
    let current = sched::live::current().ok_or(STATUS_INVALID_HANDLE)?;
    let mut entries = GDI.lock();
    let entry = entries.iter_mut().find(|entry| entry.group.ptr_eq(&Arc::downgrade(&current.thread_group))).ok_or(STATUS_INVALID_HANDLE)?;
    operation(&mut entry.state).map_err(|_| STATUS_INVALID_HANDLE)
}

/// Path recording control shares one owner transaction per call. # C: O(processes + DCs)
pub(crate) fn begin_path(dc: u32) -> Result<(), u64> { with_owner(|state| state.begin_path(dc)) }
/// # C: O(processes + DCs)
pub(crate) fn end_path(dc: u32) -> Result<(), u64> { with_owner(|state| state.end_path(dc)) }
/// # C: O(processes + DCs)
pub(crate) fn abort_path(dc: u32) -> Result<(), u64> { with_owner(|state| state.abort_path(dc)) }
/// # C: O(processes + DCs)
pub(crate) fn close_figure(dc: u32) -> Result<(), u64> { with_owner(|state| state.close_figure(dc)) }
/// # C: O(processes + DCs + path points)
pub(crate) fn flatten_path(dc: u32) -> Result<(), u64> { with_owner(|state| state.flatten_path(dc)) }
/// Path drawing consumes the path exactly as a conversion does. # C: O(processes + scan conversion + pixels)
pub(crate) fn fill_path(dc: u32) -> Result<(), u64> { with_owner(|state| state.fill_path(dc)) }
/// # C: O(processes + path points + stroked pixels)
pub(crate) fn stroke_path(dc: u32) -> Result<(), u64> { with_owner(|state| state.stroke_path(dc)) }
/// # C: O(processes + scan conversion + pixels)
pub(crate) fn stroke_and_fill_path(dc: u32) -> Result<(), u64> { with_owner(|state| state.stroke_and_fill_path(dc)) }

/// Owned copy of the closed path, taken before any usercopy. # C: O(processes + DCs + path points)
pub(crate) fn path_snapshot(dc: u32) -> Result<(alloc::vec::Vec<u8>, alloc::vec::Vec<u8>, usize), u64> {
    with_owner(|state| {
        let (points, flags) = state.path_points(dc)?;
        let bytes = crate::nt_wine_gdi_shape::encode::point_bytes(points).ok_or(GdiError::HandleLimit)?;
        let mut types = alloc::vec::Vec::new();
        types.try_reserve(flags.len()).map_err(|_| GdiError::HandleLimit)?;
        types.extend_from_slice(flags);
        Ok((bytes, types, points.len()))
    })
}

/// Convert and consume the closed path into an owned region. # C: O(processes + scan conversion)
pub(crate) fn path_region(dc: u32) -> Result<PaintRegion, u64> { with_owner(|state| state.path_to_region(dc)) }

/// Region shape creation publishes an identity through the shared lifetime transaction. # C: O(processes + shape rows)
pub(crate) fn create_elliptic_region(rect: Rect) -> Result<u32, u64> {
    region::create_with(move |state| state.create_elliptic_region(rect))
}
/// # C: O(processes + shape rows)
pub(crate) fn create_round_rect_region(rect: Rect, ellipse_width: i32, ellipse_height: i32) -> Result<u32, u64> {
    region::create_with(move |state| state.create_round_rect_region(rect, ellipse_width, ellipse_height))
}
/// # C: O(processes + N_rects²)
pub(crate) fn create_region_from_data(bytes: alloc::vec::Vec<u8>) -> Result<u32, u64> {
    region::create_with(move |state| state.create_region_from_data(&bytes))
}
/// # C: O(processes + region rectangles)
pub(crate) fn create_region(region_value: PaintRegion) -> Result<u32, u64> {
    region::create_with(move |state| state.create_region(region_value))
}

#[path = "shape/query.rs"]
mod query;
pub(crate) use query::*;
