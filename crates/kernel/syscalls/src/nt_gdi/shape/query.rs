//! Region and clip queries, and region drawing, over the canonical GDI owner.
use super::{with_owner, PaintRegion, Rect};

/// # C: O(processes + regions + rectangles² log rectangles)
pub(crate) fn regions_equal(first: u32, second: u32) -> Result<bool, u64> { with_owner(|state| state.regions_equal(first, second)) }
/// # C: O(processes + regions + rectangles)
pub(crate) fn offset_region(region: u32, x: i32, y: i32) -> Result<u32, u64> { with_owner(|state| state.offset_region(region, x, y)) }
/// # C: O(processes + regions + rectangles)
pub(crate) fn region_contains_point(region: u32, x: i32, y: i32) -> Result<bool, u64> { with_owner(|state| state.region_contains_point(region, x, y)) }
/// # C: O(processes + regions + rectangles)
pub(crate) fn region_overlaps_rect(region: u32, rect: Rect) -> Result<bool, u64> { with_owner(|state| state.region_overlaps_rect(region, rect)) }
/// # C: O(processes + regions + rectangles² log rectangles)
pub(crate) fn region_data(region: u32) -> Result<alloc::vec::Vec<u8>, u64> { with_owner(|state| state.region_data(region)) }

/// # C: O(processes + DCs + region operations)
pub(crate) fn exclude_clip_rect(dc: u32, rect: Rect) -> Result<u32, u64> { with_owner(|state| state.exclude_clip_rect(dc, rect)) }
/// # C: O(processes + DCs + region operations)
pub(crate) fn ext_select_clip_rgn(dc: u32, region: Option<PaintRegion>, mode: i32) -> Result<u32, u64> {
    with_owner(|state| state.ext_select_clip_rgn(dc, region.as_ref(), mode))
}
/// # C: O(processes + DCs + region rectangles)
pub(crate) fn offset_clip_rgn(dc: u32, x: i32, y: i32) -> Result<u32, u64> { with_owner(|state| state.offset_clip_rgn(dc, x, y)) }
/// # C: O(processes + DCs + region operations)
pub(crate) fn set_meta_rgn(dc: u32) -> Result<u32, u64> { with_owner(|state| state.set_meta_rgn(dc)) }
/// # C: O(processes + DCs + region rectangles)
pub(crate) fn pt_visible(dc: u32, x: i32, y: i32) -> Result<bool, u64> { with_owner(|state| state.pt_visible(dc, x, y)) }
/// # C: O(processes + DCs + region rectangles)
pub(crate) fn random_region(dc: u32, code: i32) -> Result<Option<PaintRegion>, u64> { with_owner(|state| state.get_random_rgn(dc, code)) }
/// Copy an owned region snapshot into an existing region identity. # C: O(processes + regions)
pub(crate) fn store_region(handle: u32, region: PaintRegion) -> Result<(), u64> { with_owner(|state| state.replace_region(handle, region)) }

/// # C: O(processes + DCs + region rectangles + pixels)
pub(crate) fn fill_region(dc: u32, region: u32, brush: u32) -> Result<(), u64> { with_owner(|state| state.fill_region(dc, region, brush)) }
/// # C: O(processes + DCs + region operations + pixels)
pub(crate) fn frame_region(dc: u32, region: u32, brush: u32, width: i32, height: i32) -> Result<(), u64> {
    with_owner(|state| state.frame_region(dc, region, brush, width, height))
}
/// # C: O(processes + DCs + region rectangles + pixels)
pub(crate) fn invert_region(dc: u32, region: u32) -> Result<(), u64> { with_owner(|state| state.invert_region(dc, region)) }
