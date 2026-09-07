//! Ordinal-to-owner routing for paths, region shapes and region clipping; 53§2.
use super::decode::{Operation, PathOp};
use super::encode::{self, DataPlan, PathPlan, PATH_FAILURE};
use crate::nt_gdi::shape;
use ipc::win32_gdi::{CLIP_ERROR, RGN_COPY};

const FALSE: u64 = 0;
const TRUE: u64 = 1;
const NO_HANDLE: u64 = 0;
/// A random-region query reports presence, absence, or failure.
const RGN_PRESENT: u64 = 1;
const RGN_ABSENT: u64 = 0;
const RGN_FAILED: u64 = -1i32 as u32 as u64;

fn handle(value: u64) -> Option<u32> { u32::try_from(value).ok() }
fn boolean(result: Result<(), u64>) -> u64 { if result.is_ok() { TRUE } else { FALSE } }

/// Route one admitted request to exactly one owner work function. # C: owner operation cost
pub(crate) fn dispatch(operation: Operation) -> u64 {
    match operation {
        Operation::Path { dc, op } => path(dc, op),
        Operation::GetPath { dc, points, types, size } => get_path(dc, points, types, size),
        Operation::SelectClipPath { dc, mode } => select_clip_path(dc, mode),
        Operation::CreateEllipticRgn { rect } => {
            shape::create_elliptic_region(rect).map_or(NO_HANDLE, u64::from)
        },
        Operation::CreateRoundRectRgn { rect, ellipse_width, ellipse_height } => {
            shape::create_round_rect_region(rect, ellipse_width, ellipse_height).map_or(NO_HANDLE, u64::from)
        },
        Operation::ExtCreateRegion { xform, count, data } => ext_create_region(xform, count, data),
        Operation::EqualRgn { first, second } => {
            let (Some(first), Some(second)) = (handle(first), handle(second)) else { return FALSE; };
            shape::regions_equal(first, second).map_or(FALSE, u64::from)
        },
        Operation::OffsetRgn { region, x, y } => {
            let Some(region) = handle(region) else { return CLIP_ERROR as u64; };
            shape::offset_region(region, x, y).map_or(CLIP_ERROR as u64, u64::from)
        },
        Operation::PtInRegion { region, x, y } => {
            let Some(region) = handle(region) else { return FALSE; };
            shape::region_contains_point(region, x, y).map_or(FALSE, u64::from)
        },
        Operation::RectInRegion { region, rect } => rect_in_region(region, rect),
        Operation::GetRegionData { region, count, data } => get_region_data(region, count, data),
        Operation::ExcludeClipRect { dc, rect } => {
            let Some(dc) = handle(dc) else { return CLIP_ERROR as u64; };
            shape::exclude_clip_rect(dc, rect).map_or(CLIP_ERROR as u64, u64::from)
        },
        Operation::ExtSelectClipRgn { dc, region, mode } => ext_select_clip_rgn(dc, region, mode),
        Operation::OffsetClipRgn { dc, x, y } => {
            let Some(dc) = handle(dc) else { return CLIP_ERROR as u64; };
            shape::offset_clip_rgn(dc, x, y).map_or(CLIP_ERROR as u64, u64::from)
        },
        Operation::PtVisible { dc, x, y } => {
            let Some(dc) = handle(dc) else { return FALSE; };
            shape::pt_visible(dc, x, y).map_or(FALSE, u64::from)
        },
        Operation::GetRandomRgn { dc, region, code } => get_random_rgn(dc, region, code),
        Operation::SetMetaRgn { dc } => {
            let Some(dc) = handle(dc) else { return CLIP_ERROR as u64; };
            shape::set_meta_rgn(dc).map_or(CLIP_ERROR as u64, u64::from)
        },
        Operation::FillRgn { dc, region, brush } => {
            let (Some(dc), Some(region), Some(brush)) = (handle(dc), handle(region), handle(brush)) else { return FALSE; };
            boolean(shape::fill_region(dc, region, brush))
        },
        Operation::FrameRgn { dc, region, brush, width, height } => {
            let (Some(dc), Some(region), Some(brush)) = (handle(dc), handle(region), handle(brush)) else { return FALSE; };
            boolean(shape::frame_region(dc, region, brush, width, height))
        },
        Operation::InvertRgn { dc, region } => {
            let (Some(dc), Some(region)) = (handle(dc), handle(region)) else { return FALSE; };
            boolean(shape::invert_region(dc, region))
        },
    }
}

/// Drawing operations consume the closed path and report only whether one existed. # C: owner operation cost
fn path(dc: u64, op: PathOp) -> u64 {
    let Some(dc) = handle(dc) else { return if matches!(op, PathOp::ToRegion) { NO_HANDLE } else { FALSE }; };
    match op {
        PathOp::Begin => boolean(shape::begin_path(dc)),
        PathOp::End => boolean(shape::end_path(dc)),
        PathOp::Abort => boolean(shape::abort_path(dc)),
        PathOp::CloseFigure => boolean(shape::close_figure(dc)),
        PathOp::Flatten => boolean(shape::flatten_path(dc)),
        // Widening needs the selected pen geometry the owner does not yet carry.
        PathOp::Widen => FALSE,
        PathOp::Fill => boolean(shape::fill_path(dc)),
        PathOp::Stroke => boolean(shape::stroke_path(dc)),
        PathOp::StrokeAndFill => boolean(shape::stroke_and_fill_path(dc)),
        PathOp::ToRegion => shape::path_region(dc)
            .and_then(shape::create_region).map_or(NO_HANDLE, u64::from),
    }
}

fn get_path(dc: u64, points: u64, types: u64, size: i32) -> u64 {
    let Some(dc) = handle(dc) else { return PATH_FAILURE as u32 as u64; };
    let Ok((point_bytes, type_bytes, count)) = shape::path_snapshot(dc) else { return PATH_FAILURE as u32 as u64; };
    match encode::path_plan(size, count) {
        PathPlan::Refuse => PATH_FAILURE as u32 as u64,
        PathPlan::Count(value) => value as u32 as u64,
        PathPlan::Copy(count) => {
            if uaccess::copy_to_user(points, &point_bytes).is_err() { return PATH_FAILURE as u32 as u64; }
            if uaccess::copy_to_user(types, &type_bytes).is_err() { return PATH_FAILURE as u32 as u64; }
            count as u64
        },
    }
}

/// The path becomes a region, that region becomes the application clip, and both are consumed. # C: scan conversion cost
fn select_clip_path(dc: u64, mode: i32) -> u64 {
    let Some(dc) = handle(dc) else { return FALSE; };
    let Ok(region) = shape::path_region(dc) else { return FALSE; };
    if shape::ext_select_clip_rgn(dc, Some(region), mode).map_or(true, |kind| kind == CLIP_ERROR) { return FALSE; }
    TRUE
}

fn ext_select_clip_rgn(dc: u64, region: u64, mode: i32) -> u64 {
    let Some(dc) = handle(dc) else { return CLIP_ERROR as u64; };
    let region = match region {
        0 => None,
        value => match crate::nt_gdi::region_snapshot_for_current(value) { Ok(region) => Some(region), Err(_) => return CLIP_ERROR as u64 },
    };
    shape::ext_select_clip_rgn(dc, region, mode).map_or(CLIP_ERROR as u64, u64::from)
}

fn ext_create_region(xform: u64, count: u32, data: u64) -> u64 {
    // A world transform on region data is a separate owner surface; refuse it rather
    // than silently creating an untransformed region.
    if xform != 0 || data == 0 { return NO_HANDLE; }
    let Ok(count) = usize::try_from(count) else { return NO_HANDLE; };
    let mut bytes = alloc::vec::Vec::new();
    if bytes.try_reserve(count).is_err() { return NO_HANDLE; }
    bytes.resize(count, 0);
    if uaccess::copy_from_user(&mut bytes, data).is_err() { return NO_HANDLE; }
    shape::create_region_from_data(bytes).map_or(NO_HANDLE, u64::from)
}

fn rect_in_region(region: u64, rect: u64) -> u64 {
    let Some(region) = handle(region) else { return FALSE; };
    let mut bytes = [0u8; 16];
    if rect == 0 || uaccess::copy_from_user(&mut bytes, rect).is_err() { return FALSE; }
    shape::region_overlaps_rect(region, encode::rect_from_bytes(bytes)).map_or(FALSE, u64::from)
}

fn get_region_data(region: u64, count: u32, data: u64) -> u64 {
    let Some(region) = handle(region) else { return 0; };
    let Ok(bytes) = shape::region_data(region) else { return 0; };
    match encode::data_plan(data, count, bytes.len()) {
        DataPlan::Size(size) => u64::from(size),
        DataPlan::Refuse => 0,
        DataPlan::Copy(size) => if uaccess::copy_to_user(data, &bytes).is_ok() { u64::from(size) } else { 0 },
    }
}

fn get_random_rgn(dc: u64, region: u64, code: i32) -> u64 {
    let (Some(dc), Some(target)) = (handle(dc), handle(region)) else { return RGN_FAILED; };
    match shape::random_region(dc, encode::region_code(code)) {
        Err(_) => RGN_FAILED,
        Ok(None) => RGN_ABSENT,
        Ok(Some(source)) => if shape::store_region(target, source).is_ok() { RGN_PRESENT } else { RGN_FAILED },
    }
}

/// Copy mode is what a selection with no region admits. # C: O(1)
const _: () = assert!(RGN_COPY == 5);
