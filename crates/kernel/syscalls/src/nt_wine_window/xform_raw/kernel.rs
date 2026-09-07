//! Kernel binding: matrices and point runs cross the boundary here.
use super::{Call, MAX_ARGUMENTS, MAX_POINTS, argument_count};
use crate::nt_gdi::dc_state::{device_geometry, with_state};
use ipc::win32_gdi::{Point, Size, Xform, XFORM_BYTES};

/// Two little-endian LONG fields.
const POINT_BYTES: usize = 8;

/// # C: canonical owner operation plus bounded usercopy
pub(crate) fn route(ordinal: u64, args: &[u64]) -> Option<u64> {
    let count = argument_count(ordinal)?;
    let Some(full) = crate::nt_wine_window::raw_gather::gather(args, count) else { return Some(0); };
    super::route(ordinal, &full[..count.min(MAX_ARGUMENTS)], execute)
}

fn execute(call: Call) -> u64 {
    match call {
        Call::GetTransform { dc, which, xform } => {
            let Ok(value) = with_state(|state| state.dc_transform(dc, which)) else { return 0; };
            u64::from(uaccess::copy_to_user(xform, &value.to_le_bytes()).is_ok())
        }
        Call::ModifyWorldTransform { dc, xform, mode } => {
            let supplied = if xform == 0 { None } else { match read_xform(xform) { Some(value) => Some(value), None => return 0 } };
            u64::from(with_state(|state| state.modify_world_transform(dc, supplied, mode)).is_ok())
        }
        Call::TransformPoints { dc, input, output, count, mode } => {
            let Some(mut points) = read_points(input, count) else { return 0; };
            if with_state(|state| state.transform_points(dc, mode, &mut points)).is_err() { return 0; }
            u64::from(write_points(output, &points))
        }
        Call::ComputeXformCoefficients { dc } => {
            let device = device_geometry();
            u64::from(with_state(|state| state.compute_xform_coefficients(dc, device)).is_ok())
        }
        Call::ScaleExt { dc, viewport, ratio, size } => {
            let device = device_geometry();
            let outcome = with_state(|state| Ok(if viewport { state.scale_viewport_ext(dc, ratio, device) }
                else { state.scale_window_ext(dc, ratio, device) }));
            let Ok(outcome) = outcome else { return 0; };
            // The previous extent is reported whether or not the scale applied.
            let (previous, admitted) = match outcome { Ok(previous) => (previous, true), Err((previous, _)) => (previous, false) };
            if size != 0 && !write_size(size, previous) { return 0; }
            u64::from(admitted)
        }
        Call::SetVirtualResolution { dc, res, size } => u64::from(with_state(|state|
            state.set_virtual_resolution(dc, Size { cx: res.0, cy: res.1 }, Size { cx: size.0, cy: size.1 })).is_ok()),
    }
}

fn read_xform(address: u64) -> Option<Xform> {
    let mut bytes = [0u8; XFORM_BYTES];
    uaccess::copy_from_user(&mut bytes, address).ok()?;
    Some(Xform::from_le_bytes(&bytes))
}

fn read_points(address: u64, count: i32) -> Option<alloc::vec::Vec<Point>> {
    let mut points = alloc::vec::Vec::new();
    if count == 0 { return Some(points); }
    if address == 0 || count > MAX_POINTS { return None; }
    points.try_reserve_exact(count as usize).ok()?;
    for index in 0..count as u64 {
        let base = address.checked_add(index * POINT_BYTES as u64)?;
        points.push(Point { x: uaccess::get_user_u32(base).ok()? as i32,
            y: uaccess::get_user_u32(base.checked_add(4)?).ok()? as i32 });
    }
    Some(points)
}

fn write_points(address: u64, points: &[Point]) -> bool {
    if points.is_empty() { return true; }
    if address == 0 { return false; }
    for (index, point) in points.iter().enumerate() {
        let mut bytes = [0u8; POINT_BYTES];
        bytes[..4].copy_from_slice(&point.x.to_le_bytes());
        bytes[4..].copy_from_slice(&point.y.to_le_bytes());
        let Some(base) = address.checked_add((index * POINT_BYTES) as u64) else { return false; };
        if uaccess::copy_to_user(base, &bytes).is_err() { return false; }
    }
    true
}

fn write_size(address: u64, size: Size) -> bool {
    let mut bytes = [0u8; POINT_BYTES];
    bytes[..4].copy_from_slice(&size.cx.to_le_bytes());
    bytes[4..].copy_from_slice(&size.cy.to_le_bytes());
    uaccess::copy_to_user(address, &bytes).is_ok()
}
