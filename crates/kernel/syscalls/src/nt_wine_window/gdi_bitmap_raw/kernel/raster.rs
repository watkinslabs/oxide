//! Blits, single pixels and gradients through the canonical raster owner.
use alloc::vec::Vec;
use ipc::win32_gdi::{BlendFunction, BltCoords, CLR_INVALID, GradientMode, TriVertex};
use super::super::{Operation, Rect};

/// A gradient vertex is six fields: two device coordinates then four
/// sixteen-bit colour channels padded to a whole word each.
const TRIVERTEX_BYTES: usize = 16;
/// One shape index is a whole word.
const INDEX_BYTES: usize = 4;
/// Shapes one request may name, bounding the kernel buffers it needs.
const MAX_SHAPES: u32 = 4096;
/// A parallelogram is named by three corner points of two words each.
const POINT_BYTES: usize = 8;
const PLG_POINTS: usize = 3;

/// Planes and depth this raster device reports; every surface is direct colour.
pub(super) fn device() -> (u32, u32) { (1, ipc::win32_gdi::SURFACE_BITS_PER_PIXEL) }

fn coords(rect: Rect) -> BltCoords { BltCoords { x: rect.x, y: rect.y, width: rect.width, height: rect.height } }

pub(super) fn dispatch(operation: Operation) -> u64 {
    match operation {
        Operation::BitBlt { dst, dst_rect, src, src_x, src_y, code } => {
            let Some((dst, src, colors, _)) = pair(dst, src) else { return 0; };
            u64::from(crate::nt_gdi::with_gdi(|state| state.bit_blt(dst, dst_rect.x, dst_rect.y, dst_rect.width,
                dst_rect.height, src, src_x, src_y, code, colors)).is_ok())
        }
        Operation::StretchBlt { dst, dst_rect, src, src_rect, code } => {
            let Some((dst, src, colors, mode)) = pair(dst, src) else { return 0; };
            u64::from(crate::nt_gdi::with_gdi(|state| state.stretch_blt(dst, coords(dst_rect), src, coords(src_rect),
                code, colors, mode)).is_ok())
        }
        Operation::MaskBlt { dst, dst_rect, src, src_x, src_y, mask, mask_x, mask_y, code } => {
            let Some((dst, src, colors, _)) = pair(dst, src) else { return 0; };
            let mask = if mask == 0 { None } else { Some(u32::try_from(mask).ok()).flatten() };
            u64::from(crate::nt_gdi::with_gdi(|state| state.mask_blt(dst, dst_rect.x, dst_rect.y, dst_rect.width,
                dst_rect.height, src, src_x, src_y, mask, mask_x, mask_y, code, colors)).is_ok())
        }
        Operation::PlgBlt { dst, points, src, src_x, src_y, width, height, mask, mask_x, mask_y } => {
            let Some((dst, src, colors, _)) = pair(dst, src) else { return 0; };
            let Some(points) = read_points(points) else { return 0; };
            let mask = if mask == 0 { None } else { Some(u32::try_from(mask).ok()).flatten() };
            u64::from(crate::nt_gdi::with_gdi(|state| state.plg_blt(dst, points, src, src_x, src_y, width, height,
                mask, mask_x, mask_y, colors)).is_ok())
        }
        Operation::TransparentBlt { dst, dst_rect, src, src_rect, transparent } => {
            let Some((dst, src, _, _)) = pair(dst, src) else { return 0; };
            u64::from(crate::nt_gdi::with_gdi(|state| state.transparent_blt(dst, coords(dst_rect), src,
                coords(src_rect), colorref_xrgb(transparent))).is_ok())
        }
        Operation::AlphaBlend { dst, dst_rect, src, src_rect, blend } => {
            let Some((dst, src, _, _)) = pair(dst, src) else { return 0; };
            let blend = BlendFunction::from_dword(blend);
            u64::from(crate::nt_gdi::with_gdi(|state| state.alpha_blend(dst, coords(dst_rect), src, coords(src_rect), blend)).is_ok())
        }
        Operation::GradientFill { dc, vertices, vertex_count, indexes, shape_count, mode } =>
            gradient(dc, vertices, vertex_count, indexes, shape_count, mode),
        Operation::GetPixel { dc, x, y } => {
            let Ok(dc) = u32::try_from(dc) else { return u64::from(CLR_INVALID); };
            match crate::nt_gdi::with_gdi(|state| state.get_pixel(dc, x, y)) {
                Ok(color) => u64::from(xrgb_colorref(color)), Err(_) => u64::from(CLR_INVALID),
            }
        }
        Operation::SetPixel { dc, x, y, color } => {
            let Ok(dc) = u32::try_from(dc) else { return u64::from(CLR_INVALID); };
            match crate::nt_gdi::with_gdi(|state| state.set_pixel(dc, x, y, colorref_xrgb(color))) {
                Ok(stored) => u64::from(xrgb_colorref(stored)), Err(_) => u64::from(CLR_INVALID),
            }
        }
        Operation::ExtFloodFill { dc, x, y, color, kind } => {
            let Ok(handle) = u32::try_from(dc) else { return 0; };
            let Ok((colors, _)) = crate::nt_gdi::colors_for(dc) else { return 0; };
            u64::from(crate::nt_gdi::with_gdi(|state| state.ext_flood_fill(handle, x, y, colorref_xrgb(color), kind, colors)).is_ok())
        }
        _ => 0,
    }
}

/// COLORREF and the canonical surface word are byte-reversed views of the same
/// three channels. # C: O(1)
fn colorref_xrgb(color: u32) -> u32 { ((color & 0xff) << 16) | (color & 0xff00) | ((color >> 16) & 0xff) }
fn xrgb_colorref(color: u32) -> u32 { if color == CLR_INVALID { color } else { colorref_xrgb(color) } }

/// Resolve both device contexts and the destination's raster attributes; the
/// attributes come from the client's own record and never from a mirror.
/// # C: O(processes + DCs)
fn pair(dst: u64, src: u64) -> Option<(u32, u32, ipc::win32_gdi::SharedDcColors, u32)> {
    let (dst_handle, src_handle) = (u32::try_from(dst).ok()?, u32::try_from(src).ok()?);
    let (colors, mode) = crate::nt_gdi::colors_for(dst).ok()?;
    Some((dst_handle, src_handle, colors, mode))
}

fn read_points(address: u64) -> Option<[(i32, i32); PLG_POINTS]> {
    let mut bytes = [0u8; POINT_BYTES * PLG_POINTS];
    uaccess::copy_from_user(&mut bytes, address).ok()?;
    let word = |at: usize| i32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]]);
    Some([(word(0), word(4)), (word(8), word(12)), (word(16), word(20))])
}

fn gradient(dc: u64, vertices: u64, vertex_count: u32, indexes: u64, shape_count: u32, mode: GradientMode) -> u64 {
    let Ok(dc) = u32::try_from(dc) else { return 0; };
    if vertices == 0 || indexes == 0 || vertex_count == 0 || shape_count == 0 { return 0; }
    if vertex_count > MAX_SHAPES || shape_count > MAX_SHAPES { return 0; }
    let Some(vertices) = read_vertices(vertices, vertex_count) else { return 0; };
    let stride = if mode == ipc::win32_gdi::GRADIENT_FILL_TRIANGLE { 3 } else { 2 };
    let Some(count) = shape_count.checked_mul(stride) else { return 0; };
    let Some(indexes) = read_indexes(indexes, count) else { return 0; };
    u64::from(crate::nt_gdi::with_gdi(|state| state.gradient_fill(dc, &vertices, &indexes, mode)).is_ok())
}

fn read_vertices(address: u64, count: u32) -> Option<Vec<TriVertex>> {
    let mut bytes = Vec::new();
    let len = (count as usize).checked_mul(TRIVERTEX_BYTES)?;
    bytes.try_reserve(len).ok()?;
    bytes.resize(len, 0);
    uaccess::copy_from_user(&mut bytes, address).ok()?;
    let mut out = Vec::new();
    out.try_reserve_exact(count as usize).ok()?;
    for chunk in bytes.chunks_exact(TRIVERTEX_BYTES) {
        let word = |at: usize| i32::from_le_bytes([chunk[at], chunk[at + 1], chunk[at + 2], chunk[at + 3]]);
        let short = |at: usize| u16::from_le_bytes([chunk[at], chunk[at + 1]]);
        out.push(TriVertex { x: word(0), y: word(4), red: short(8), green: short(10), blue: short(12), alpha: short(14) });
    }
    Some(out)
}

fn read_indexes(address: u64, count: u32) -> Option<Vec<u32>> {
    let mut bytes = Vec::new();
    let len = (count as usize).checked_mul(INDEX_BYTES)?;
    bytes.try_reserve(len).ok()?;
    bytes.resize(len, 0);
    uaccess::copy_from_user(&mut bytes, address).ok()?;
    let mut out = Vec::new();
    out.try_reserve_exact(count as usize).ok()?;
    for chunk in bytes.chunks_exact(INDEX_BYTES) { out.push(u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]])); }
    Some(out)
}
