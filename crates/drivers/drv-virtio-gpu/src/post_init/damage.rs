// Geometry for a damaged-rectangle scanout upload: turn the console's
// damage rect into the per-scanline copy into the resource backing plus the
// (x, y, w, h, offset) the device commands carry. The offset a
// TRANSFER_TO_HOST_2D names is the byte position of the rect's top-left
// pixel inside the backing, i.e. `y * pitch + x * bpp`; RESOURCE_FLUSH
// carries the same rect.
//
// Pure arithmetic, no device or lock state, so every clamp and every
// offset is host-testable — which matters because a wrong offset here
// writes the frame at the wrong place rather than failing loudly.

use fbcon::kernel::FlushRect;

/// Bytes per pixel of the XRGB scanout formats this driver posts.
pub const BYTES_PER_PIXEL: usize = 4;

/// A clamped damage upload: `h` scanlines of `row_bytes`, walking the source
/// surface at `src_stride_b` and the resource backing at `dst_stride_b`.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct CopyPlan {
    pub x: u32,
    pub y: u32,
    pub w: u32,
    pub h: u32,
    pub src_off: usize,
    pub dst_off: u64,
    pub row_bytes: usize,
    pub src_stride_b: usize,
    pub dst_stride_b: usize,
}

impl CopyPlan {
    /// Whole rect is contiguous in both buffers, so the per-scanline walk
    /// collapses to one copy. # C: O(1)
    pub fn is_contiguous(&self) -> bool {
        self.row_bytes == self.src_stride_b && self.row_bytes == self.dst_stride_b
    }

    /// Bytes this plan copies. # C: O(1)
    pub fn bytes(&self) -> usize {
        self.row_bytes * self.h as usize
    }
}

/// Rows of `stride` that fit in `len` starting at `off` with `row_bytes` per
/// row, i.e. how many scanlines the buffer can actually serve.
fn rows_that_fit(off: usize, stride: usize, row_bytes: usize, len: usize) -> u32 {
    if stride == 0 {
        return 0;
    }
    let last = match off.checked_add(row_bytes) {
        Some(v) => v,
        None => return 0,
    };
    if last > len {
        return 0;
    }
    let spare = (len - last) / stride;
    spare.saturating_add(1).min(u32::MAX as usize) as u32
}

/// Clamp `rect` against a `dst_w` x `dst_h` resource whose backing is
/// `dst_len` bytes, sourced from a `src_len`-byte surface. `None` when
/// nothing survives the clamp — the caller then issues no device command at
/// all. # C: O(1)
pub fn plan_copy(rect: FlushRect, dst_w: u32, dst_h: u32, src_len: usize, dst_len: usize) -> Option<CopyPlan> {
    if rect.stride_px == 0 || dst_w == 0 || dst_h == 0 {
        return None;
    }
    let (x, y) = (rect.x, rect.y);
    if x >= dst_w || x >= rect.stride_px || y >= dst_h {
        return None;
    }
    let w = rect.w.min(dst_w - x).min(rect.stride_px - x);
    let h = rect.h.min(dst_h - y);
    if w == 0 || h == 0 {
        return None;
    }
    let src_stride_b = rect.stride_px as usize * BYTES_PER_PIXEL;
    let dst_stride_b = dst_w as usize * BYTES_PER_PIXEL;
    let row_bytes = w as usize * BYTES_PER_PIXEL;
    let src_off = y as usize * src_stride_b + x as usize * BYTES_PER_PIXEL;
    let dst_off = y as usize * dst_stride_b + x as usize * BYTES_PER_PIXEL;
    let h = h
        .min(rows_that_fit(src_off, src_stride_b, row_bytes, src_len))
        .min(rows_that_fit(dst_off, dst_stride_b, row_bytes, dst_len));
    if h == 0 {
        return None;
    }
    Some(CopyPlan {
        x, y, w, h,
        src_off,
        dst_off: dst_off as u64,
        row_bytes,
        src_stride_b,
        dst_stride_b,
    })
}

#[cfg(test)]
mod tests;
