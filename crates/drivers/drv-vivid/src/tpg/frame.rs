#![allow(unused_imports)]
use v4l2::uapi::fourcc;
use super::formats::render_line_at_map;
use super::pixel::{chroma_u, chroma_v, luma, sample_pixel};
use super::{Motion, RenderMap};

/// Bytes one whole frame of the pattern occupies for this format and size.
/// # C: O(1)
pub fn frame_bytes(pixelformat: u32, width: u32, height: u32) -> usize {
    fourcc::sizeimage(pixelformat, width, height, 0) as usize
}

/// Per-plane allocation sizes for Linux's multi-planar Vivid formats.
/// Single-planar formats return their complete frame as plane zero.
pub fn plane_sizes(pixelformat: u32, width: u32, height: u32)
    -> ([u32; v4l2::uapi::layout::MAX_PLANES], usize)
{
    let mut sizes = [0u32; v4l2::uapi::layout::MAX_PLANES];
    let y = width.saturating_mul(height);
    let cw = width.div_ceil(2);
    let ch = height.div_ceil(2);
    match pixelformat {
        fourcc::NV12M | fourcc::NV21M => {
            sizes[0] = y;
            sizes[1] = cw.saturating_mul(ch).saturating_mul(2);
            (sizes, 2)
        }
        fourcc::YUV420M | fourcc::YVU420M => {
            sizes[0] = y;
            sizes[1] = cw.saturating_mul(ch);
            sizes[2] = sizes[1];
            (sizes, 3)
        }
        fourcc::NV16M | fourcc::NV61M => {
            sizes[0] = y;
            sizes[1] = cw.saturating_mul(height).saturating_mul(2);
            (sizes, 2)
        }
        fourcc::YUV422M | fourcc::YVU422M => {
            sizes[0] = y;
            sizes[1] = cw.saturating_mul(height);
            sizes[2] = sizes[1];
            (sizes, 3)
        }
        fourcc::YUV444M | fourcc::YVU444M => {
            sizes[0] = y;
            sizes[1] = y;
            sizes[2] = y;
            (sizes, 3)
        }
        _ => { sizes[0] = fourcc::sizeimage(pixelformat, width, height, 0); (sizes, 1) }
    }
}

/// Render a whole frame into `dst`. Returns the bytes written. # C: O(pixels)
pub fn render_frame(pixelformat: u32, width: u32, height: u32, shift: u32, dst: &mut [u8]) -> usize {
    render_frame_motion(pixelformat, width, height, shift, 0, Motion { horizontal: 0, vertical: 0 }, dst)
}

pub fn render_frame_motion(pixelformat: u32, width: u32, height: u32, shift: u32,
                            frame: u32, motion: Motion, dst: &mut [u8]) -> usize {
    render_frame_motion_map(pixelformat, width, height, shift, frame, motion, None, dst)
}

/// Render a frame while sampling `source` into `dest`, leaving pixels outside
/// the compose rectangle black. The output geometry remains the negotiated
/// format, as it does for a scaler-backed capture node.
pub fn render_frame_motion_window(pixelformat: u32, width: u32, height: u32, shift: u32,
                                   frame: u32, motion: Motion, map: RenderMap,
                                   dst: &mut [u8]) -> usize {
    render_frame_motion_map(pixelformat, width, height, shift, frame, motion, Some(map), dst)
}

fn render_frame_motion_map(pixelformat: u32, width: u32, height: u32, shift: u32,
                            frame: u32, motion: Motion, map: Option<RenderMap>, dst: &mut [u8]) -> usize {
    if matches!(pixelformat, fourcc::NV12 | fourcc::NV21 | fourcc::NV16 |
        fourcc::NV24 | fourcc::NV42 |
        fourcc::NV12M | fourcc::NV21M | fourcc::YUV420 | fourcc::YVU420 |
        fourcc::YUV420M | fourcc::YVU420M | fourcc::YUV422P | fourcc::YUV422M |
        fourcc::NV16M | fourcc::NV61M | fourcc::YVU422M |
        fourcc::YUV444M | fourcc::YVU444M) {
        return render_planar(pixelformat, width, height, shift, frame, motion, map, dst);
    }
    let stride = fourcc::bytesperline(pixelformat, width) as usize;
    if stride == 0 { return 0; }
    let mut written = 0usize;
    for y in 0..height {
        if written + stride > dst.len() { break; }
        let n = render_line_at_map(pixelformat, width, height, y, shift, frame, motion, map,
                                    &mut dst[written..written + stride]);
        if n == 0 { return written; }
        written += stride;
    }
    written
}

/// Render the single-planar layouts Linux calls packed planar formats. The
/// queue still owns one plane; the chroma sections simply follow the luma
/// section inside that plane.
pub(super) fn render_planar(pixelformat: u32, width: u32, height: u32, shift: u32,
                 frame: u32, motion: Motion, map: Option<RenderMap>, dst: &mut [u8]) -> usize {
    let y_bytes = width as usize * height as usize;
    let full_chroma = matches!(pixelformat, fourcc::NV24 | fourcc::NV42 |
        fourcc::YUV444M | fourcc::YVU444M);
    let chroma_width = if full_chroma { width as usize } else { width.div_ceil(2) as usize };
    let chroma_height = height.div_ceil(2) as usize;
    let total = fourcc::sizeimage(pixelformat, width, height, 0) as usize;
    if dst.len() < total { return 0; }
    for y in 0..height {
        for x in 0..width {
            dst[y as usize * width as usize + x as usize] =
                luma(sample_pixel(x, y, width, height, shift, frame, motion, map));
        }
    }
    let rows = if matches!(pixelformat, fourcc::NV16 | fourcc::NV61 | fourcc::NV24 |
        fourcc::NV42 | fourcc::YUV422P | fourcc::YUV444M | fourcc::YVU444M) {
        height as usize
    } else {
        chroma_height
    };
    let chroma_bytes = chroma_width * rows;
    let sample = |x: usize, y: usize| {
        let px = (if full_chroma { x } else { x * 2 })
            .min(width.saturating_sub(1) as usize) as u32;
        let py = (y * if rows == height as usize { 1 } else { 2 })
            .min(height.saturating_sub(1) as usize) as u32;
        let c = sample_pixel(px, py, width, height, shift, frame, motion, map);
        (chroma_u(c), chroma_v(c))
    };
    match pixelformat {
        fourcc::NV12 | fourcc::NV21 | fourcc::NV16 | fourcc::NV61 |
        fourcc::NV24 | fourcc::NV42 | fourcc::NV12M | fourcc::NV21M |
        fourcc::NV16M | fourcc::NV61M => {
            let start = y_bytes;
            for y in 0..rows {
                for x in 0..chroma_width {
                    let (u, v) = sample(x, y);
                    let at = start + (y * chroma_width + x) * 2;
                    if matches!(pixelformat, fourcc::NV12 | fourcc::NV12M | fourcc::NV16 |
                        fourcc::NV24) {
                        dst[at..at + 2].copy_from_slice(&[u, v]);
                    }
                    else if matches!(pixelformat, fourcc::NV21 | fourcc::NV21M | fourcc::NV42 |
                        fourcc::NV61 | fourcc::NV61M) {
                        dst[at..at + 2].copy_from_slice(&[v, u]);
                    }
                    else { dst[at..at + 2].copy_from_slice(&[u, v]); }
                }
            }
        }
        fourcc::YUV420 | fourcc::YVU420 | fourcc::YUV420M | fourcc::YVU420M => {
            let first = y_bytes;
            let second = first + chroma_bytes;
            for y in 0..chroma_height {
                for x in 0..chroma_width {
                    let (u, v) = sample(x, y);
                    let at = y * chroma_width + x;
                    let yuv = matches!(pixelformat, fourcc::YUV420 | fourcc::YUV420M);
                    dst[first + at] = if yuv { u } else { v };
                    dst[second + at] = if yuv { v } else { u };
                }
            }
        }
        fourcc::YUV422P | fourcc::YUV422M | fourcc::YVU422M |
        fourcc::YUV444M | fourcc::YVU444M => {
            let first = y_bytes;
            let second = first + chroma_bytes;
            for y in 0..height as usize {
                for x in 0..chroma_width {
                    let (u, v) = sample(x, y);
                    let at = y * chroma_width + x;
                    let yuv = matches!(pixelformat, fourcc::YUV422P | fourcc::YUV422M |
                        fourcc::YUV444M);
                    dst[first + at] = if yuv { u } else { v };
                    dst[second + at] = if yuv { v } else { u };
                }
            }
        }
        _ => return 0,
    }
    total
}
