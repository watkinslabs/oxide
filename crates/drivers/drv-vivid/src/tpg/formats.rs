#![allow(unused_imports)]
use v4l2::uapi::fourcc;
use super::frame::render_planar;
use super::pixel::{chroma_u, chroma_v, luma, sample_pixel};
use super::{Motion, RenderMap, Rgb};

/// Render one line of the pattern into `dst`, which must be at least the
/// format's stride. Returns the bytes written, or zero for a format this
/// generator does not produce.
/// # C: O(width)
pub fn render_line(pixelformat: u32, width: u32, shift: u32, dst: &mut [u8]) -> usize {
    render_line_at(pixelformat, width, 1, 0, shift, 0, Motion { horizontal: 0, vertical: 0 }, dst)
}

pub fn render_line_at(pixelformat: u32, width: u32, height: u32, y: u32, shift: u32,
                      frame: u32, motion: Motion, dst: &mut [u8]) -> usize {
    render_line_at_map(pixelformat, width, height, y, shift, frame, motion, None, dst)
}

pub(super) fn render_line_at_map(pixelformat: u32, width: u32, height: u32, y: u32, shift: u32,
                      frame: u32, motion: Motion, map: Option<RenderMap>, dst: &mut [u8]) -> usize {
    match pixelformat {
        fourcc::RGB24 => render_triples(width, height, y, shift, frame, motion, map, dst, |c| [c.r, c.g, c.b]),
        fourcc::BGR24 => render_triples(width, height, y, shift, frame, motion, map, dst, |c| [c.b, c.g, c.r]),
        fourcc::BGR666 => render_bgr666(width, height, y, shift, frame, motion, map, dst),
        fourcc::HSV24 => render_triples(width, height, y, shift, frame, motion, map, dst, hsv),
        fourcc::GREY => {
            let need = width as usize;
            if dst.len() < need { return 0; }
            for x in 0..width { dst[x as usize] = luma(sample_pixel(x, y, width, height, shift, frame, motion, map)); }
            need
        }
        fourcc::RGB332 => {
            let need = width as usize;
            if dst.len() < need { return 0; }
            for x in 0..width {
                let c = sample_pixel(x, y, width, height, shift, frame, motion, map);
                dst[x as usize] = (c.r & 0xe0) | ((c.g & 0xe0) >> 3) | (c.b >> 6);
            }
            need
        }
        fourcc::Y12 => render_luma12(width, height, y, shift, frame, motion, map, dst),
        fourcc::Y10 => render_luma16(width, height, y, shift, frame, motion, map, dst, 10, false),
        fourcc::Y16 => render_luma16(width, height, y, shift, frame, motion, map, dst, 16, false),
        fourcc::Y16_BE => render_luma16(width, height, y, shift, frame, motion, map, dst, 16, true),
        fourcc::NV12 | fourcc::NV21 | fourcc::NV16 | fourcc::NV61 | fourcc::NV24 | fourcc::NV42 |
        fourcc::NV12M | fourcc::NV21M | fourcc::NV16M | fourcc::NV61M |
        fourcc::YUV420 | fourcc::YVU420 | fourcc::YUV420M | fourcc::YVU420M |
        fourcc::YUV422P | fourcc::YUV422M | fourcc::YVU422M |
        fourcc::YUV444M | fourcc::YVU444M => {
            render_luma_line(width, height, y, shift, frame, motion, map, dst)
        }
        fourcc::RGB565 | fourcc::RGB565X => {
            let need = width as usize * 2;
            if dst.len() < need { return 0; }
            for x in 0..width {
                let c = sample_pixel(x, y, width, height, shift, frame, motion, map);
                let v = ((c.r as u16 & 0xf8) << 8) | ((c.g as u16 & 0xfc) << 3) | (c.b as u16 >> 3);
                let bytes = if pixelformat == fourcc::RGB565 {
                    v.to_le_bytes()
                } else {
                    v.to_be_bytes()
                };
                dst[x as usize * 2..x as usize * 2 + 2].copy_from_slice(&bytes);
            }
            need
        }
        fourcc::YUV555 => render_yuv16(width, height, y, shift, frame, motion, map, dst, 0),
        fourcc::YUV565 => render_yuv16(width, height, y, shift, frame, motion, map, dst, 1),
        fourcc::YUV444 => render_yuv16(width, height, y, shift, frame, motion, map, dst, 2),
        fourcc::RGB444 | fourcc::ARGB444 | fourcc::XRGB444 | fourcc::RGBA444 |
        fourcc::RGBX444 | fourcc::ABGR444 | fourcc::XBGR444 | fourcc::BGRA444 |
        fourcc::BGRX444 | fourcc::RGB555 | fourcc::ARGB555 | fourcc::XRGB555 |
        fourcc::RGBA555 | fourcc::RGBX555 | fourcc::ABGR555 | fourcc::XBGR555 |
        fourcc::BGRA555 | fourcc::BGRX555 | fourcc::RGB555X | fourcc::ARGB555X |
        fourcc::XRGB555X => render_rgb16(pixelformat, width, height, y, shift, frame, motion, map, dst),
        fourcc::YUV32 | fourcc::AYUV32 | fourcc::XYUV32 | fourcc::VUYA32 |
        fourcc::VUYX32 | fourcc::YUVA32 | fourcc::YUVX32 =>
            render_yuv32(pixelformat, width, height, y, shift, frame, motion, map, dst),
        fourcc::RGB32 | fourcc::RGBA32 | fourcc::RGBX32 | fourcc::BGR32 |
        fourcc::ABGR32 | fourcc::XBGR32 | fourcc::BGRA32 | fourcc::BGRX32 =>
            render_rgb32(pixelformat, width, height, y, shift, frame, motion, map, dst),
        fourcc::HSV32 => render_hsv32(width, height, y, shift, frame, motion, map, dst),
        fourcc::SBGGR8 | fourcc::SGBRG8 | fourcc::SGRBG8 | fourcc::SRGGB8 =>
            render_bayer8(pixelformat, width, height, y, shift, frame, motion, map, dst),
        fourcc::SBGGR10 | fourcc::SGBRG10 | fourcc::SGRBG10 | fourcc::SRGGB10 =>
            render_bayer10(pixelformat, width, height, y, shift, frame, motion, map, dst),
        fourcc::SBGGR12 | fourcc::SGBRG12 | fourcc::SGRBG12 | fourcc::SRGGB12 =>
            render_bayer12(pixelformat, width, height, y, shift, frame, motion, map, dst),
        fourcc::SBGGR16 | fourcc::SGBRG16 | fourcc::SGRBG16 | fourcc::SRGGB16 =>
            render_bayer16(pixelformat, width, height, y, shift, frame, motion, map, dst),
        fourcc::XRGB32 => render_quads(width, height, y, shift, frame, motion, map, dst, false),
        fourcc::ARGB32 => render_quads(width, height, y, shift, frame, motion, map, dst, true),
        fourcc::YUYV => render_yuv(width, height, y, shift, frame, motion, map, dst, 0),
        fourcc::UYVY => render_yuv(width, height, y, shift, frame, motion, map, dst, 1),
        fourcc::YVYU => render_yuv(width, height, y, shift, frame, motion, map, dst, 2),
        fourcc::VYUY => render_yuv(width, height, y, shift, frame, motion, map, dst, 3),
        _ => 0,
    }
}

fn render_bgr666(width: u32, height: u32, y: u32, shift: u32, frame: u32, motion: Motion,
                 map: Option<RenderMap>, dst: &mut [u8]) -> usize {
    let need = width as usize * 4;
    if dst.len() < need { return 0; }
    for x in 0..width {
        let c = sample_pixel(x, y, width, height, shift, frame, motion, map);
        let at = x as usize * 4;
        dst[at] = (c.b << 2) | (c.g >> 4);
        dst[at + 1] = (c.g << 4) | (c.r >> 2);
        dst[at + 2] = c.r << 6;
        dst[at + 3] = 0;
    }
    need
}

fn render_bayer8(pixelformat: u32, width: u32, height: u32, y: u32, shift: u32,
                 frame: u32, motion: Motion, map: Option<RenderMap>, dst: &mut [u8]) -> usize {
    let need = width as usize;
    if dst.len() < need { return 0; }
    for x in 0..width {
        let c = sample_pixel(x, y, width, height, shift, frame, motion, map);
        dst[x as usize] = match pixelformat {
            fourcc::SBGGR8 => match (y & 1, x & 1) {
                (0, 0) => c.b, (0, 1) | (1, 0) => c.g, (1, 1) => c.r,
                _ => unreachable!(),
            },
            fourcc::SGBRG8 => match (y & 1, x & 1) {
                (0, 0) | (1, 1) => c.g, (0, 1) => c.b, (1, 0) => c.r,
                _ => unreachable!(),
            },
            fourcc::SGRBG8 => match (y & 1, x & 1) {
                (0, 0) | (1, 1) => c.g, (0, 1) => c.r, (1, 0) => c.b,
                _ => unreachable!(),
            },
            fourcc::SRGGB8 => match (y & 1, x & 1) {
                (0, 0) => c.r, (0, 1) | (1, 0) => c.g, (1, 1) => c.b,
                _ => unreachable!(),
            },
            _ => return 0,
        };
    }
    need
}

fn render_bayer10(pixelformat: u32, width: u32, height: u32, y: u32, shift: u32,
                  frame: u32, motion: Motion, map: Option<RenderMap>, dst: &mut [u8]) -> usize {
    let need = width as usize * 2;
    if dst.len() < need { return 0; }
    for x in 0..width {
        let c = sample_pixel(x, y, width, height, shift, frame, motion, map);
        let v = match pixelformat {
            fourcc::SBGGR10 => match (y & 1, x & 1) {
                (0, 0) => c.b, (0, 1) | (1, 0) => c.g, (1, 1) => c.r,
                _ => unreachable!(),
            },
            fourcc::SGBRG10 => match (y & 1, x & 1) {
                (0, 0) | (1, 1) => c.g, (0, 1) => c.b, (1, 0) => c.r,
                _ => unreachable!(),
            },
            fourcc::SGRBG10 => match (y & 1, x & 1) {
                (0, 0) | (1, 1) => c.g, (0, 1) => c.r, (1, 0) => c.b,
                _ => unreachable!(),
            },
            fourcc::SRGGB10 => match (y & 1, x & 1) {
                (0, 0) => c.r, (0, 1) | (1, 0) => c.g, (1, 1) => c.b,
                _ => unreachable!(),
            },
            _ => return 0,
        };
        let value = ((v as u16) << 2) | ((v as u16) >> 6);
        let at = x as usize * 2;
        dst[at..at + 2].copy_from_slice(&value.to_le_bytes());
    }
    need
}

fn render_bayer12(pixelformat: u32, width: u32, height: u32, y: u32, shift: u32,
                  frame: u32, motion: Motion, map: Option<RenderMap>, dst: &mut [u8]) -> usize {
    let need = width as usize * 2;
    if dst.len() < need { return 0; }
    for x in 0..width {
        let c = sample_pixel(x, y, width, height, shift, frame, motion, map);
        let v = match pixelformat {
            fourcc::SBGGR12 => match (y & 1, x & 1) {
                (0, 0) => c.b, (0, 1) | (1, 0) => c.g, (1, 1) => c.r,
                _ => unreachable!(),
            },
            fourcc::SGBRG12 => match (y & 1, x & 1) {
                (0, 0) | (1, 1) => c.g, (0, 1) => c.b, (1, 0) => c.r,
                _ => unreachable!(),
            },
            fourcc::SGRBG12 => match (y & 1, x & 1) {
                (0, 0) | (1, 1) => c.g, (0, 1) => c.r, (1, 0) => c.b,
                _ => unreachable!(),
            },
            fourcc::SRGGB12 => match (y & 1, x & 1) {
                (0, 0) => c.r, (0, 1) | (1, 0) => c.g, (1, 1) => c.b,
                _ => unreachable!(),
            },
            _ => return 0,
        };
        let value = ((v as u16) << 4) | ((v as u16) >> 4);
        let at = x as usize * 2;
        dst[at..at + 2].copy_from_slice(&value.to_le_bytes());
    }
    need
}

fn render_bayer16(pixelformat: u32, width: u32, height: u32, y: u32, shift: u32,
                  frame: u32, motion: Motion, map: Option<RenderMap>, dst: &mut [u8]) -> usize {
    let need = width as usize * 2;
    if dst.len() < need { return 0; }
    for x in 0..width {
        let c = sample_pixel(x, y, width, height, shift, frame, motion, map);
        let v = match pixelformat {
            fourcc::SBGGR16 => match (y & 1, x & 1) {
                (0, 0) => c.b, (0, 1) | (1, 0) => c.g, (1, 1) => c.r,
                _ => unreachable!(),
            },
            fourcc::SGBRG16 => match (y & 1, x & 1) {
                (0, 0) | (1, 1) => c.g, (0, 1) => c.b, (1, 0) => c.r,
                _ => unreachable!(),
            },
            fourcc::SGRBG16 => match (y & 1, x & 1) {
                (0, 0) | (1, 1) => c.g, (0, 1) => c.r, (1, 0) => c.b,
                _ => unreachable!(),
            },
            fourcc::SRGGB16 => match (y & 1, x & 1) {
                (0, 0) => c.r, (0, 1) | (1, 0) => c.g, (1, 1) => c.b,
                _ => unreachable!(),
            },
            _ => return 0,
        };
        let at = x as usize * 2;
        dst[at..at + 2].copy_from_slice(&(v as u16).to_le_bytes());
    }
    need
}

fn render_yuv16(width: u32, height: u32, y: u32, shift: u32, frame: u32, motion: Motion,
                map: Option<RenderMap>, dst: &mut [u8], kind: u8) -> usize {
    let need = width as usize * 2;
    if dst.len() < need { return 0; }
    for x in 0..width {
        let c = sample_pixel(x, y, width, height, shift, frame, motion, map);
        let yy = luma(c);
        let u = chroma_u(c);
        let v = chroma_v(c);
        let value = match kind {
            // Linux first reduces each component to the format's bit depth,
            // then writes the split fields in little-endian byte order.
            0 => {
                let y5 = yy >> 3;
                let u5 = u >> 3;
                let v5 = v >> 3;
                (((0x80 | (y5 << 2) | (u5 >> 3)) as u16) << 8)
                    | ((u5 as u16) << 5) | v5 as u16
            }
            1 => {
                let y5 = yy >> 3;
                let u6 = u >> 2;
                let v5 = v >> 3;
                (((y5 << 3) | (u6 >> 3)) as u16) << 8
                    | ((u6 as u16) << 5) | v5 as u16
            }
            _ => {
                let y4 = yy >> 4;
                let u4 = u >> 4;
                let v4 = v >> 4;
                (((0xf0 | y4) as u16) << 8) | ((u4 as u16) << 4) | v4 as u16
            }
        };
        dst[x as usize * 2..x as usize * 2 + 2].copy_from_slice(&value.to_le_bytes());
    }
    need
}

fn render_rgb16(pixelformat: u32, width: u32, height: u32, y: u32, shift: u32,
                frame: u32, motion: Motion, map: Option<RenderMap>, dst: &mut [u8]) -> usize {
    let need = width as usize * 2;
    if dst.len() < need { return 0; }
    for x in 0..width {
        let c = sample_pixel(x, y, width, height, shift, frame, motion, map);
        let r = c.r as u16;
        let g = c.g as u16;
        let b = c.b as u16;
        let alpha = if matches!(pixelformat, fourcc::ARGB444 | fourcc::ARGB555 |
            fourcc::RGBA444 | fourcc::RGBA555 | fourcc::ABGR444 | fourcc::ABGR555 |
            fourcc::BGRA444 | fourcc::BGRA555 | fourcc::ARGB555X) { 0xff } else { 0 };
        let bytes = match pixelformat {
            fourcc::RGB444 | fourcc::XRGB444 | fourcc::ARGB444 =>
                [((g << 4) | b) as u8, ((alpha & 0xf0) | r) as u8],
            fourcc::RGBX444 | fourcc::RGBA444 =>
                [((b << 4) | (alpha >> 4)) as u8, ((r << 4) | g) as u8],
            fourcc::XBGR444 | fourcc::ABGR444 =>
                [((g << 4) | r) as u8, ((alpha & 0xf0) | b) as u8],
            fourcc::BGRX444 | fourcc::BGRA444 =>
                [((r << 4) | (alpha >> 4)) as u8, ((b << 4) | g) as u8],
            fourcc::RGB555 | fourcc::XRGB555 | fourcc::ARGB555 =>
                [((g << 5) | b) as u8, ((alpha & 0x80) | (r << 2) | (g >> 3)) as u8],
            fourcc::RGBX555 | fourcc::RGBA555 =>
                [((g << 6) | (b << 1) | ((alpha & 0x80) >> 7)) as u8,
                 ((r << 3) | (g >> 2)) as u8],
            fourcc::XBGR555 | fourcc::ABGR555 =>
                [((g << 5) | r) as u8, ((alpha & 0x80) | (b << 2) | (g >> 3)) as u8],
            fourcc::BGRX555 | fourcc::BGRA555 =>
                [((g << 6) | (r << 1) | ((alpha & 0x80) >> 7)) as u8,
                 ((b << 3) | (g >> 2)) as u8],
            fourcc::RGB555X | fourcc::XRGB555X | fourcc::ARGB555X =>
                [((alpha & 0x80) | (r << 2) | (g >> 3)) as u8, ((g << 5) | b) as u8],
            _ => return 0,
        };
        dst[x as usize * 2..x as usize * 2 + 2].copy_from_slice(&bytes);
    }
    need
}

fn render_yuv32(pixelformat: u32, width: u32, height: u32, y: u32, shift: u32,
                frame: u32, motion: Motion, map: Option<RenderMap>, dst: &mut [u8]) -> usize {
    let need = width as usize * 4;
    if dst.len() < need { return 0; }
    for x in 0..width {
        let c = sample_pixel(x, y, width, height, shift, frame, motion, map);
        let yv = luma(c);
        let u = chroma_u(c);
        let v = chroma_v(c);
        let alpha = if matches!(pixelformat, fourcc::YUV32 | fourcc::AYUV32 |
            fourcc::VUYA32 | fourcc::YUVA32) { 255 } else { 0 };
        let bytes = match pixelformat {
            fourcc::VUYA32 | fourcc::VUYX32 => [v, u, yv, alpha],
            fourcc::YUVA32 | fourcc::YUVX32 => [yv, u, v, alpha],
            _ => [alpha, yv, u, v],
        };
        dst[x as usize * 4..x as usize * 4 + 4].copy_from_slice(&bytes);
    }
    need
}

fn render_rgb32(pixelformat: u32, width: u32, height: u32, y: u32, shift: u32,
                frame: u32, motion: Motion, map: Option<RenderMap>, dst: &mut [u8]) -> usize {
    let need = width as usize * 4;
    if dst.len() < need { return 0; }
    for x in 0..width {
        let c = sample_pixel(x, y, width, height, shift, frame, motion, map);
        let alpha = if matches!(pixelformat, fourcc::RGB32 | fourcc::BGR32 |
            fourcc::RGBX32 | fourcc::XBGR32 | fourcc::BGRX32) { 0 } else { 255 };
        let bytes = match pixelformat {
            fourcc::RGB32 | fourcc::RGBA32 | fourcc::RGBX32 => [alpha, c.r, c.g, c.b],
            fourcc::BGR32 | fourcc::ABGR32 | fourcc::XBGR32 => [c.b, c.g, c.r, alpha],
            fourcc::BGRA32 | fourcc::BGRX32 => [alpha, c.b, c.g, c.r],
            _ => return 0,
        };
        dst[x as usize * 4..x as usize * 4 + 4].copy_from_slice(&bytes);
    }
    need
}

fn hsv(c: Rgb) -> [u8; 3] {
    let r = (c.r >> 4) as i32;
    let g = (c.g >> 4) as i32;
    let b = (c.b >> 4) as i32;
    let max = r.max(g).max(b);
    let min = r.min(g).min(b);
    if max == 0 { return [0, 0, 0]; }
    let diff = max - min;
    let sat = ((255 * diff + max / 2) / max) as u8;
    if sat == 0 { return [0, sat, max as u8]; }
    let third_size = 85i32;
    let (aux, third) = if max == r { (g - b, 0) } else if max == g { (b - r, third_size) }
        else { (r - g, third_size * 2) };
    let mut hue = (aux * (third_size / 2) + diff / 2) / diff + third;
    hue &= 0xff;
    [hue as u8, sat, max as u8]
}

fn render_hsv32(width: u32, height: u32, y: u32, shift: u32, frame: u32,
                motion: Motion, map: Option<RenderMap>, dst: &mut [u8]) -> usize {
    let need = width as usize * 4;
    if dst.len() < need { return 0; }
    for x in 0..width {
        let [h, s, v] = hsv(sample_pixel(x, y, width, height, shift, frame, motion, map));
        dst[x as usize * 4..x as usize * 4 + 4].copy_from_slice(&[0, h, s, v]);
    }
    need
}

fn render_luma16(width: u32, height: u32, y: u32, shift: u32, frame: u32, motion: Motion,
                 map: Option<RenderMap>, dst: &mut [u8], bits: u32, big_endian: bool) -> usize {
    let need = width as usize * 2;
    if dst.len() < need { return 0; }
    for x in 0..width {
        let luma = luma(sample_pixel(x, y, width, height, shift, frame, motion, map));
        let value = if bits == 10 {
            ((luma as u16) << 2) & 0x03ff
        } else {
            if luma == 0xff { 0xffff } else { (luma as u16) << 8 }
        };
        let bytes = if big_endian { value.to_be_bytes() } else { value.to_le_bytes() };
        dst[x as usize * 2..x as usize * 2 + 2].copy_from_slice(&bytes);
    }
    need
}

fn render_luma12(width: u32, height: u32, y: u32, shift: u32, frame: u32, motion: Motion,
                 map: Option<RenderMap>, dst: &mut [u8]) -> usize {
    let need = width as usize * 2;
    if dst.len() < need { return 0; }
    for x in 0..width {
        let luma = luma(sample_pixel(x, y, width, height, shift, frame, motion, map));
        let bytes = ((luma as u16) << 4).to_le_bytes();
        dst[x as usize * 2..x as usize * 2 + 2].copy_from_slice(&bytes);
    }
    need
}

fn render_quads(width: u32, height: u32, y: u32, shift: u32, frame: u32, motion: Motion,
                map: Option<RenderMap>, dst: &mut [u8], alpha: bool) -> usize {
    let need = width as usize * 4;
    if dst.len() < need { return 0; }
    for x in 0..width as usize {
        let c = sample_pixel(x as u32, y, width, height, shift, frame, motion, map);
        let at = x * 4;
        // Linux's little-endian TPG stores X/alpha first for XRGB/ARGB and
        // BGR components after it.
        dst[at] = if alpha { 255 } else { 0 };
        dst[at + 1] = c.b;
        dst[at + 2] = c.g;
        dst[at + 3] = c.r;
    }
    need
}

fn render_triples(width: u32, height: u32, y: u32, shift: u32, frame: u32, motion: Motion,
                  map: Option<RenderMap>, dst: &mut [u8], order: impl Fn(Rgb) -> [u8; 3]) -> usize {
    let need = width as usize * 3;
    if dst.len() < need { return 0; }
    for x in 0..width as usize {
        let bytes = order(sample_pixel(x as u32, y, width, height, shift, frame, motion, map));
        dst[x * 3..x * 3 + 3].copy_from_slice(&bytes);
    }
    need
}

/// A packed 4:2:2 line. Two pixels share one chroma pair, taken from the left
/// pixel of each pair — the same subsampling a camera does, so a bar boundary
/// falling between the two shows the left bar's colour rather than a blend the
/// pattern never contained.
fn render_yuv(width: u32, height: u32, y: u32, shift: u32, frame: u32, motion: Motion,
             map: Option<RenderMap>, dst: &mut [u8], order: u8) -> usize {
    let need = width as usize * 2;
    if dst.len() < need { return 0; }
    let mut x = 0u32;
    while x < width {
        let left = sample_pixel(x, y, width, height, shift, frame, motion, map);
        let right = sample_pixel((x + 1).min(width - 1), y, width, height, shift, frame, motion, map);
        let (y0, y1) = (luma(left), luma(right));
        let (u, v) = (chroma_u(left), chroma_v(left));
        let at = x as usize * 2;
        match order {
            0 => { dst[at] = y0; dst[at + 1] = u; }
            1 => { dst[at] = u; dst[at + 1] = y0; }
            2 => { dst[at] = y0; dst[at + 1] = v; }
            _ => { dst[at] = v; dst[at + 1] = y0; }
        }
        if x + 1 < width {
            match order {
                0 => { dst[at + 2] = y1; dst[at + 3] = v; }
                1 => { dst[at + 2] = v; dst[at + 3] = y1; }
                2 => { dst[at + 2] = y1; dst[at + 3] = u; }
                _ => { dst[at + 2] = u; dst[at + 3] = y1; }
            }
        }
        x += 2;
    }
    need
}

fn render_luma_line(width: u32, height: u32, y: u32, shift: u32, frame: u32,
                    motion: Motion, map: Option<RenderMap>, dst: &mut [u8]) -> usize {
    let need = width as usize;
    if dst.len() < need { return 0; }
    for x in 0..width {
        dst[x as usize] = luma(sample_pixel(x, y, width, height, shift, frame, motion, map));
    }
    need
}
