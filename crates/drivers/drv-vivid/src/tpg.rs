//! The test-pattern generator: eight vertical colour bars, scrolling by one
//! bar per frame so a viewer can tell a live stream from a frozen one.
//!
//! Pure arithmetic over a byte slice. Nothing here knows about buffers,
//! devices or the kernel, which is why every pixel rule below is checked by a
//! hosted test.

use v4l2::format::Rect;
use v4l2::uapi::fourcc;

/// One bar's colour, as full-range 8-bit red, green and blue.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Rgb { pub r: u8, pub g: u8, pub b: u8 }

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Motion { pub horizontal: i8, pub vertical: i8 }

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct RenderMap { pub source: Rect, pub dest: Rect, pub output_width: u32, pub output_height: u32 }

const OBJECT: Rgb = Rgb { r: 128, g: 128, b: 128 };
const OBJECT_SIZE: u32 = 32;

/// The eight bars, in the order a colour-bar pattern puts them: descending
/// luminance, which is what makes the pattern useful for judging a display.
pub const BARS: &[Rgb] = &[
    Rgb { r: 255, g: 255, b: 255 },
    Rgb { r: 255, g: 255, b: 0 },
    Rgb { r: 0, g: 255, b: 255 },
    Rgb { r: 0, g: 255, b: 0 },
    Rgb { r: 255, g: 0, b: 255 },
    Rgb { r: 255, g: 0, b: 0 },
    Rgb { r: 0, g: 0, b: 255 },
    Rgb { r: 0, g: 0, b: 0 },
];

/// Which bar covers pixel column `x` of a `width`-wide frame, with the pattern
/// rotated `shift` bars to the left. # C: O(1)
pub fn bar_at(x: u32, width: u32, shift: u32) -> Rgb {
    let count = BARS.len() as u32;
    let width = width.max(1);
    // Integer arithmetic only: the bar index is the column scaled into the bar
    // count, so the boundaries land on the same columns every frame instead of
    // drifting with a rounded bar width.
    let index = ((x.min(width - 1) as u64 * count as u64) / width as u64) as u32;
    BARS[((index + shift) % count) as usize]
}

fn object_at(x: u32, y: u32, width: u32, height: u32, frame: u32, motion: Motion) -> bool {
    if width <= 1 || height <= 1 { return false; }
    fn position(frame: u32, extent: u32, velocity: i8) -> u32 {
        let size = OBJECT_SIZE.min(extent.max(1));
        let span = extent.saturating_sub(size);
        if span == 0 || velocity == 0 { return span / 2; }
        let period = span.saturating_mul(2).max(1);
        let distance = (frame as u64 * velocity.unsigned_abs() as u64 % period as u64) as u32;
        let offset = if distance > span { period - distance } else { distance };
        if velocity < 0 { span - offset } else { offset }
    }
    let ox = position(frame, width, motion.horizontal);
    let oy = position(frame, height, motion.vertical);
    x >= ox && x < ox + OBJECT_SIZE.min(width.max(1))
        && y >= oy && y < oy + OBJECT_SIZE.min(height.max(1))
}

fn pixel(x: u32, y: u32, width: u32, height: u32, shift: u32, frame: u32, motion: Motion) -> Rgb {
    if object_at(x, y, width, height, frame, motion) { OBJECT } else { bar_at(x, width, shift) }
}

fn sample_pixel(x: u32, y: u32, width: u32, height: u32, shift: u32, frame: u32,
                motion: Motion, map: Option<RenderMap>) -> Rgb {
    let Some(map) = map else { return pixel(x, y, width, height, shift, frame, motion); };
    if x < map.dest.left.max(0) as u32 || y < map.dest.top.max(0) as u32
        || x >= map.dest.left.max(0) as u32 + map.dest.width
        || y >= map.dest.top.max(0) as u32 + map.dest.height { return Rgb { r: 0, g: 0, b: 0 }; }
    let dx = x - map.dest.left.max(0) as u32;
    let dy = y - map.dest.top.max(0) as u32;
    let sx = map.source.left.max(0) as u32
        + dx.saturating_mul(map.source.width) / map.dest.width.max(1);
    let sy = map.source.top.max(0) as u32
        + dy.saturating_mul(map.source.height) / map.dest.height.max(1);
    pixel(sx.min(width.saturating_sub(1)), sy.min(height.saturating_sub(1)),
          width, height, shift, frame, motion)
}

/// Full-range BT.601 luma of a colour. # C: O(1)
pub fn luma(c: Rgb) -> u8 {
    let y = 77u32 * c.r as u32 + 150 * c.g as u32 + 29 * c.b as u32;
    (y >> 8) as u8
}

/// Full-range BT.601 blue-difference chroma, offset to unsigned. # C: O(1)
pub fn chroma_u(c: Rgb) -> u8 {
    let y = luma(c) as i32;
    (128 + ((c.b as i32 - y) * 144 >> 8)).clamp(0, 255) as u8
}

/// Full-range BT.601 red-difference chroma, offset to unsigned. # C: O(1)
pub fn chroma_v(c: Rgb) -> u8 {
    let y = luma(c) as i32;
    (128 + ((c.r as i32 - y) * 183 >> 8)).clamp(0, 255) as u8
}

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

fn render_line_at_map(pixelformat: u32, width: u32, height: u32, y: u32, shift: u32,
                      frame: u32, motion: Motion, map: Option<RenderMap>, dst: &mut [u8]) -> usize {
    match pixelformat {
        fourcc::RGB24 => render_triples(width, height, y, shift, frame, motion, map, dst, |c| [c.r, c.g, c.b]),
        fourcc::BGR24 => render_triples(width, height, y, shift, frame, motion, map, dst, |c| [c.b, c.g, c.r]),
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
        fourcc::YUV32 | fourcc::AYUV32 | fourcc::XYUV32 | fourcc::VUYA32 |
        fourcc::VUYX32 | fourcc::YUVA32 | fourcc::YUVX32 =>
            render_yuv32(pixelformat, width, height, y, shift, frame, motion, map, dst),
        fourcc::XRGB32 => render_quads(width, height, y, shift, frame, motion, map, dst, false),
        fourcc::ARGB32 => render_quads(width, height, y, shift, frame, motion, map, dst, true),
        fourcc::YUYV => render_yuv(width, height, y, shift, frame, motion, map, dst, 0),
        fourcc::UYVY => render_yuv(width, height, y, shift, frame, motion, map, dst, 1),
        fourcc::YVYU => render_yuv(width, height, y, shift, frame, motion, map, dst, 2),
        fourcc::VYUY => render_yuv(width, height, y, shift, frame, motion, map, dst, 3),
        _ => 0,
    }
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

fn render_luma_line(width: u32, height: u32, y: u32, shift: u32, frame: u32,
                    motion: Motion, map: Option<RenderMap>, dst: &mut [u8]) -> usize {
    let need = width as usize;
    if dst.len() < need { return 0; }
    for x in 0..width {
        dst[x as usize] = luma(sample_pixel(x, y, width, height, shift, frame, motion, map));
    }
    need
}

/// Render the single-planar layouts Linux calls packed planar formats. The
/// queue still owns one plane; the chroma sections simply follow the luma
/// section inside that plane.
fn render_planar(pixelformat: u32, width: u32, height: u32, shift: u32,
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
