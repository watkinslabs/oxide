//! The test-pattern generator: eight vertical colour bars, scrolling by one
//! bar per frame so a viewer can tell a live stream from a frozen one.
//!
//! Pure arithmetic over a byte slice. Nothing here knows about buffers,
//! devices or the kernel, which is why every pixel rule below is checked by a
//! hosted test.

use v4l2::uapi::fourcc;

/// One bar's colour, as full-range 8-bit red, green and blue.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Rgb { pub r: u8, pub g: u8, pub b: u8 }

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Motion { pub horizontal: i8, pub vertical: i8 }

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
    match pixelformat {
        fourcc::RGB24 => render_triples(width, height, y, shift, frame, motion, dst, |c| [c.r, c.g, c.b]),
        fourcc::BGR24 => render_triples(width, height, y, shift, frame, motion, dst, |c| [c.b, c.g, c.r]),
        fourcc::GREY => {
            let need = width as usize;
            if dst.len() < need { return 0; }
            for x in 0..width { dst[x as usize] = luma(pixel(x, y, width, height, shift, frame, motion)); }
            need
        }
        fourcc::Y10 => render_luma16(width, height, y, shift, frame, motion, dst, 10, false),
        fourcc::Y16 => render_luma16(width, height, y, shift, frame, motion, dst, 16, false),
        fourcc::Y16_BE => render_luma16(width, height, y, shift, frame, motion, dst, 16, true),
        fourcc::NV12 | fourcc::NV21 | fourcc::NV16 |
        fourcc::YUV420 | fourcc::YVU420 | fourcc::YUV422P => {
            render_luma_line(width, height, y, shift, frame, motion, dst)
        }
        fourcc::RGB565 | fourcc::RGB565X => {
            let need = width as usize * 2;
            if dst.len() < need { return 0; }
            for x in 0..width {
                let c = pixel(x, y, width, height, shift, frame, motion);
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
        fourcc::XRGB32 => render_quads(width, height, y, shift, frame, motion, dst, false),
        fourcc::ARGB32 => render_quads(width, height, y, shift, frame, motion, dst, true),
        fourcc::YUYV => render_yuv(width, height, y, shift, frame, motion, dst, 0),
        fourcc::UYVY => render_yuv(width, height, y, shift, frame, motion, dst, 1),
        fourcc::YVYU => render_yuv(width, height, y, shift, frame, motion, dst, 2),
        fourcc::VYUY => render_yuv(width, height, y, shift, frame, motion, dst, 3),
        _ => 0,
    }
}

fn render_luma16(width: u32, height: u32, y: u32, shift: u32, frame: u32, motion: Motion,
                 dst: &mut [u8], bits: u32, big_endian: bool) -> usize {
    let need = width as usize * 2;
    if dst.len() < need { return 0; }
    for x in 0..width {
        let luma = luma(pixel(x, y, width, height, shift, frame, motion));
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

fn render_quads(width: u32, height: u32, y: u32, shift: u32, frame: u32, motion: Motion,
                dst: &mut [u8], alpha: bool) -> usize {
    let need = width as usize * 4;
    if dst.len() < need { return 0; }
    for x in 0..width as usize {
        let c = pixel(x as u32, y, width, height, shift, frame, motion);
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
                  dst: &mut [u8], order: impl Fn(Rgb) -> [u8; 3]) -> usize {
    let need = width as usize * 3;
    if dst.len() < need { return 0; }
    for x in 0..width as usize {
        let bytes = order(pixel(x as u32, y, width, height, shift, frame, motion));
        dst[x * 3..x * 3 + 3].copy_from_slice(&bytes);
    }
    need
}

/// A packed 4:2:2 line. Two pixels share one chroma pair, taken from the left
/// pixel of each pair — the same subsampling a camera does, so a bar boundary
/// falling between the two shows the left bar's colour rather than a blend the
/// pattern never contained.
fn render_yuv(width: u32, height: u32, y: u32, shift: u32, frame: u32, motion: Motion,
              dst: &mut [u8], order: u8) -> usize {
    let need = width as usize * 2;
    if dst.len() < need { return 0; }
    let mut x = 0u32;
    while x < width {
        let left = pixel(x, y, width, height, shift, frame, motion);
        let right = pixel((x + 1).min(width - 1), y, width, height, shift, frame, motion);
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

/// Render a whole frame into `dst`. Returns the bytes written. # C: O(pixels)
pub fn render_frame(pixelformat: u32, width: u32, height: u32, shift: u32, dst: &mut [u8]) -> usize {
    render_frame_motion(pixelformat, width, height, shift, 0, Motion { horizontal: 0, vertical: 0 }, dst)
}

pub fn render_frame_motion(pixelformat: u32, width: u32, height: u32, shift: u32,
                            frame: u32, motion: Motion, dst: &mut [u8]) -> usize {
    if matches!(pixelformat, fourcc::NV12 | fourcc::NV21 | fourcc::NV16 |
        fourcc::YUV420 | fourcc::YVU420 | fourcc::YUV422P) {
        return render_planar(pixelformat, width, height, shift, frame, motion, dst);
    }
    let stride = fourcc::bytesperline(pixelformat, width) as usize;
    if stride == 0 { return 0; }
    let mut written = 0usize;
    for y in 0..height {
        if written + stride > dst.len() { break; }
        let n = render_line_at(pixelformat, width, height, y, shift, frame, motion,
                                &mut dst[written..written + stride]);
        if n == 0 { return written; }
        written += stride;
    }
    written
}

fn render_luma_line(width: u32, height: u32, y: u32, shift: u32, frame: u32,
                    motion: Motion, dst: &mut [u8]) -> usize {
    let need = width as usize;
    if dst.len() < need { return 0; }
    for x in 0..width {
        dst[x as usize] = luma(pixel(x, y, width, height, shift, frame, motion));
    }
    need
}

/// Render the single-planar layouts Linux calls packed planar formats. The
/// queue still owns one plane; the chroma sections simply follow the luma
/// section inside that plane.
fn render_planar(pixelformat: u32, width: u32, height: u32, shift: u32,
                 frame: u32, motion: Motion, dst: &mut [u8]) -> usize {
    let y_bytes = width as usize * height as usize;
    let chroma_width = width.div_ceil(2) as usize;
    let chroma_height = height.div_ceil(2) as usize;
    let total = fourcc::sizeimage(pixelformat, width, height, 0) as usize;
    if dst.len() < total { return 0; }
    for y in 0..height {
        for x in 0..width {
            dst[y as usize * width as usize + x as usize] =
                luma(pixel(x, y, width, height, shift, frame, motion));
        }
    }
    let rows = if matches!(pixelformat, fourcc::NV16 | fourcc::YUV422P) {
        height as usize
    } else {
        chroma_height
    };
    let chroma_bytes = chroma_width * rows;
    let sample = |x: usize, y: usize| {
        let px = (x * 2).min(width.saturating_sub(1) as usize) as u32;
        let py = (y * if rows == height as usize { 1 } else { 2 })
            .min(height.saturating_sub(1) as usize) as u32;
        let c = pixel(px, py, width, height, shift, frame, motion);
        (chroma_u(c), chroma_v(c))
    };
    match pixelformat {
        fourcc::NV12 | fourcc::NV21 | fourcc::NV16 => {
            let start = y_bytes;
            for y in 0..rows {
                for x in 0..chroma_width {
                    let (u, v) = sample(x, y);
                    let at = start + (y * chroma_width + x) * 2;
                    if pixelformat == fourcc::NV12 { dst[at..at + 2].copy_from_slice(&[u, v]); }
                    else if pixelformat == fourcc::NV21 { dst[at..at + 2].copy_from_slice(&[v, u]); }
                    else { dst[at..at + 2].copy_from_slice(&[u, v]); }
                }
            }
        }
        fourcc::YUV420 | fourcc::YVU420 => {
            let first = y_bytes;
            let second = first + chroma_bytes;
            for y in 0..chroma_height {
                for x in 0..chroma_width {
                    let (u, v) = sample(x, y);
                    let at = y * chroma_width + x;
                    dst[first + at] = if pixelformat == fourcc::YUV420 { u } else { v };
                    dst[second + at] = if pixelformat == fourcc::YUV420 { v } else { u };
                }
            }
        }
        fourcc::YUV422P => {
            let first = y_bytes;
            let second = first + chroma_bytes;
            for y in 0..height as usize {
                for x in 0..chroma_width {
                    let (u, v) = sample(x, y);
                    let at = y * chroma_width + x;
                    dst[first + at] = u;
                    dst[second + at] = v;
                }
            }
        }
        _ => return 0,
    }
    total
}
