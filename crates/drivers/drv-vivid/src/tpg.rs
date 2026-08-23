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
        fourcc::RGB565 => {
            let need = width as usize * 2;
            if dst.len() < need { return 0; }
            for x in 0..width {
                let c = pixel(x, y, width, height, shift, frame, motion);
                let v = ((c.r as u16 & 0xf8) << 8) | ((c.g as u16 & 0xfc) << 3) | (c.b as u16 >> 3);
                dst[x as usize * 2..x as usize * 2 + 2].copy_from_slice(&v.to_le_bytes());
            }
            need
        }
        fourcc::YUYV => render_yuv(width, height, y, shift, frame, motion, dst, true),
        fourcc::UYVY => render_yuv(width, height, y, shift, frame, motion, dst, false),
        _ => 0,
    }
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
              dst: &mut [u8], luma_first: bool) -> usize {
    let need = width as usize * 2;
    if dst.len() < need { return 0; }
    let mut x = 0u32;
    while x < width {
        let left = pixel(x, y, width, height, shift, frame, motion);
        let right = pixel((x + 1).min(width - 1), y, width, height, shift, frame, motion);
        let (y0, y1) = (luma(left), luma(right));
        let (u, v) = (chroma_u(left), chroma_v(left));
        let at = x as usize * 2;
        if luma_first { dst[at] = y0; dst[at + 1] = u; }
        else { dst[at] = u; dst[at + 1] = y0; }
        if x + 1 < width {
            if luma_first { dst[at + 2] = y1; dst[at + 3] = v; }
            else { dst[at + 2] = v; dst[at + 3] = y1; }
        }
        x += 2;
    }
    need
}

/// Bytes one whole frame of the pattern occupies for this format and size.
/// # C: O(1)
pub fn frame_bytes(pixelformat: u32, width: u32, height: u32) -> usize {
    fourcc::bytesperline(pixelformat, width) as usize * height as usize
}

/// Render a whole frame into `dst`. Returns the bytes written. # C: O(pixels)
pub fn render_frame(pixelformat: u32, width: u32, height: u32, shift: u32, dst: &mut [u8]) -> usize {
    render_frame_motion(pixelformat, width, height, shift, 0, Motion { horizontal: 0, vertical: 0 }, dst)
}

pub fn render_frame_motion(pixelformat: u32, width: u32, height: u32, shift: u32,
                            frame: u32, motion: Motion, dst: &mut [u8]) -> usize {
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
