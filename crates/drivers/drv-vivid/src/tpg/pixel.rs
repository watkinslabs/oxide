#![allow(unused_imports)]
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

pub(super) fn sample_pixel(x: u32, y: u32, width: u32, height: u32, shift: u32, frame: u32,
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

