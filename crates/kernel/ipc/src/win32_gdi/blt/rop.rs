//! Ternary raster truth table and stretch sampling; 31fk§4.

/// Stretch modes, by the values the shared device-context attribute holds.
pub type StretchMode = u32;
pub const BLACKONWHITE: StretchMode = 1;
pub const WHITEONBLACK: StretchMode = 2;
pub const COLORONCOLOR: StretchMode = 3;
pub const HALFTONE: StretchMode = 4;
const RGB_MASK: u32 = 0x00ff_ffff;
/// A code whose source rows differ from its no-source rows reads its source.
const SOURCE_PAIR_MASK: u8 = 0x33;

/// Apply one ternary truth table bitwise across three XRGB operands. The
/// table's bit index is the pattern, source and destination bits in that
/// order, most significant first. # C: O(1)
pub fn rop3(table: u8, pattern: u32, source: u32, destination: u32) -> u32 {
    let mut out = 0;
    for index in 0..8u32 {
        if table & (1 << index) == 0 { continue; }
        let operand = |value: u32, set: bool| if set { value } else { !value };
        out |= operand(pattern, index & 4 != 0) & operand(source, index & 2 != 0) & operand(destination, index & 1 != 0);
    }
    out & RGB_MASK
}

/// A code reads its source when its truth table distinguishes the two source
/// values. # C: O(1)
pub fn rop_uses_source(code: u32) -> bool {
    let table = (code >> 16) as u8;
    (table >> 2) & SOURCE_PAIR_MASK != table & SOURCE_PAIR_MASK
}

/// Clamp one signed extent to a bound, taking a negative size as an extent
/// running back from the origin. # C: O(1)
pub fn signed_span(origin: i32, size: i32, low: i32, high: i32) -> (i32, i32) {
    let start = i64::from(origin);
    let end = start + i64::from(size);
    let (start, end) = if size < 0 { (end + 1, start + 1) } else { (start, end) };
    (start.clamp(i64::from(low), i64::from(high)) as i32, end.clamp(i64::from(low), i64::from(high)) as i32)
}

/// One immutable source raster and the rule for reducing several source pixels
/// to one destination pixel.
pub struct Sampler<'a> { pub pixels: &'a [u32], pub width: i32, pub height: i32, pub mode: StretchMode }

impl Sampler<'_> {
    fn pixel(&self, x: i32, y: i32) -> Option<u32> {
        if x < 0 || y < 0 || x >= self.width || y >= self.height { return None; }
        self.pixels.get(y as usize * self.width as usize + x as usize).copied()
    }

    /// Source range one destination column or row maps to, in source units.
    /// A destination extent never maps to an empty source range. # C: O(1)
    fn span(destination: i32, origin: i32, extent: i32, source_origin: i32, source_extent: i32) -> (i32, i32) {
        let offset = i64::from(destination) - i64::from(origin);
        let scale = |value: i64| i64::from(source_origin) + value * i64::from(source_extent) / i64::from(extent);
        let (first, last) = (scale(offset), scale(offset + 1));
        let (low, high) = if first <= last { (first, last) } else { (last, first) };
        (low as i32, (high.max(low + 1)) as i32)
    }

    /// Sample the source rectangle covering one destination pixel. Shrinking
    /// merges the covered source pixels the way the destination's stretch mode
    /// asks: keeping dark pixels, keeping light ones, taking the first, or
    /// averaging them. # C: O(covered source pixels)
    pub fn at(&self, dst: super::BltCoords, src: super::BltCoords, x: i32, y: i32) -> Option<u32> {
        if dst.width == 0 || dst.height == 0 { return None; }
        let (left, right) = Self::span(x, dst.x, dst.width, src.x, src.width);
        let (top, bottom) = Self::span(y, dst.y, dst.height, src.y, src.height);
        if self.mode == COLORONCOLOR { return self.pixel(left, top); }
        let mut merged: Option<u32> = None;
        let (mut sum, mut count) = ([0u64; 3], 0u64);
        for row in top..bottom { for column in left..right {
            let Some(pixel) = self.pixel(column, row) else { continue; };
            count += 1;
            sum[0] += u64::from((pixel >> 16) & 0xff); sum[1] += u64::from((pixel >> 8) & 0xff); sum[2] += u64::from(pixel & 0xff);
            merged = Some(match (merged, self.mode) {
                (None, _) => pixel,
                (Some(previous), BLACKONWHITE) => previous & pixel,
                (Some(previous), WHITEONBLACK) => previous | pixel,
                (Some(previous), _) => previous,
            });
        } }
        if self.mode == HALFTONE && count > 0 {
            let channel = |index: usize| ((sum[index] / count) & 0xff) as u32;
            return Some((channel(0) << 16) | (channel(1) << 8) | channel(2));
        }
        merged
    }
}

#[cfg(test)]
#[path = "../tests/blt_rop.rs"]
mod tests;
