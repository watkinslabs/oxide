//! Alpha compositing and gradient interpolation; 31fk§4.
use alloc::vec::Vec;
use super::super::Rect;

/// The only blend operation Windows defines.
pub const AC_SRC_OVER: u8 = 0;
/// Source pixels carry premultiplied alpha in their high byte.
pub const AC_SRC_ALPHA: u8 = 1;
/// Gradient shapes, by the values the caller selects.
pub type GradientMode = u32;
pub const GRADIENT_FILL_RECT_H: GradientMode = 0;
pub const GRADIENT_FILL_RECT_V: GradientMode = 1;
pub const GRADIENT_FILL_TRIANGLE: GradientMode = 2;
const OPAQUE_ALPHA: u32 = 255;
/// Gradient vertex channels are sixteen bits wide; a colour byte is the high half.
const VERTEX_CHANNEL_SHIFT: u32 = 8;

/// The blend record a caller packs into one double word.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlendFunction { pub op: u8, pub flags: u8, pub source_constant_alpha: u8, pub alpha_format: u8 }

impl BlendFunction {
    /// Unpack the record from its double word, low byte first. # C: O(1)
    pub fn from_dword(value: u32) -> Self {
        Self { op: value as u8, flags: (value >> 8) as u8, source_constant_alpha: (value >> 16) as u8, alpha_format: (value >> 24) as u8 }
    }

    /// Source-over composite. A source carrying premultiplied alpha scales its
    /// own alpha by the constant one; otherwise the constant alpha alone
    /// weights the source. # C: O(1)
    pub fn apply(&self, source: u32, destination: u32) -> u32 {
        let constant = u32::from(self.source_constant_alpha);
        let carries_alpha = self.alpha_format & AC_SRC_ALPHA != 0;
        let source_alpha = if carries_alpha { (source >> 24) & 0xff } else { OPAQUE_ALPHA };
        let alpha = source_alpha * constant / OPAQUE_ALPHA;
        let channel = |shift: u32| {
            let src = (source >> shift) & 0xff;
            let dst = (destination >> shift) & 0xff;
            // Premultiplied source channels are already scaled by their alpha.
            let scaled = if carries_alpha { src * constant / OPAQUE_ALPHA } else { src * alpha / OPAQUE_ALPHA };
            ((scaled + dst * (OPAQUE_ALPHA - alpha) / OPAQUE_ALPHA).min(0xff)) << shift
        };
        channel(16) | channel(8) | channel(0)
    }
}

/// One gradient vertex: device position and sixteen-bit colour channels.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TriVertex { pub x: i32, pub y: i32, pub red: u16, pub green: u16, pub blue: u16, pub alpha: u16 }

impl TriVertex {
    fn xrgb(&self) -> (i64, i64, i64) {
        (i64::from(self.red >> VERTEX_CHANNEL_SHIFT), i64::from(self.green >> VERTEX_CHANNEL_SHIFT), i64::from(self.blue >> VERTEX_CHANNEL_SHIFT))
    }
}

/// One shape the caller asked to fill.
pub enum Shape { Rect { rect: Rect, vertical: bool, from: TriVertex, to: TriVertex },
    Triangle { points: [TriVertex; 3] } }

impl Shape {
    /// # C: O(1)
    pub fn bounds(&self) -> Rect {
        match self {
            Self::Rect { rect, .. } => *rect,
            Self::Triangle { points } => super::bounding(&[(points[0].x, points[0].y), (points[1].x, points[1].y), (points[2].x, points[2].y)]),
        }
    }

    /// Interpolated XRGB at one position, or nothing when the shape does not
    /// cover it. # C: O(1)
    pub fn color_at(&self, x: i32, y: i32) -> Option<u32> {
        match self {
            Self::Rect { rect, vertical, from, to } => {
                if x < rect.left || x >= rect.right || y < rect.top || y >= rect.bottom { return None; }
                let (position, origin, extent) = if *vertical { (y, rect.top, rect.bottom - rect.top) } else { (x, rect.left, rect.right - rect.left) };
                if extent <= 0 { return None; }
                let numerator = i64::from(position - origin);
                let (start, end) = (from.xrgb(), to.xrgb());
                let mix = |a: i64, b: i64| (a + (b - a) * numerator / i64::from(extent)).clamp(0, 255) as u32;
                Some((mix(start.0, end.0) << 16) | (mix(start.1, end.1) << 8) | mix(start.2, end.2))
            }
            Self::Triangle { points } => {
                let area = edge(points[0], points[1], points[2]);
                if area == 0 { return None; }
                let weights = [edge_at(points[1], points[2], x, y), edge_at(points[2], points[0], x, y), edge_at(points[0], points[1], x, y)];
                let sign = if area > 0 { 1 } else { -1 };
                if weights.iter().any(|weight| weight * sign < 0) { return None; }
                let channel = |select: fn(&TriVertex) -> i64| {
                    let sum: i64 = (0..3).map(|index| weights[index] * select(&points[index])).sum();
                    (sum / area).clamp(0, 255) as u32
                };
                Some((channel(|vertex| vertex.xrgb().0) << 16) | (channel(|vertex| vertex.xrgb().1) << 8) | channel(|vertex| vertex.xrgb().2))
            }
        }
    }
}

fn edge(a: TriVertex, b: TriVertex, c: TriVertex) -> i64 { edge_at(a, b, c.x, c.y) }

fn edge_at(a: TriVertex, b: TriVertex, x: i32, y: i32) -> i64 {
    (i64::from(b.x) - i64::from(a.x)) * (i64::from(y) - i64::from(a.y))
        - (i64::from(b.y) - i64::from(a.y)) * (i64::from(x) - i64::from(a.x))
}

/// Build the shapes a request names. Every index must name a supplied vertex,
/// and a mode past the named ones is refused. # C: O(shapes)
pub fn gradient_shapes(vertices: &[TriVertex], indexes: &[u32], mode: GradientMode) -> Option<Vec<Shape>> {
    if vertices.is_empty() || indexes.is_empty() || mode > GRADIENT_FILL_TRIANGLE { return None; }
    let stride = if mode == GRADIENT_FILL_TRIANGLE { 3 } else { 2 };
    if indexes.len() % stride != 0 { return None; }
    if indexes.iter().any(|index| *index as usize >= vertices.len()) { return None; }
    let mut shapes = Vec::new();
    shapes.try_reserve_exact(indexes.len() / stride).ok()?;
    for group in indexes.chunks_exact(stride) {
        let at = |slot: usize| vertices[group[slot] as usize];
        if stride == 3 { shapes.push(Shape::Triangle { points: [at(0), at(1), at(2)] }); continue; }
        let (from, to) = (at(0), at(1));
        shapes.push(Shape::Rect { rect: Rect { left: from.x.min(to.x), top: from.y.min(to.y), right: from.x.max(to.x), bottom: from.y.max(to.y) },
            vertical: mode == GRADIENT_FILL_RECT_V, from, to });
    }
    Some(shapes)
}

#[cfg(test)]
#[path = "../tests/blt_blend.rs"]
mod tests;
