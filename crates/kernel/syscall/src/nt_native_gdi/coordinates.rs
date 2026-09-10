//! Logical MM_TEXT coordinates become device coordinates before native rasterization.
use super::{TextRequest, OPAQUE, CLIPPED};

impl TextRequest {
    /// Translate positions and active rectangles once; preserve lengths, advances and logical current position.
    /// Invalid device coordinates fail before any native callback or pixel mutation. # C: O(1)
    pub fn translated(mut self, origin: (i64, i64)) -> Option<Self> {
        let point = |x: i32, y: i32| Some((i32::try_from(i64::from(x).checked_add(origin.0)?).ok()?,
            i32::try_from(i64::from(y).checked_add(origin.1)?).ok()?));
        if self.count != 0 { (self.x, self.y) = point(self.x, self.y)?; }
        if self.has_rect != 0 && self.flags & (OPAQUE | CLIPPED) != 0 {
            let (left, top) = point(self.rect[0], self.rect[1])?;
            let (right, bottom) = point(self.rect[2], self.rect[3])?;
            self.rect = [left, top, right, bottom];
        }
        Some(self)
    }
}


#[cfg(test)]
#[path = "tests/coordinates.rs"]
mod tests;
