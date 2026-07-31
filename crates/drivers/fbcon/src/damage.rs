// Damage accumulation for the fbcon surface. The VT layer already renders
// only the cells that changed (dirty rows + the cursor cell); this records
// WHICH pixels those writes touched so the flush sink can upload that
// rectangle instead of the whole frame, the way Linux fbcon feeds a merged
// damage clip to the display driver rather than re-posting the scanout.
//
// Pure geometry over pixel coordinates — no renderer, surface or device
// state — so the merge and clamp rules are host-testable without a
// framebuffer.

/// A damaged pixel region of a `stride_px`-wide surface: columns `x..x+w`
/// by scanlines `y..y+h`. Handed to a flush sink alongside the full pixel
/// buffer, which the sink indexes at `stride_px`.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct FlushRect {
    pub x: u32,
    pub y: u32,
    pub w: u32,
    pub h: u32,
    /// Pixels per scanline of the buffer the rect indexes into.
    pub stride_px: u32,
}

impl FlushRect {
    /// Byte offset of the rect's top-left pixel within a `stride_px`-wide,
    /// 4-bytes-per-pixel buffer. # C: O(1)
    pub fn byte_offset(&self) -> u64 {
        (self.y as u64 * self.stride_px as u64 + self.x as u64) * BYTES_PER_PIXEL
    }
}

/// Bytes per pixel of the 0x00RRGGBB surface the renderer produces.
pub const BYTES_PER_PIXEL: u64 = 4;

/// Bounding box of every pixel written since the last [`Damage::take`].
/// Half-open in both axes; empty when either axis has no extent.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Damage {
    x0: u32,
    y0: u32,
    x1: u32,
    y1: u32,
}

impl Damage {
    /// Nothing damaged. # C: O(1)
    pub const fn empty() -> Self {
        Damage { x0: u32::MAX, y0: u32::MAX, x1: 0, y1: 0 }
    }

    /// No pixel is recorded as damaged. # C: O(1)
    pub fn is_empty(&self) -> bool {
        self.x0 >= self.x1 || self.y0 >= self.y1
    }

    /// Merge the pixel region `x..x+w` by `y..y+h` into the bounding box.
    /// Zero-extent regions are ignored. # C: O(1)
    pub fn add(&mut self, x: u32, y: u32, w: u32, h: u32) {
        if w == 0 || h == 0 {
            return;
        }
        self.x0 = self.x0.min(x);
        self.y0 = self.y0.min(y);
        self.x1 = self.x1.max(x.saturating_add(w));
        self.y1 = self.y1.max(y.saturating_add(h));
    }

    /// Forget all recorded damage. # C: O(1)
    pub fn clear(&mut self) {
        *self = Damage::empty();
    }

    /// Take the accumulated box clamped to a `stride_px` x `height_px`
    /// surface, leaving nothing damaged. `None` when the clamped box is
    /// empty — the sink then has no work and must not be called.
    /// # C: O(1)
    pub fn take(&mut self, stride_px: u32, height_px: u32) -> Option<FlushRect> {
        let taken = *self;
        self.clear();
        if taken.is_empty() {
            return None;
        }
        let x1 = taken.x1.min(stride_px);
        let y1 = taken.y1.min(height_px);
        let (x0, y0) = (taken.x0, taken.y0);
        if x0 >= x1 || y0 >= y1 {
            return None;
        }
        Some(FlushRect { x: x0, y: y0, w: x1 - x0, h: y1 - y0, stride_px })
    }
}

impl Default for Damage {
    fn default() -> Self {
        Damage::empty()
    }
}

#[cfg(test)]
mod tests;
