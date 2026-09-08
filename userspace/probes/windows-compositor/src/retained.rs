//! The window surface the backend keeps between frames.
//!
//! A frame carries only its damaged sub-rectangle, so the surface a window
//! shows is held here and updated in place. That is also what lets a re-expose
//! be answered without asking the application to paint again, and what keeps
//! the caret overlay out of the pixels the application drew.
use crate::geometry::Rect;
use crate::protocol::{Frame, TransportError, MAX_PIXELS};

pub(crate) struct Retained { pub width: u32, pub height: u32, pixels: Vec<u32>, held: Option<Rect> }

impl Retained {
    /// A window's whole extent. The storage exists at once; the pixels do
    /// not. A surface holds only what has been presented into it, and what a
    /// frame has never covered is not black, it is unknown: the window owns
    /// those pixels and is the only thing that can state them.
    /// # C: O(width * height)
    pub(crate) fn new(width: u32, height: u32) -> Result<Self, TransportError> {
        let count = usize::try_from(width).ok().and_then(|w| usize::try_from(height).ok().and_then(|h| w.checked_mul(h)))
            .filter(|count| *count > 0 && *count <= MAX_PIXELS).ok_or(TransportError::InvalidFrame)?;
        let mut pixels = Vec::new();
        pixels.try_reserve_exact(count).map_err(|_| TransportError::InvalidFrame)?;
        pixels.resize(count, 0xff00_0000);
        Ok(Self { width, height, pixels, held: None })
    }

    /// Whether the surface holds every pixel of `rect` - whether a frame has
    /// covered all of it. A surface asked for pixels it was never given
    /// answers with storage, not with the window: restoring that over an
    /// exposure paints the window's own content away. # C: O(1)
    pub(crate) fn holds(&self, rect: Rect) -> bool {
        self.held.is_some_and(|h| rect.left >= h.left && rect.top >= h.top && rect.right <= h.right && rect.bottom <= h.bottom)
    }

    /// The rectangle the surface holds pixels for, for a test that reads the
    /// display back and compares only what the surface claims.
    #[cfg(test)]
    pub(crate) fn held_for_test(&self) -> Option<Rect> { self.held }

    /// Write one frame's sub-rectangle into the surface at the origin the
    /// frame names, leaving every other pixel as the last frame left it, and
    /// record that the surface now holds those pixels.
    /// # C: O(damage width * damage height)
    pub(crate) fn apply(&mut self, frame: &Frame) -> Result<(), TransportError> {
        if frame.width != self.width || frame.height != self.height { return Err(TransportError::InvalidFrame); }
        let row = usize::try_from(frame.damage.right - frame.damage.left).map_err(|_| TransportError::InvalidFrame)?;
        for (index, y) in (frame.damage.top..frame.damage.bottom).enumerate() {
            let source = frame.row(index).ok_or(TransportError::InvalidFrame)?;
            let start = (y as usize).checked_mul(self.width as usize).and_then(|v| v.checked_add(frame.damage.left as usize))
                .ok_or(TransportError::InvalidFrame)?;
            let end = start.checked_add(row).ok_or(TransportError::InvalidFrame)?;
            self.pixels.get_mut(start..end).ok_or(TransportError::InvalidFrame)?.copy_from_slice(source);
        }
        let d = frame.damage;
        self.held = Some(match self.held { Some(h) => Rect { left: h.left.min(d.left), top: h.top.min(d.top), right: h.right.max(d.right), bottom: h.bottom.max(d.bottom) }, None => d });
        Ok(())
    }

    /// Every retained pixel, for a test that compares the surface with what
    /// the display holds for the same window.
    #[cfg(test)]
    pub(crate) fn pixels_for_test(&self) -> Vec<u32> { self.pixels.clone() }

    /// A horizontal run of retained pixels. # C: O(1)
    pub(crate) fn run(&self, y: usize, x: usize, width: usize) -> Option<&[u32]> {
        let start = y.checked_mul(self.width as usize)?.checked_add(x)?;
        self.pixels.get(start..start.checked_add(width)?)
    }
}

#[cfg(test)]
#[path = "tests/retained.rs"]
mod tests;
