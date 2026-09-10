//! The area of a surface that frames have actually covered.
//!
//! A surface's storage exists at its whole extent from the moment it is
//! allocated, but its pixels do not: only what a frame has presented is the
//! window's own content. Which part that is has to be the real area, not an
//! enclosing rectangle — two disjoint paints do not make the space between
//! them the window's, and serving an exposure from there puts the colour of
//! empty storage over pixels the window owns. The backend also stops
//! forwarding an exposure it believes it served, so over-claiming does not
//! merely paint one bad frame: nothing ever asks the window to repaint, and
//! the damage stays for the life of the window.
//!
//! Under-claiming is safe and costs one repaint, so the bound below drops the
//! oldest area rather than widening what is claimed.
use crate::geometry::Rect;

/// Areas retained before the oldest is dropped. A window paints in a handful
/// of regions per frame; past this the set is worth less than the repaint it
/// saves.
pub(crate) const MAX_AREAS: usize = 32;

#[derive(Default)]
pub(crate) struct Coverage { areas: Vec<Rect> }

/// The parts of `a` no part of `b` covers, appended to `out`. An untouched
/// `a` appends itself. # C: O(1), at most four pieces
pub(crate) fn subtract(a: Rect, b: Rect, out: &mut Vec<Rect>) {
    if b.right <= a.left || b.left >= a.right || b.bottom <= a.top || b.top >= a.bottom { out.push(a); return; }
    if a.top < b.top { out.push(Rect { top: a.top, bottom: b.top, ..a }); }
    if b.bottom < a.bottom { out.push(Rect { top: b.bottom, bottom: a.bottom, ..a }); }
    let (top, bottom) = (a.top.max(b.top), a.bottom.min(b.bottom));
    if a.left < b.left { out.push(Rect { left: a.left, right: b.left, top, bottom }); }
    if b.right < a.right { out.push(Rect { left: b.right, right: a.right, top, bottom }); }
}

impl Coverage {
    /// Record that a frame covered `rect`. An area already covered by the new
    /// one is dropped, so a window that repaints the same region does not
    /// grow the set. # C: O(areas)
    pub(crate) fn cover(&mut self, rect: Rect) {
        self.areas.retain(|a| !contains(rect, *a));
        if self.areas.iter().any(|a| contains(*a, rect)) { return; }
        if self.areas.len() >= MAX_AREAS { self.areas.remove(0); }
        self.areas.push(rect);
    }

    /// Whether every pixel of `rect` has been covered. # C: O(areas) pieces
    pub(crate) fn holds(&self, rect: Rect) -> bool {
        let mut work = alloc_one(rect);
        for area in &self.areas {
            if work.is_empty() { return true; }
            let mut next = Vec::with_capacity(work.len());
            for piece in work.drain(..) { subtract(piece, *area, &mut next); }
            work = next;
        }
        work.is_empty()
    }

    /// Exact retained areas; gaps never become replayable pixels. # C: O(1)
    pub(crate) fn areas(&self) -> &[Rect] { &self.areas }

    /// Nothing has been covered. # C: O(1)
    pub(crate) fn is_empty(&self) -> bool { self.areas.is_empty() }

    /// The areas covered, for a test that states exactly what a surface was
    /// given rather than what encloses it. # C: O(areas)
    #[cfg(test)]
    pub(crate) fn areas_for_test(&self) -> Vec<Rect> { self.areas.clone() }
}

fn alloc_one(rect: Rect) -> Vec<Rect> { if rect.right > rect.left && rect.bottom > rect.top { vec![rect] } else { Vec::new() } }

/// Whether `outer` covers every pixel of `inner`. # C: O(1)
fn contains(outer: Rect, inner: Rect) -> bool {
    inner.left >= outer.left && inner.top >= outer.top && inner.right <= outer.right && inner.bottom <= outer.bottom
}

#[cfg(test)]
#[path = "tests/coverage.rs"]
mod tests;
