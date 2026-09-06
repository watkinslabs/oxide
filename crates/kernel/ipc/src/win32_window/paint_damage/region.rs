use super::{Vec, WindowError, WindowRect};
const MAX_RECTS: usize = 4096;

/// Exact pairwise-disjoint coverage; no bounding-box replacement on overflow.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PaintRegion { rects: Vec<WindowRect> }
impl PaintRegion {
    /// # C: O(1)
    pub fn from_rect(rect: WindowRect) -> Result<Self, WindowError> {
        let mut out = Self::default(); push(&mut out.rects, rect)?; Ok(out)
    }
    /// # C: O(N_rects²)
    pub fn from_rects(rects: &[WindowRect]) -> Result<Self, WindowError> {
        let mut out = Self::default();
        for rect in rects { out.union(&Self::from_rect(*rect)?)?; }
        Ok(out)
    }
    /// # C: O(1)
    pub fn rects(&self) -> &[WindowRect] { &self.rects }
    /// # C: O(1)
    pub fn is_empty(&self) -> bool { self.rects.is_empty() }
    /// # C: O(N_rects)
    pub fn bounds(&self) -> Option<WindowRect> {
        let mut iter = self.rects.iter(); let mut bounds = *iter.next()?;
        for rect in iter {
            bounds.left = bounds.left.min(rect.left); bounds.top = bounds.top.min(rect.top);
            bounds.right = bounds.right.max(rect.right); bounds.bottom = bounds.bottom.max(rect.bottom);
        }
        Some(bounds)
    }
    /// # C: O(N_rects)
    pub fn try_copy(&self) -> Result<Self, WindowError> {
        let mut rects = Vec::new(); rects.try_reserve(self.rects.len()).map_err(|_| WindowError::NoMemory)?;
        rects.extend_from_slice(&self.rects); Ok(Self { rects })
    }
    /// # C: O(N_rects)
    pub fn clipped(&self, clip: WindowRect) -> Result<Self, WindowError> {
        let mut out = Self::default();
        for rect in &self.rects { if let Some(rect) = intersection(*rect, clip) { push(&mut out.rects, rect)?; } }
        Ok(out)
    }
    /// # C: O(N_rects)
    pub fn translated(&self, dx: i32, dy: i32) -> Result<Self, WindowError> {
        let mut out = Self::default();
        for r in &self.rects {
            let left = r.left.checked_add(dx).ok_or(WindowError::InvalidParent)?;
            let right = r.right.checked_add(dx).ok_or(WindowError::InvalidParent)?;
            let top = r.top.checked_add(dy).ok_or(WindowError::InvalidParent)?;
            let bottom = r.bottom.checked_add(dy).ok_or(WindowError::InvalidParent)?;
            push(&mut out.rects, WindowRect { left, top, right, bottom })?;
        }
        Ok(out)
    }
    /// Reflect coverage around the canonical client width. # C: O(N_rects)
    pub fn mirrored(&self, width: i32) -> Result<Self, WindowError> {
        let mut out = Self::default();
        for r in &self.rects {
            let left = width.checked_sub(r.right).ok_or(WindowError::InvalidParent)?;
            let right = width.checked_sub(r.left).ok_or(WindowError::InvalidParent)?;
            push(&mut out.rects, WindowRect { left, right, top: r.top, bottom: r.bottom })?;
        }
        Ok(out)
    }
    /// Commit only after exact subtraction succeeds. # C: O(N_rects * N_cuts * fragments)
    pub fn subtract(&mut self, other: &Self) -> Result<(), WindowError> {
        let mut next = self.try_copy()?;
        for cut in &other.rects {
            let mut rects = Vec::new();
            for rect in next.rects { subtract_one(&mut rects, rect, *cut)?; }
            next.rects = rects;
        }
        *self = next; Ok(())
    }
    /// Union preserves exact holes and never duplicates overlapping coverage. # C: O(N_rects² * fragments)
    pub fn union(&mut self, other: &Self) -> Result<(), WindowError> {
        let mut added = other.try_copy()?; added.subtract(self)?;
        if self.rects.len().saturating_add(added.rects.len()) > MAX_RECTS { return Err(WindowError::NoMemory); }
        self.rects.try_reserve(added.rects.len()).map_err(|_| WindowError::NoMemory)?;
        self.rects.extend(added.rects); Ok(())
    }
}
fn intersection(a: WindowRect, b: WindowRect) -> Option<WindowRect> {
    let r = WindowRect { left: a.left.max(b.left), top: a.top.max(b.top), right: a.right.min(b.right), bottom: a.bottom.min(b.bottom) };
    (r.left < r.right && r.top < r.bottom).then_some(r)
}
fn push(out: &mut Vec<WindowRect>, r: WindowRect) -> Result<(), WindowError> {
    if r.left >= r.right || r.top >= r.bottom { return Ok(()); }
    if out.len() == MAX_RECTS { return Err(WindowError::NoMemory); }
    out.try_reserve(1).map_err(|_| WindowError::NoMemory)?; out.push(r); Ok(())
}
fn subtract_one(out: &mut Vec<WindowRect>, r: WindowRect, cut: WindowRect) -> Result<(), WindowError> {
    let Some(i) = intersection(r, cut) else { return push(out, r); };
    for piece in [
        WindowRect { left: r.left, top: r.top, right: r.right, bottom: i.top },
        WindowRect { left: r.left, top: i.bottom, right: r.right, bottom: r.bottom },
        WindowRect { left: r.left, top: i.top, right: i.left, bottom: i.bottom },
        WindowRect { left: i.right, top: i.top, right: r.right, bottom: i.bottom },
    ] { push(out, piece)?; }
    Ok(())
}
