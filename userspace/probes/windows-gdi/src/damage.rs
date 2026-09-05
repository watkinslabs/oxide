use crate::Rect;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum DamageError { Empty, Reversed }

/// One coalesced half-open client damage region. # C: O(1) storage
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct DamageRegion { rect: Option<Rect> }

impl DamageRegion {
    /// Start with no pending damage. # C: O(1)
    pub const fn empty() -> Self { Self { rect: None } }

    /// Build a pending region, rejecting malformed or empty rectangles. # C: O(1)
    pub fn from_rect(rect: Rect) -> Result<Self, DamageError> {
        let mut region = Self::empty();
        region.add(rect)?;
        Ok(region)
    }

    /// Add one client rectangle and coalesce it with pending damage. # C: O(1)
    pub fn add(&mut self, rect: Rect) -> Result<(), DamageError> {
        if rect.right < rect.left || rect.bottom < rect.top { return Err(DamageError::Reversed); }
        if rect.right == rect.left || rect.bottom == rect.top { return Err(DamageError::Empty); }
        self.rect = Some(match self.rect {
            Some(current) => Rect {
                left: current.left.min(rect.left), top: current.top.min(rect.top),
                right: current.right.max(rect.right), bottom: current.bottom.max(rect.bottom),
            },
            None => rect,
        });
        Ok(())
    }

    /// Return the coalesced region without clearing it. # C: O(1)
    pub const fn get(&self) -> Option<Rect> { self.rect }

    /// Consume the coalesced region after a successful presentation. # C: O(1)
    pub const fn take(&mut self) -> Option<Rect> {
        let rect = self.rect;
        self.rect = None;
        rect
    }
}

impl Default for DamageRegion {
    fn default() -> Self { Self::empty() }
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: Rect = Rect { left: 4, top: 8, right: 12, bottom: 20 };

    #[test]
    fn fresh_region_is_empty_and_take_is_idempotent() {
        let mut region = DamageRegion::empty();
        assert_eq!(region.get(), None);
        assert_eq!(region.take(), None);
        assert_eq!(region.take(), None);
    }

    #[test]
    fn from_rect_preserves_half_open_edges() {
        assert_eq!(DamageRegion::from_rect(A).unwrap().get(), Some(A));
        assert_eq!(DamageRegion::from_rect(Rect { left: -8, top: -4, right: 0, bottom: 1 }).unwrap().get(), Some(Rect { left: -8, top: -4, right: 0, bottom: 1 }));
    }

    #[test]
    fn adjacent_and_disjoint_invalidations_share_one_bounding_region() {
        let mut region = DamageRegion::from_rect(A).unwrap();
        region.add(Rect { left: 12, top: 2, right: 16, bottom: 8 }).unwrap();
        region.add(Rect { left: 0, top: 24, right: 3, bottom: 28 }).unwrap();
        assert_eq!(region.get(), Some(Rect { left: 0, top: 2, right: 16, bottom: 28 }));
    }

    #[test]
    fn zero_width_or_height_is_rejected_without_mutating_pending_damage() {
        let mut region = DamageRegion::from_rect(A).unwrap();
        assert_eq!(region.add(Rect { left: 4, top: 8, right: 4, bottom: 20 }), Err(DamageError::Empty));
        assert_eq!(region.add(Rect { left: 4, top: 8, right: 12, bottom: 8 }), Err(DamageError::Empty));
        assert_eq!(region.get(), Some(A));
    }

    #[test]
    fn reversed_edges_are_distinguished_from_empty_damage() {
        let mut region = DamageRegion::empty();
        assert_eq!(region.add(Rect { left: 9, top: 0, right: 8, bottom: 1 }), Err(DamageError::Reversed));
        assert_eq!(region.add(Rect { left: 0, top: 9, right: 1, bottom: 8 }), Err(DamageError::Reversed));
        assert_eq!(region.get(), None);
    }

    #[test]
    fn take_clears_only_after_the_caller_requests_consumption() {
        let mut region = DamageRegion::from_rect(A).unwrap();
        assert_eq!(region.get(), Some(A));
        assert_eq!(region.take(), Some(A));
        assert_eq!(region.get(), None);
        region.add(Rect { left: 1, top: 2, right: 3, bottom: 4 }).unwrap();
        assert_eq!(region.take(), Some(Rect { left: 1, top: 2, right: 3, bottom: 4 }));
    }
}
