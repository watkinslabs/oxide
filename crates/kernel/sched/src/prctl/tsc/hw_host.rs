// Host / non-kernel target: no counter-trap control register exists. The mode
// is still stored and reported, so the decision tests above stay meaningful.

/// # SAFETY: no-op.
/// # C: O(1)
pub unsafe fn set_trapped(on: bool) { let _ = on; }
