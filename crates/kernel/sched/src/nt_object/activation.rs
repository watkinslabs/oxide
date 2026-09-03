//! Native activation-context lifetime state.

use alloc::sync::Arc;
use core::sync::atomic::{AtomicU32, Ordering};

pub struct NtActivationContext { references: AtomicU32 }

impl NtActivationContext {
    pub fn new() -> Arc<Self> { Arc::new(Self { references: AtomicU32::new(1) }) }

    /// Acquire one user or activation-stack reference. # C: O(1)
    pub fn add_ref(&self) -> bool {
        self.references.fetch_update(Ordering::AcqRel, Ordering::Acquire,
            |current| if current == 0 { None } else { current.checked_add(1) }).is_ok()
    }

    /// Release one reference and report whether object identity can retire.
    /// # C: O(1)
    pub fn release(&self) -> Option<bool> {
        self.references.fetch_update(Ordering::AcqRel, Ordering::Acquire,
            |current| current.checked_sub(1)).ok().map(|previous| previous == 1)
    }

    pub fn references(&self) -> u32 { self.references.load(Ordering::Acquire) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn references_retire_only_after_the_final_owner() {
        let context = NtActivationContext::new();
        assert_eq!(context.references(), 1);
        assert!(context.add_ref());
        assert_eq!(context.release(), Some(false));
        assert_eq!(context.release(), Some(true));
        assert_eq!(context.release(), None);
        assert!(!context.add_ref());
    }
}
