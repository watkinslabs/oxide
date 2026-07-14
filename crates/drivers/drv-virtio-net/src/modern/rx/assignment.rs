use core::sync::atomic::{AtomicU64, Ordering};

pub(in crate::modern) const INITIAL_GENERATION: u64 = 1;

pub(in crate::modern) struct RxAssignments {
    current: AtomicU64,
    descriptors: alloc::vec::Vec<AtomicU64>,
}

impl RxAssignments {
    /// Create generation state for one RX queue. # C: O(descriptor_count)
    pub(in crate::modern) fn new(descriptor_count: usize) -> Self {
        let mut descriptors = alloc::vec::Vec::with_capacity(descriptor_count);
        for _ in 0..descriptor_count {
            descriptors.push(AtomicU64::new(INITIAL_GENERATION));
        }
        Self { current: AtomicU64::new(INITIAL_GENERATION), descriptors }
    }

    /// Read the assignment generation accepted by the driver. # C: O(1)
    pub(in crate::modern) fn current(&self) -> u64 {
        self.current.load(Ordering::Acquire)
    }

    /// Advance assignment after old ingress leases have drained. # C: O(1)
    pub(in crate::modern) fn retire(&self) {
        self.current.fetch_add(1, Ordering::AcqRel);
    }

    /// Locate one descriptor's posted assignment tag. # C: O(1)
    pub(in crate::modern) fn descriptor(&self, desc_id: u16) -> Option<&AtomicU64> {
        self.descriptors.get(desc_id as usize)
    }
}

/// Validate completion ownership and return the generation used on repost. # C: O(1)
pub(in crate::modern) fn completion(posted_generation: u64, expected_generation: u64,
                                    current_generation: u64) -> (bool, u64) {
    (
        expected_generation == current_generation
            && posted_generation == expected_generation,
        current_generation,
    )
}
