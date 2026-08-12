//! RTL8125 four-object DMA ownership transaction.

/// Ordered mapping rollback for descriptor and packet storage.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum DmaStep { MapRxDesc, MapTxDesc, MapRxData, MapTxData, UnmapRxDesc, UnmapTxDesc, UnmapRxData }

/// Return rollback operations for the first failed map attempt. # C: O(1)
pub const fn rollback_after_failed_map(mapped: usize) -> [Option<DmaStep>; 3] {
    match mapped { 0 => [None, None, None], 1 => [Some(DmaStep::UnmapRxDesc), None, None], 2 => [Some(DmaStep::UnmapRxDesc), Some(DmaStep::UnmapTxDesc), None], _ => [Some(DmaStep::UnmapRxDesc), Some(DmaStep::UnmapTxDesc), Some(DmaStep::UnmapRxData)] }
}

#[cfg(test)]
mod tests { use super::*; #[test] fn mapping_failure_retires_exact_prior_dma_owners() { assert_eq!(rollback_after_failed_map(0), [None; 3]); assert_eq!(rollback_after_failed_map(1)[0], Some(DmaStep::UnmapRxDesc)); assert_eq!(rollback_after_failed_map(2)[1], Some(DmaStep::UnmapTxDesc)); assert_eq!(rollback_after_failed_map(3)[2], Some(DmaStep::UnmapRxData)); } }
