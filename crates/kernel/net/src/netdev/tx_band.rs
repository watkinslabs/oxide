// Which transmit band a packet's priority puts it in.
//
// This is the whole of what `SO_PRIORITY` — and the per-message override that
// mirrors it — decides: the default transmit discipline is three FIFO bands,
// drained strictly in order, and the priority selects one of them. Without a
// band the option is admitted, stored, and never asked about again.
//
// Kept ungated and free of the queue it drives so the mapping itself is a
// hosted test rather than a boot.

/// The largest priority the band map is indexed by; every value is reduced
/// into the map by this mask.
pub const TC_PRIO_MAX: u32 = 15;

/// Three bands, drained highest first.
pub const TX_BANDS: usize = 3;

/// Priority-to-band map of the default transmit discipline.
const PRIO_TO_BAND: [u8; TC_PRIO_MAX as usize + 1] =
    [1, 2, 2, 2, 1, 2, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1];

/// The band a packet of this priority is queued in. Band 0 drains before band
/// 1, which drains before band 2. # C: O(1)
pub fn band_for(priority: u32) -> usize {
    PRIO_TO_BAND[(priority & TC_PRIO_MAX) as usize] as usize
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The interactive band (`TC_PRIO_INTERACTIVE`, and the bulk value beside
    /// it) is the one an unprivileged sender may ask for, and it is the one
    /// that drains first.
    #[test]
    fn the_interactive_priorities_are_the_ones_that_drain_first() {
        assert_eq!(band_for(6), 0);
        assert_eq!(band_for(7), 0);
        for priority in [0u32, 4, 8, 9, 10, 11, 12, 13, 14, 15] {
            assert_eq!(band_for(priority), 1, "priority {priority}");
        }
        for priority in [1u32, 2, 3, 5] {
            assert_eq!(band_for(priority), 2, "priority {priority}");
        }
    }

    /// A priority above the map's range is reduced into it rather than
    /// selecting a band that does not exist.
    #[test]
    fn a_priority_past_the_map_is_reduced_into_it() {
        for priority in 0..64u32 {
            assert_eq!(band_for(priority), band_for(priority & TC_PRIO_MAX));
            assert!(band_for(priority) < TX_BANDS);
        }
        assert_eq!(band_for(u32::MAX), band_for(TC_PRIO_MAX));
    }
}
