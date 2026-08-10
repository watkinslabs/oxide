// How large the LPI tables are, and why it is not `1 << IDbits`.
//
// The redistributor is told a base address and an ID width; it reads one
// configuration byte per LPI and writes one pending bit per LPI, so the bytes
// strictly needed are `1 << IDbits` and `(1 << IDbits) / 8`. Neither is the
// size to allocate:
//
//   - the pending table must be 64 KiB aligned, and is architecturally sized
//     at that granule.
//   - the configuration table must ALSO be allocated at that granule, because
//     of who else reads it. A kernel started by a relocation finds LPIs still
//     enabled, adopts the tables the registers point at rather than allocating
//     its own, and rewrites the configuration table over its whole granule. A
//     table allocated at `1 << IDbits` = 16 KiB is then cleared 48 KiB past
//     its end — over memory that kernel has already given to something else,
//     which surfaces much later as a poisoned pointer in an unrelated driver.
//
// Ungated so the sizes are checkable without a machine: the interrupt
// controller itself only compiles for one target, and a size that is wrong is
// wrong in a way no test on that target would report either.

/// Granule both LPI tables are allocated, reserved and adopted at.
pub const LPI_TABLE_GRANULE: u64 = 0x1_0000;

/// Bytes to allocate for the LPI configuration table at `id_bits`.
///
/// One byte per LPI, rounded UP to the granule — never down, and never the
/// exact byte count: the size an adopting kernel assumes is the granule, so
/// anything smaller is memory it writes and nobody owns.
/// # C: O(1)
pub const fn table_bytes(id_bits: u32) -> u64 {
    let need = 1u64 << id_bits;
    need.div_ceil(LPI_TABLE_GRANULE) * LPI_TABLE_GRANULE
}

/// Buddy order of one granule, given the page size.
///
/// The order fixes the ALIGNMENT as well as the size, which is what makes the
/// allocation satisfy GICR_PENDBASER's 64 KiB requirement without a separate
/// alignment step that could disagree with it.
/// # C: O(1)
pub const fn table_order(page_bytes: u64) -> u8 {
    (LPI_TABLE_GRANULE / page_bytes).trailing_zeros() as u8
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The width this kernel configures, and the one the evidence was taken at.
    const ID_BITS: u32 = 14;

    #[test]
    fn a_table_narrower_than_the_granule_is_still_a_whole_granule() {
        // 14 bits is 16 KiB of configuration bytes. Allocating that is the
        // defect: an adopting kernel clears the full granule.
        assert_eq!(1u64 << ID_BITS, 0x4000);
        assert_eq!(table_bytes(ID_BITS), LPI_TABLE_GRANULE);
        for b in 1..=16 { assert_eq!(table_bytes(b), LPI_TABLE_GRANULE, "{b} bits still rounds up"); }
    }

    #[test]
    fn a_table_wider_than_the_granule_grows_by_whole_granules() {
        assert_eq!(table_bytes(17), 2 * LPI_TABLE_GRANULE);
        assert_eq!(table_bytes(18), 4 * LPI_TABLE_GRANULE);
        // Never rounds DOWN: every width is covered by what it returns.
        for b in 1..=24 { assert!(table_bytes(b) >= 1u64 << b, "{b} bits is not covered"); }
        for b in 1..=24 { assert_eq!(table_bytes(b) % LPI_TABLE_GRANULE, 0); }
    }

    #[test]
    fn the_order_names_the_granule_and_therefore_its_alignment() {
        assert_eq!(table_order(0x1000), 4, "64 KiB is sixteen 4 KiB pages");
        assert_eq!(0x1000u64 << table_order(0x1000), LPI_TABLE_GRANULE);
        assert_eq!(0x4000u64 << table_order(0x4000), LPI_TABLE_GRANULE);
        assert_eq!(table_order(LPI_TABLE_GRANULE), 0);
    }
}
