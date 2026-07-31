// Host-testable GICv3 interrupt-group (GICD_IGROUPR) encoding.
//
// A GICv3 with a single security state (GICD_CTLR.DS==1) delivers Group 0
// interrupts as FIQ and Non-secure Group 1 interrupts as IRQ. The reset value
// of GICD_IGROUPRn is IMPLEMENTATION DEFINED and is zero (= Group 0) on the
// virt machine, so an SPI left at its reset group is signalled on the FIQ
// vector and never reaches the IRQ dispatcher. Distributor bring-up therefore
// has to declare every SPI as Non-secure Group 1 before enabling the groups.
//
// SGIs/PPIs carry the same requirement in the per-CPU redistributor
// (GICR_IGROUPR0) — that one is already programmed per line by the private-line
// enable path, which is why the CNTV PPI worked while SPIs did not.

/// INTIDs described by one GICD_IGROUPR word (one bit per INTID).
pub(crate) const INTIDS_PER_IGROUPR: u32 = 32;
/// First SPI INTID. INTIDs below this are SGIs/PPIs and live in the
/// redistributor, not the distributor.
pub(crate) const SPI_BASE: u32 = 32;
/// Architectural ceiling on distributor SPI INTIDs (1020..1023 are special).
pub(crate) const MAX_SPI_LINES: u32 = 1020;
/// `GICD_TYPER.ITLinesNumber` field mask (bits 4:0).
pub(crate) const TYPER_ITLINES_MASK: u32 = 0x1f;

/// Number of distributor INTIDs implemented, decoded from `GICD_TYPER`:
/// `ITLinesNumber` counts 32-INTID blocks minus one, and the result is capped
/// at the architectural 1020 (INTIDs 1020..1023 are reserved/special).
/// # C: O(1)
pub(crate) fn gic_line_nr(typer: u32) -> u32 {
    let lines = ((typer & TYPER_ITLINES_MASK) + 1) * INTIDS_PER_IGROUPR;
    if lines > MAX_SPI_LINES { MAX_SPI_LINES } else { lines }
}

/// Byte offsets from `GICD_IGROUPR` of the words covering every implemented
/// SPI. Word 0 (INTIDs 0..31) is deliberately skipped: those are the
/// redistributor's SGIs/PPIs and the distributor copy is reserved on a GICv3
/// with affinity routing enabled.
/// # C: O(SPI words)
pub(crate) fn spi_igroupr_offsets(typer: u32) -> impl Iterator<Item = u32> {
    let lines = gic_line_nr(typer);
    (SPI_BASE..lines).step_by(INTIDS_PER_IGROUPR as usize).map(|i| i / 8)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The virt machine reports ITLinesNumber=7 (`GICD_TYPER & 0x1f`), i.e.
    /// 8 blocks of 32 = 256 INTIDs.
    #[test]
    fn line_count_decodes_itlines_blocks_of_32() {
        assert_eq!(gic_line_nr(0), 32);
        assert_eq!(gic_line_nr(7), 256);
        assert_eq!(gic_line_nr(0x0007_0000 | 7), 256, "only bits 4:0 select the count");
    }

    /// ITLinesNumber=31 would decode to 1024; the architecture caps the
    /// distributor at 1020 because 1020..1023 are reserved INTIDs.
    #[test]
    fn line_count_caps_at_the_architectural_maximum() {
        assert_eq!(gic_line_nr(31), MAX_SPI_LINES);
    }

    /// SPI words start at INTID 32 (byte offset 4) and step one word per 32
    /// INTIDs. INTIDs 0..31 are redistributor-owned and must not be written
    /// through the distributor.
    #[test]
    fn spi_words_skip_the_sgi_ppi_word() {
        let offs: alloc::vec::Vec<u32> = spi_igroupr_offsets(7).collect();
        assert_eq!(offs, alloc::vec![4, 8, 12, 16, 20, 24, 28]);
    }

    /// The PL011 line on the virt machine is SPI 1 = INTID 33, which lives in
    /// the first SPI word — the word a bring-up that only touched the
    /// redistributor never wrote, leaving the line in Group 0 (FIQ).
    #[test]
    fn pl011_intid_is_covered_by_the_first_spi_word() {
        const PL011_INTID: u32 = 33;
        let want = PL011_INTID / 8 / 4 * 4;
        assert!(spi_igroupr_offsets(7).any(|o| o == want));
        assert_eq!(want, 4);
    }

    /// A distributor reporting only the minimum 32 INTIDs has no SPIs at all,
    /// so the loop must produce nothing rather than write the reserved word 0.
    #[test]
    fn minimum_distributor_has_no_spi_words() {
        assert_eq!(spi_igroupr_offsets(0).count(), 0);
    }
}
