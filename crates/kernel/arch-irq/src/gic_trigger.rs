const INTIDS_PER_ICFGR: u32 = 16;
const BITS_PER_INTID: u32 = 2;
const EDGE_TRIGGER: u32 = 0b10;

/// Replace one GIC ICFGR trigger bit while preserving every other field.
/// Linux `gic_configure_irq` changes only bit[2N+1]: clear for level, set for
/// edge. # C: O(1)
pub(crate) fn icfgr_with_trigger(cur: u32, intid: u32, level: bool) -> u32 {
    let shift = (intid % INTIDS_PER_ICFGR) * BITS_PER_INTID;
    let mask = EDGE_TRIGGER << shift;
    if level { cur & !mask } else { cur | mask }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CNTV_PPI: u32 = 27;
    const CNTV_TRIGGER_BIT: u32 = 1 << 23;

    #[test]
    fn ppi_level_and_edge_touch_only_the_selected_trigger_bit() {
        let cur = u32::MAX;
        assert_eq!(icfgr_with_trigger(cur, CNTV_PPI, true), cur & !CNTV_TRIGGER_BIT);

        let cur = 0;
        assert_eq!(icfgr_with_trigger(cur, CNTV_PPI, false), CNTV_TRIGGER_BIT);
    }
}
