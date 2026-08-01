// Slot-count decode from ID_AA64DFR0_EL1, the boot cache, and the `dbg_info`
// word the hardware-debug regsets report.

use super::common::dfr0;
use crate::hw_breakpoint::idreg::*;

#[test]
fn idreg_fields_hold_count_minus_one() {
    // A core reporting BRPs=5/WRPs=3 implements six breakpoints, four
    // watchpoints — the common QEMU `virt` topology.
    let id = dfr0(DEBUGVER_V8 as u64, 5, 3);
    assert_eq!(brps(id), 6);
    assert_eq!(wrps(id), 4);
    assert_eq!(debug_ver(id), DEBUGVER_V8);
}

#[test]
fn idreg_minimum_topology_is_one_of_each() {
    let id = dfr0(DEBUGVER_V8 as u64, 0, 0);
    assert_eq!(brps(id), 1);
    assert_eq!(wrps(id), 1);
}

#[test]
fn idreg_maximum_topology_is_the_architectural_ceiling() {
    let id = dfr0(DEBUGVER_V8 as u64, 15, 15);
    assert_eq!(brps(id) as usize, ARM_MAX_BRP);
    assert_eq!(wrps(id) as usize, ARM_MAX_WRP);
}

#[test]
fn idreg_fields_do_not_bleed_into_each_other() {
    // Every bit outside the three decoded fields set: the decode must not move.
    let fields = (DFR0_FIELD_MASK << DFR0_DEBUGVER_SHIFT)
        | (DFR0_FIELD_MASK << DFR0_BRPS_SHIFT)
        | (DFR0_FIELD_MASK << DFR0_WRPS_SHIFT);
    let id = dfr0(DEBUGVER_V8 as u64, 2, 7) | !fields;
    assert_eq!(brps(id), 3);
    assert_eq!(wrps(id), 8);
    assert_eq!(debug_ver(id), DEBUGVER_V8);
}

/// The slot-count cache is process-global, so its whole contract lives in one
/// test — split across several, parallel test threads would race on it.
#[test]
fn idreg_cache_latches_the_decoded_topology() {
    init_from_id(dfr0(DEBUGVER_V8 as u64, 5, 3));
    assert_eq!(num_brps(), 6);
    assert_eq!(num_wrps(), 4);
    assert_eq!(arch_version(), DEBUGVER_V8);
    assert_eq!(dbg_info_slots(break_dbg_info()), 6);
    assert_eq!(dbg_info_slots(watch_dbg_info()), 4);
    assert_eq!(dbg_info_arch(break_dbg_info()), DEBUGVER_V8);

    // A core reporting no self-hosted debug latches no slots at all.
    init_from_id(dfr0(0, 5, 3));
    assert_eq!(num_brps(), 0);
    assert_eq!(num_wrps(), 0);
    assert_eq!(dbg_info_slots(break_dbg_info()), 0);

    // The architectural ceiling is enforced at latch time.
    init_from_id(dfr0(DEBUGVER_V8 as u64, 15, 15));
    assert_eq!(num_brps() as usize, ARM_MAX_BRP);
    assert_eq!(num_wrps() as usize, ARM_MAX_WRP);
}

// ---------------------------------------------------------------------------
// dbg_info
// ---------------------------------------------------------------------------

#[test]
fn dbg_info_packs_arch_version_above_slot_count() {
    let w = dbg_info(DEBUGVER_V8, 6);
    assert_eq!(w & DBG_INFO_NUM_MASK, 6);
    assert_eq!(w >> DBG_INFO_ARCH_SHIFT, DEBUGVER_V8 as u32);
}

#[test]
fn dbg_info_round_trips_every_slot_count() {
    for n in 0..=ARM_MAX_BRP as u8 {
        let w = dbg_info(DEBUGVER_V8, n);
        assert_eq!(dbg_info_slots(w), n);
        assert_eq!(dbg_info_arch(w), DEBUGVER_V8);
    }
}

