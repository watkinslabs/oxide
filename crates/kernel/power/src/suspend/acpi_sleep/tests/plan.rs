// The write order a sleep entry issues. Every assertion here is about
// SEQUENCE, because every value in the plan is correct in isolation and the
// bug this file exists to catch is a merged or reordered pair.

use super::*;
use firmware::acpi::{SPACE_SYSTEM_IO, SPACE_SYSTEM_MEMORY};

fn port(address: u64) -> Gas {
    Gas { space_id: SPACE_SYSTEM_IO, bit_width: 16, bit_offset: 0, access_width: 0, address }
}

const PM1A: u64 = 0x604;
const PM1B: u64 = 0x606;
const STS_A: u64 = 0x600;
const STS_B: u64 = 0x602;

fn kinds(plan: &SleepPlan) -> alloc::vec::Vec<SleepWriteKind> {
    (0..plan.len()).filter_map(|i| plan.get(i)).map(|w| w.kind).collect()
}

#[test]
fn the_legacy_type_and_enable_writes_are_two_separate_writes() {
    // Hardware exists that latches the transition on the SLP_EN edge and
    // samples SLP_TYP from the previous bus cycle. One merged write enters
    // whatever state the SLP_TYP field happened to hold.
    let plan = legacy_plan(port(PM1A), None, Some((port(STS_A), 2)), None, 0, 5, 0);
    assert_eq!(kinds(&plan), [SleepWriteKind::WakeStatusClear, SleepWriteKind::SleepType, SleepWriteKind::SleepEnable]);
    let typed = plan.get(1).unwrap();
    let enabled = plan.get(2).unwrap();
    assert_eq!(typed.gas.address, enabled.gas.address, "both writes go to the same register");
    assert_ne!(typed.value, enabled.value);
    // The first write must NOT carry the enable bit, or the split is a lie.
    assert_eq!(typed.value & 0x2000, 0, "the SLP_TYP write carried SLP_EN");
    assert_eq!(enabled.value & 0x2000, 0x2000, "the second write did not set SLP_EN");
    assert_eq!(enabled.value, typed.value | 0x2000);
}

#[test]
fn the_wake_status_is_cleared_before_anything_else() {
    let plan = legacy_plan(port(PM1A), Some(port(PM1B)), Some((port(STS_A), 2)), Some((port(STS_B), 2)), 0, 5, 6);
    assert_eq!(kinds(&plan), [
        SleepWriteKind::WakeStatusClear, SleepWriteKind::WakeStatusClear,
        SleepWriteKind::SleepType, SleepWriteKind::SleepType,
        SleepWriteKind::SleepEnable, SleepWriteKind::SleepEnable,
    ]);
    assert_eq!(plan.len(), MAX_SLEEP_WRITES);
    assert_eq!(plan.get(0).unwrap().value, PM1_WAKE_STATUS as u32);
    assert_eq!(plan.get(0).unwrap().gas.address, STS_A);
    assert_eq!(plan.get(1).unwrap().gas.address, STS_B);
}

#[test]
fn both_pm1_registers_are_typed_before_either_is_enabled() {
    // The paired register is a second half of the same transition; enabling
    // A before B is typed leaves B holding a stale SLP_TYP.
    let plan = legacy_plan(port(PM1A), Some(port(PM1B)), None, None, 0, 5, 6);
    assert_eq!(kinds(&plan), [
        SleepWriteKind::SleepType, SleepWriteKind::SleepType,
        SleepWriteKind::SleepEnable, SleepWriteKind::SleepEnable,
    ]);
    assert_eq!(plan.get(0).unwrap().gas.address, PM1A);
    assert_eq!(plan.get(1).unwrap().gas.address, PM1B);
    assert_eq!(plan.get(2).unwrap().gas.address, PM1A);
    assert_eq!(plan.get(3).unwrap().gas.address, PM1B);
}

#[test]
fn the_sleep_types_land_in_the_pm1_slp_typ_field() {
    let plan = legacy_plan(port(PM1A), Some(port(PM1B)), None, None, 0, 5, 6);
    // Bits 12:10 of the PM1 control register.
    assert_eq!(plan.get(0).unwrap().value, 5 << 10);
    assert_eq!(plan.get(1).unwrap().value, 6 << 10);
    assert_eq!(plan.get(2).unwrap().value, (5 << 10) | 0x2000);
    assert_eq!(plan.get(3).unwrap().value, (6 << 10) | 0x2000);
}

#[test]
fn the_live_control_bits_survive_the_sleep_write() {
    // SCI_EN and the bus-master controls share the register. A sleep entry
    // that clears them does not come back.
    let base = 0xc7ff;
    let plan = legacy_plan(port(PM1A), None, None, None, base, 5, 0);
    let typed = plan.get(0).unwrap().value as u16;
    let preserved = base & !(0x1c00 | 0x2000);
    assert_eq!(typed & preserved, preserved, "a preserved PM1 control bit was cleared");
}

#[test]
fn a_machine_with_no_pm1b_issues_no_pm1b_write() {
    let plan = legacy_plan(port(PM1A), None, None, None, 0, 5, 0);
    assert_eq!(plan.len(), 2);
    for index in 0..plan.len() { assert_eq!(plan.get(index).unwrap().gas.address, PM1A); }
}

#[test]
fn a_machine_with_no_status_register_still_sleeps() {
    // The wake-status clear is skipped rather than the entry refused: an
    // absent event block is a firmware shape, not a failure.
    let plan = legacy_plan(port(PM1A), None, None, None, 0, 5, 0);
    assert!(!kinds(&plan).contains(&SleepWriteKind::WakeStatusClear));
    assert!(!plan.is_empty());
}

#[test]
fn the_pm1_writes_are_sixteen_bits_wide() {
    let plan = legacy_plan(port(PM1A), Some(port(PM1B)), Some((port(STS_A), 4)), None, 0, 5, 6);
    for index in 0..plan.len() {
        assert_eq!(plan.get(index).unwrap().width, 2, "write {index} used the wrong access width");
    }
}

#[test]
fn the_reduced_register_takes_type_and_enable_in_one_write() {
    // The opposite of the legacy rule, and mirroring the split here would
    // issue a transition-less write the hardware does not expect.
    let control = Gas { space_id: SPACE_SYSTEM_MEMORY, bit_width: 8, bit_offset: 0, access_width: 0, address: 0xfed0_0000 };
    let status = Gas { space_id: SPACE_SYSTEM_MEMORY, bit_width: 8, bit_offset: 0, access_width: 0, address: 0xfed0_0004 };
    let plan = reduced_plan(control, status, 5);
    assert_eq!(kinds(&plan), [SleepWriteKind::WakeStatusClear, SleepWriteKind::SleepTypeAndEnable]);
    assert_eq!(plan.get(0).unwrap().value, REDUCED_WAKE_STATUS as u32);
    assert_eq!(plan.get(0).unwrap().gas.address, status.address);
    let w = plan.get(1).unwrap();
    assert_eq!(w.gas.address, control.address);
    assert_eq!(w.value, ((5 << REDUCED_SLEEP_TYPE_SHIFT) | REDUCED_SLEEP_ENABLE) as u32);
    assert_eq!(w.width, 1, "the reduced-hardware registers are byte-wide");
}

#[test]
fn a_reduced_sleep_type_cannot_overflow_its_field() {
    let control = Gas { space_id: SPACE_SYSTEM_IO, bit_width: 8, bit_offset: 0, access_width: 0, address: 0x600 };
    let status = Gas { space_id: SPACE_SYSTEM_IO, bit_width: 8, bit_offset: 0, access_width: 0, address: 0x601 };
    for sleep_type in 0..=7u8 {
        let value = reduced_plan(control, status, sleep_type).get(1).unwrap().value as u8;
        assert_eq!(value & !(REDUCED_SLEEP_TYPE_MASK | REDUCED_SLEEP_ENABLE), 0,
            "sleep type {sleep_type} set a bit outside SLP_TYP|SLP_EN");
        assert_eq!((value & REDUCED_SLEEP_TYPE_MASK) >> REDUCED_SLEEP_TYPE_SHIFT, sleep_type);
    }
}
