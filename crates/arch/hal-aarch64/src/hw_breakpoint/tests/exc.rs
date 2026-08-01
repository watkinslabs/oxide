// Debug-exception classification: which slot fired, and the SIGTRAP si_code
// the task must receive.

use hal::siginfo::code;

use super::common::{armed, esr, uctrl};
use crate::hw_breakpoint::ctrl::*;
use crate::hw_breakpoint::exc::*;
use crate::hw_breakpoint::state::HwBreakpointState;

#[test]
fn classifier_ignores_non_debug_exception_classes() {
    let st = armed();
    // Data abort from a lower EL is not a debug exception.
    assert_eq!(classify(esr(0x24, 0), 0x2000, 0x4004, &st, 6, 4), None);
    assert!(!is_debug_ec(0x24));
    for ec in [EC_BREAKPT_LOWER, EC_BREAKPT_CURRENT, EC_SOFTSTEP_LOWER, EC_SOFTSTEP_CURRENT,
               EC_WATCHPT_LOWER, EC_WATCHPT_CURRENT, EC_BRK64] {
        assert!(is_debug_ec(ec), "ec {ec:#x}");
    }
}

#[test]
fn classifier_names_the_breakpoint_slot_and_reports_a_hardware_trap() {
    let st = armed();
    let ev = classify(esr(EC_BREAKPT_LOWER, 0), 0, 0x4004, &st, 6, 4).unwrap();
    assert_eq!(ev, DebugEvent::Breakpoint { slot: Some(1), addr: 0x4004 });
    assert_eq!(ev.si_code(), code::TRAP_HWBKPT);
    assert_eq!(ev.addr(), 0x4004);
    assert_eq!(ev.slot(), Some(1));
    assert_eq!(ev.reg_file(), Some(RegFile::Break));
}

#[test]
fn classifier_reports_no_slot_when_no_breakpoint_matches() {
    let st = armed();
    let ev = classify(esr(EC_BREAKPT_CURRENT, 0), 0, 0x8000, &st, 6, 4).unwrap();
    assert_eq!(ev, DebugEvent::Breakpoint { slot: None, addr: 0x8000 });
    assert_eq!(ev.si_code(), code::TRAP_HWBKPT);
}

#[test]
fn classifier_requires_the_bas_byte_as_well_as_the_value_register() {
    // A breakpoint whose BAS selects only the second instruction of the pair
    // must not claim a PC in the first.
    let mut st = HwBreakpointState::empty();
    st.set_addr(RegFile::Break, 0, 0x4004).unwrap();
    st.set_ctrl(RegFile::Break, 0, uctrl(TYPE_EXECUTE, BAS_LEN_4)).unwrap();
    assert_eq!(match_breakpoint(0x4004, &st, 6), Some(0));
    assert_eq!(match_breakpoint(0x4008, &st, 6), None);
}

#[test]
fn classifier_honours_the_implemented_slot_count() {
    let st = armed();
    // Slot 1 is armed but a machine with one breakpoint cannot have hit it.
    assert_eq!(match_breakpoint(0x4004, &st, 1), None);
    assert_eq!(match_breakpoint(0x4004, &st, 2), Some(1));
}

#[test]
fn classifier_names_the_watchpoint_slot_and_its_access_direction() {
    let st = armed();
    let store = classify(esr(EC_WATCHPT_LOWER, ESR_WNR), 0x2002, 0x9000, &st, 6, 4).unwrap();
    assert_eq!(store, DebugEvent::Watchpoint { slot: Some(2), addr: 0x2002, write: true });
    assert_eq!(store.si_code(), code::TRAP_HWBKPT);
    assert_eq!(store.reg_file(), Some(RegFile::Watch));
    let load = classify(esr(EC_WATCHPT_LOWER, 0), 0x2000, 0x9000, &st, 6, 4).unwrap();
    assert_eq!(load, DebugEvent::Watchpoint { slot: Some(2), addr: 0x2000, write: false });
}

#[test]
fn classifier_skips_a_watchpoint_whose_access_type_does_not_match() {
    let mut st = HwBreakpointState::empty();
    st.set_addr(RegFile::Watch, 0, 0x2000).unwrap();
    st.set_ctrl(RegFile::Watch, 0, uctrl(TYPE_LOAD, BAS_LEN_4)).unwrap();
    assert_eq!(match_watchpoint(0x2000, false, &st, 4), Some(0));
    assert_eq!(match_watchpoint(0x2000, true, &st, 4), None);
}

#[test]
fn watch_distance_is_zero_inside_the_watched_bytes() {
    // Four bytes at 0x2000: the reported address may be any of them.
    for off in 0..4u64 { assert_eq!(watch_distance(0x2000 + off, 0x2000, BAS_LEN_4), 0); }
    assert_eq!(watch_distance(0x1ffc, 0x2000, BAS_LEN_4), 4);
    assert_eq!(watch_distance(0x2007, 0x2000, BAS_LEN_4), 4);
    // A shifted BAS moves the watched window inside the doubleword.
    assert_eq!(watch_distance(0x2004, 0x2000, BAS_LEN_4 << 4), 0);
    assert_eq!(watch_distance(0x2000, 0x2000, BAS_LEN_4 << 4), 4);
}

#[test]
fn classifier_attributes_a_near_miss_to_the_closest_watchpoint() {
    // Hardware may report an address beside the watched bytes when one access
    // spans watched and unwatched memory; the nearest armed slot is named.
    let mut st = HwBreakpointState::empty();
    st.set_addr(RegFile::Watch, 0, 0x1000).unwrap();
    st.set_ctrl(RegFile::Watch, 0, uctrl(TYPE_LOAD_STORE, BAS_LEN_1)).unwrap();
    st.set_addr(RegFile::Watch, 1, 0x2000).unwrap();
    st.set_ctrl(RegFile::Watch, 1, uctrl(TYPE_LOAD_STORE, BAS_LEN_1)).unwrap();
    assert_eq!(match_watchpoint(0x1ff0, false, &st, 4), Some(1));
    assert_eq!(match_watchpoint(0x1010, false, &st, 4), Some(0));
}

#[test]
fn classifier_reports_a_single_step_as_a_trace_trap() {
    let st = armed();
    let ev = classify(esr(EC_SOFTSTEP_LOWER, 0), 0, 0x4008, &st, 6, 4).unwrap();
    assert_eq!(ev, DebugEvent::SingleStep { addr: 0x4008 });
    assert_eq!(ev.si_code(), code::TRAP_TRACE);
    assert_eq!(ev.slot(), None);
    assert_eq!(ev.reg_file(), None);
    assert_eq!(classify(esr(EC_SOFTSTEP_CURRENT, 0), 0, 0x4008, &st, 6, 4).unwrap().si_code(),
               code::TRAP_TRACE);
}

#[test]
fn classifier_reports_a_software_break_with_its_immediate() {
    let st = armed();
    let ev = classify(esr(EC_BRK64, 0x900), 0, 0x4010, &st, 6, 4).unwrap();
    assert_eq!(ev, DebugEvent::SoftwareBreak { addr: 0x4010, comment: 0x900 });
    assert_eq!(ev.si_code(), code::TRAP_BRKPT);
}

#[test]
fn esr_field_accessors_split_the_register() {
    let e = esr(EC_WATCHPT_LOWER, 0x1234);
    assert_eq!(esr_ec(e), EC_WATCHPT_LOWER);
    assert_eq!(esr_iss(e), 0x1234);
}
