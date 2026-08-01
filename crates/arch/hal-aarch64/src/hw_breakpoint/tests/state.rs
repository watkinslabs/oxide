// The per-task hardware-debug value type and its write ordering.

use super::common::{uctrl, UEND};
use crate::hw_breakpoint::ctrl::*;
use crate::hw_breakpoint::idreg::{ARM_MAX_BRP, ARM_MAX_WRP};
use crate::hw_breakpoint::state::HwBreakpointState;

#[test]
fn state_default_is_disarmed() {
    let st = HwBreakpointState::default();
    assert!(!st.is_armed());
    assert_eq!(st, HwBreakpointState::empty());
    assert_eq!(st.get(RegFile::Break, 0), Some((0, 0)));
    assert_eq!(st.get(RegFile::Break, ARM_MAX_BRP), None);
}

#[test]
fn state_is_armed_once_a_slot_is_enabled() {
    let mut st = HwBreakpointState::empty();
    st.set_addr(RegFile::Break, 0, 0x4000).unwrap();
    assert!(!st.is_armed(), "an address alone must not arm a slot");
    st.set_ctrl(RegFile::Break, 0, uctrl(TYPE_EXECUTE, BAS_LEN_4)).unwrap();
    assert!(st.is_armed());
    assert_eq!(st.get(RegFile::Break, 0).unwrap().0, 0x4000);

    let mut st2 = HwBreakpointState::empty();
    st2.set_ctrl(RegFile::Watch, 3, uctrl(TYPE_STORE, BAS_LEN_8)).unwrap();
    assert!(st2.is_armed());
    st2.disarm();
    assert!(!st2.is_armed());
}

#[test]
fn state_write_order_does_not_change_the_installed_slot() {
    let c = uctrl(TYPE_LOAD_STORE, BAS_LEN_2);
    let mut a = HwBreakpointState::empty();
    a.set_addr(RegFile::Watch, 1, 0x2006).unwrap();
    a.set_ctrl(RegFile::Watch, 1, c).unwrap();
    let mut b = HwBreakpointState::empty();
    b.set_ctrl(RegFile::Watch, 1, c).unwrap();
    b.set_addr(RegFile::Watch, 1, 0x2006).unwrap();
    assert_eq!(a.get(RegFile::Watch, 1), b.get(RegFile::Watch, 1));
    assert_eq!(a.get(RegFile::Watch, 1), Some((0x2000, encode(Ctrl {
        enabled: true, privilege: PRIV_EL0, kind: TYPE_LOAD_STORE, bas: BAS_LEN_2 << 6,
    }))));
}

#[test]
fn state_reinstalling_a_slot_does_not_drift() {
    // Writing the same control word twice must resolve to the same registers:
    // resolving is applied to the request, never to an already-resolved word.
    let mut st = HwBreakpointState::empty();
    st.set_addr(RegFile::Watch, 0, 0x2003).unwrap();
    st.set_ctrl(RegFile::Watch, 0, uctrl(TYPE_LOAD, BAS_LEN_1)).unwrap();
    let first = st.get(RegFile::Watch, 0);
    st.set_ctrl(RegFile::Watch, 0, uctrl(TYPE_LOAD, BAS_LEN_1)).unwrap();
    assert_eq!(st.get(RegFile::Watch, 0), first);
}

#[test]
fn state_refuses_a_slot_past_the_architectural_ceiling() {
    let mut st = HwBreakpointState::empty();
    assert_eq!(st.set_addr(RegFile::Break, ARM_MAX_BRP, 0x1000), Err(HwBpError::Slot));
    assert_eq!(st.set_ctrl(RegFile::Watch, ARM_MAX_WRP, 0), Err(HwBpError::Slot));
}

#[test]
fn state_leaves_a_slot_untouched_on_a_refused_write() {
    let mut st = HwBreakpointState::empty();
    st.set_addr(RegFile::Break, 0, 0x4000).unwrap();
    st.set_ctrl(RegFile::Break, 0, uctrl(TYPE_EXECUTE, BAS_LEN_4)).unwrap();
    let good = st.get(RegFile::Break, 0);
    assert_eq!(st.set_addr(RegFile::Break, 0, UEND), Err(HwBpError::KernelAddress));
    assert_eq!(st.get(RegFile::Break, 0), good);
}

