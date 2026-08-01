// Fixtures shared by the hardware-debug test modules.

use crate::hw_breakpoint::ctrl::{encode, Ctrl, PRIV_EL0, BAS_LEN_4, TYPE_EXECUTE, TYPE_LOAD_STORE};
use crate::hw_breakpoint::exc::ESR_EC_SHIFT;
use crate::hw_breakpoint::idreg::{DFR0_BRPS_SHIFT, DFR0_DEBUGVER_SHIFT, DFR0_WRPS_SHIFT};
use crate::hw_breakpoint::state::HwBreakpointState;
use crate::hw_breakpoint::RegFile;

/// User range the ladder tests validate against — the platform's user ceiling.
pub const UEND: u64 = hal::USER_VA_END;

/// Build an `ID_AA64DFR0_EL1` carrying the three debug fields this layer reads.
pub fn dfr0(ver: u64, brp_m1: u64, wrp_m1: u64) -> u64 {
    (ver << DFR0_DEBUGVER_SHIFT) | (brp_m1 << DFR0_BRPS_SHIFT) | (wrp_m1 << DFR0_WRPS_SHIFT)
}

/// An armed, EL0-privileged control word as a task would supply it.
pub fn uctrl(kind: u8, bas: u8) -> u32 {
    encode(Ctrl { enabled: true, privilege: PRIV_EL0, kind, bas })
}

/// Assemble an `ESR_EL1` from an exception class and an ISS.
pub fn esr(ec: u32, iss: u64) -> u64 { ((ec as u64) << ESR_EC_SHIFT) | iss }

/// Task with breakpoint 1 on the instruction at 0x4004 and watchpoint 2 on the
/// four bytes at 0x2000.
pub fn armed() -> HwBreakpointState {
    let mut st = HwBreakpointState::empty();
    st.set_addr(RegFile::Break, 1, 0x4004).unwrap();
    st.set_ctrl(RegFile::Break, 1, uctrl(TYPE_EXECUTE, BAS_LEN_4)).unwrap();
    st.set_addr(RegFile::Watch, 2, 0x2000).unwrap();
    st.set_ctrl(RegFile::Watch, 2, uctrl(TYPE_LOAD_STORE, BAS_LEN_4)).unwrap();
    st
}
