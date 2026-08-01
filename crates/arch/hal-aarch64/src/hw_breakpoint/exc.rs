// Debug-exception classifier: raw `ESR_EL1`/`FAR_EL1` in, the SIGTRAP a task
// must receive and the slot that produced it out.
//
// Pure decision logic, no target gate. The fault path calls `classify` and
// takes the `si_code` from the returned event rather than re-deriving one, so
// the debug si_code contract has a single owner. si_code numbers themselves
// belong to `hal::siginfo::code` and are never redefined here (`07§5`).

use hal::siginfo::code;

use super::ctrl::{decode, RegFile, TYPE_LOAD, TYPE_STORE};
use super::state::HwBreakpointState;

/// `ESR_EL1.EC` field position.
pub const ESR_EC_SHIFT: u32 = 26;
/// `ESR_EL1.EC` field width.
pub const ESR_EC_MASK: u64 = 0x3f;
/// `ESR_EL1.ISS` field width.
pub const ESR_ISS_MASK: u64 = 0x1ff_ffff;
/// `ESR_EL1.ISS.WnR` — set when the aborting access was a write.
pub const ESR_WNR: u64 = 1 << 6;
/// `BRK` immediate occupies the low 16 bits of `ISS`.
pub const ESR_BRK_COMMENT_MASK: u64 = 0xffff;

/// EC — hardware breakpoint taken from a lower exception level.
pub const EC_BREAKPT_LOWER: u32 = 0x30;
/// EC — hardware breakpoint taken from the current exception level.
pub const EC_BREAKPT_CURRENT: u32 = 0x31;
/// EC — software step taken from a lower exception level.
pub const EC_SOFTSTEP_LOWER: u32 = 0x32;
/// EC — software step taken from the current exception level.
pub const EC_SOFTSTEP_CURRENT: u32 = 0x33;
/// EC — watchpoint taken from a lower exception level.
pub const EC_WATCHPT_LOWER: u32 = 0x34;
/// EC — watchpoint taken from the current exception level.
pub const EC_WATCHPT_CURRENT: u32 = 0x35;
/// EC — `BRK` instruction executed in AArch64 state.
pub const EC_BRK64: u32 = 0x3c;

/// Bytes an A64 instruction occupies; a breakpoint match compares the PC
/// rounded down to this and then selects the byte within it.
pub const A64_INSN_ALIGN: u64 = 4;

/// `ESR_EL1.EC`.
/// # C: O(1)
pub const fn esr_ec(esr: u64) -> u32 { ((esr >> ESR_EC_SHIFT) & ESR_EC_MASK) as u32 }

/// `ESR_EL1.ISS`.
/// # C: O(1)
pub const fn esr_iss(esr: u64) -> u64 { esr & ESR_ISS_MASK }

/// Exception class belongs to the self-hosted debug family.
/// # C: O(1)
pub const fn is_debug_ec(ec: u32) -> bool {
    matches!(ec, EC_BREAKPT_LOWER | EC_BREAKPT_CURRENT | EC_SOFTSTEP_LOWER
                 | EC_SOFTSTEP_CURRENT | EC_WATCHPT_LOWER | EC_WATCHPT_CURRENT | EC_BRK64)
}

/// What a debug exception was, and which slot produced it.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum DebugEvent {
    /// Instruction breakpoint. `slot` is `None` when no armed DBGBVR matches
    /// the reported PC, which means the slot was disarmed after the exception
    /// was taken.
    Breakpoint {
        /// Matching DBGBVR/DBGBCR index.
        slot: Option<u8>,
        /// PC the breakpoint fired on.
        addr: u64,
    },
    /// Data watchpoint. `write` distinguishes a store from a load.
    Watchpoint {
        /// Matching DBGWVR/DBGWCR index — the exact match, else the nearest
        /// armed watchpoint, since the reported address may lie beside the
        /// watched bytes when one access touches watched and unwatched bytes.
        slot: Option<u8>,
        /// Reported data address.
        addr: u64,
        /// Access was a store.
        write: bool,
    },
    /// Software step completed.
    SingleStep {
        /// PC the step landed on.
        addr: u64,
    },
    /// `BRK` executed by the task.
    SoftwareBreak {
        /// PC of the `BRK`.
        addr: u64,
        /// `BRK` immediate.
        comment: u16,
    },
}

impl DebugEvent {
    /// SIGTRAP `si_code` this event is delivered with.
    /// # C: O(1)
    pub const fn si_code(&self) -> i32 {
        match self {
            DebugEvent::Breakpoint { .. } | DebugEvent::Watchpoint { .. } => code::TRAP_HWBKPT,
            DebugEvent::SingleStep { .. }                                 => code::TRAP_TRACE,
            DebugEvent::SoftwareBreak { .. }                              => code::TRAP_BRKPT,
        }
    }

    /// `si_addr` this event is delivered with.
    /// # C: O(1)
    pub const fn addr(&self) -> u64 {
        match *self {
            DebugEvent::Breakpoint { addr, .. } | DebugEvent::Watchpoint { addr, .. }
            | DebugEvent::SingleStep { addr } | DebugEvent::SoftwareBreak { addr, .. } => addr,
        }
    }

    /// Register-file slot the event names, if any.
    /// # C: O(1)
    pub const fn slot(&self) -> Option<u8> {
        match *self {
            DebugEvent::Breakpoint { slot, .. } | DebugEvent::Watchpoint { slot, .. } => slot,
            _ => None,
        }
    }

    /// Register file the event's slot indexes, if any.
    /// # C: O(1)
    pub const fn reg_file(&self) -> Option<RegFile> {
        match *self {
            DebugEvent::Breakpoint { .. } => Some(RegFile::Break),
            DebugEvent::Watchpoint { .. } => Some(RegFile::Watch),
            _ => None,
        }
    }
}

/// Armed DBGBVR/DBGBCR slot whose value register matches the instruction the
/// PC names AND whose `BAS` selects the PC's byte within that instruction.
/// # C: O(n_brps)
pub fn match_breakpoint(pc: u64, st: &HwBreakpointState, n_brps: u8) -> Option<u8> {
    let n = (n_brps as usize).min(st.brk.len());
    let want = pc & !(A64_INSN_ALIGN - 1);
    let byte = 1u8 << (pc & (A64_INSN_ALIGN - 1));
    for i in 0..n {
        let s = st.brk[i];
        if !s.enabled() || s.addr != want { continue; }
        if decode(s.ctrl).bas & byte != 0 { return Some(i as u8); }
    }
    None
}

/// Distance from `addr` to the bytes a watchpoint covers; zero on a hit.
/// # C: O(1)
pub fn watch_distance(addr: u64, val: u64, bas: u8) -> u64 {
    if bas == 0 { return u64::MAX; }
    let low = val.wrapping_add(bas.trailing_zeros() as u64);
    let high = val.wrapping_add((u8::BITS - 1 - bas.leading_zeros()) as u64);
    if addr < low { low - addr } else { addr.saturating_sub(high) }
}

/// Armed DBGWVR/DBGWCR slot the reported data address belongs to.
///
/// Hardware may report an address beside the watched bytes when one
/// instruction touches watched and unwatched bytes together, so an exact hit
/// wins and otherwise the nearest armed watchpoint of a matching access type
/// is named.
/// # C: O(n_wrps)
pub fn match_watchpoint(addr: u64, write: bool, st: &HwBreakpointState, n_wrps: u8) -> Option<u8> {
    let n = (n_wrps as usize).min(st.wp.len());
    let access = if write { TYPE_STORE } else { TYPE_LOAD };
    let mut best: Option<(u64, u8)> = None;
    for i in 0..n {
        let s = st.wp[i];
        if !s.enabled() { continue; }
        let c = decode(s.ctrl);
        if c.kind & access == 0 { continue; }
        let d = watch_distance(addr, s.addr, c.bas);
        if d == u64::MAX { continue; }
        match best {
            Some((bd, _)) if bd <= d => {}
            _ => best = Some((d, i as u8)),
        }
        if d == 0 { break; }
    }
    best.map(|(_, i)| i)
}

/// Classify a debug exception. `None` when the exception class is not a debug
/// class this layer owns.
/// # C: O(n_brps + n_wrps)
/// # Ctx: exception
pub fn classify(esr: u64, far: u64, pc: u64, st: &HwBreakpointState, n_brps: u8, n_wrps: u8)
    -> Option<DebugEvent>
{
    match esr_ec(esr) {
        EC_BREAKPT_LOWER | EC_BREAKPT_CURRENT =>
            Some(DebugEvent::Breakpoint { slot: match_breakpoint(pc, st, n_brps), addr: pc }),
        EC_WATCHPT_LOWER | EC_WATCHPT_CURRENT => {
            let write = esr & ESR_WNR != 0;
            Some(DebugEvent::Watchpoint {
                slot: match_watchpoint(far, write, st, n_wrps), addr: far, write,
            })
        }
        EC_SOFTSTEP_LOWER | EC_SOFTSTEP_CURRENT => Some(DebugEvent::SingleStep { addr: pc }),
        EC_BRK64 => Some(DebugEvent::SoftwareBreak {
            addr: pc, comment: (esr_iss(esr) & ESR_BRK_COMMENT_MASK) as u16,
        }),
        _ => None,
    }
}
