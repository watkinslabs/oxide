// DR6 (debug status) bit contract + the #DB cause classifier.
//
// Pure decision logic, no target gate: the classifier that turns a raw DR6
// into the SIGTRAP `si_code` the fault handler must report is fully hosted-
// testable. si_code numbers are owned by `hal::siginfo::code` — never
// redefined here (`07§5`).

use hal::siginfo::code;

use super::dr7::HBP_NUM;

/// DR6.B0 — DR0 matched.
pub const DR6_B0: u64 = 1 << 0;
/// DR6.B1 — DR1 matched.
pub const DR6_B1: u64 = 1 << 1;
/// DR6.B2 — DR2 matched.
pub const DR6_B2: u64 = 1 << 2;
/// DR6.B3 — DR3 matched.
pub const DR6_B3: u64 = 1 << 3;
/// All four breakpoint-hit bits.
pub const DR6_TRAP_BITS: u64 = DR6_B0 | DR6_B1 | DR6_B2 | DR6_B3;
/// DR6.BLD — bus-lock detected (bit 11).
pub const DR6_BUS_LOCK: u64 = 1 << 11;
/// DR6.BD — debug-register access while DR7.GD set (bit 13).
pub const DR6_BD: u64 = 1 << 13;
/// DR6.BS — single-step (RFLAGS.TF) trap (bit 14).
pub const DR6_BS: u64 = 1 << 14;
/// DR6.BT — task-switch trap via TSS debug flag (bit 15).
pub const DR6_BT: u64 = 1 << 15;
/// DR6 bits that read as one on an untriggered register — the reset value.
/// Bits inside it (bus-lock, and the RTM indicator above bit 15) are
/// active-LOW in hardware, so software must flip by this mask before decoding.
pub const DR6_RESERVED_ONES: u64 = 0xFFFF_0FF0;
/// Every cause bit software may consume from a normalised DR6.
pub const DR6_CAUSE_MASK: u64 = DR6_TRAP_BITS | DR6_BUS_LOCK | DR6_BD | DR6_BS | DR6_BT;

/// Turn a raw hardware DR6 into the all-causes-active-high form every function
/// below consumes: clears the read-as-one bits and inverts the active-low ones.
/// An untriggered DR6 normalises to zero.
/// # C: O(1)
pub const fn normalize(raw: u64) -> u64 { raw ^ DR6_RESERVED_ONES }

/// Decoded #DB cause. `hits` is a DR0-DR3 bitmask, not a slot index, because
/// one instruction can match several watched spans at once.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct Dr6Status {
    /// Bitmask of matched slots (bit `i` ⇒ DR`i`).
    pub hits: u8,
    /// RFLAGS.TF single-step trap.
    pub single_step: bool,
    /// Task-switch trap.
    pub task_switch: bool,
    /// General-detect trap (debug-register access under DR7.GD).
    pub general_detect: bool,
    /// Bus-lock trap.
    pub bus_lock: bool,
}

impl Dr6Status {
    /// Split a NORMALISED DR6 (see `normalize`) into its cause bits.
    /// # C: O(HBP_NUM)
    pub fn decode(dr6: u64) -> Self {
        Self {
            hits:           (dr6 & DR6_TRAP_BITS) as u8,
            single_step:    dr6 & DR6_BS != 0,
            task_switch:    dr6 & DR6_BT != 0,
            general_detect: dr6 & DR6_BD != 0,
            bus_lock:       dr6 & DR6_BUS_LOCK != 0,
        }
    }

    /// Any cause bit set — a DR6 with none is a #DB this layer did not produce.
    /// # C: O(1)
    pub fn is_empty(&self) -> bool {
        self.hits == 0 && !self.single_step && !self.task_switch
            && !self.general_detect && !self.bus_lock
    }

    /// Lowest matched slot, or `None` when the trap was not a data/exec match.
    /// # C: O(HBP_NUM)
    pub fn first_slot(&self) -> Option<usize> {
        let mut i = 0;
        while i < HBP_NUM {
            if self.hits & (1 << i) != 0 { return Some(i); }
            i += 1;
        }
        None
    }

    /// Slot `i` matched.
    /// # C: O(1)
    pub fn hit(&self, slot: usize) -> bool { self.hits & (1u8 << slot) != 0 }

    /// SIGTRAP `si_code` for this trap. Single-step outranks a breakpoint
    /// match; a #DB with neither reports as a plain breakpoint trap.
    /// # C: O(1)
    pub fn si_code(&self) -> i32 {
        if self.single_step { code::TRAP_TRACE }
        else if self.hits != 0 { code::TRAP_HWBKPT }
        else { code::TRAP_BRKPT }
    }
}

/// `si_code` for a normalised DR6 without materialising the decode.
/// # C: O(1)
pub fn si_code_for(dr6: u64) -> i32 { Dr6Status::decode(dr6).si_code() }

/// `si_code` straight from a raw hardware DR6.
/// # C: O(1)
pub fn si_code_for_raw(raw: u64) -> i32 { si_code_for(normalize(raw)) }
