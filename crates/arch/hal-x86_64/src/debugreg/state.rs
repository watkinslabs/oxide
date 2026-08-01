// Per-task debug-register state: the value a task carries and the ptrace
// mutators that keep it installable. Plain data — no allocation, no lock, no
// target gate — so a task struct embeds it by value and hosted tests drive it.

use hal::USER_VA_END;

use super::dr6::{normalize, Dr6Status, DR6_CAUSE_MASK};
use super::dr7::{
    validate_addr, validate_dr7, Dr7Error, DR7_EMPTY, DR7_ENABLE_MASK, HBP_NUM,
};

/// One task's DR0-DR3/DR6/DR7 shadow. `Default` is the architectural reset
/// state: no slot armed, DR7's reserved-one bit set.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct DebugRegs {
    /// DR0-DR3 breakpoint addresses.
    pub addr: [u64; HBP_NUM],
    /// DR6 status accumulated for the task since it last read it.
    pub dr6: u64,
    /// DR7 control.
    pub dr7: u64,
}

impl Default for DebugRegs {
    fn default() -> Self { Self { addr: [0; HBP_NUM], dr6: 0, dr7: DR7_EMPTY } }
}

impl DebugRegs {
    /// Reset state — every slot disarmed.
    /// # C: O(1)
    pub const fn empty() -> Self { Self { addr: [0; HBP_NUM], dr6: 0, dr7: DR7_EMPTY } }

    /// At least one DR7 enable bit set. The context-switch gate: a task whose
    /// state is not armed costs no debug-register writes on switch.
    /// # C: O(1)
    pub const fn is_armed(&self) -> bool { self.dr7 & DR7_ENABLE_MASK != 0 }

    /// Read one of the seven ptrace-visible debug registers by its
    /// `u_debugreg` index (0-3 address, 6 status, 7 control); 4 and 5 alias
    /// 6 and 7 as they do in hardware.
    /// # C: O(1)
    pub fn get(&self, idx: usize) -> Option<u64> {
        match idx {
            0..=3 => Some(self.addr[idx]),
            4 | 6 => Some(self.dr6),
            5 | 7 => Some(self.dr7),
            _     => None,
        }
    }

    /// Install a breakpoint address, refusing anything outside userspace.
    /// # C: O(1)
    pub fn set_addr(&mut self, slot: usize, addr: u64) -> Result<(), Dr7Error> {
        self.set_addr_limit(slot, addr, USER_VA_END)
    }

    /// `set_addr` with an explicit user-range bound.
    /// # C: O(1)
    pub fn set_addr_limit(&mut self, slot: usize, addr: u64, user_end: u64)
        -> Result<(), Dr7Error>
    {
        if slot >= HBP_NUM { return Err(Dr7Error::KernelAddress { slot }); }
        validate_addr(slot, addr, user_end)?;
        self.addr[slot] = addr;
        Ok(())
    }

    /// Install a DR7, validating every armed slot against the currently held
    /// DR0-DR3. Leaves the state untouched on error.
    /// # C: O(HBP_NUM)
    pub fn set_dr7(&mut self, dr7: u64) -> Result<(), Dr7Error> {
        self.set_dr7_limit(dr7, USER_VA_END)
    }

    /// `set_dr7` with an explicit user-range bound.
    /// # C: O(HBP_NUM)
    pub fn set_dr7_limit(&mut self, dr7: u64, user_end: u64) -> Result<(), Dr7Error> {
        self.dr7 = validate_dr7(dr7, &self.addr, user_end)?;
        Ok(())
    }

    /// Record the cause bits of a #DB the task must see on its next DR6 read.
    /// `dr6` is normalised (`dr6::normalize`), not the raw register.
    /// # C: O(1)
    pub fn record_dr6(&mut self, dr6: u64) { self.dr6 |= dr6 & DR6_CAUSE_MASK; }

    /// `record_dr6` fed straight from a raw hardware DR6 read.
    /// # C: O(1)
    pub fn record_dr6_raw(&mut self, raw: u64) { self.record_dr6(normalize(raw)); }

    /// Decode the recorded status.
    /// # C: O(HBP_NUM)
    pub fn status(&self) -> Dr6Status { Dr6Status::decode(self.dr6) }

    /// Drop the recorded status, as a ptrace DR6 write of zero does.
    /// # C: O(1)
    pub fn clear_dr6(&mut self) { self.dr6 = 0; }

    /// Disarm every slot — `PTRACE_DETACH`/`execve` semantics.
    /// # C: O(1)
    pub fn disarm(&mut self) { *self = Self::empty(); }
}
