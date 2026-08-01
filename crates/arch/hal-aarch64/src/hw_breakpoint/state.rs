// Per-task hardware-debug register state: the plain value a task struct
// embeds. No allocation, no lock, no target gate, so hosted tests drive it and
// the context-switch path copies it by value.

use hal::USER_VA_END;

use super::ctrl::{decode, encode, parse, Ctrl, HwBpError, Installed, RegFile, CTRL_E};
use super::idreg::{ARM_MAX_BRP, ARM_MAX_WRP};

/// One debug register pair.
///
/// `addr`/`ctrl` are the RESOLVED words — alignment-rounded address and
/// offset-shifted `BAS` — which are what the register file takes and what a
/// hardware-debug GETREGSET reports. `req_addr`/`req_ctrl` keep the last
/// values the task asked for, because resolving is not idempotent: re-parsing
/// a resolved pair would add the already-applied byte offset a second time.
/// A debugger writing the address and the control word in either order
/// therefore lands on the same slot.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct DbgSlot {
    /// DBGBVR/DBGWVR — resolved match address.
    pub addr: u64,
    /// Last address the task requested.
    pub req_addr: u64,
    /// DBGBCR/DBGWCR — resolved control word.
    pub ctrl: u32,
    /// Last control word the task requested.
    pub req_ctrl: u32,
}

impl DbgSlot {
    /// Disarmed slot.
    /// # C: O(1)
    pub const fn empty() -> Self { Self { addr: 0, req_addr: 0, ctrl: 0, req_ctrl: 0 } }

    /// Slot's `E` bit is set.
    /// # C: O(1)
    pub const fn enabled(&self) -> bool { self.ctrl & CTRL_E != 0 }

    /// Decoded resolved control fields.
    /// # C: O(1)
    pub const fn fields(&self) -> Ctrl { decode(self.ctrl) }
}

/// A task's breakpoint and watchpoint register files. `Default` is the
/// architectural reset state: every slot disarmed.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct HwBreakpointState {
    /// DBGBVR/DBGBCR pairs.
    pub brk: [DbgSlot; ARM_MAX_BRP],
    /// DBGWVR/DBGWCR pairs.
    pub wp: [DbgSlot; ARM_MAX_WRP],
}

impl Default for HwBreakpointState {
    fn default() -> Self { Self::empty() }
}

impl HwBreakpointState {
    /// Reset state — no slot armed.
    /// # C: O(1)
    pub const fn empty() -> Self {
        Self { brk: [DbgSlot::empty(); ARM_MAX_BRP], wp: [DbgSlot::empty(); ARM_MAX_WRP] }
    }

    /// The register file a `RegFile` selects.
    /// # C: O(1)
    pub fn file(&self, file: RegFile) -> &[DbgSlot] {
        match file { RegFile::Break => &self.brk, RegFile::Watch => &self.wp }
    }

    /// Mutable view of the register file a `RegFile` selects.
    /// # C: O(1)
    pub fn file_mut(&mut self, file: RegFile) -> &mut [DbgSlot] {
        match file { RegFile::Break => &mut self.brk, RegFile::Watch => &mut self.wp }
    }

    /// At least one slot in either file is armed. The context-switch gate: a
    /// task whose state is not armed costs no debug-register writes on switch.
    /// # C: O(ARM_MAX_BRP + ARM_MAX_WRP)
    pub fn is_armed(&self) -> bool {
        self.brk.iter().any(DbgSlot::enabled) || self.wp.iter().any(DbgSlot::enabled)
    }

    /// Resolved `(addr, ctrl)` of a slot, as a hardware-debug GETREGSET
    /// reports it. An index past the architectural ceiling has no register.
    /// # C: O(1)
    pub fn get(&self, file: RegFile, idx: usize) -> Option<(u64, u32)> {
        self.file(file).get(idx).map(|s| (s.addr, s.ctrl))
    }

    /// Install a validated slot, recording the request that produced it.
    /// # C: O(1)
    pub fn put(&mut self, file: RegFile, idx: usize, req: (u64, u32), v: Installed)
        -> Result<(), HwBpError>
    {
        let slots = self.file_mut(file);
        if idx >= slots.len() { return Err(HwBpError::Slot); }
        slots[idx] = DbgSlot {
            addr: v.addr, ctrl: encode(v.ctrl), req_addr: req.0, req_ctrl: req.1,
        };
        Ok(())
    }

    /// Set a slot's address, re-resolving against the control word the task
    /// last requested.
    /// # C: O(1)
    pub fn set_addr(&mut self, file: RegFile, idx: usize, addr: u64) -> Result<(), HwBpError> {
        self.set_addr_limit(file, idx, addr, USER_VA_END)
    }

    /// `set_addr` with an explicit user-range bound.
    /// # C: O(1)
    pub fn set_addr_limit(&mut self, file: RegFile, idx: usize, addr: u64, user_end: u64)
        -> Result<(), HwBpError>
    {
        let req_ctrl = match self.file(file).get(idx) {
            Some(s) => s.req_ctrl,
            None    => return Err(HwBpError::Slot),
        };
        let v = parse(file, req_ctrl, addr, user_end)?;
        self.put(file, idx, (addr, req_ctrl), v)
    }

    /// Set a slot's control word, re-resolving against the address the task
    /// last requested.
    /// # C: O(1)
    pub fn set_ctrl(&mut self, file: RegFile, idx: usize, ctrl: u32) -> Result<(), HwBpError> {
        self.set_ctrl_limit(file, idx, ctrl, USER_VA_END)
    }

    /// `set_ctrl` with an explicit user-range bound.
    /// # C: O(1)
    pub fn set_ctrl_limit(&mut self, file: RegFile, idx: usize, ctrl: u32, user_end: u64)
        -> Result<(), HwBpError>
    {
        let req_addr = match self.file(file).get(idx) {
            Some(s) => s.req_addr,
            None    => return Err(HwBpError::Slot),
        };
        let v = parse(file, ctrl, req_addr, user_end)?;
        self.put(file, idx, (req_addr, ctrl), v)
    }

    /// Disarm every slot — the `execve`/detach reset.
    /// # C: O(1)
    pub fn disarm(&mut self) { *self = Self::empty(); }
}
