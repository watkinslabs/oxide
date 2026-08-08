// `IORING_REGISTER_RESTRICTIONS` — the per-ring allow-list a sandbox installs
// before it hands the ring to less-trusted code.
//
// Restrictions may only be registered while the ring is still disabled
// (`IORING_SETUP_R_DISABLED`), exactly once, and take effect from the moment
// `IORING_REGISTER_ENABLE_RINGS` runs. Two independent allow-lists come out of
// one registration: which register opcodes remain callable, and which SQE
// opcodes and SQE flags remain submittable. A restriction that is registered
// but not enforced would be worse than none at all, so the enforcement points
// are the same two ladders every call goes through.

use syscall::errno::Errno;

use super::ops::OP_LAST;
use super::register_op::IORING_REGISTER_LAST;

/// `struct io_uring_restriction` — {opcode u16, op_or_flags u8, resv u8,
/// resv2[3] u32}.
pub const RESTRICTION_BYTES: u64 = 16;

/// `IORING_RESTRICTION_REGISTER_OP` — allow one `io_uring_register` opcode.
pub const IORING_RESTRICTION_REGISTER_OP: u16 = 0;
/// `IORING_RESTRICTION_SQE_OP` — allow one SQE opcode.
pub const IORING_RESTRICTION_SQE_OP: u16 = 1;
/// `IORING_RESTRICTION_SQE_FLAGS_ALLOWED` — the SQE flags that may be set.
pub const IORING_RESTRICTION_SQE_FLAGS_ALLOWED: u16 = 2;
/// `IORING_RESTRICTION_SQE_FLAGS_REQUIRED` — the SQE flags that must be set.
pub const IORING_RESTRICTION_SQE_FLAGS_REQUIRED: u16 = 3;
/// One past the last restriction opcode.
pub const IORING_RESTRICTION_LAST: u16 = 4;

/// Largest restriction array one registration accepts.
pub const IORING_MAX_RESTRICTIONS: u32 =
    (1 << 14) + IORING_REGISTER_LAST + OP_LAST as u32;

/// A ring's restriction state. `Default` is "nothing registered", which
/// permits everything. # C: n/a
#[derive(Clone, Copy, Default, PartialEq, Eq, Debug)]
pub struct Restrictions {
    register_op: u64,
    sqe_op: [u64; 2],
    pub sqe_flags_allowed: u8,
    pub sqe_flags_required: u8,
    /// An SQE-side rule was registered, so the SQE ladder enforces.
    pub op_registered: bool,
    /// A register-side rule was registered, so the register ladder enforces.
    pub reg_registered: bool,
}

/// One decoded `struct io_uring_restriction`. # C: O(1)
pub fn decode_one(b: &[u8]) -> Option<(u16, u8)> {
    if b.len() < RESTRICTION_BYTES as usize { return None; }
    Some((u16::from_le_bytes([b[0], b[1]]), b[2]))
}

impl Restrictions {
    /// Fold one decoded restriction in. An out-of-range opcode or an unknown
    /// restriction kind is `EINVAL` and abandons the whole registration.
    /// # C: O(1)
    pub fn apply(&mut self, kind: u16, val: u8) -> Result<(), Errno> {
        match kind {
            IORING_RESTRICTION_REGISTER_OP => {
                if val as u32 >= IORING_REGISTER_LAST { return Err(Errno::Einval); }
                self.register_op |= 1u64 << val;
                self.reg_registered = true;
            }
            IORING_RESTRICTION_SQE_OP => {
                if val >= OP_LAST { return Err(Errno::Einval); }
                self.sqe_op[(val / 64) as usize] |= 1u64 << (val % 64);
                self.op_registered = true;
            }
            IORING_RESTRICTION_SQE_FLAGS_ALLOWED => {
                self.sqe_flags_allowed = val;
                self.op_registered = true;
            }
            IORING_RESTRICTION_SQE_FLAGS_REQUIRED => {
                self.sqe_flags_required = val;
                self.op_registered = true;
            }
            _ => return Err(Errno::Einval),
        }
        Ok(())
    }

    /// An empty registration still arms both ladders — which, with no opcode
    /// allowed, is a ring that can do nothing. That is the point: an empty
    /// allow-list must not read as "no restrictions". # C: O(1)
    pub fn arm_empty(&mut self) {
        self.op_registered = true;
        self.reg_registered = true;
    }

    /// Whether anything at all has been registered. # C: O(1)
    pub fn registered(&self) -> bool { self.op_registered || self.reg_registered }

    /// `io_uring_register` admission for one opcode. # C: O(1)
    pub fn allows_register(&self, opcode: u32) -> bool {
        if !self.reg_registered { return true; }
        opcode < IORING_REGISTER_LAST && self.register_op & (1u64 << opcode) != 0
    }

    /// SQE admission: the opcode must be allowed, every required flag present,
    /// and no flag outside the allowed-plus-required set. # C: O(1)
    pub fn allows_sqe(&self, opcode: u8, sqe_flags: u8) -> bool {
        if !self.op_registered { return true; }
        if opcode >= OP_LAST { return false; }
        if self.sqe_op[(opcode / 64) as usize] & (1u64 << (opcode % 64)) == 0 { return false; }
        if sqe_flags & self.sqe_flags_required != self.sqe_flags_required { return false; }
        if sqe_flags & !(self.sqe_flags_allowed | self.sqe_flags_required) != 0 { return false; }
        true
    }
}

#[cfg(test)]
#[path = "restriction/tests.rs"]
mod tests;
