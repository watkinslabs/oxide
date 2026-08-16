// futex2 (`futex_wait`/`futex_wake`/`futex_waitv`/`futex_requeue`) flag and
// operand validation. Non-gated so the accept/reject ladder is hosted-tested;
// the syscall shims are `#[cfg(target_os = "oxide-kernel")]` and compile their
// own test modules away.
//
// The rules mirror `futex2_to_flags` + `futex_flags_valid` +
// `futex_validate_input`: a futex2 caller passes a size class, an optional
// private bit, and optional NUMA/MPOL bits, and the kernel rejects every
// combination it cannot serve — it never silently downgrades one.
//
// Node keying itself lives in `futex_numa`; this module only decides whether
// the flag word is admissible.

use vmm::mempolicy::uapi::NR_NODE_IDS;

/// `FUTEX2_SIZE_U8` — 1-byte futex.
pub const FUTEX2_SIZE_U8: u32 = 0x00;
/// `FUTEX2_SIZE_U16` — 2-byte futex.
pub const FUTEX2_SIZE_U16: u32 = 0x01;
/// `FUTEX2_SIZE_U32` — the one size class the futex contract implements.
pub const FUTEX2_SIZE_U32: u32 = 0x02;
/// `FUTEX2_SIZE_U64` — 8-byte futex.
pub const FUTEX2_SIZE_U64: u32 = 0x03;
/// Size class occupies bits [1:0].
pub const FUTEX2_SIZE_MASK: u32 = 0x03;
/// `FUTEX2_NUMA` — the futex word is followed by a node-id word.
pub const FUTEX2_NUMA: u32 = 0x04;
/// `FUTEX2_MPOL` — key the futex by the mapping's memory policy.
pub const FUTEX2_MPOL: u32 = 0x08;
/// `FUTEX2_PRIVATE` — numerically identical to `FUTEX_PRIVATE_FLAG`.
pub const FUTEX2_PRIVATE: u32 = 0x80;
/// Every bit a futex2 caller may set. Anything outside is `EINVAL`.
pub const FUTEX2_VALID_MASK: u32 =
    FUTEX2_SIZE_MASK | FUTEX2_NUMA | FUTEX2_MPOL | FUTEX2_PRIVATE;

/// Why a futex2 flag word was rejected. Every variant maps to `EINVAL` at the
/// ABI boundary; the split exists so tests name the rule that fired.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Futex2Reject {
    /// A bit outside `FUTEX2_VALID_MASK` was set.
    UnknownBit,
    /// A size class other than 32-bit. The futex contract implements the
    /// 32-bit word only; the other three classes are reserved and rejected
    /// rather than served at some other width.
    UnsupportedSize,
    /// `FUTEX2_NUMA` on a size class whose word cannot represent both
    /// `FUTEX_NO_NODE` and every valid node id on this machine.
    NumaNodeIdWidth,
}

/// Decoded, accepted futex2 flags.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Futex2Flags {
    /// Futex word width in bytes (`1 << (flags & FUTEX2_SIZE_MASK)`).
    pub size_bytes: u32,
    /// `FUTEX2_PRIVATE`: key on `(mm, addr)` rather than the shared mapping.
    pub private: bool,
    /// `FUTEX2_NUMA`: a node-id word follows the futex word.
    pub numa: bool,
    /// `FUTEX2_MPOL`: derive the node from the mapping's memory policy when
    /// the caller expressed no preference.
    pub mpol: bool,
}

impl Futex2Flags {
    /// Bytes the futex operand occupies in user memory, and therefore both the
    /// natural-alignment requirement and the span that must be accessible.
    /// `FUTEX2_NUMA` doubles it: the node-id word sits immediately after the
    /// futex word and is read (and sometimes written) by the same operation.
    /// # C: O(1)
    pub const fn access_bytes(&self) -> u32 {
        if self.numa { self.size_bytes * 2 } else { self.size_bytes }
    }
}

/// Whether a futex word of `size_bytes` can hold every node id this machine
/// can produce *and* the `FUTEX_NO_NODE` sentinel. The sentinel is the
/// all-ones value at that width, so the node count must stay strictly below
/// it — a machine with as many nodes as the width can encode would make a
/// real node id indistinguishable from "no preference".
/// # C: O(1)
pub const fn numa_node_id_fits(size_bytes: u32) -> bool {
    let bits = 8 * size_bytes;
    if bits >= 64 { return true; }
    let max = u64::MAX >> (64 - bits);
    NR_NODE_IDS < max
}

/// Validate a futex2 `flags` word.
/// # C: O(1)
pub const fn validate_futex2_flags(flags: u32) -> Result<Futex2Flags, Futex2Reject> {
    if flags & !FUTEX2_VALID_MASK != 0 { return Err(Futex2Reject::UnknownBit); }
    if flags & FUTEX2_SIZE_MASK != FUTEX2_SIZE_U32 { return Err(Futex2Reject::UnsupportedSize); }
    let size_bytes = 1 << (flags & FUTEX2_SIZE_MASK);
    let numa = flags & FUTEX2_NUMA != 0;
    if numa && !numa_node_id_fits(size_bytes) { return Err(Futex2Reject::NumaNodeIdWidth); }
    Ok(Futex2Flags {
        size_bytes,
        private: flags & FUTEX2_PRIVATE != 0,
        numa,
        mpol: flags & FUTEX2_MPOL != 0,
    })
}

/// `futex_validate_input`: a value or mask passed as `unsigned long` must fit
/// the futex word width. A 32-bit futex handed `val = 1 << 40` is `EINVAL`,
/// never a silent truncation to `0` — truncating would make a caller's
/// mismatched compare-value look like a match and park it forever.
/// # C: O(1)
pub const fn validate_futex2_input(size_bytes: u32, val: u64) -> bool {
    let bits = 8 * size_bytes;
    if bits >= 64 { return true; }
    (val >> bits) == 0
}

#[cfg(test)]
#[path = "futex2_flags/tests.rs"]
mod tests;
