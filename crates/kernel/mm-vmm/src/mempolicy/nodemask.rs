// Nodemask <-> userspace bitmap conventions for the mempolicy syscall ABI.
//
// The `maxnode` argument is NOT a bit count: it is decremented first, so
// `maxnode` is "highest node id the caller cares about, plus one". Every
// off-by-one below is that `--maxnode`.
//
// Expressed as pure functions over a word-reader / a copy plan so the hosted
// suite can exercise them; the slot files supply the usercopy.

use super::uapi::{
    BITS_PER_LONG, MAX_NODEMASK_BITS, MAX_NUMNODES, NODEMASK_COPY_MAX_BYTES, NR_NODE_IDS,
};
use crate::Error;

/// One `nodemask_t`. `MAX_NUMNODES` is 64 (`uapi::MAX_NUMNODES`), so a mask is
/// exactly one word and bit N means "node N".
#[derive(Copy, Clone, Debug, Eq, PartialEq, Default, Hash)]
pub struct NodeMask(pub u64);

impl NodeMask {
    pub const EMPTY: NodeMask = NodeMask(0);

    /// `node_isset`. # C: O(1)
    pub fn is_set(self, node: u16) -> bool {
        (node as u64) < MAX_NUMNODES && self.0 & (1u64 << node) != 0
    }
    /// `nodes_empty`. # C: O(1)
    pub fn is_empty(self) -> bool { self.0 == 0 }
    /// `nodes_weight`. # C: O(1)
    pub fn weight(self) -> u32 { self.0.count_ones() }
    /// `first_node` — `MAX_NUMNODES` when empty, matching Linux's sentinel.
    /// # C: O(1)
    pub fn first(self) -> u16 {
        if self.0 == 0 { MAX_NUMNODES as u16 } else { self.0.trailing_zeros() as u16 }
    }
    /// `nodes_and`. # C: O(1)
    pub fn and(self, other: NodeMask) -> NodeMask { NodeMask(self.0 & other.0) }
    /// `nodes_subset(self, other)`. # C: O(1)
    pub fn subset_of(self, other: NodeMask) -> bool { self.0 & !other.0 == 0 }
    /// `node_set` on an empty mask. # C: O(1)
    pub fn single(node: u16) -> NodeMask { NodeMask(1u64 << node) }
}

/// `node_states[N_MEMORY]` intersected with `cpuset_current_mems_allowed`:
/// oxide is single-node UMA, so exactly node 0.
/// # C: O(1)
pub fn nodes_with_memory() -> NodeMask { NodeMask::single(super::uapi::NODE_ID_LOCAL) }

/// MPOL_F_RELATIVE_NODES remap: fold `orig` to the weight
/// of `rel`, then map it onto `rel`'s set bits. With a single allowed node
/// this collapses to "node 0 iff orig is non-empty", but the fold is written
/// out so the shape survives a multi-node PMM.
/// # C: O(MAX_NUMNODES)
pub fn relative_nodemask(orig: NodeMask, rel: NodeMask) -> NodeMask {
    let w = rel.weight();
    if w == 0 { return NodeMask::EMPTY; }
    // nodes_fold: gather orig's set bits modulo `w`.
    let mut folded: u64 = 0;
    for bit in 0..MAX_NUMNODES {
        if orig.0 & (1u64 << bit) != 0 { folded |= 1u64 << ((bit as u32) % w); }
    }
    // nodes_onto: the i-th set bit of `folded` selects the i-th set bit of rel.
    let mut out: u64 = 0;
    let mut rem = rel.0;
    let mut i = 0u32;
    while rem != 0 {
        let b = rem.trailing_zeros();
        if folded & (1u64 << i) != 0 { out |= 1u64 << b; }
        rem &= rem - 1;
        i += 1;
    }
    NodeMask(out)
}

/// Read one `unsigned long` word from a user nodemask and clear the bits
/// above `bits`. `bits` must be `<= 64`; `bits % 64 == 0` leaves the word
/// untouched (a "clear nothing" no-op guard for the exact-multiple case).
/// # C: O(1)
fn mask_to_bits(word: u64, bits: u64) -> u64 {
    let rem = bits % BITS_PER_LONG;
    if rem == 0 { word } else { word & ((1u64 << rem) - 1) }
}

/// Validate and read a user-supplied nodemask. `nmask_present` is "the user
/// pointer was non-NULL"; `read_word(i)` fetches `nmask[i]` (8 bytes) and
/// reports `Error::Fault` for an unreadable word.
///
/// Ordering, load-bearing:
/// 1. `--maxnode` FIRST. `maxnode == 0` therefore underflows to `ULONG_MAX`,
///    which trips the `MAX_NODEMASK_BITS` ceiling → `EINVAL` (only a NULL
///    `nmask` escapes with an empty mask).
/// 2. `maxnode - 1 == 0` or NULL `nmask` → empty mask, success.
/// 3. `maxnode - 1 > PAGE_SIZE * 8` → `EINVAL`.
/// 4. Words describing nodes at or above `MAX_NUMNODES` must be all-zero;
///    a set bit up there is `EINVAL`, an unreadable word is `EFAULT`.
/// # C: O((maxnode - MAX_NUMNODES) / 64)
pub fn get_nodes<F>(nmask_present: bool, maxnode: u64, mut read_word: F) -> Result<NodeMask, Error>
where F: FnMut(u64) -> Result<u64, Error>
{
    let mut maxnode = maxnode.wrapping_sub(1);
    if maxnode == 0 || !nmask_present { return Ok(NodeMask::EMPTY); }
    if maxnode > MAX_NODEMASK_BITS { return Err(Error::Inval); }
    while maxnode > MAX_NUMNODES {
        let bits = core::cmp::min(maxnode, BITS_PER_LONG);
        let mut t = mask_to_bits(read_word((maxnode - 1) / BITS_PER_LONG)?, bits);
        if maxnode - bits >= MAX_NUMNODES {
            maxnode -= bits;
        } else {
            maxnode = MAX_NUMNODES;
            // MAX_NUMNODES % BITS_PER_LONG == 0 ⇒ the mask is `!0`, i.e. the
            // whole overflow word must be zero.
            t &= !((1u64 << (MAX_NUMNODES % BITS_PER_LONG)) - 1);
        }
        if t != 0 { return Err(Error::Inval); }
    }
    Ok(NodeMask(mask_to_bits(read_word(0)?, maxnode)))
}

/// The three-part write a nodemask-to-user copy performs.
/// `clear_bytes == 0` means no zero-fill tail.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct NodemaskOut {
    /// Bytes of the kernel nodemask copied to `mask[0..]`.
    pub copy_bytes: u64,
    /// Byte offset from `mask` at which the zero-fill tail starts.
    pub clear_off: u64,
    /// Length of the zero-fill tail.
    pub clear_bytes: u64,
}

/// `get_mempolicy(2)`'s nodemask-out plan: the caller's `maxnode - 1`
/// bits are rounded up to a 64-bit boundary to get the byte count it expects.
/// A request wider than `nr_node_ids` is satisfied by copying the real mask
/// and zero-filling the rest — libnuma always asks for far more than exists.
/// `> PAGE_SIZE` is `EINVAL`.
/// # C: O(1)
pub fn copy_nodes_to_user_plan(maxnode: u64) -> Result<NodemaskOut, Error> {
    // ALIGN(maxnode - 1, 64) / 8, in unsigned-long wrapping arithmetic.
    let bits = maxnode.wrapping_sub(1);
    let copy = bits.wrapping_add(BITS_PER_LONG - 1) & !(BITS_PER_LONG - 1);
    let copy = copy / 8;
    let nbytes = NR_NODE_IDS.div_ceil(BITS_PER_LONG) * 8;
    if copy > nbytes {
        if copy > NODEMASK_COPY_MAX_BYTES { return Err(Error::Inval); }
        return Ok(NodemaskOut { copy_bytes: nbytes, clear_off: nbytes, clear_bytes: copy - nbytes });
    }
    Ok(NodemaskOut { copy_bytes: copy, clear_off: 0, clear_bytes: 0 })
}
