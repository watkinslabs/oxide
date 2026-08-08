// Argument ladders for the mempolicy syscalls, in Linux's exact order. Kept
// out of the slot files (which are `#![cfg(target_os = "oxide-kernel")]` and
// therefore untestable) so the hosted suite exercises the errno ordering.

use super::uapi::*;
use crate::Error;

/// Page-align `len`. Wraps to 0 for a `len` within a page of `u64::MAX` —
/// which is exactly why `mbind`/`set_mempolicy_home_node` then see
/// `end == start` and return 0, while `mseal` catches the wrap explicitly.
/// # C: O(1)
pub fn page_align(len: u64) -> u64 {
    len.wrapping_add(hal::PAGE_SIZE_BYTES - 1) & !(hal::PAGE_SIZE_BYTES - 1)
}

/// A start/length pair that survived validation. `None` is Linux's
/// `end == start ⇒ return 0` early exit, which is success with no work.
pub type MaybeRange = Option<(u64, u64)>;

/// The `start`/`len` validation shared identically by `mbind(2)` and
/// `set_mempolicy_home_node(2)`.
/// # C: O(1)
pub fn align_range(start: u64, len: u64) -> Result<MaybeRange, Error> {
    if start & (hal::PAGE_SIZE_BYTES - 1) != 0 { return Err(Error::Inval); }
    let len = page_align(len);
    let end = start.wrapping_add(len);
    if end < start { return Err(Error::Inval); }
    if end == start { return Ok(None); }
    Ok(Some((start, end)))
}

/// `mbind(2)`'s flag ladder, checked ahead of the address range: an
/// undefined bit outranks the missing capability. `MPOL_MF_LAZY` is
/// deliberately not in `MPOL_MF_VALID`, so it is EINVAL.
/// # C: O(1)
pub fn mbind_flags(flags: u64, cap_sys_nice: bool) -> Result<(), Error> {
    if flags & !MPOL_MF_VALID != 0 { return Err(Error::Inval); }
    if flags & MPOL_MF_MOVE_ALL != 0 && !cap_sys_nice { return Err(Error::Perm); }
    Ok(())
}

/// `move_pages(2)`'s flag ladder. Narrower than mbind's: `MPOL_MF_STRICT`
/// is rejected here.
/// # C: O(1)
pub fn move_pages_flags(flags: u64, cap_sys_nice: bool) -> Result<(), Error> {
    if flags & !MPOL_MF_MOVE_VALID != 0 { return Err(Error::Inval); }
    if flags & MPOL_MF_MOVE_ALL != 0 && !cap_sys_nice { return Err(Error::Perm); }
    Ok(())
}

/// `set_mempolicy_home_node(2)`'s home-node check: `home_node` is an unsigned
/// long argument, so the "no node" sentinel `-1` arrives as `ULONG_MAX` and
/// is rejected by the `>= MAX_NUMNODES` test — the syscall has no way to
/// CLEAR a home node.
/// # C: O(1)
pub fn home_node_ok(home_node: u64) -> bool {
    home_node < MAX_NUMNODES && home_node == NODE_ID_LOCAL as u64
}

/// `move_pages(2)`'s per-entry node check: a node id
/// that is out of range, or in range but carrying no memory, is `ENODEV`; a
/// node outside the target task's cpuset is `EACCES`. Both abort the whole
/// syscall rather than landing in the status array.
///
/// On a single-node PMM the `EACCES` leg is unreachable: the only node with
/// memory is `NODE_ID_LOCAL`, which is always inside the cpuset, and every
/// other id fails `node_state(node, N_MEMORY)` first.
/// # C: O(1)
pub fn move_pages_target_node(node: i32) -> Result<u16, MovePagesNodeErr> {
    if node < 0 || node as u64 >= MAX_NUMNODES { return Err(MovePagesNodeErr::NoDev); }
    if node as u16 != NODE_ID_LOCAL { return Err(MovePagesNodeErr::NoDev); }
    Ok(node as u16)
}

/// Errno-carrying outcome of [`move_pages_target_node`].
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum MovePagesNodeErr {
    /// `-ENODEV`.
    NoDev,
    /// `-EACCES` — unreachable while the PMM is single-node; kept so the
    /// ladder still mirrors the full move_pages(2) contract.
    Access,
}
