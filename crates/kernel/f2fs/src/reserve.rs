//! Who may spend the volume's held-back space.
//!
//! `reserve_root=` and `reserve_node=` hold blocks and node slots back from
//! the ordinary availability figure so that a full volume is still writable by
//! someone. Subtracting them from EVERY caller would reserve space nobody can
//! ever reach, which is the same as not having the option at all — the point
//! is that the last blocks belong to a named party.
//!
//! The decision is a pure function of the mount's two ids and three ambient
//! facts about the caller, so it can be tested without a volume, a task or a
//! medium. The facts arrive through `vfs::fsreserve`; nothing here holds a
//! credential.

use vfs::ReservedCaller;

/// The default reserved gid, which does NOT hand the pool to group 0: a volume
/// that never named a group has not reserved for one, and treating the default
/// as a real membership would admit every caller whose fsgid is root's.
pub const ROOT_GID: u32 = 0;

/// The mount options the decision reads.
#[derive(Copy, Clone, PartialEq, Eq, Debug, Default)]
pub struct Reserve {
    /// Blocks held back, zero when `reserve_root=` was not given.
    pub blocks: u32,
    /// Node slots held back, zero when `reserve_node=` was not given.
    pub nodes: u32,
    pub resuid: u32,
    pub resgid: u32,
}

/// Whether this caller may spend the held-back space.
///
/// `caller` is `None` for kernel context, which is admitted: the pool exists
/// so the machine can still write when the volume is full, and the kernel's
/// own writes are the first thing that must not be stopped.
///
/// `quota_file` marks an allocation for a quota file, admitted for the same
/// reason — refusing it strands the accounting that would say why the volume
/// filled.
///
/// `cap` says whether this call site honours `CAP_SYS_RESOURCE`. It is not
/// always set: the block half of a node allocation only honours it when the
/// node reserve is in force.
/// # C: O(1)
pub fn allow_reserved_root(r: &Reserve, caller: Option<&ReservedCaller>, quota_file: bool,
                           cap: bool) -> bool {
    let Some(c) = caller else { return true };
    if quota_file { return true; }
    if c.fsuid == r.resuid { return true; }
    if r.resgid != ROOT_GID && c.in_res_group { return true; }
    cap && c.cap_sys_resource
}

/// Blocks an allocation may take up, given the decision. # C: O(1)
pub fn available_blocks(user_block_count: u64, r: &Reserve, allow: bool) -> u64 {
    if allow { user_block_count } else { user_block_count.saturating_sub(u64::from(r.blocks)) }
}

/// Node slots an allocation may take up, given the decision. # C: O(1)
pub fn available_nodes(total_nodes: u64, r: &Reserve, allow: bool) -> u64 {
    if allow { total_nodes } else { total_nodes.saturating_sub(u64::from(r.nodes)) }
}

#[cfg(test)]
#[path = "tests/reserve.rs"]
mod tests;
