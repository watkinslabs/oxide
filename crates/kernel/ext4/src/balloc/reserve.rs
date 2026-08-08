// Reserved-block admission: who may consume the superblock's reserved blocks
// once the filesystem is otherwise out of space.
//
// `resuid=`/`resgid=` are the mount options this decides, and they are only
// options at all because the reserve exists: a filesystem keeps
// `s_r_blocks_count` blocks back so a full disk still leaves the administrator
// (and the daemons that keep the machine alive) room to work. Without this gate
// the reserve is a number nobody consults and both options are decoration.
//
// UNGATED on purpose: the whole admission decision is stated here so
// `cargo test` reaches it without a device, a mount or a running task.

use alloc::vec::Vec;

use crate::mount_opts::Ext4Behaviour;

/// The credentials one block allocation is charged to.
///
/// Carried rather than fetched inside the decision so the answer is a pure
/// function of the state that produced it — the fetch is [`current_alloc_cred`].
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AllocCred {
    /// Filesystem uid of the allocating context.
    pub uid: u32,
    /// Its supplementary groups.
    pub gids: Vec<u32>,
    /// Whether it holds the capability that overrides resource limits.
    pub cap_sys_resource: bool,
}

impl AllocCred {
    /// The credentials of a context with no task behind it — a kernel thread,
    /// the mount path, the boot chain. Their filesystem uid is root's, which is
    /// what makes the filesystem's own housekeeping able to finish on a disk
    /// that is full for everybody else. # C: O(1)
    pub fn kernel_context() -> Self {
        Self { uid: ROOT_UID, gids: Vec::new(), cap_sys_resource: true }
    }
}

/// The uid the reserve belongs to when no mount option moved it.
pub const ROOT_UID: u32 = 0;

/// Why an allocation may enter the reserve regardless of who asked for it.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ReserveFlags {
    /// The allocation belongs to a quota file. Quota accounting has to be able
    /// to record that the disk filled up, so its own blocks come out of the
    /// reserve rather than being the first casualty of a full filesystem.
    pub use_root_blocks: bool,
    /// The allocation is metadata a caller already past the point of no return
    /// needs — an extent tree being rewritten cannot answer ENOSPC halfway and
    /// leave a half-built tree behind.
    pub use_reserved: bool,
}

impl ReserveFlags {
    /// An ordinary file-data allocation: no claim on the reserve of its own.
    pub const DATA: Self = Self { use_root_blocks: false, use_reserved: false };
    /// A quota file's own blocks.
    pub const QUOTA_FILE: Self = Self { use_root_blocks: true, use_reserved: false };
    /// Metadata whose caller cannot back out.
    pub const METADATA_NOFAIL: Self = Self { use_root_blocks: false, use_reserved: true };
}

/// Whether this allocation may be satisfied out of the reserved blocks.
///
/// The credential half is the mount options': the user `resuid=` names, a
/// member of the group `resgid=` names, or a context holding the capability
/// that overrides resource limits. The flag half is the allocation's own: a
/// quota file, or metadata whose caller is already committed.
/// # C: O(len(cred.gids))
pub fn may_dip_into_reserve(b: &Ext4Behaviour, cred: &AllocCred, flags: ReserveFlags) -> bool {
    if b.may_use_reserved(cred.uid, &cred.gids) { return true; }
    flags.use_root_blocks || flags.use_reserved || cred.cap_sys_resource
}

/// Whether `want` blocks may be taken when `free` are left and `r_blocks` of
/// them are reserved.
///
/// The reserve is subtracted first: an allocation with no claim on it must
/// leave the whole reserve behind, which is what makes the reserve a reserve
/// rather than a number. Only once that fails does the claim matter, and a
/// claim buys exactly the reserve and no more — nothing may allocate a block
/// that is not free.
/// # C: O(1)
pub fn has_free_blocks(free: u64, want: u64, r_blocks: u64, may_dip: bool) -> bool {
    if free >= r_blocks.saturating_add(want) { return true; }
    may_dip && free >= want
}

/// The credentials of the context running right now.
///
/// A context with no task is the kernel's own, and gets root's answer — the
/// mount path, journal recovery and orphan cleanup all allocate before any task
/// exists, and refusing them would make a nearly-full filesystem unmountable.
/// # C: O(len(groups))
pub fn current_alloc_cred() -> AllocCred {
    let Some(t) = sched::current() else { return AllocCred::kernel_context() };
    AllocCred {
        uid: t.creds.fsuid.load(::core::sync::atomic::Ordering::Acquire),
        gids: t.creds.group_list().map(|g| g.to_vec()).unwrap_or_default(),
        cap_sys_resource: t.has_cap(sched::cap::SYS_RESOURCE),
    }
}

#[cfg(test)]
mod tests;
