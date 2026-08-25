// The security modules this kernel carries.
//
// A module is listed here once it registers a hook the kernel actually
// reaches. Listing one that answers nothing would publish an identity to
// userspace for a policy that cannot refuse anything, which reads to a
// caller as a module that is running and permissive.

use alloc::vec::Vec;

use crate::blob::{BlobKind, BlobRequest};
use crate::module::{LsmInfo, LSM_FLAG_EXCLUSIVE, LSM_FLAG_LEGACY_MAJOR};
use crate::uapi;

/// Order the modules initialise in when the boot line says nothing.
///
/// Path-based mediation runs ahead of label-based, matching the reference
/// order, so a sandbox a process built for itself is consulted before the
/// system-wide policy and a refusal by either stands.
pub const BUILTIN_ORDER: &str = "landlock,bpf,selinux";

/// Capability checks are the fixed first security module, as in Linux.
pub fn capability() -> LsmInfo {
    LsmInfo::new("capability", uapi::LSM_ID_CAPABILITY).order(crate::module::Order::First)
}

/// Slot each module asks for, in units of one typed value per object.
///
/// Sizes are slot counts rather than byte counts: this kernel's per-object
/// state is a typed value the object owns, so what a module needs is a place
/// to put one, not a run of bytes to lay a structure over.
const ONE_SLOT: u32 = 1;

/// Path-based mediation.
pub fn landlock() -> LsmInfo {
    LsmInfo::new("landlock", uapi::LSM_ID_LANDLOCK)
        .blobs(BlobRequest::NONE
            .with(BlobKind::Cred, ONE_SLOT)
            .with(BlobKind::File, ONE_SLOT)
            .with(BlobKind::Inode, ONE_SLOT)
            .with(BlobKind::Superblock, ONE_SLOT))
}

/// Label-based mandatory access control.
pub fn selinux(enabled: bool) -> LsmInfo {
    LsmInfo::new("selinux", uapi::LSM_ID_SELINUX)
        .flags(LSM_FLAG_LEGACY_MAJOR | LSM_FLAG_EXCLUSIVE)
        .enabled(enabled)
        .blobs(BlobRequest::NONE
            .with(BlobKind::Cred, ONE_SLOT)
            .with(BlobKind::Task, ONE_SLOT)
            .with(BlobKind::File, ONE_SLOT)
            .with(BlobKind::Inode, ONE_SLOT)
            .with(BlobKind::Superblock, ONE_SLOT)
            .with(BlobKind::Sock, ONE_SLOT)
            .with(BlobKind::Ipc, ONE_SLOT)
            .with(BlobKind::MsgMsg, ONE_SLOT))
}

/// BPF LSM hook provider. Its programs are attached dynamically, but the
/// provider itself is still part of the resolved hook order.
pub fn bpf() -> LsmInfo { LsmInfo::new("bpf", uapi::LSM_ID_BPF) }

/// Every module compiled into this kernel, in declaration order.
///
/// Declaration order is not initialisation order — the boot list decides
/// that — but it does decide which module a legacy selection excludes first,
/// so it is fixed here rather than left to whoever registers.
/// # C: O(1)
pub fn builtin(selinux_enabled: bool) -> Vec<LsmInfo> {
    alloc::vec![capability(), landlock(), bpf(), selinux(selinux_enabled)]
}

#[cfg(test)]
#[path = "tests/modules.rs"]
mod tests;
