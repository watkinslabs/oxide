// Namespaces + cgroup v2 per `26`.
//
// Owns the `/proc/<pid>/ns/<type>` real Inode (`NsInode`) and the
// setns/has_cap_for plumbing. Concrete per-task namespace owners live
// on `sched::Task`; this crate bridges userspace fd handles to them.
//
// cgroup v2 hierarchy walker is a follow-up once the cgroup tree+
// controllers (cpu/memory/pids/io) get wired.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

extern crate alloc;

#[cfg(test)]
extern crate std;

pub mod proc_ns;
pub mod time_ns;
pub mod uts_ns;
mod listns;
mod owner;

pub use proc_ns::{
    CLONE_NEWCGROUP, CLONE_NEWIPC, CLONE_NEWNET, CLONE_NEWNS, CLONE_NEWTIME,
    CLONE_NEWPID, CLONE_NEWUSER, CLONE_NEWUTS,
    NsInode, NsKind, has_cap_for, has_net_admin_for, has_net_bind_service_for, has_net_raw_for,
    net_ns_inode, ns_inode_for, setns_apply, setns_from_fd,
};
pub use listns::{listns_page, ListNsEntry, ListNsError, ListNsKind, ListNsOwnerFilter, ListNsPage};
pub use owner::NsOwner;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Error { Inval, Perm }

pub type KResult<T> = core::result::Result<T, Error>;

/// Boot-time init reporter. Real per-task ns slots are owned by
/// `sched::Task`; this crate provides the inode-side bridge.
/// # SAFETY: caller is the boot path; pre-init; single-CPU.
/// # C: O(1)
/// # Ctx: pre-init, IRQ-off, single-CPU
pub unsafe fn init() -> KResult<()> { Ok(()) }

#[cfg(test)]
mod tests {
    use super::*;
    // SAFETY: hosted-test path; init has no side effects.
    #[test] fn init_ok() { unsafe { assert!(init().is_ok()); } }
}
