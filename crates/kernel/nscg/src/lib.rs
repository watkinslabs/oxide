// Namespaces + cgroup v2 per `26`.
//
// Owns the `/proc/<pid>/ns/<type>` real Inode (`NsInode`) and the
// setns/has_cap_for plumbing. Per-task ns id slots themselves live
// on `sched::Task` (uts/ipc/net/pid/user/cgroup/mount); this crate
// is the inode-side surface that bridges userspace fd handles to
// those slots.
//
// cgroup v2 hierarchy walker is a follow-up once the cgroup tree+
// controllers (cpu/memory/pids/io) get wired. v1 ships pid_ns plus
// user_ns parent registry; network ownership lives in `network-namespace`.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

extern crate alloc;

pub mod proc_ns;
pub mod uts_ns;

pub use proc_ns::{
    CLONE_NEWCGROUP, CLONE_NEWIPC, CLONE_NEWNET, CLONE_NEWNS,
    CLONE_NEWPID, CLONE_NEWUSER, CLONE_NEWUTS,
    NsInode, NsKind, has_cap_for, has_net_admin_for, has_net_raw_for,
    net_ns_inode, ns_inode_for, setns_apply, setns_from_fd,
};

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
