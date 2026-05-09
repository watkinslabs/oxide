// Namespaces + cgroup v2 per `26`.
//
// Owns the `/proc/<pid>/ns/<type>` real Inode (`NsInode`) and the
// setns/has_cap_for plumbing. Per-task ns id slots themselves live
// on `sched::Task` (uts/ipc/net/pid/user/cgroup/mount); this crate
// is the inode-side surface that bridges userspace fd handles to
// those slots.
//
// cgroup v2 hierarchy walker rides v2.x once the cgroup tree+
// controllers (cpu/memory/pids/io) get wired. v1 ships pid_ns +
// user_ns parent registry only.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

extern crate alloc;

pub mod proc_ns;

pub use proc_ns::{
    CLONE_NEWCGROUP, CLONE_NEWIPC, CLONE_NEWNET, CLONE_NEWNS,
    CLONE_NEWPID, CLONE_NEWUSER, CLONE_NEWUTS,
    NsInode, NsKind, has_cap_for, ns_inode_for, setns_apply,
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
