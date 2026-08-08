// A pidfd's `ioctl(2)` surface — the live half. The command vocabulary and
// every admission decision live ungated in `crate::pidfs_ioctl`; this file and
// its children are kernel-only and do work, never decide.
//
// Module manifest:
//   `info`       — `PIDFD_GET_INFO`: snapshot, mask arbitration, copy-out.
//   `namespaces` — the ten `PIDFD_GET_*_NAMESPACE` descriptors.

#![cfg(target_os = "oxide-kernel")]

pub mod info;
pub mod namespaces;

use crate::pidfs_ioctl::{decide, PidfsIoctl};

/// Dispatch one pidfd ioctl after the fd has been confirmed to be a pidfd.
/// A command this file does not name is Linux's `ENOIOCTLCMD`, which the
/// vfs turns into `ENOTTY` for userspace.
/// # C: O(N_tasks)
pub fn handle_pidfd_ioctl(identity: alloc::sync::Arc<sched::pid::PidIdentity>, req: u64, arg: u64) -> i64 {
    match decide(req) {
        Some(PidfsIoctl::Info { size }) => info::get_info(&identity, size, arg),
        Some(PidfsIoctl::Namespace(kind)) => namespaces::get_namespace(&identity, kind, arg),
        None => -(syscall::errno::Errno::Enotty.as_i32() as i64),
    }
}
