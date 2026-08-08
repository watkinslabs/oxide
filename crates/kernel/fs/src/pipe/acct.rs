// Who a pipe's page charge is booked against.
//
// The arithmetic — the ladders, the limits and the per-user counter — lives in
// `vfs::pipe_limits`, where procfs can bind the sysctl leaves to it. This file
// is only the live lookup: which account the running task charges, and which
// capabilities exempt it from the two per-user limits.

use core::sync::atomic::Ordering;
use vfs::pipe_limits::PipeCaps;

/// Account and standing of the running task.
///
/// Off the scheduler (hosted tests, boot smoke) there is no task to ask: the
/// charge lands on account 0 with no exemption, so the ladders run exactly as
/// they do for an ordinary process.
/// # C: O(1)
pub(super) fn current_account() -> (u32, PipeCaps) {
    match sched::current() {
        Some(t) => {
            let sys_resource = t.has_cap(sched::cap::SYS_RESOURCE);
            let unprivileged = !sys_resource && !t.has_cap(sched::cap::SYS_ADMIN);
            (t.creds.ruid.load(Ordering::Acquire), PipeCaps { sys_resource, unprivileged })
        }
        None => (0, PipeCaps { sys_resource: false, unprivileged: true }),
    }
}
