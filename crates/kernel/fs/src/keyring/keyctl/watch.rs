// `KEYCTL_WATCH_KEY` argument marshalling: turn the caller's descriptor into
// the queue behind it, then call the core.

use syscall::SyscallArgs;
use syscall::errno::Errno;

use crate::watch_queue;

use super::super::ops::{watch, Ctx};
use super::super::err;

/// `keyctl(KEYCTL_WATCH_KEY, key, watch_queue_fd, watch_id)`.
///
/// The descriptor must be a NOTIFICATION pipe. An ordinary pipe, or anything
/// that is not a pipe at all, is EINVAL: there is nowhere to deliver to, and
/// silently accepting the call would leave a caller believing it is watching
/// something. # C: O(log N + watches)
pub fn watch_key(c: &Ctx, args: &SyscallArgs) -> i64 {
    let (serial, fd, watch_id) = (args.a1 as i32, args.a2 as i32, args.a3 as i32);
    // The watchpoint id is vetted before the descriptor is looked up, matching
    // the order the core documents: an id that could never be delivered is
    // EINVAL whatever the caller passed as a queue.
    if let Err(e) = watch::vet_watch_id(watch_id) { return err(e); }
    let Some(file) = current_file(fd) else { return err(Errno::Ebadf) };
    let Some(queue) = watch_queue::queue_of(file.inode()) else { return err(Errno::Einval) };
    watch::watch_key_core(c, serial, queue, watch_id)
}

/// The open file behind a descriptor of the calling task. # C: O(1)
#[cfg(target_os = "oxide-kernel")]
fn current_file(fd: i32) -> Option<alloc::sync::Arc<vfs::File>> {
    let cur = sched::current()?;
    // SAFETY: the running task on this CPU with preemption off is the sole reader of its own fd-table slot.
    let fdt = unsafe { cur.fd_table_ref() }?.clone();
    fdt.get(fd).ok()
}

/// Hosted builds have no descriptor table; the core is driven directly by the
/// tests, which pass a queue rather than a descriptor.
#[cfg(not(target_os = "oxide-kernel"))]
fn current_file(_fd: i32) -> Option<alloc::sync::Arc<vfs::File>> { None }
