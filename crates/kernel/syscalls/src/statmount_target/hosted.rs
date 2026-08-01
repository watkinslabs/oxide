// Hosted stand-ins for the scheduler / nsfs / fd-table facts `statmount(2)` and
// `listmount(2)` sample. A hosted test has no current task, no descriptor table
// and no user namespace, so each fact reports its "nothing there" answer and
// the harness exercises the mount-tree half of both syscalls against a real
// fixture tree.

use alloc::sync::Arc;
use syscall::errno::Errno;

fn neg(e: Errno) -> i64 { -(e.as_i32() as i64) }

/// No descriptor table: every fd is bad. # C: O(1)
pub(crate) fn ns_from_fd(_fd: u32) -> Result<u64, i64> { Err(neg(Errno::Ebadf)) }

/// No descriptor table: every fd is bad. # C: O(1)
pub(crate) fn mount_of_fd(_fd: u32) -> Result<u64, i64> { Err(neg(Errno::Ebadf)) }

/// No task, so no capability in any namespace. # C: O(1)
pub(crate) fn may_admin_ns(_ns: u64) -> bool { false }

/// No `fs_struct`, so the namespace root stands in. # C: O(1)
pub(crate) fn caller_fs_root() -> Option<(u64, Arc<vfs::dentry::Dentry>)> { None }

/// No task, so no user namespace to resolve id mappings into. # C: O(1)
pub(crate) fn current_user_ns() -> Option<namespace_identity::NamespaceRef> { None }

/// Hosted buffers are ordinary process memory; only a null base with a nonzero
/// length is a fault, which is what the harness passes to exercise that rung.
/// # C: O(1)
pub(crate) fn user_readable(addr: u64, len: u64) -> Result<(), i64> {
    if len != 0 && addr == 0 { return Err(neg(Errno::Efault)); }
    Ok(())
}
/// [`user_readable`] for a write target. # C: O(1)
pub(crate) fn user_writable(addr: u64, len: u64) -> Result<(), i64> { user_readable(addr, len) }
