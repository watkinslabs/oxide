// `IORING_OP_SPLICE` and `IORING_OP_TEE`.
//
// Both reach the transfer machinery directly rather than through the syscall
// shim, for one reason: the syscall takes its offsets as `loff_t __user *` and
// the entry carries them as VALUES. Going through the shim would mean writing
// the entry's offsets into user memory that the caller never supplied, so the
// shim's copy-in/copy-out is exactly the part that does not apply here.
//
// The input description has an indirection no other opcode's has —
// `SPLICE_F_FD_IN_FIXED` makes `splice_fd_in` a registered-file index — and it
// is resolved here, where the registration table is reachable, rather than by
// the generic descriptor resolution that only knows about the entry's own
// `fd`.

use alloc::sync::Arc;

use syscall::errno::Errno;
use vfs::File;

use crate::io_uring_abi::splice::{prep, SpliceOp};

use super::router::Op;

fn err(e: Errno) -> i64 { -(e.as_i32() as i64) }

/// Resolve a descriptor of the submitting task. # C: O(1)
fn task_file(fd: i32) -> Result<Arc<File>, i64> {
    let Some(cur) = sched::live::current() else { return Err(err(Errno::Ebadf)) };
    // SAFETY: running task on this CPU; preempt-off; sole reader of the fd_table slot for the splice input descriptor.
    let Some(fdt) = (unsafe { cur.fd_table_ref() }) else { return Err(err(Errno::Ebadf)) };
    fdt.clone().get(fd).map_err(|_| err(Errno::Ebadf))
}

/// The input description: a registered file when the entry said so, otherwise
/// a descriptor of the task. # C: O(1)
fn in_file(op: &Op, sp: &SpliceOp) -> Result<Arc<File>, i64> {
    if sp.fd_in_fixed { super::fdres::fixed_file(op.inode, sp.fd_in as u32) }
    else { task_file(sp.fd_in) }
}

/// Both entries, decoded and with both descriptions resolved. Ordered as the
/// reference orders it: a descriptor that names nothing is `EBADF` even when
/// the transfer would have moved no bytes, so a caller cannot mistake a bad
/// descriptor for an empty transfer. # C: O(1)
fn operands(op: &Op) -> Result<(SpliceOp, Arc<File>, Arc<File>), i64> {
    let sp = prep(op.sqe).map_err(err)?;
    let out = task_file(op.fd)?;
    let inf = in_file(op, &sp)?;
    Ok((sp, inf, out))
}

/// # C: O(len)
pub fn splice(op: &Op) -> i64 {
    let (sp, inf, out) = match operands(op) { Ok(v) => v, Err(e) => return e };
    if sp.len == 0 { return 0; }
    let (mut oi, mut oo) = (sp.off_in, sp.off_out);
    ::fs::splice::do_splice(&inf, oi.as_mut(), &out, oo.as_mut(), sp.len as usize, sp.flags as u64)
}

/// # C: O(len)
pub fn tee(op: &Op) -> i64 {
    let (sp, inf, out) = match operands(op) { Ok(v) => v, Err(e) => return e };
    if sp.len == 0 { return 0; }
    ::fs::splice::do_tee(&inf, &out, sp.len as usize, sp.flags as u64)
}
