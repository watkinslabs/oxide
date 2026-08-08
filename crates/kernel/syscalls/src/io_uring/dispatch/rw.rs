// Read/write family, fixed-buffer transfers, and the size/sync operations.
//
// `off == -1` means "use the description's own file position", which is what
// `IORING_FEAT_RW_CUR_POS` promises: the same entry works for a pipe or a
// socket, where a positional read has no meaning.

use alloc::sync::Arc;

use syscall::errno::Errno;
use vfs::File;

use crate::io_uring_abi::ops::IORING_FSYNC_DATASYNC;

use super::router::{call, Op};

fn err(e: Errno) -> i64 { -(e.as_i32() as i64) }

/// The SQE offset meaning "use the file position".
const CUR_POS: u64 = u64::MAX;

/// Resolve the operation's descriptor to an open description. # C: O(1)
fn file_of(fd: i32) -> Result<Arc<File>, i64> {
    let Some(cur) = sched::live::current() else { return Err(err(Errno::Ebadf)) };
    // SAFETY: running task on this CPU; preempt-off; sole reader of the fd_table slot.
    let Some(fdt) = (unsafe { cur.fd_table_ref() }) else { return Err(err(Errno::Ebadf)) };
    fdt.clone().get(fd).map_err(|_| err(Errno::Ebadf))
}

/// # C: O(len)
pub fn read(op: &Op) -> i64 {
    if op.sqe.off == CUR_POS {
        call(crate::s000_read::sys_read, [op.fd as u64, op.addr, op.len as u64, 0, 0, 0])
    } else {
        call(crate::s017_pread64::sys_pread64, [op.fd as u64, op.addr, op.len as u64, op.sqe.off, 0, 0])
    }
}

/// # C: O(len)
pub fn write(op: &Op) -> i64 {
    if op.sqe.off == CUR_POS {
        call(crate::s001_write::sys_write, [op.fd as u64, op.addr, op.len as u64, 0, 0, 0])
    } else {
        call(crate::s018_pwrite64::sys_pwrite64, [op.fd as u64, op.addr, op.len as u64, op.sqe.off, 0, 0])
    }
}

/// The vectored forms carry their offset the same way, and the positional
/// vectored syscall already treats `-1` as "current position". # C: O(len)
pub fn readv(op: &Op) -> i64 {
    call(crate::s295_preadv::sys_preadv2,
         [op.fd as u64, op.addr, op.len as u64, op.sqe.off, 0, op.sqe.op_flags as u64])
}

/// # C: O(len)
pub fn writev(op: &Op) -> i64 {
    call(crate::s296_pwritev::sys_pwritev2,
         [op.fd as u64, op.addr, op.len as u64, op.sqe.off, 0, op.sqe.op_flags as u64])
}

/// Transfer between a registered buffer and a file. The bytes move through the
/// frames pinned at registration time, never through the caller's current
/// mapping, so the transfer is unaffected by anything the process does to its
/// address space in between. # C: O(len)
fn fixed(op: &Op, write: bool) -> i64 {
    let file = match file_of(op.fd) { Ok(f) => f, Err(e) => return e };
    // Take an owning handle on the pinned buffer and drop the lock: the
    // transfer below sleeps, and no spinlock may be held across it.
    let buf = {
        let g = op.inode.reg.lock();
        let Some(bufs) = g.buffers.as_ref() else { return err(Errno::Efault) };
        let Some(slot) = bufs.get(op.sqe.buf_index as usize) else { return err(Errno::Efault) };
        Arc::clone(&slot.buf)
    };
    if buf.is_empty() { return err(Errno::Efault); }
    // The SQE address names a window inside the registered buffer.
    let Some(off_in_buf) = op.addr.checked_sub(buf.base) else { return err(Errno::Efault) };
    let mut pos = op.sqe.off as i64;
    if pos < 0 && op.sqe.off != CUR_POS { return err(Errno::Einval); }
    let mut failed: i64 = 0;
    let walked = buf.for_each_chunk(off_in_buf, op.len as u64, |chunk| {
        let r = if write { file.pwrite(chunk, pos) } else { file.pread(chunk, pos) };
        match r {
            Ok(0) => None,
            Ok(n) => { pos += n as i64; Some(n) }
            Err(e) => { failed = crate::namei_common::errno_from_vfs(e); None }
        }
    });
    match walked {
        Err(e) => err(e),
        Ok(0) if failed != 0 => failed,
        Ok(n) => n as i64,
    }
}

/// # C: O(len)
pub fn read_fixed(op: &Op) -> i64 { fixed(op, false) }

/// # C: O(len)
pub fn write_fixed(op: &Op) -> i64 { fixed(op, true) }

/// # C: O(dirty pages)
pub fn fsync(op: &Op) -> i64 {
    let f = if op.sqe.op_flags & IORING_FSYNC_DATASYNC != 0 {
        crate::misc::sys_fdatasync
    } else {
        crate::misc::sys_fsync
    };
    call(f, [op.fd as u64, 0, 0, 0, 0, 0])
}

/// # C: O(range)
pub fn sync_file_range(op: &Op) -> i64 {
    call(crate::misc::sys_sync_file_range,
         [op.fd as u64, op.sqe.off, op.sqe.len as u64, op.sqe.op_flags as u64, 0, 0])
}

/// `fallocate` takes its mode from `len` and its length from `addr`.
/// # C: O(range)
pub fn fallocate(op: &Op) -> i64 {
    call(crate::s285_fallocate::sys_fallocate,
         [op.fd as u64, op.sqe.len as u64, op.sqe.off, op.sqe.addr, 0, 0])
}

/// # C: O(1)
pub fn ftruncate(op: &Op) -> i64 {
    call(crate::s077_ftruncate::sys_ftruncate, [op.fd as u64, op.sqe.off, 0, 0, 0, 0])
}

/// # C: O(range)
pub fn fadvise(op: &Op) -> i64 {
    let len = if op.sqe.addr != 0 { op.sqe.addr } else { op.sqe.len as u64 };
    call(crate::s221_fadvise64::sys_fadvise64,
         [op.fd as u64, op.sqe.off, len, op.sqe.op_flags as u64, 0, 0])
}

/// # C: O(range)
pub fn madvise(op: &Op) -> i64 {
    let len = if op.sqe.off != 0 { op.sqe.off } else { op.sqe.len as u64 };
    call(crate::s028_madvise::sys_madvise, [op.sqe.addr, len, op.sqe.op_flags as u64, 0, 0, 0])
}
