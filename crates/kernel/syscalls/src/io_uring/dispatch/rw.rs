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
pub(super) fn file_of(fd: i32) -> Result<Arc<File>, i64> {
    let Some(cur) = sched::live::current() else { return Err(err(Errno::Ebadf)) };
    // SAFETY: running task on this CPU; preempt-off; sole reader of the fd_table slot.
    let Some(fdt) = (unsafe { cur.fd_table_ref() }) else { return Err(err(Errno::Ebadf)) };
    fdt.clone().get(fd).map_err(|_| err(Errno::Ebadf))
}

/// The polled-ring admission for one transfer, and the high-priority refusal
/// for a ring that is not polled.
///
/// Resolved here rather than in the entry's own admission because the answer
/// depends on the DESCRIPTION, not on the entry: whether the transfer bypasses
/// the page cache, and whether the backend behind this description exposes a
/// poll for completed I/O at all. Reported as `EOPNOTSUPP`, which is what
/// separates "this file cannot serve a polled transfer" from the `EINVAL` a
/// malformed entry gets. # C: O(1)
pub(super) fn polled_admission(op: &Op, hipri: bool) -> Result<(), i64> {
    use crate::io_uring_abi::iopoll::{admit_rw, RwTarget};
    let ring_iopoll = crate::io_uring::iopoll::polled(&op.inode);
    if !ring_iopoll && !hipri { return Ok(()); }
    let file = file_of(op.fd)?;
    let t = RwTarget {
        ring_iopoll,
        direct: file.flags().contains(vfs::OpenFlags::O_DIRECT),
        file_pollable: crate::io_uring::iopoll::file_pollable(&file),
        hipri,
    };
    admit_rw(&t).map_err(err)
}

/// Whether the description carries integrity metadata beside its data.
///
/// No storage target registered here exposes an integrity profile, so no
/// description can serve an attribute vector yet. The answer is asked of the
/// description rather than assumed, so the admission ladder below is the one
/// that runs the moment a target does. # C: O(1)
fn has_metadata(_f: &Arc<File>) -> bool { false }

/// The attribute vector the entry points at, if any: decoded, validated, and
/// checked against what the description can carry.
///
/// Refused BEFORE the transfer, because an attribute the target cannot honour
/// must not be answered by a transfer that silently dropped it — that is the
/// difference the feature bit announces. # C: O(1)
pub(super) fn attr_admission(op: &Op) -> Result<(), i64> {
    use crate::io_uring_abi::rw_attr::{admit_target, op_takes_attr, parse_pi, wants_attr,
                                       ATTR_PI_BYTES};
    if !op_takes_attr(op.sqe.opcode) { return Ok(()); }
    if !wants_attr(op.sqe.pad2).map_err(err)? { return Ok(()); }
    let mut b = [0u8; ATTR_PI_BYTES];
    if uaccess::copy_from_user(&mut b, op.sqe.addr3).is_err() { return Err(err(Errno::Efault)); }
    let pi = parse_pi(&b).map_err(err)?;
    if pi.len != 0 && !uaccess::access_ok(pi.addr, pi.len as usize) {
        return Err(err(Errno::Efault));
    }
    let file = file_of(op.fd)?;
    admit_target(has_metadata(&file), file.flags().contains(vfs::OpenFlags::O_DIRECT))
        .map_err(err)
}

/// `RWF_HIPRI` out of the vectored forms' `rw_flags` word. # C: O(1)
fn hipri_of(op: &Op) -> bool {
    op.sqe.op_flags as u64 & crate::rwf::RWF_HIPRI != 0
}

/// # C: O(len)
#[inline(always)]
pub fn read(op: &Op) -> i64 {
    if let Err(e) = attr_admission(op) { return e; }
    if let Err(e) = polled_admission(op, false) { return e; }
    if op.sqe.off == CUR_POS {
        call(crate::s000_read::sys_read, [op.fd as u64, op.addr, op.len as u64, 0, 0, 0])
    } else {
        call(crate::s017_pread64::sys_pread64, [op.fd as u64, op.addr, op.len as u64, op.sqe.off, 0, 0])
    }
}

/// # C: O(len)
#[inline(always)]
pub fn write(op: &Op) -> i64 {
    if let Err(e) = attr_admission(op) { return e; }
    if let Err(e) = polled_admission(op, false) { return e; }
    if op.sqe.off == CUR_POS {
        call(crate::s001_write::sys_write, [op.fd as u64, op.addr, op.len as u64, 0, 0, 0])
    } else {
        call(crate::s018_pwrite64::sys_pwrite64, [op.fd as u64, op.addr, op.len as u64, op.sqe.off, 0, 0])
    }
}

/// The vectored forms carry their offset the same way, and the positional
/// vectored syscall already treats `-1` as "current position". # C: O(len)
#[inline(always)]
pub fn readv(op: &Op) -> i64 {
    if let Err(e) = attr_admission(op) { return e; }
    if let Err(e) = polled_admission(op, hipri_of(op)) { return e; }
    call(crate::s295_preadv::sys_preadv2,
         [op.fd as u64, op.addr, op.len as u64, op.sqe.off, 0, op.sqe.op_flags as u64])
}

/// # C: O(len)
#[inline(always)]
pub fn writev(op: &Op) -> i64 {
    if let Err(e) = attr_admission(op) { return e; }
    if let Err(e) = polled_admission(op, hipri_of(op)) { return e; }
    call(crate::s296_pwritev::sys_pwritev2,
         [op.fd as u64, op.addr, op.len as u64, op.sqe.off, 0, op.sqe.op_flags as u64])
}

/// Transfer between a registered buffer and a file. The bytes move through the
/// frames pinned at registration time, never through the caller's current
/// mapping, so the transfer is unaffected by anything the process does to its
/// address space in between. # C: O(len)
fn fixed(op: &Op, write: bool) -> i64 {
    if let Err(e) = attr_admission(op) { return e; }
    if let Err(e) = polled_admission(op, false) { return e; }
    let file = match file_of(op.fd) { Ok(f) => f, Err(e) => return e };
    let buf = match super::fdres::reg_buf(op.inode, op.sqe.buf_index as u32) {
        Ok(b) => b, Err(e) => return e,
    };
    // The SQE address names a window inside the registered buffer.
    let w = match crate::io_uring_abi::recvsend::fixed::window(buf.base, buf.len, op.addr, op.len) {
        Ok(w) => w, Err(e) => return err(e),
    };
    let off_in_buf = w.off;
    let mut pos = op.sqe.off as i64;
    if pos < 0 && op.sqe.off != CUR_POS { return err(Errno::Einval); }
    let mut failed: i64 = 0;
    let walked = buf.for_each_chunk(off_in_buf, w.len, |chunk| {
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
#[inline(always)]
pub fn fsync(op: &Op) -> i64 {
    let f = if op.sqe.op_flags & IORING_FSYNC_DATASYNC != 0 {
        crate::misc::sys_fdatasync
    } else {
        crate::misc::sys_fsync
    };
    call(f, [op.fd as u64, 0, 0, 0, 0, 0])
}

/// # C: O(range)
#[inline(always)]
pub fn sync_file_range(op: &Op) -> i64 {
    call(crate::misc::sys_sync_file_range,
         [op.fd as u64, op.sqe.off, op.sqe.len as u64, op.sqe.op_flags as u64, 0, 0])
}

/// `fallocate` takes its mode from `len` and its length from `addr`.
/// # C: O(range)
#[inline(always)]
pub fn fallocate(op: &Op) -> i64 {
    call(crate::s285_fallocate::sys_fallocate,
         [op.fd as u64, op.sqe.len as u64, op.sqe.off, op.sqe.addr, 0, 0])
}

/// # C: O(1)
#[inline(always)]
pub fn ftruncate(op: &Op) -> i64 {
    call(crate::s077_ftruncate::sys_ftruncate, [op.fd as u64, op.sqe.off, 0, 0, 0, 0])
}

/// # C: O(range)
#[inline(always)]
pub fn fadvise(op: &Op) -> i64 {
    let len = if op.sqe.addr != 0 { op.sqe.addr } else { op.sqe.len as u64 };
    call(crate::s221_fadvise64::sys_fadvise64,
         [op.fd as u64, op.sqe.off, len, op.sqe.op_flags as u64, 0, 0])
}

/// # C: O(range)
#[inline(always)]
pub fn madvise(op: &Op) -> i64 {
    let len = if op.sqe.off != 0 { op.sqe.off } else { op.sqe.len as u64 };
    call(crate::s028_madvise::sys_madvise, [op.sqe.addr, len, op.sqe.op_flags as u64, 0, 0, 0])
}
