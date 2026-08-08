// Operations on ring state itself: updating the registered-file table,
// handing buffers to the kernel, moving a completion or a descriptor into
// another ring, and turning a direct descriptor back into an ordinary one.

use syscall::errno::Errno;

use crate::io_uring::cqe::Cqe;
use crate::io_uring::ctx::IoUringInode;

use super::fdres::{fixed_file, install_scratch};
use super::router::Op;

fn err(e: Errno) -> i64 { -(e.as_i32() as i64) }

/// `IORING_MSG_DATA` — deliver `len` as a completion result carrying
/// `user_data`.
pub const IORING_MSG_DATA: u64 = 0;
/// `IORING_MSG_SEND_FD` — move a registered descriptor into the target ring.
pub const IORING_MSG_SEND_FD: u64 = 1;
/// `IORING_FIXED_FD_NO_CLOEXEC` — install without close-on-exec.
pub const IORING_FIXED_FD_NO_CLOEXEC: u32 = 1;

/// Update registered-file slots from a user array of descriptors, exactly as
/// the register opcode does — one implementation, two entry points.
/// # C: O(nr)
pub fn files_update(op: &Op) -> i64 {
    crate::io_uring::register::files::update_slots(op.inode, op.sqe.addr, op.sqe.len,
                                                   op.sqe.off as u32)
}

/// Resolve the ring behind a descriptor. # C: O(1)
fn ring_at(fd: i32) -> Result<alloc::sync::Arc<IoUringInode>, i64> {
    let Some(cur) = sched::live::current() else { return Err(err(Errno::Ebadf)) };
    // SAFETY: running task on this CPU; preempt-off; sole reader of the fd_table slot.
    let Some(fdt) = (unsafe { cur.fd_table_ref() }) else { return Err(err(Errno::Ebadf)) };
    let file = fdt.clone().get(fd).map_err(|_| err(Errno::Ebadf))?;
    let inode = crate::io_uring::ring_of(&file).map_err(err)?;
    crate::io_uring::ring_ctx(&inode).ok_or(err(Errno::Ebadf))
}

/// Post a completion — or move a descriptor — into another ring. # C: O(1)
pub fn msg_ring(op: &Op) -> i64 {
    let target = match ring_at(op.fd) { Ok(t) => t, Err(e) => return e };
    match op.sqe.addr {
        IORING_MSG_DATA => {
            target.post_cqe(Cqe::new(op.sqe.off, op.sqe.len as i32));
            0
        }
        IORING_MSG_SEND_FD => {
            let file = match fixed_file(op.inode, op.sqe.addr3 as u32) { Ok(f) => f, Err(e) => return e };
            let want = op.sqe.file_index();
            let mut g = target.reg.lock();
            let Some(table) = g.files.as_mut() else { return err(Errno::Enxio) };
            let slot = if want == super::fdres::IORING_FILE_INDEX_ALLOC {
                match table.iter().position(|s| s.file.is_none()) { Some(i) => i, None => return err(Errno::Enfile) }
            } else {
                let i = (want as usize).wrapping_sub(1);
                if want == 0 || i >= table.len() { return err(Errno::Einval); }
                i
            };
            table[slot].file = Some(file);
            drop(g);
            target.post_cqe(Cqe::new(op.sqe.off, 0));
            0
        }
        _ => err(Errno::Einval),
    }
}

/// Hand `nbufs` buffers of `len` bytes each, starting at `addr` with ids from
/// `off`, to group `buf_group`. # C: O(nbufs)
pub fn provide_buffers(op: &Op) -> i64 {
    let nbufs = op.sqe.fd;
    if nbufs <= 0 { return err(Errno::Einval); }
    if op.sqe.len == 0 { return err(Errno::Einval); }
    let bid = op.sqe.off as u16;
    let total = (nbufs as u64).checked_mul(op.sqe.len as u64);
    match total {
        Some(t) if op.sqe.addr.checked_add(t).is_some() => {}
        _ => return err(Errno::Eoverflow),
    }
    let mut g = op.inode.reg.lock();
    match g.provide_bufs(op.sqe.buf_index, op.sqe.addr, op.sqe.len, bid, nbufs as u32) {
        Ok(()) => nbufs as i64,
        Err(e) => err(e),
    }
}

/// # C: O(nbufs)
pub fn remove_buffers(op: &Op) -> i64 {
    let nbufs = op.sqe.fd;
    if nbufs <= 0 { return err(Errno::Einval); }
    let mut g = op.inode.reg.lock();
    match g.remove_bufs(op.sqe.buf_index, nbufs as u32) {
        Ok(0) => err(Errno::Enoent),
        Ok(n) => n as i64,
        Err(e) => err(e),
    }
}

/// Install a registered file as an ordinary descriptor and report it.
/// # C: O(N_fds)
pub fn fixed_fd_install(op: &Op) -> i64 {
    use crate::io_uring_abi::ops::IOSQE_FIXED_FILE;
    if op.sqe.flags & IOSQE_FIXED_FILE == 0 { return err(Errno::Ebadf); }
    if op.sqe.op_flags & !IORING_FIXED_FD_NO_CLOEXEC != 0 { return err(Errno::Einval); }
    // `op.fd` is already a descriptor carrying the registered description; the
    // scratch registration is released when the operation ends, so install a
    // second, lasting one.
    let file = match fixed_file(op.inode, op.sqe.fd as u32) { Ok(f) => f, Err(e) => return e };
    let cloexec = op.sqe.op_flags & IORING_FIXED_FD_NO_CLOEXEC == 0;
    match install_scratch(file) {
        Ok(s) => {
            let fd = s.0;
            core::mem::forget(s);
            if cloexec { set_cloexec(fd); }
            fd as i64
        }
        Err(e) => e,
    }
}

/// # C: O(1)
fn set_cloexec(fd: i32) {
    if let Some(cur) = sched::live::current() {
        // SAFETY: running task on this CPU; preempt-off; sole reader of the fd_table slot.
        if let Some(t) = unsafe { cur.fd_table_ref() } { let _ = t.clone().set_cloexec(fd, true); }
    }
}
