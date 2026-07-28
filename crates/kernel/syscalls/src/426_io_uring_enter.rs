// sys_io_uring_enter (NR_IO_URING_ENTER=426) per docs/53§0 — per-syscall file.
// Ring geometry and `IORING_OP_*` dispatch live in the io_uring module; this
// file drains SQ head→tail and posts CQEs.

#![cfg(target_os = "oxide-kernel")]

use crate::io_uring::{dispatch_op, ring_of, IoUringInode};
use crate::io_uring_abi::enter::{cq_has_room, sq_index_valid};
use crate::io_uring_abi::layout::{
    RING_CQ_HEAD, RING_CQ_OVERFLOW, RING_CQ_TAIL, RING_SQ_DROPPED, RING_SQ_HEAD, RING_SQ_TAIL,
};
use crate::io_uring_sqe::OpArgs;

/// `sys_io_uring_enter(fd, to_submit, min_complete, flags, sig, sigsz)`
/// — slot 426.
/// # C: O(to_submit)
pub fn sys_io_uring_enter(args: &syscall::SyscallArgs) -> i64 {
    use syscall::errno::Errno;
    let fd        = args.a0 as i32;
    let to_submit = args.a1 as u32;
    let _min_cmpl = args.a2;
    let _flags    = args.a3;
    let cur = match sched::live::current() {
        Some(c) => c, None => return -(Errno::Ebadf.as_i32() as i64),
    };
    // SAFETY: running task on this CPU; preempt-off; sole reader of fd_table slot.
    let fdt = match unsafe { cur.fd_table_ref() } {
        Some(t) => t.clone(), None => return -(Errno::Ebadf.as_i32() as i64),
    };
    let file = match fdt.get(fd) {
        Ok(f) => f, Err(_) => return -(Errno::Ebadf.as_i32() as i64),
    };
    // Linux io_uring_ctx_get_file(): EOPNOTSUPP for a non-io_uring fd.
    let inode_ref = match ring_of(&file) { Ok(i) => i, Err(e) => return -(e.as_i32() as i64) };
    let ring_inode: &IoUringInode = match inode_ref.private::<IoUringInode>() {
        Some(d) => d, None => return -(Errno::Eopnotsupp.as_i32() as i64),
    };
    let g = ring_inode.ring.lock();

    let mut submitted: u32 = 0;
    let mut sq_h = g.hdr_load(RING_SQ_HEAD);
    let sq_t     = g.hdr_load(RING_SQ_TAIL);
    let mut cq_t = g.hdr_load(RING_CQ_TAIL);
    while submitted < to_submit && sq_h != sq_t {
        // The CQ ring has no overflow list, so a full CQ stops submission
        // instead of overwriting completions the caller has not reaped.
        // `IORING_FEAT_NODROP` is deliberately NOT reported (abi::layout).
        let cq_h = g.hdr_load(RING_CQ_HEAD);
        if !cq_has_room(cq_t, cq_h, g.cq_entries) {
            g.hdr_store(RING_CQ_OVERFLOW, g.hdr_load(RING_CQ_OVERFLOW).wrapping_add(1));
            break;
        }
        let idx = g.sq_index(sq_h);
        if !sq_index_valid(idx, g.sq_entries) {
            // Linux io_get_sqe(): an out-of-range SQ index is counted in
            // sq_dropped and the entry is skipped, not executed.
            g.hdr_store(RING_SQ_DROPPED, g.hdr_load(RING_SQ_DROPPED).wrapping_add(1));
            sq_h = sq_h.wrapping_add(1);
            continue;
        }
        let sqe = g.sqe_at(idx);
        // SQE layout (Linux struct io_uring_sqe): opcode@0, flags@1, ioprio@2,
        // fd@4, off@8, addr@16, len@24, op_flags@28, user_data@32,
        // buf_index@40 (union).
        // SAFETY: sqe is inside the SQEs frame (sqe_at masks the index into range); the frame is HHDM-mapped for the ring's lifetime; the ring spinlock serialises kernel readers.
        let op = unsafe {
            OpArgs {
                opcode:    core::ptr::read_volatile((sqe +  0) as *const u8),
                flags:     core::ptr::read_volatile((sqe +  1) as *const u8),
                fd:        core::ptr::read_volatile((sqe +  4) as *const i32),
                off:       core::ptr::read_volatile((sqe +  8) as *const u64),
                addr:      core::ptr::read_volatile((sqe + 16) as *const u64),
                len:       core::ptr::read_volatile((sqe + 24) as *const u32),
                op_flags:  core::ptr::read_volatile((sqe + 28) as *const u32),
                buf_index: core::ptr::read_volatile((sqe + 40) as *const u16),
            }
        };
        // SAFETY: same frame and lock as the SQE read above; user_data is the opaque cookie echoed into the CQE.
        let user_data = unsafe { core::ptr::read_volatile((sqe + 32) as *const u64) };
        let res: i64 = dispatch_op(ring_inode, &op);

        let cqe = g.cqe_at(cq_t);
        // SAFETY: cqe_at masks the index into the CQE array, which rings_size bounded inside the rings frame; the ring spinlock serialises kernel writers.
        unsafe {
            core::ptr::write_volatile((cqe +  0) as *mut u64, user_data);
            core::ptr::write_volatile((cqe +  8) as *mut i32, res as i32);
            core::ptr::write_volatile((cqe + 12) as *mut u32, 0);
        }
        cq_t = cq_t.wrapping_add(1);
        // Publish each completion before advancing the SQ head so a reaper
        // never sees a consumed SQE with no CQE behind it.
        g.hdr_store(RING_CQ_TAIL, cq_t);
        sq_h = sq_h.wrapping_add(1);
        g.hdr_store(RING_SQ_HEAD, sq_h);
        submitted += 1;
    }
    drop(g);
    // Signal the registered completion eventfd once per enter if any CQEs were
    // posted (Linux signals per-CQE; once is sufficient for the level-triggered
    // eventfd counter to wake an epoll/read waiter).
    if submitted > 0 { ring_inode.signal_eventfd(); }
    submitted as i64
}
