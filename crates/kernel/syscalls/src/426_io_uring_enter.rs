// sys_io_uring_enter (NR_IO_URING_ENTER=426) per docs/53§0 —
// per-syscall-file module. The ring machinery + IORING_OP_*
// dispatch (`dispatch_op`) stay in the io_uring module; this file
// holds only the syscall handler, calling that machinery via
// `crate::io_uring::*`.

#![cfg(target_os = "oxide-kernel")]

use alloc::sync::Arc;

use crate::io_uring::{
    dispatch_op, IoUringInode, CQE_SIZE, OFF_CQ_HDR, OFF_CQ_RING, OFF_SQ_HDR,
    OFF_SQ_RING, SQE_SIZE,
};

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
    if (file.inode().ino() & 0xFFFF_FFFF_0000_0000) != 0x494F_5552_0000_0000 {
        return -(Errno::Einval.as_i32() as i64);
    }
    let inode_ref = file.inode().clone();
    let raw = Arc::into_raw(inode_ref);
    // SAFETY: ino tag check above confirms this inode is an IoUringInode; Arc::clone before into_raw bumped the refcount, so from_raw consumes a balanced strong count without leaking.
    let ring_inode = unsafe { Arc::from_raw(raw as *const IoUringInode) };
    let g = ring_inode.ring.lock();
    let mask = g.entries - 1;
    let sqe_arr   = g.page_va + g.sqe_off as u64;
    let sq_ring   = g.page_va + OFF_SQ_RING as u64;
    let cq_ring   = g.page_va + OFF_CQ_RING as u64;
    let sq_head_p = (g.page_va + OFF_SQ_HDR as u64    ) as *mut u32;
    let sq_tail_p = (g.page_va + OFF_SQ_HDR as u64 + 4) as *mut u32;
    let cq_tail_p = (g.page_va + OFF_CQ_HDR as u64 + 4) as *mut u32;

    let mut submitted: u32 = 0;
    // SAFETY: ring page lives in HHDM-mapped kernel memory; all reads/writes here use canonical kernel virtual addresses; spinlock guarantees single-mutator.
    unsafe {
        let mut sq_h = core::ptr::read_volatile(sq_head_p);
        let sq_t     = core::ptr::read_volatile(sq_tail_p);
        let mut cq_t = core::ptr::read_volatile(cq_tail_p);
        while submitted < to_submit && sq_h != sq_t {
            let idx = core::ptr::read_volatile((sq_ring + (sq_h & mask) as u64 * 4) as *const u32);
            let sqe = sqe_arr + (idx & mask) as u64 * SQE_SIZE as u64;
            let opcode  = core::ptr::read_volatile((sqe +  0) as *const u8);
            let _flags  = core::ptr::read_volatile((sqe +  1) as *const u8);
            let _ioprio = core::ptr::read_volatile((sqe +  2) as *const u16);
            let fd_op   = core::ptr::read_volatile((sqe +  4) as *const i32);
            let off_op  = core::ptr::read_volatile((sqe +  8) as *const u64);
            let addr    = core::ptr::read_volatile((sqe + 16) as *const u64);
            let lenfld  = core::ptr::read_volatile((sqe + 24) as *const u32);
            let user_data = core::ptr::read_volatile((sqe + 32) as *const u64);

            let res: i64 = dispatch_op(opcode, fd_op, off_op, addr, lenfld);

            let cqe = cq_ring + (cq_t & mask) as u64 * CQE_SIZE as u64;
            core::ptr::write_volatile((cqe +  0) as *mut u64, user_data);
            core::ptr::write_volatile((cqe +  8) as *mut i32, res as i32);
            core::ptr::write_volatile((cqe + 12) as *mut u32, 0);
            cq_t = cq_t.wrapping_add(1);

            sq_h = sq_h.wrapping_add(1);
            submitted += 1;
        }
        core::ptr::write_volatile(sq_head_p, sq_h);
        core::ptr::write_volatile(cq_tail_p, cq_t);
    }
    submitted as i64
}
