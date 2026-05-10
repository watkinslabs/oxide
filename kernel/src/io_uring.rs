// io_uring per `30` — narrow first cut for v2 phase 23.
//
// Linux io_uring shares two rings between kernel and userspace via
// mmap on the io_uring fd: the Submission Queue (SQ) and Completion
// Queue (CQ). Userspace writes SQEs (64 bytes each), advances the
// SQ tail, and calls io_uring_enter; the kernel drains entries from
// SQ head to tail, executes each opcode, and posts CQEs (16 bytes
// each) advancing the CQ tail.
//
// This implementation:
//
//   * io_uring_setup(entries, params): allocates a per-ring kernel
//     page laying out the SQ + CQ + SQE array; returns an fd whose
//     mmap exposes those structures to userspace. Writes the
//     io_uring_params offsets so liburing finds the rings.
//   * io_uring_enter(fd, to_submit, min_complete, flags, sig, sigsz):
//     drains SQ head→tail, runs each opcode synchronously (no
//     worker threads — every op completes inline), posts CQEs.
//   * io_uring_register: silent-0 (no fixed-buffer / file
//     registration v1).
//
// Opcodes honored synchronously:
//   IORING_OP_NOP       → 0
//   IORING_OP_READV     → readv
//   IORING_OP_WRITEV    → writev
//   IORING_OP_READ      → pread64
//   IORING_OP_WRITE     → pwrite64
//   IORING_OP_SEND      → sendto
//   IORING_OP_RECV      → recvfrom
//   IORING_OP_ACCEPT    → accept
//   IORING_OP_CONNECT   → connect
//   IORING_OP_CLOSE     → close
//   IORING_OP_OPENAT    → openat
//   IORING_OP_FSYNC     → 0 (no journal-aware fsync v1)
//
// Deferred follow-ups (each its own substrate task):
//   - SQPOLL (kernel poll thread), IOPOLL (NVMe-style polled cmpl).
//   - Fixed-buffer / fixed-file registration.
//   - Multishot ACCEPT / POLL.
//   - Chained SQEs (IOSQE_IO_LINK).
//   - Timeout / cancel ops.
//   - BUF_RING.
//   - Userspace mmap on the io_uring fd (currently the rings live
//     in HHDM-mapped kernel memory; making them visible to user
//     mode requires a per-ring AS-mapping helper that lands when
//     MAP_SHARED for the page-cache substrate is wired).

#![cfg(target_os = "oxide-kernel")]
#![allow(dead_code)]

use alloc::sync::Arc;
use core::sync::atomic::{AtomicU32, Ordering};

use sync::{Spinlock, TaskList as RingLockClass};

const SQE_SIZE: usize = 64;
const CQE_SIZE: usize = 16;

const IORING_OP_NOP:        u8 = 0;
const IORING_OP_READV:      u8 = 1;
const IORING_OP_WRITEV:     u8 = 2;
const IORING_OP_FSYNC:      u8 = 3;
const IORING_OP_ACCEPT:     u8 = 13;
const IORING_OP_CONNECT:    u8 = 16;
const IORING_OP_OPENAT:     u8 = 18;
const IORING_OP_CLOSE:      u8 = 19;
const IORING_OP_READ:       u8 = 22;
const IORING_OP_WRITE:      u8 = 23;
const IORING_OP_SEND:       u8 = 26;
const IORING_OP_RECV:       u8 = 27;

/// One io_uring instance — owns a kernel page laying out SQ + CQ + SQE array.
pub struct IoUring {
    pub page_pa: u64,
    pub page_va: u64,
    pub entries: u32,
    pub sq_off: u32,
    pub cq_off: u32,
    pub sqe_off: u32,
    pub sq_head: AtomicU32,
    pub sq_tail: AtomicU32,
    pub cq_head: AtomicU32,
    pub cq_tail: AtomicU32,
}

const PAGE: u64 = 4096;

/// Layout for the kernel page:
///   +0x000    SQ ring header (head u32, tail u32, ring_mask u32, ring_entries u32)
///   +0x010    SQ ring (entries × u32 indices into SQE array)
///   +0x100    CQ ring header
///   +0x110    CQ ring (entries × CQE_SIZE)
///   +0x800    SQE array (entries × SQE_SIZE)
const OFF_SQ_HDR:  u32 = 0x0000;
const OFF_SQ_RING: u32 = 0x0010;
const OFF_CQ_HDR:  u32 = 0x0100;
const OFF_CQ_RING: u32 = 0x0110;
const OFF_SQE_ARR: u32 = 0x0800;

const MAX_ENTRIES: u32 = 64;

pub struct IoUringInode {
    pub ring: Spinlock<IoUring, RingLockClass>,
}

impl IoUringInode {
    /// Allocate a new ring with `entries` SQEs (rounded up to power of 2).
    /// # C: O(1)
    pub fn new(entries: u32) -> Option<Arc<Self>> {
        let n = entries.next_power_of_two().max(1).min(MAX_ENTRIES);
        let pa = pmm::setup::alloc_one_frame()?;
        let va = pa + crate::user_as::hhdm_offset();
        // SAFETY: HHDM-mapped page just allocated; zero a single 4 KiB region; sole writer until we publish.
        unsafe { core::ptr::write_bytes(va as *mut u8, 0, PAGE as usize); }
        // SAFETY: page just allocated and zeroed; no aliasing; ring_mask + ring_entries fields written through HHDM mapping.
        unsafe {
            let p = va as *mut u32;
            *p.add(2) = n - 1;
            *p.add(3) = n;
            let q = (va + OFF_CQ_HDR as u64) as *mut u32;
            *q.add(2) = n - 1;
            *q.add(3) = n;
        }
        Some(Arc::new(Self {
            ring: Spinlock::new(IoUring {
                page_pa: pa, page_va: va,
                entries: n,
                sq_off: OFF_SQ_HDR, cq_off: OFF_CQ_HDR, sqe_off: OFF_SQE_ARR,
                sq_head: AtomicU32::new(0),
                sq_tail: AtomicU32::new(0),
                cq_head: AtomicU32::new(0),
                cq_tail: AtomicU32::new(0),
            }),
        }))
    }
}

impl vfs::Inode for IoUringInode {
    fn ino(&self) -> vfs::Ino {
        // High-bits tag distinct from socket / ext4 / pipe inodes.
        0x494F_5552_0000_0000u64 | (self as *const _ as u64 & 0xFFFF_FFFF) as vfs::Ino
    }
    fn file_type(&self) -> vfs::FileType { vfs::FileType::Regular }
    fn size(&self) -> u64 { PAGE }
    fn lookup(&self, _n: &str) -> vfs::KResult<vfs::InodeRef> { Err(vfs::VfsError::Enotdir) }
    fn read(&self, _o: u64, _b: &mut [u8]) -> vfs::KResult<usize> { Err(vfs::VfsError::Einval) }
    fn write(&self, _o: u64, _b: &[u8]) -> vfs::KResult<usize> { Err(vfs::VfsError::Einval) }
}

/// `sys_io_uring_setup(entries, *params)` — slot 425.
/// # C: O(1)
pub fn kernel_sys_io_uring_setup(args: &syscall::SyscallArgs) -> i64 {
    use alloc::string::ToString;
    use vfs::{Dentry, File, OpenFlags};
    use syscall::errno::Errno;
    let entries = args.a0 as u32;
    let params  = args.a1;
    if entries == 0 || entries > MAX_ENTRIES {
        return -(Errno::Einval.as_i32() as i64);
    }
    let inode = match IoUringInode::new(entries) {
        Some(i) => i, None => return -(Errno::Enomem.as_i32() as i64),
    };
    if params != 0 && params < hal::USER_VA_END {
        let n = inode.ring.lock().entries;
        // SAFETY: params validated < USER_VA_END; struct io_uring_params is 120 bytes; CPL=0 writes through caller's AS.
        unsafe {
            for i in 0..120usize {
                core::ptr::write_volatile((params + i as u64) as *mut u8, 0);
            }
            core::ptr::write_volatile((params       ) as *mut u32, n);
            core::ptr::write_volatile((params +   4 ) as *mut u32, n);
            // sq_off at +40
            core::ptr::write_volatile((params + 40 +  0) as *mut u32, OFF_SQ_HDR    );
            core::ptr::write_volatile((params + 40 +  4) as *mut u32, OFF_SQ_HDR + 4);
            core::ptr::write_volatile((params + 40 +  8) as *mut u32, OFF_SQ_HDR + 8);
            core::ptr::write_volatile((params + 40 + 12) as *mut u32, OFF_SQ_HDR +12);
            core::ptr::write_volatile((params + 40 + 24) as *mut u32, OFF_SQ_RING);
            // cq_off at +72
            core::ptr::write_volatile((params + 72 +  0) as *mut u32, OFF_CQ_HDR    );
            core::ptr::write_volatile((params + 72 +  4) as *mut u32, OFF_CQ_HDR + 4);
            core::ptr::write_volatile((params + 72 +  8) as *mut u32, OFF_CQ_HDR + 8);
            core::ptr::write_volatile((params + 72 + 12) as *mut u32, OFF_CQ_HDR +12);
            core::ptr::write_volatile((params + 72 + 20) as *mut u32, OFF_CQ_RING);
        }
    }
    let cur = match crate::sched::current() {
        Some(c) => c, None => return -(Errno::Ebadf.as_i32() as i64),
    };
    // SAFETY: running task on this CPU; preempt-off; sole reader of fd_table slot.
    let fdt = match unsafe { cur.fd_table_ref() } {
        Some(t) => t.clone(), None => return -(Errno::Ebadf.as_i32() as i64),
    };
    let inode_ref: vfs::InodeRef = inode as vfs::InodeRef;
    let dentry = Dentry::new(None, "[io_uring]".to_string(), inode_ref.clone());
    let file = File::new(inode_ref, dentry, OpenFlags::O_RDWR);
    match fdt.alloc(file) { Ok(fd) => fd as i64, Err(e) => -(e as i64) }
}

/// `sys_io_uring_enter(fd, to_submit, min_complete, flags, sig, sigsz)`
/// — slot 426.
/// # C: O(to_submit)
pub fn kernel_sys_io_uring_enter(args: &syscall::SyscallArgs) -> i64 {
    use syscall::errno::Errno;
    let fd        = args.a0 as i32;
    let to_submit = args.a1 as u32;
    let _min_cmpl = args.a2;
    let _flags    = args.a3;
    let cur = match crate::sched::current() {
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

fn dispatch_op(opcode: u8, fd: i32, off: u64, addr: u64, len: u32) -> i64 {
    let sa = syscall::SyscallArgs {
        a0: fd as u64, a1: addr, a2: len as u64, a3: off, a4: 0, a5: 0,
    };
    match opcode {
        IORING_OP_NOP    => 0,
        IORING_OP_READ   => crate::syscalls::fs::kernel_sys_pread64(&sa),
        IORING_OP_WRITE  => crate::syscalls::fs::kernel_sys_pwrite64(&sa),
        IORING_OP_READV  => crate::syscalls::fs::kernel_sys_readv(&sa),
        IORING_OP_WRITEV => crate::syscalls::fs::kernel_sys_writev(&sa),
        IORING_OP_FSYNC  => 0,
        IORING_OP_CLOSE  => crate::syscalls::kernel_sys_close(&sa),
        IORING_OP_OPENAT => crate::syscalls::open::kernel_sys_openat(&sa),
        IORING_OP_SEND   => crate::syscalls::net::kernel_sys_sendto(&sa),
        IORING_OP_RECV   => crate::syscalls::net::kernel_sys_recvfrom(&sa),
        IORING_OP_ACCEPT => crate::syscalls::net::kernel_sys_accept(&sa),
        IORING_OP_CONNECT => crate::syscalls::net::kernel_sys_connect(&sa),
        _ => -(syscall::errno::Errno::Einval.as_i32() as i64),
    }
}

/// `sys_io_uring_register(fd, op, arg, nr_args)` — slot 427.
/// v1: silent 0 (no fixed-buffer / file registration).
/// # C: O(1)
pub fn kernel_sys_io_uring_register(_args: &syscall::SyscallArgs) -> i64 { 0 }
