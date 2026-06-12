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
use core::sync::atomic::AtomicU32;

use sync::{Spinlock, TaskList as RingLockClass};

pub(crate) const SQE_SIZE: usize = 64;
pub(crate) const CQE_SIZE: usize = 16;

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
pub(crate) const OFF_SQ_HDR:  u32 = 0x0000;
pub(crate) const OFF_SQ_RING: u32 = 0x0010;
pub(crate) const OFF_CQ_HDR:  u32 = 0x0100;
pub(crate) const OFF_CQ_RING: u32 = 0x0110;
const OFF_SQE_ARR: u32 = 0x0800;

pub(crate) const MAX_ENTRIES: u32 = 64;

pub struct IoUringInode {
    pub ring: Spinlock<IoUring, RingLockClass>,
}

impl IoUringInode {
    /// Allocate a new ring with `entries` SQEs (rounded up to power of 2).
    /// # C: O(1)
    pub fn new(entries: u32) -> Option<Arc<Self>> {
        let n = entries.next_power_of_two().max(1).min(MAX_ENTRIES);
        let pa = pmm::setup::alloc_one_frame()?;
        let va = pa + pmm::user_as::hhdm_offset();
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

/// Physical backing for `mmap(io_uring_fd)` — the single ring page (Linux
/// maps SQ ring / CQ ring / SQE array; oxide lays all three out in this one
/// page at the `sq_off`/`cq_off`/`sqe_off` offsets reported by setup, so a
/// single PhysRange mapping exposes them). The page is never freed (it
/// outlives the fd), so the mapping can't dangle. Returns `(page_pa, PAGE)`.
/// # C: O(1).
pub fn mmap_backing(inode: &vfs::InodeRef, _offset: u64) -> Option<(u64, u64)> {
    let iu = inode.as_any()?.downcast_ref::<IoUringInode>()?;
    let pa = iu.ring.lock().page_pa;
    Some((pa, PAGE))
}

impl vfs::Inode for IoUringInode {
    fn as_any(&self) -> Option<&dyn core::any::Any> { Some(self) }
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

/// IORING_OP_* → underlying syscall dispatch. Runs each opcode
/// synchronously (no worker threads). Called by the slot-426
/// `sys_io_uring_enter` handler in s426_io_uring_enter.
/// # C: O(1) match + one syscall handler call
pub(crate) fn dispatch_op(opcode: u8, fd: i32, off: u64, addr: u64, len: u32) -> i64 {
    let sa = syscall::SyscallArgs {
        a0: fd as u64, a1: addr, a2: len as u64, a3: off, a4: 0, a5: 0,
    };
    match opcode {
        IORING_OP_NOP    => 0,
        IORING_OP_READ   => crate::s017_pread64::sys_pread64(&sa),
        IORING_OP_WRITE  => crate::s018_pwrite64::sys_pwrite64(&sa),
        IORING_OP_READV  => crate::s019_readv::sys_readv(&sa),
        IORING_OP_WRITEV => crate::s020_writev::sys_writev(&sa),
        IORING_OP_FSYNC  => 0,
        IORING_OP_CLOSE  => crate::s003_close::sys_close(&sa),
        IORING_OP_OPENAT => crate::s257_openat::sys_openat(&sa),
        IORING_OP_SEND   => crate::s044_sendto::sys_sendto(&sa),
        IORING_OP_RECV   => crate::net_recv::sys_recvfrom(&sa),
        IORING_OP_ACCEPT => crate::s043_accept::sys_accept(&sa),
        IORING_OP_CONNECT => crate::s042_connect::sys_connect(&sa),
        _ => -(syscall::errno::Errno::Einval.as_i32() as i64),
    }
}

// The three io_uring syscall handlers moved to per-syscall files
// per docs/53§0; re-exported here so the dispatch.rs call sites
// (`crate::io_uring::sys_io_uring_*`) keep resolving:
//   * sys_io_uring_setup    (425) → s425_io_uring_setup
//   * sys_io_uring_enter    (426) → s426_io_uring_enter
//   * sys_io_uring_register (427) → s427_io_uring_register
pub use crate::s425_io_uring_setup::sys_io_uring_setup;
pub use crate::s426_io_uring_enter::sys_io_uring_enter;
pub use crate::s427_io_uring_register::sys_io_uring_register;
