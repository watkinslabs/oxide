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
use alloc::vec::Vec;
use core::sync::atomic::AtomicU32;

use sync::{Spinlock, TaskList as RingLockClass};
use vfs::File;
use vfs::{Inode, InodeBuilder, InodeRef, FileOps, FileType, default_inode_ops, mk_mode, get_next_ino};
use crate::io_uring_sqe::OpArgs;

pub(crate) const SQE_SIZE: usize = 64;
pub(crate) const CQE_SIZE: usize = 16;

pub(crate) const IORING_OP_NOP:         u8 = 0;
pub(crate) const IORING_OP_READV:       u8 = 1;
pub(crate) const IORING_OP_WRITEV:      u8 = 2;
pub(crate) const IORING_OP_FSYNC:       u8 = 3;
pub(crate) const IORING_OP_READ_FIXED:  u8 = 4;
pub(crate) const IORING_OP_WRITE_FIXED: u8 = 5;
pub(crate) const IORING_OP_ACCEPT:      u8 = 13;
pub(crate) const IORING_OP_CONNECT:     u8 = 16;
pub(crate) const IORING_OP_OPENAT:      u8 = 18;
pub(crate) const IORING_OP_CLOSE:       u8 = 19;
pub(crate) const IORING_OP_READ:        u8 = 22;
pub(crate) const IORING_OP_WRITE:       u8 = 23;
pub(crate) const IORING_OP_SEND:        u8 = 26;
pub(crate) const IORING_OP_RECV:        u8 = 27;

/// IOSQE_FIXED_FILE — SQE `flags` bit 0: `fd` field is an index into the
/// registered-files array, not a raw fd.
pub(crate) const IOSQE_FIXED_FILE: u8 = 1 << 0;

/// Cap on registered iovecs / files, mirroring Linux `UIO_MAXIOV`.
pub(crate) const IORING_MAX_REG: u32 = 1024;

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

impl Drop for IoUring {
    /// Release the ring's kernel page (audit #9: `alloc_object_frame` at
    /// `IoUring::new` bumped the object refcount but nothing dropped it, so the
    /// frame leaked per ring). Any user mmap of the ring balances its own
    /// inc_ref/AS-teardown dec around this object ref. # C: O(1)
    fn drop(&mut self) {
        if self.page_pa != 0 {
            // SAFETY: page_pa was alloc_object_frame'd in IoUring::new (object
            // refcount 1, mapcount 0); release exactly that object reference.
            unsafe { pmm::setup::dec_object_ref_and_maybe_free_frame(self.page_pa); }
        }
    }
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

/// Resources registered against a ring via `io_uring_register(2)`. Linux
/// keeps fixed buffers, fixed files and the completion eventfd on the ring
/// context (`struct io_ring_ctx`); oxide mirrors that here, guarded by its
/// own lock so registration never contends the SQ/CQ ring lock.
#[derive(Default)]
pub struct IoUringReg {
    /// Fixed buffers: (user_base, len). Indexed by SQE `buf_index`.
    /// `None` = no `REGISTER_BUFFERS` done (distinguishes from empty set so
    /// `UNREGISTER_BUFFERS` can return `ENXIO`).
    pub buffers: Option<Vec<(u64, u64)>>,
    /// Fixed files: a `None` slot = the `-1` empty-slot Linux allows. The
    /// outer `Option` = no `REGISTER_FILES` done.
    pub files: Option<Vec<Option<Arc<File>>>>,
    /// Completion eventfd — signalled (+1) on every CQE post.
    pub eventfd: Option<Arc<File>>,
}

pub struct IoUringInode {
    pub ring: Spinlock<IoUring, RingLockClass>,
    pub reg:  Spinlock<IoUringReg, RingLockClass>,
}

impl IoUringInode {
    /// Allocate a new ring with `entries` SQEs (rounded up to power of 2).
    /// # C: O(1)
    pub fn new(entries: u32) -> Option<Arc<Self>> {
        let n = entries.next_power_of_two().max(1).min(MAX_ENTRIES);
        let pa = pmm::setup::alloc_object_frame()?;
        let va = pa + pmm::user_as::hhdm_offset();
        // SAFETY: HHDM-mapped page just allocated; zero a single 4 KiB region; sole writer until we publish.
        hal::zerotrap::trap((va as *mut u8) as *const u8, (PAGE as usize) as usize);
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
            reg: Spinlock::new(IoUringReg::default()),
        }))
    }

    /// Resolve SQE `buf_index` to the registered buffer's user range, then
    /// clamp the requested `[off, off+len)` window inside it. Returns the
    /// effective `(user_addr, byte_len)` for the fixed I/O, or an errno.
    /// Linux: `EFAULT` if no such buffer index, `EINVAL`/`EFAULT` on an
    /// out-of-range window. # C: O(1)
    pub fn fixed_buf_window(&self, buf_index: u16, off: u64, len: u32) -> Result<(u64, u64), i64> {
        use syscall::errno::Errno;
        let g = self.reg.lock();
        let bufs = match g.buffers.as_ref() {
            Some(b) => b, None => return Err(-(Errno::Efault.as_i32() as i64)),
        };
        let (base, blen) = match bufs.get(buf_index as usize) {
            Some(&bl) => bl, None => return Err(-(Errno::Efault.as_i32() as i64)),
        };
        let want = len as u64;
        // off + want must lie within [0, blen]; reject wrap and overrun.
        let end = match off.checked_add(want) { Some(e) => e, None => return Err(-(Errno::Efault.as_i32() as i64)) };
        if end > blen { return Err(-(Errno::Efault.as_i32() as i64)); }
        let addr = match base.checked_add(off) { Some(a) => a, None => return Err(-(Errno::Efault.as_i32() as i64)) };
        if addr >= hal::USER_VA_END || (want > 0 && (addr + want) > hal::USER_VA_END) {
            return Err(-(Errno::Efault.as_i32() as i64));
        }
        Ok((addr, want))
    }

    /// Resolve a fixed-file index (IOSQE_FIXED_FILE) to its `Arc<File>`.
    /// Linux: `EBADF` if no files registered, the index is out of range, or
    /// the slot is the empty `-1`. # C: O(1)
    pub fn fixed_file(&self, idx: u32) -> Result<Arc<File>, i64> {
        use syscall::errno::Errno;
        let g = self.reg.lock();
        match g.files.as_ref().and_then(|f| f.get(idx as usize)).and_then(|s| s.clone()) {
            Some(f) => Ok(f),
            None    => Err(-(Errno::Ebadf.as_i32() as i64)),
        }
    }

    /// Signal the registered completion eventfd (+1), if any. Called after
    /// each CQE post so an `epoll`/`read` waiter on the eventfd wakes.
    /// # C: O(1)
    pub fn signal_eventfd(&self) {
        let efd = { self.reg.lock().eventfd.clone() };
        if let Some(f) = efd {
            let one = 1u64.to_ne_bytes();
            let _ = f.inode().write(0, &one);
        }
    }
}

/// Physical backing for `mmap(io_uring_fd)` — the single ring page (Linux
/// maps SQ ring / CQ ring / SQE array; oxide lays all three out in this one
/// page). The caller (`009_mmap`) maps this as a `kframe`
/// (`VmaBacking::KernelFrame`), NOT a PhysRange: the ring is a refcounted RAM
/// frame (`alloc_object_frame`), so the mapping inc_ref's it and holds it
/// alive for the mapping's whole lifetime. The frame is freed only once BOTH
/// the fd is closed (`IoUring::Drop` drops the ring's own ref) AND every user
/// mapping is gone (AS-teardown/munmap drops each mapping's ref) — matching
/// Linux `vm_file`-reference semantics. Mapping it as a PhysRange instead was
/// a free-while-mapped UAF (state.md). Returns `(page_pa, PAGE)`.
/// # C: O(1).
pub fn mmap_backing(inode: &vfs::InodeRef, _offset: u64) -> Option<(u64, u64)> {
    let iu = inode.private::<IoUringInode>()?;
    let pa = iu.ring.lock().page_pa;
    Some((pa, PAGE))
}

/// io_uring ino high-bits tag (`"IOUR"`), distinct from socket/ext4/pipe inodes.
pub(crate) const IO_URING_INO_TAG: u64 = 0x494F_5552_0000_0000;

/// `file_operations` for an io_uring fd: the ring is consumed via
/// `io_uring_enter`/`mmap`, not `read`/`write`, so both are `Einval` (Linux).
/// # C: O(1)
struct IoUringFileOps;
impl FileOps for IoUringFileOps {
    fn read(&self, _inode: &Inode, _o: u64, _b: &mut [u8]) -> vfs::KResult<usize> { Err(vfs::VfsError::Einval) }
    fn write(&self, _inode: &Inode, _o: u64, _b: &[u8]) -> vfs::KResult<usize> { Err(vfs::VfsError::Einval) }
}

/// Wrap ring backend state into a concrete `vfs::Inode`: `i_private` carries the
/// `IoUringInode` (ring + registration state), `i_size = PAGE`, the ino tagged
/// `"IOUR"` | a process-wide anon ino. # C: O(1)
pub fn make_io_uring_inode(data: Arc<IoUringInode>) -> InodeRef {
    let ino = IO_URING_INO_TAG | get_next_ino() as u64;
    InodeBuilder::new(ino, mk_mode(FileType::Regular, 0o600), default_inode_ops(), Arc::new(IoUringFileOps))
        .size(PAGE)
        .private(data)
        .build()
}

/// IORING_OP_* → underlying syscall dispatch. Runs each opcode
/// synchronously (no worker threads). Called by the slot-426
/// `sys_io_uring_enter` handler in s426_io_uring_enter. `inode` carries the
/// registered buffers/files so FIXED ops + IOSQE_FIXED_FILE resolve.
/// # C: O(1) match + one syscall handler call
pub(crate) fn dispatch_op(inode: &IoUringInode, op: &OpArgs) -> i64 {
    use syscall::errno::Errno;
    // IOSQE_FIXED_FILE: the SQE `fd` field is an index into the registered
    // files array; resolve it to a real fd by mapping the fixed file into a
    // scratch fd in the caller's table. We instead reuse the per-op handlers
    // which take a raw fd, so resolve the fixed file to its lowest-numbered
    // existing fd is impossible — instead install it transiently.
    let (fd, fixed_file) = if (op.flags & IOSQE_FIXED_FILE) != 0 {
        match inode.fixed_file(op.fd as u32) {
            Ok(f)  => (op.fd, Some(f)),
            Err(e) => return e,
        }
    } else { (op.fd, None) };

    // For a fixed file we hand the per-op handlers a temporary fd installed
    // in the caller's table (handlers resolve fd→File via the fd table), then
    // remove it afterwards. This keeps each handler unmodified.
    let scratch = match &fixed_file {
        Some(f) => match install_scratch_fd(f.clone()) { Ok(s) => Some(s), Err(e) => return e },
        None => None,
    };
    let eff_fd = scratch.unwrap_or(fd);

    let res = match op.opcode {
        IORING_OP_NOP    => 0,
        IORING_OP_READ   => run(eff_fd, op.addr, op.len as u64, op.off, crate::s017_pread64::sys_pread64),
        IORING_OP_WRITE  => run(eff_fd, op.addr, op.len as u64, op.off, crate::s018_pwrite64::sys_pwrite64),
        IORING_OP_READV  => run(eff_fd, op.addr, op.len as u64, op.off, crate::s019_readv::sys_readv),
        IORING_OP_WRITEV => run(eff_fd, op.addr, op.len as u64, op.off, crate::s020_writev::sys_writev),
        IORING_OP_FSYNC  => 0,
        IORING_OP_CLOSE  => run(eff_fd, op.addr, op.len as u64, op.off, crate::s003_close::sys_close),
        IORING_OP_OPENAT => run(eff_fd, op.addr, op.len as u64, op.off, crate::s257_openat::sys_openat),
        IORING_OP_SEND   => run(eff_fd, op.addr, op.len as u64, op.off, crate::s044_sendto::sys_sendto),
        IORING_OP_RECV   => run(eff_fd, op.addr, op.len as u64, op.off, crate::net_recv::sys_recvfrom),
        IORING_OP_ACCEPT => crate::s043_accept::sys_accept4(&op.accept_args(eff_fd)),
        IORING_OP_CONNECT => run(eff_fd, op.addr, op.len as u64, op.off, crate::s042_connect::sys_connect),
        IORING_OP_READ_FIXED => match inode.fixed_buf_window(op.buf_index, op.off, op.len) {
            Ok((addr, n)) => run(eff_fd, addr, n, op.off, crate::s017_pread64::sys_pread64),
            Err(e) => e,
        },
        IORING_OP_WRITE_FIXED => match inode.fixed_buf_window(op.buf_index, op.off, op.len) {
            Ok((addr, n)) => run(eff_fd, addr, n, op.off, crate::s018_pwrite64::sys_pwrite64),
            Err(e) => e,
        },
        _ => -(Errno::Einval.as_i32() as i64),
    };

    if let Some(s) = scratch { remove_scratch_fd(s); }
    res
}

/// Invoke a per-op syscall handler with the io_uring SQE operand mapping
/// (`fd, addr, len, off` → `a0,a1,a2,a3`). # C: one handler call
fn run(fd: i32, addr: u64, len: u64, off: u64, f: fn(&syscall::SyscallArgs) -> i64) -> i64 {
    let sa = syscall::SyscallArgs { a0: fd as u64, a1: addr, a2: len, a3: off, a4: 0, a5: 0 };
    f(&sa)
}

/// Install `file` at the lowest free fd in the current task's table so a raw-fd
/// op handler can resolve it (used for IOSQE_FIXED_FILE). # C: O(N)
fn install_scratch_fd(file: Arc<File>) -> Result<i32, i64> {
    use syscall::errno::Errno;
    let cur = match sched::live::current() { Some(c) => c, None => return Err(-(Errno::Ebadf.as_i32() as i64)) };
    // SAFETY: running task on this CPU; preempt-off; sole reader of fd_table slot for io_uring fixed-file scratch install.
    let fdt = match unsafe { cur.fd_table_ref() } { Some(t) => t.clone(), None => return Err(-(Errno::Ebadf.as_i32() as i64)) };
    match fdt.alloc_limit(file, cur.nofile_soft()) { Ok(fd) => Ok(fd), Err(e) => Err(-(e as i64)) }
}

/// Remove a scratch fd installed by `install_scratch_fd`. # C: O(1)
fn remove_scratch_fd(fd: i32) {
    if let Some(cur) = sched::live::current() {
        // SAFETY: running task on this CPU; preempt-off; sole reader of fd_table slot for io_uring fixed-file scratch removal.
        if let Some(t) = unsafe { cur.fd_table_ref() } { let _ = t.clone().close(fd); }
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
