// userfaultfd(2) per `27` — MISSING-mode fault handling.
//
// Register a VA range with the fd; a NotPresent fault in that range is
// intercepted by the mm-pmm fault handler (`do_handle` → `uffd_for` →
// `UffdContext::missing_fault`), which enqueues a `uffd_msg` PAGEFAULT
// event on this inode, wakes the monitor thread blocked in `read`, and
// BLOCKS the faulting thread. The monitor materialises the page bytes
// and issues `UFFDIO_COPY`/`UFFDIO_ZEROPAGE` to install them (allocating
// a real PMM frame and mapping it into the faulting AS) then the faulter
// retries the instruction; `UFFDIO_WAKE` wakes faulters without a page
// (they re-fault).
//
// WP (write-protect) mode is NOT yet wired: `UFFDIO_REGISTER(MODE_WP)`
// records the range so UNREGISTER works but installs no fault intercept
// (see `ioctl.rs`). MISSING mode is fully functional.
//
// Module manifest:
//   - mod.rs (this file): msg/state types, inode ctor, sys_userfaultfd,
//     FileOps (blocking read / poll), UffdContext impl (fault block/wake).
//   - ioctl.rs: UFFDIO_* dispatch (API/REGISTER/UNREGISTER/COPY/ZEROPAGE/WAKE).
//   - tests.rs: hosted non-parking logic tests.

#![allow(dead_code)]

use alloc::sync::Arc;
use alloc::vec::Vec;
use alloc::collections::VecDeque;
use core::sync::atomic::{AtomicU16, AtomicU64, Ordering};

use sync::{Spinlock, TaskList as UffdLockClass};
use vfs::{FileOps, Inode, InodeBuilder, InodeRef, KResult, PollSubscribers, default_inode_ops, mk_mode};

mod ioctl;
#[cfg(test)]
mod tests;

pub use ioctl::handle_uffd_ioctl;

/// negotiated feature set — `features=0` (no THREAD_ID / EVENT_* etc.).
const UFFD_API_FEATURE_SET: u64 = 0;

/// `uffd_msg.event` — a page fault (Linux `UFFD_EVENT_PAGEFAULT`).
const UFFD_EVENT_PAGEFAULT: u8 = 0x12;
/// `uffd_msg.arg.pagefault.flags` — the fault was a write (Linux
/// `UFFD_PAGEFAULT_FLAG_WRITE`).
const UFFD_PAGEFAULT_FLAG_WRITE: u64 = 1 << 0;

/// Hosted-test stand-in: `WaitList` only exists under the live scheduler.
/// Blocking arms are `oxide-kernel`-gated, so hosted builds never reach
/// `park`; the stub keeps the type/symbols present for compilation.
#[cfg(not(target_os = "oxide-kernel"))]
struct WaitList;
#[cfg(not(target_os = "oxide-kernel"))]
impl WaitList {
    const fn new() -> Self { Self }
    fn wake_all(&self) {}
    /// # SAFETY: never invoked under hosted; blocking arms are cfg-gated out.
    unsafe fn park(&self) { unreachable!("uffd park under hosted"); }
}
#[cfg(target_os = "oxide-kernel")]
use sched::live::wait_list::WaitList;

/// `struct uffd_msg` (Linux) — 32 bytes per event. Field ORDER is ABI: the
/// `arg.pagefault` union places `flags` at byte 8 and `address` at byte 16
/// (a real uffd monitor reads `msg.arg.pagefault.address` at offset 16), with
/// the thread id in the trailing `feat` union at byte 24.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct UffdMsg {
    pub event:  u8,
    pub _r0:    u8,
    pub _r1:    u16,
    pub _r2:    u32,
    pub flags:  u64,
    pub addr:   u64,
    pub ptid:   u64,
}

/// A `UFFDIO_REGISTER`ed range on this fd.
pub struct RegisteredRange {
    pub start: u64,
    pub end:   u64,
    pub mode:  u64,
}

/// Locked userfaultfd state.
pub struct UfState {
    pub api_set: bool,
    pub ranges:  Vec<RegisteredRange>,
    pub events:  VecDeque<UffdMsg>,
}

/// Per-inode userfaultfd state (Linux `i_private` + `userfaultfd_ctx`).
pub struct UfData {
    pub state: Spinlock<UfState, UffdLockClass>,
    pub flags: AtomicU16,
    /// Monitor threads blocked in `read` waiting for an event.
    read_waiters: WaitList,
    /// Faulting threads blocked in `missing_fault` waiting for a resolve.
    fault_waiters: WaitList,
    /// Monotonic wake generation: bumped by COPY/ZEROPAGE/WAKE. A parked
    /// faulter snapshots it before parking and returns (retries its
    /// instruction) once it advances — closes the lost-wake race without
    /// needing a per-address resolved-set.
    wake_gen: AtomicU64,
    /// The inode's epoll/poll subscriber set (same `Arc` the inode holds),
    /// so `missing_fault` can notify pollers from `&UfData` alone.
    poll: Arc<PollSubscribers>,
}

impl UfData {
    /// Bump the wake generation and wake every blocked faulter so each
    /// re-checks its address (retries the faulting instruction). Called by
    /// UFFDIO_COPY/ZEROPAGE/WAKE after their work completes.
    /// # C: O(N_faulters)
    pub(crate) fn wake_faulters(&self) {
        self.wake_gen.fetch_add(1, Ordering::AcqRel);
        self.fault_waiters.wake_all();
    }
}

/// UfData ino tag (high bits distinct from socket/io_uring/pipe).
mod ids {
    pub(crate) const INO_TAG: vfs::Ino = 0x5546_4644_0000_0000;
    pub(crate) const INO_ID_MASK: vfs::Ino = 0xFFFF_FFFF;
}
static NEXT_UFFD_INO: AtomicU64 = AtomicU64::new(1);

/// `make_userfaultfd_inode(flags)` — a Regular pseudo-inode whose `read`
/// drains queued `uffd_msg` events and whose `poll` reports POLLIN when
/// events are queued. # C: O(1)
pub fn make_userfaultfd_inode(flags: u16) -> InodeRef {
    let ino = ids::INO_TAG | (NEXT_UFFD_INO.fetch_add(1, Ordering::Relaxed) & ids::INO_ID_MASK);
    let poll = Arc::new(PollSubscribers::new());
    InodeBuilder::new(ino, mk_mode(vfs::FileType::Regular, 0),
        default_inode_ops(), Arc::new(UffdFileOps))
        .poll_subs_arc(poll.clone())
        .private(Arc::new(UfData {
            state: Spinlock::new(UfState {
                api_set: false,
                ranges:  Vec::new(),
                events:  VecDeque::new(),
            }),
            flags: AtomicU16::new(flags),
            read_waiters:  WaitList::new(),
            fault_waiters: WaitList::new(),
            wake_gen: AtomicU64::new(0),
            poll,
        }))
        .build()
}

/// `i_fop` for a userfaultfd inode. # C: O(1)
struct UffdFileOps;
impl FileOps for UffdFileOps {
    /// BLOCKING read (Linux `userfaultfd_read`): pop the next queued
    /// `uffd_msg`; if the queue is empty, PARK until a fault enqueues one
    /// (interruptible → EINTR). A short `buf` (< 32) → EINVAL.
    /// # C: O(1) + block
    fn read(&self, inode: &Inode, _o: u64, buf: &mut [u8]) -> KResult<usize> {
        if buf.len() < core::mem::size_of::<UffdMsg>() { return Err(vfs::VfsError::Einval); }
        let d = match inode.private::<UfData>() { Some(d) => d, None => return Err(vfs::VfsError::Einval) };
        loop {
            if let Some(m) = d.state.lock().events.pop_front() {
                return Ok(copy_msg_out(&m, buf));
            }
            #[cfg(target_os = "oxide-kernel")]
            {
                if sched::live::deliverable_signals_self() != 0 { return Err(vfs::VfsError::Eintr); }
                // SAFETY: running task; preempt-off; park marks Sleeping + bumps the Arc before we schedule, and a fault enqueue will wake read_waiters.
                unsafe { d.read_waiters.park(); }
                // SAFETY: process ctx; runqueue installed; preempt-off; current Sleeping so schedule won't re-enqueue until a fault wake fires.
                unsafe { sched::live::schedule::schedule(); }
            }
            #[cfg(not(target_os = "oxide-kernel"))]
            return Err(vfs::VfsError::Eagain);
        }
    }
    /// Non-blocking read (O_NONBLOCK): EAGAIN on an empty queue (Linux),
    /// never EINVAL and never a park. # C: O(1)
    fn read_nonblock(&self, inode: &Inode, _o: u64, buf: &mut [u8]) -> KResult<usize> {
        if buf.len() < core::mem::size_of::<UffdMsg>() { return Err(vfs::VfsError::Einval); }
        let d = match inode.private::<UfData>() { Some(d) => d, None => return Err(vfs::VfsError::Einval) };
        match d.state.lock().events.pop_front() {
            Some(m) => Ok(copy_msg_out(&m, buf)),
            None    => Err(vfs::VfsError::Eagain),
        }
    }
    /// POLLIN iff an event is queued (a `read` won't block). # C: O(1)
    fn poll(&self, inode: &Inode) -> u32 {
        match inode.private::<UfData>() {
            Some(d) if !d.state.lock().events.is_empty() => vfs::POLL_IN,
            _ => 0,
        }
    }
    fn write(&self, _inode: &Inode, _o: u64, _b: &[u8]) -> KResult<usize> { Err(vfs::VfsError::Einval) }
}

/// Serialise a `uffd_msg` into the caller's buffer (32 bytes). # C: O(1)
fn copy_msg_out(m: &UffdMsg, buf: &mut [u8]) -> usize {
    // SAFETY: UffdMsg is repr(C) + Copy with no padding-sensitive reads; transmute_copy reads exactly size_of::<UffdMsg>() bytes from the aligned `m`.
    let bytes: [u8; core::mem::size_of::<UffdMsg>()] = unsafe { core::mem::transmute_copy(m) };
    buf[..bytes.len()].copy_from_slice(&bytes);
    bytes.len()
}

impl vmm::UffdContext for UfData {
    /// Linux `handle_userfault` (MISSING leg): enqueue a PAGEFAULT event
    /// for `addr`, wake the monitor + pollers, then BLOCK this faulting
    /// thread until a COPY/ZEROPAGE/WAKE bumps the wake generation. Returns
    /// so the fault handler retries the instruction (which either hits the
    /// now-present page or re-faults + re-enqueues).
    /// # C: O(1) enqueue + block
    fn missing_fault(&self, addr: u64, write: bool) {
        #[cfg(target_os = "oxide-kernel")]
        let ptid = sched::live::current().map(|c| c.tid as u64).unwrap_or(0);
        #[cfg(not(target_os = "oxide-kernel"))]
        let ptid = 0u64;
        let msg = UffdMsg {
            event: UFFD_EVENT_PAGEFAULT,
            _r0: 0, _r1: 0, _r2: 0,
            addr,
            flags: if write { UFFD_PAGEFAULT_FLAG_WRITE } else { 0 },
            ptid,
        };
        // Snapshot the wake generation BEFORE publishing: any resolve that
        // races between here and the park below advances it, so the loop
        // returns instead of sleeping through the wake.
        let start_gen = self.wake_gen.load(Ordering::Acquire);
        self.state.lock().events.push_back(msg);
        self.read_waiters.wake_all();
        self.poll.notify();
        #[cfg(target_os = "oxide-kernel")]
        loop {
            if self.wake_gen.load(Ordering::Acquire) != start_gen { break; }
            // A deliverable (e.g. fatal) signal breaks the wait — return so
            // the fault path retries and the signal is delivered to userspace.
            if sched::live::deliverable_signals_self() != 0 { break; }
            // SAFETY: running (faulting) task; preempt-off; park marks Sleeping + bumps the Arc before schedule, and a COPY/ZEROPAGE/WAKE will wake fault_waiters.
            unsafe { self.fault_waiters.park(); }
            // SAFETY: fault ctx entered from user mode with a saved frame; runqueue installed; preempt-off; current Sleeping so schedule won't re-enqueue until a resolve wake fires.
            unsafe { sched::live::schedule::schedule(); }
        }
        // Silence unused-var warning on hosted (no loop reads start_gen).
        let _ = start_gen;
    }
}

/// `userfaultfd(flags)` — slot 323. Returns a fresh fd.
/// # C: O(1)
pub fn sys_userfaultfd(args: &syscall::SyscallArgs) -> i64 {
    use vfs::{File, OpenFlags};
    use syscall::errno::Errno;
    const O_NONBLOCK: u64 = 0o0_004_000;
    const O_CLOEXEC:  u64 = 0o2_000_000;
    let raw   = args.a0;
    let flags = raw as u16;
    let inode_ref = make_userfaultfd_inode(flags);
    let cur = match sched::current() {
        Some(c) => c, None => return -(Errno::Ebadf.as_i32() as i64),
    };
    // SAFETY: running task on this CPU; preempt-off; sole reader of fd_table slot.
    let fdt = match unsafe { cur.fd_table_ref() } {
        Some(t) => t.clone(), None => return -(Errno::Ebadf.as_i32() as i64),
    };
    let dentry = vfs::dcache::d_alloc_pseudo("[userfaultfd]", inode_ref.clone(), &crate::anon_dname::ANON_INODE_OPS);
    let mut fl = OpenFlags::O_RDWR;
    if (raw & O_NONBLOCK) != 0 { fl |= OpenFlags::O_NONBLOCK; }
    let file = File::new(inode_ref, dentry, fl);
    match fdt.alloc_limit(file, cur.nofile_soft()) {
        Ok(fd) => {
            if (raw & O_CLOEXEC) != 0 { let _ = fdt.set_cloexec(fd, true); }
            fd as i64
        }
        Err(e) => -(e as i64),
    }
}

/// Lift a generic `vfs::InodeRef` to `Arc<UfData>` via `i_private`.
fn as_uffd(inode: &vfs::InodeRef) -> Option<Arc<UfData>> {
    inode.i_private().clone().downcast::<UfData>().ok()
}
