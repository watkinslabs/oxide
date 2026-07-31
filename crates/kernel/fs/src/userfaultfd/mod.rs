// userfaultfd(2) per `27` — MISSING-mode fault handling.
//
// Register a VA range with the fd; a NotPresent fault in that range is
// intercepted by the mm-pmm fault handler (`do_handle` → `uffd_for` →
// `UffdContext::missing_fault`), which enqueues a `uffd_msg` PAGEFAULT
// event on this inode, wakes the monitor thread blocked in `read`, and
// BLOCKS the faulting thread. The monitor materialises the page bytes
// and issues `UFFDIO_COPY`/`UFFDIO_ZEROPAGE` to install them (allocating
// a real PMM frame and mapping it into `ctx->mm`) then the faulter
// retries the instruction; `UFFDIO_WAKE` wakes faulters without a page
// (they re-fault).
//
// WP / MINOR / MOVE / POISON / CONTINUE are NOT implemented, and
// `UFFDIO_REGISTER` refuses `MODE_WP` and `MODE_MINOR` with EINVAL exactly as
// a Linux kernel without `pgtable_supports_uffd_wp()` /
// `CONFIG_HAVE_ARCH_USERFAULTFD_MINOR` does (`policy::check_register_mode`) —
// a silently-accepted registration that never delivers is worse than a
// refusal, because a monitor using WP as a write barrier would believe it.
//
// Module manifest:
//   - mod.rs (this file): msg/state types, inode ctor, sys_userfaultfd,
//     FileOps (blocking read / poll), UffdContext impl (fault block/wake).
//   - uapi.rs: Linux UAPI numbers, struct sizes/offsets, feature + mode bits.
//   - policy.rs: UNGATED decision logic — range validation, the create gate,
//     API negotiation, register-mode ladder, dst-VMA ladder, return protocol.
//   - ioctl.rs: UFFDIO_* dispatch (API/REGISTER/UNREGISTER/COPY/ZEROPAGE/WAKE).
//   - install.rs / install_hosted.rs: the page-install loop (kernel / host).
//   - tests/: hosted logic tests (policy ladders + ioctl behaviour).

#![allow(dead_code)]

use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use alloc::collections::VecDeque;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use sync::{Spinlock, TaskList as UffdLockClass};
use vfs::{FileOps, Inode, InodeBuilder, InodeRef, KResult, PollSubscribers, default_inode_ops, mk_mode};

pub mod policy;
pub mod uapi;
mod ioctl;
#[cfg(target_os = "oxide-kernel")]
mod install;
#[cfg(not(target_os = "oxide-kernel"))]
mod install_hosted;
#[cfg(test)]
mod tests;

#[cfg(target_os = "oxide-kernel")]
use install::install_pages;
#[cfg(not(target_os = "oxide-kernel"))]
use install_hosted::install_pages;

pub use ioctl::handle_uffd_ioctl;

use uapi::{UFFD_EVENT_PAGEFAULT, UFFD_PAGEFAULT_FLAG_WRITE};

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
    pub ranges:  Vec<RegisteredRange>,
    pub events:  VecDeque<UffdMsg>,
}

/// Per-inode userfaultfd state (Linux `i_private` + `userfaultfd_ctx`).
pub struct UfData {
    pub state: Spinlock<UfState, UffdLockClass>,
    /// Linux `ctx->flags` — the `userfaultfd(2)` flag word, including
    /// `UFFD_USER_MODE_ONLY`. u32, not u16: `O_CLOEXEC` is 0o2000000 and was
    /// being truncated away by the old `as u16`.
    pub flags: AtomicU32,
    /// Linux `ctx->features` — the negotiated set plus the kernel-private
    /// `UFFD_FEATURE_INITIALIZED` bit that marks a completed `UFFDIO_API`.
    pub features: AtomicU64,
    /// Linux `ctx->mm`, captured at `userfaultfd(2)` time and `mmgrab`ed.
    /// EVERY range op (REGISTER/UNREGISTER/COPY/ZEROPAGE) targets THIS mm,
    /// never `current`'s: the fd is inheritable and sendable over SCM_RIGHTS,
    /// so a holder in another process must not be able to redirect an install
    /// into its own address space. `Weak` is Linux's `mmgrab`/`mmget_not_zero`
    /// pair — it keeps no address space alive (which would also be an Arc
    /// cycle, since the registered VMAs hold this context) and upgrade
    /// failure is Linux's ESRCH.
    mm: Weak<vmm::AddressSpace>,
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

    /// Linux `mmget_not_zero(ctx->mm)`: the address space this fd owns, or
    /// `None` once it has been torn down (the ioctl paths turn that into
    /// ESRCH, exactly as `userfaultfd_copy`'s `else return -ESRCH` arm does).
    /// # C: O(1)
    pub(crate) fn mm(&self) -> Option<Arc<vmm::AddressSpace>> { self.mm.upgrade() }
}

/// UfData ino tag (high bits distinct from socket/io_uring/pipe).
mod ids {
    pub(crate) const INO_TAG: vfs::Ino = 0x5546_4644_0000_0000;
    pub(crate) const INO_ID_MASK: vfs::Ino = 0xFFFF_FFFF;
}
static NEXT_UFFD_INO: AtomicU64 = AtomicU64::new(1);

/// `make_userfaultfd_inode(flags, mm)` — a Regular pseudo-inode whose `read`
/// drains queued `uffd_msg` events and whose `poll` reports POLLIN when
/// events are queued. `mm` is Linux's `ctx->mm = current->mm` + `mmgrab`.
/// # C: O(1)
pub fn make_userfaultfd_inode(flags: u32, mm: Weak<vmm::AddressSpace>) -> InodeRef {
    let ino = ids::INO_TAG | (NEXT_UFFD_INO.fetch_add(1, Ordering::Relaxed) & ids::INO_ID_MASK);
    let poll = Arc::new(PollSubscribers::new());
    InodeBuilder::new(ino, mk_mode(vfs::FileType::Regular, 0),
        default_inode_ops(), Arc::new(UffdFileOps))
        .poll_subs_arc(poll.clone())
        .private(Arc::new(UfData {
            state: Spinlock::new(UfState {
                ranges:  Vec::new(),
                events:  VecDeque::new(),
            }),
            flags: AtomicU32::new(flags),
            features: AtomicU64::new(0),
            mm,
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
        let d = match inode.private::<UfData>() { Some(d) => d, None => return Err(vfs::VfsError::Einval) };
        // Linux `userfaultfd_read_iter`: `if (!userfaultfd_is_initialized(ctx))
        // return -EINVAL;` runs BEFORE the `iov_iter_count(to) < sizeof(msg)`
        // short-buffer test, so a pre-handshake read with a short buffer is
        // EINVAL for the handshake reason.
        if !policy::is_initialized(d.features.load(Ordering::Acquire)) {
            return Err(vfs::VfsError::Einval);
        }
        if buf.len() < core::mem::size_of::<UffdMsg>() { return Err(vfs::VfsError::Einval); }
        loop {
            if let Some(m) = d.state.lock().events.pop_front() {
                return Ok(copy_msg_out(&m, buf));
            }
            #[cfg(target_os = "oxide-kernel")]
            {
                // Linux `userfaultfd_ctx_read` (`mm/userfaultfd.c:3401-3403`):
                // `if (signal_pending(current)) { ret = -ERESTARTSYS; break; }`.
                if sched::live::deliverable_signals_self() != 0 {
                    return Err(vfs::VfsError::Erestartsys);
                }
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
        let d = match inode.private::<UfData>() { Some(d) => d, None => return Err(vfs::VfsError::Einval) };
        if !policy::is_initialized(d.features.load(Ordering::Acquire)) {
            return Err(vfs::VfsError::Einval);
        }
        if buf.len() < core::mem::size_of::<UffdMsg>() { return Err(vfs::VfsError::Einval); }
        match d.state.lock().events.pop_front() {
            Some(m) => Ok(copy_msg_out(&m, buf)),
            None    => Err(vfs::VfsError::Eagain),
        }
    }
    /// POLLIN iff an event is queued (a `read` won't block). Linux
    /// `userfaultfd_poll` returns `EPOLLERR` before the `UFFDIO_API`
    /// handshake; its second `EPOLLERR` arm (any fd without `O_NONBLOCK`) is
    /// not reproducible here because `FileOps::poll` sees only the inode, not
    /// the open-file flags.
    /// # C: O(1)
    /// Linux `file_can_poll` — this description has a `->poll`. # C: O(1)
    fn can_poll(&self, _file: &vfs::File) -> bool { true }
    fn poll(&self, inode: &Inode) -> u32 {
        let Some(d) = inode.private::<UfData>() else { return 0 };
        if !policy::is_initialized(d.features.load(Ordering::Acquire)) { return vfs::POLL_ERR; }
        if !d.state.lock().events.is_empty() { vfs::POLL_IN } else { 0 }
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
    /// `true` so the fault handler retries the instruction (which either hits
    /// the now-present page or re-faults + re-enqueues).
    ///
    /// Returns `false` WITHOUT enqueueing when the fault came from kernel mode
    /// and this context is `UFFD_USER_MODE_ONLY` — Linux's `VM_FAULT_SIGBUS`
    /// arm. That is what makes the flag mean something: it is the escape hatch
    /// `userfaultfd_syscall_allowed` hands every unprivileged caller, so if it
    /// were unenforced an unprivileged uffd could still stall the kernel
    /// inside a uaccess on a registered page.
    /// # C: O(1) enqueue + block
    fn missing_fault(&self, addr: u64, write: bool, user_mode: bool) -> bool {
        if !policy::may_deliver_fault(self.flags.load(Ordering::Acquire), user_mode) {
            return false;
        }
        let feats = self.features.load(Ordering::Acquire);
        // Linux `userfault_msg`: the tid is filled ONLY when the monitor
        // negotiated UFFD_FEATURE_THREAD_ID; otherwise the field reads 0.
        #[cfg(target_os = "oxide-kernel")]
        let ptid = if feats & uapi::feature::THREAD_ID != 0 {
            sched::live::current().map(|c| c.tid as u64).unwrap_or(0)
        } else { 0 };
        #[cfg(not(target_os = "oxide-kernel"))]
        let ptid = 0u64;
        let msg = UffdMsg {
            event: UFFD_EVENT_PAGEFAULT,
            _r0: 0, _r1: 0, _r2: 0,
            addr,
            flags: if write { UFFD_PAGEFAULT_FLAG_WRITE } else { 0 },
            ptid,
        };
        let _ = feats;
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
        true
    }
}

/// Linux `capable(CAP_SYS_PTRACE)` == `ns_capable(&init_user_ns, …)`: the
/// capability must be held in the INITIAL user namespace. An effective-set-only
/// test would let any user reach the privileged arm of
/// `userfaultfd_syscall_allowed` by first calling `unshare(CLONE_NEWUSER)`,
/// where they are root — which is exactly the bypass the sysctl exists to stop.
/// # C: O(1)
fn capable_sys_ptrace(cur: &sched::Task) -> bool {
    cur.has_cap(sched::cap::SYS_PTRACE)
        && cur.namespace_owner(namespace_identity::NamespaceKind::User)
              .is_none_or(|ns| ns.is_initial())
}

/// `userfaultfd(flags)` — slot 323. Returns a fresh fd.
///
/// Linux `SYSCALL_DEFINE1(userfaultfd)`:
/// `if (!userfaultfd_syscall_allowed(flags)) return -EPERM; return new_userfaultfd(flags);`
/// — the EPERM gate runs FIRST, then `new_userfaultfd` rejects unknown flag
/// bits with EINVAL. See `policy::check_create`.
/// # C: O(1)
pub fn sys_userfaultfd(args: &syscall::SyscallArgs) -> i64 {
    use vfs::{File, OpenFlags};
    use syscall::errno::Errno;
    let raw = args.a0 as u32;
    let cur = match sched::current() {
        Some(c) => c, None => return -(Errno::Einval.as_i32() as i64),
    };
    if let Err(e) = policy::check_create(raw, capable_sys_ptrace(&cur),
                                         vmm::uffd::unprivileged_userfaultfd() != 0) {
        return -(e.as_i32() as i64);
    }
    // SAFETY: running task on this CPU; preempt-off; single-mutator mm slot per 13§5; we only take a weak reference.
    let mm = match unsafe { cur.mm_ref() } {
        Some(m) => Arc::downgrade(m), None => return -(Errno::Einval.as_i32() as i64),
    };
    let inode_ref = make_userfaultfd_inode(raw, mm);
    // SAFETY: running task on this CPU; preempt-off; sole reader of fd_table slot.
    let fdt = match unsafe { cur.fd_table_ref() } {
        Some(t) => t.clone(), None => return -(Errno::Ebadf.as_i32() as i64),
    };
    let dentry = vfs::dcache::d_alloc_pseudo("[userfaultfd]", inode_ref.clone(), &crate::anon_dname::ANON_INODE_OPS);
    let mut fl = OpenFlags::O_RDWR;
    if (raw & uapi::O_NONBLOCK) != 0 { fl |= OpenFlags::O_NONBLOCK; }
    let file = File::new(inode_ref, dentry, fl);
    match fdt.alloc_limit(file, cur.nofile_soft()) {
        Ok(fd) => {
            if (raw & uapi::O_CLOEXEC) != 0 { let _ = fdt.set_cloexec(fd, true); }
            fd as i64
        }
        Err(e) => -(e as i64),
    }
}

/// Lift a generic `vfs::InodeRef` to `Arc<UfData>` via `i_private`.
fn as_uffd(inode: &vfs::InodeRef) -> Option<Arc<UfData>> {
    inode.i_private().clone().downcast::<UfData>().ok()
}
