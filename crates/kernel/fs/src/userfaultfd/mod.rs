// userfaultfd(2) per `27`.
//
// A registered range routes its faults to a monitor holding this fd instead of
// resolving them in the kernel. Four registration/resolve modes share one
// message queue, one block/wake protocol and one destination ladder:
//
//   MISSING — an absent page is reported; the monitor supplies contents with
//             UFFDIO_COPY / UFFDIO_ZEROPAGE, or releases the faulter with
//             UFFDIO_WAKE.
//   MINOR   — a page the backing already holds but the page table does not is
//             reported; the monitor publishes it with UFFDIO_CONTINUE.
//   WP      — a write to a page armed by UFFDIO_WRITEPROTECT is reported; the
//             monitor releases it by resolving the same range.
//   POISON  — UFFDIO_POISON marks pages unrecoverable, so an access raises a
//             memory error instead of faulting a page in.
//
// UFFDIO_MOVE relocates pages between two anonymous mappings of the address
// space the fd owns, without copying them.
//
// Module manifest:
//   - mod.rs (this file): context state, inode ctor, sys_userfaultfd.
//   - msg.rs: the message type, the blocking read/poll, and the ONE fault
//     delivery path every mode goes through.
//   - uapi.rs: numbers, struct sizes/offsets, feature and mode bits.
//   - policy/: UNGATED decision logic — every ladder, errno and reply bitmap.
//   - ioctl/: UFFDIO_* dispatch and the per-command ABI shims.
//   - work/: the page work each resolve performs (target-gated) plus its
//     hosted stand-in.
//   - tests/: hosted logic tests.

#![allow(dead_code)]

use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use alloc::collections::VecDeque;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use sync::{Spinlock, TaskList as UffdLockClass};
use vfs::{InodeBuilder, InodeRef, PollSubscribers, default_inode_ops, mk_mode};

pub mod policy;
pub mod uapi;
pub mod work;
mod ioctl;
mod msg;
#[cfg(test)]
mod tests;

pub use ioctl::handle_uffd_ioctl;
pub use msg::UffdMsg;

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
    /// The address space captured at `userfaultfd(2)` time. EVERY range op
    /// targets THIS one, never the caller's: the fd is inheritable and
    /// sendable over a socket, so a holder in another process must not be able
    /// to redirect an install into its own address space. `Weak` keeps no
    /// address space alive — which would also be a reference cycle, since the
    /// registered VMAs hold this context — and an upgrade failure is ESRCH.
    mm: Weak<vmm::AddressSpace>,
    /// Monitor threads blocked in `read` waiting for an event.
    read_waiters: WaitList,
    /// Faulting threads blocked in delivery waiting for a resolve.
    fault_waiters: WaitList,
    /// Monotonic wake generation: bumped by every resolve. A parked
    /// faulter snapshots it before parking and returns (retries its
    /// instruction) once it advances — closes the lost-wake race without
    /// needing a per-address resolved-set.
    wake_gen: AtomicU64,
    /// The inode's epoll/poll subscriber set (same `Arc` the inode holds),
    /// so delivery can notify pollers from `&UfData` alone.
    poll: Arc<PollSubscribers>,
}

impl UfData {
    /// Bump the wake generation and wake every blocked faulter so each
    /// re-checks its address (retries the faulting instruction). Called by
    /// every resolve after its work completes.
    /// # C: O(N_faulters)
    pub(crate) fn wake_faulters(&self) {
        self.wake_gen.fetch_add(1, Ordering::AcqRel);
        self.fault_waiters.wake_all();
    }

    /// The current wake generation. A resolve bumps it; a parked faulter
    /// returns once it moves. Exposed so a test can tell "this command
    /// released the blocked threads" from "it silently did not".
    /// # C: O(1)
    pub(crate) fn wake_generation(&self) -> u64 { self.wake_gen.load(Ordering::Acquire) }

    /// The address space this fd owns, or `None` once it has been torn down
    /// (the ioctl paths turn that into ESRCH).
    /// # C: O(1)
    pub(crate) fn mm(&self) -> Option<Arc<vmm::AddressSpace>> { self.mm.upgrade() }
}

/// userfaultfd's reserved inode-number range, owned by `vfs::pseudo_ino`.
static NEXT_UFFD_INO: vfs::pseudo_ino::RegionAllocator
    = vfs::pseudo_ino::RegionAllocator::new(&vfs::pseudo_ino::USERFAULTFD);

/// A Regular pseudo-inode whose `read` drains queued events and whose `poll`
/// reports POLLIN when events are queued. `mm` is the address space the fd is
/// bound to for its whole life.
/// # C: O(1)
pub fn make_userfaultfd_inode(flags: u32, mm: Weak<vmm::AddressSpace>) -> InodeRef {
    let ino = NEXT_UFFD_INO.alloc();
    let poll = Arc::new(PollSubscribers::new());
    InodeBuilder::new(ino, mk_mode(vfs::FileType::Regular, 0),
        default_inode_ops(), Arc::new(msg::UffdFileOps))
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

/// The privileged arm of the creation gate requires the capability in the
/// INITIAL user namespace. An effective-set-only test would let any user reach
/// that arm by first unsharing a user namespace where they are root — exactly
/// the bypass the sysctl exists to stop.
/// # C: O(1)
pub(crate) fn capable_sys_ptrace(cur: &sched::Task) -> bool {
    cur.has_cap(sched::cap::SYS_PTRACE)
        && cur.namespace_owner(namespace_identity::NamespaceKind::User)
              .is_none_or(|ns| ns.is_initial())
}

/// `userfaultfd(flags)` — slot 323. Returns a fresh fd.
///
/// The EPERM gate runs FIRST and unknown flag bits are rejected after it, so
/// an unprivileged caller passing garbage flags sees EPERM. See
/// `policy::check_create`.
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
pub(crate) fn as_uffd(inode: &vfs::InodeRef) -> Option<Arc<UfData>> {
    inode.i_private().clone().downcast::<UfData>().ok()
}

/// Whether an inode really is a userfaultfd, by the identity of its private
/// state. The ioctl router used the inode NUMBER's high half instead, which
/// reserves a range but proves no ownership: any inode reusing that half was
/// routed here, and the handler then took its unrelated private state for a
/// context. # C: O(1)
pub fn is_uffd_inode(inode: &vfs::InodeRef) -> bool { as_uffd(inode).is_some() }
