//! Slot 271 `ppoll` against Linux `fs/select.c::SYSCALL_DEFINE5(ppoll)`:
//! the `set_user_sigmask`/`TIF_RESTORE_SIGMASK` handshake, the timespec
//! argument rules, the remaining-time writeback, and register-then-recheck.

use std::boxed::Box;
use std::ptr;
use std::sync::atomic::{AtomicPtr, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use sched::{SchedClass, Task};
use syscall::{errno::Errno, SyscallArgs};
use vfs::{Dentry, FdTable, File, FileOps, FileType, InodeBuilder, OpenFlags,
          default_inode_ops, mk_mode};

/// Pointer the userbuf stub always faults on, so EFAULT ordering is testable.
const BAD_PTR: u64 = 0xdead_0000;
const SIGUSR1_BIT: u64 = 1 << (10 - 1);
const SIGUSR2_BIT: u64 = 1 << (12 - 1);

mod userbuf {
    use syscall::errno::Errno;

    fn check(ptr: u64) -> Result<(), i64> {
        if ptr == 0 || ptr == super::BAD_PTR { Err(-(Errno::Efault.as_i32() as i64)) } else { Ok(()) }
    }

    pub(crate) fn validate_user_buf(ptr: u64, _len: u64, _align: u64) -> Result<(), i64> { check(ptr) }
    pub(crate) fn validate_user_buf_readable(ptr: u64, _len: u64, _align: u64) -> Result<(), i64> { check(ptr) }
    pub(crate) fn validate_user_buf_writable(ptr: u64, _len: u64, _align: u64) -> Result<(), i64> { check(ptr) }
}

mod poll {
    pub(crate) mod poll_common {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

        pub(crate) static NOW_NS: AtomicU64 = AtomicU64::new(0);
        pub(crate) static PARK_CALLS: AtomicUsize = AtomicUsize::new(0);
        pub(crate) static PARK_OBSERVED: AtomicU64 = AtomicU64::new(u64::MAX);
        /// Signal bitmap the park raises, simulating a signal that arrives
        /// while the caller sleeps under the temporary mask.
        pub(crate) static SIGNAL_ON_PARK: AtomicU64 = AtomicU64::new(0);
        pub(crate) static GENERATION: AtomicU64 = AtomicU64::new(0);
        pub(crate) static SUBSCRIBES: AtomicUsize = AtomicUsize::new(0);
        /// Subscribe count observed at the first readiness scan — proves every
        /// waiter registration precedes the first scan.
        pub(crate) static SUBSCRIBES_AT_FIRST_POLL: AtomicUsize = AtomicUsize::new(usize::MAX);

        pub(crate) fn monotonic_ns() -> u64 { NOW_NS.load(Ordering::SeqCst) }

        pub(crate) struct PollWaiter;

        impl PollWaiter {
            pub(crate) fn new() -> Arc<Self> { Arc::new(Self) }
            pub(crate) fn subscribe(self: &Arc<Self>, _subs: &vfs::PollSubscribers) {
                SUBSCRIBES.fetch_add(1, Ordering::SeqCst);
            }
            pub(crate) fn unsubscribe(&self, _subs: &vfs::PollSubscribers) {}
            pub(crate) fn generation(&self) -> u64 { GENERATION.load(Ordering::SeqCst) }
            pub(crate) unsafe fn park_until(&self, observed: u64, _deadline_ns: u64) {
                PARK_CALLS.fetch_add(1, Ordering::SeqCst);
                PARK_OBSERVED.store(observed, Ordering::SeqCst);
                let sig = SIGNAL_ON_PARK.load(Ordering::SeqCst);
                if sig != 0 {
                    if let Some(cur) = sched::current() { cur.sigpending.fetch_or(sig, Ordering::Release); }
                }
            }
        }
    }

    pub(crate) mod s007_poll {
        pub(crate) use crate::poll_engine::{current_task, sys_poll_deadline};
    }
}

#[path = "../src/pselect_ppoll.rs"]
mod pselect_ppoll;

#[path = "../src/pselect_ppoll_edge.rs"]
mod pselect_ppoll_edge;

#[path = "../src/007_poll.rs"]
mod poll_engine;

#[path = "../src/271_ppoll.rs"]
mod production_ppoll;

static TEST_LOCK: Mutex<()> = Mutex::new(());
static CURRENT: AtomicPtr<Task> = AtomicPtr::new(ptr::null_mut());
static NEXT_INO: AtomicU64 = AtomicU64::new(0x7710);
/// Nanoseconds the fake clock advances on every `->poll` call, so a wait can
/// consume part of its timeout without a real sleep.
static ADVANCE_ON_POLL: AtomicU64 = AtomicU64::new(0);
/// Generation bump injected during the readiness scan — a notification landing
/// in the snapshot-to-park gap.
static NOTIFY_ON_POLL: AtomicUsize = AtomicUsize::new(0);

struct PollOps(u32);

impl FileOps for PollOps {
    fn poll(&self, _inode: &vfs::inode::Inode) -> u32 {
        if poll::poll_common::SUBSCRIBES_AT_FIRST_POLL.load(Ordering::SeqCst) == usize::MAX {
            poll::poll_common::SUBSCRIBES_AT_FIRST_POLL
                .store(poll::poll_common::SUBSCRIBES.load(Ordering::SeqCst), Ordering::SeqCst);
        }
        let step = ADVANCE_ON_POLL.load(Ordering::SeqCst);
        if step != 0 { poll::poll_common::NOW_NS.fetch_add(step, Ordering::SeqCst); }
        if NOTIFY_ON_POLL.swap(0, Ordering::SeqCst) != 0 {
            poll::poll_common::GENERATION.fetch_add(1, Ordering::SeqCst);
        }
        self.0
    }
}

fn hooked_current() -> Option<&'static Task> {
    let p = CURRENT.load(Ordering::Acquire);
    // SAFETY: tests store only leaked Task pointers and clear the pointer before returning.
    if p.is_null() { None } else { Some(unsafe { &*p }) }
}

fn begin() -> MutexGuard<'static, ()> {
    let guard = TEST_LOCK.lock().unwrap();
    CURRENT.store(ptr::null_mut(), Ordering::Release);
    sched::set_current_hook(hooked_current);
    poll::poll_common::NOW_NS.store(0, Ordering::SeqCst);
    poll::poll_common::PARK_CALLS.store(0, Ordering::SeqCst);
    poll::poll_common::PARK_OBSERVED.store(u64::MAX, Ordering::SeqCst);
    poll::poll_common::SIGNAL_ON_PARK.store(0, Ordering::SeqCst);
    poll::poll_common::GENERATION.store(0, Ordering::SeqCst);
    poll::poll_common::SUBSCRIBES.store(0, Ordering::SeqCst);
    poll::poll_common::SUBSCRIBES_AT_FIRST_POLL.store(usize::MAX, Ordering::SeqCst);
    ADVANCE_ON_POLL.store(0, Ordering::SeqCst);
    NOTIFY_ON_POLL.store(0, Ordering::SeqCst);
    guard
}

fn install_task(mask: u64) -> &'static Task {
    let task = Box::leak(Box::new(Task::new(0x7710, "ppoll", SchedClass::Normal { weight: 1024 })));
    task.set_current_blocked(mask);
    CURRENT.store(task as *const Task as *mut Task, Ordering::Release);
    task
}

fn mk_file(mask: u32) -> Arc<File> {
    let ino = NEXT_INO.fetch_add(1, Ordering::Relaxed);
    let inode = InodeBuilder::new(ino, mk_mode(FileType::Regular, 0o644),
        default_inode_ops(), Arc::new(PollOps(mask)))
        .poll_subs(vfs::PollSubscribers::new())
        .build();
    let dentry = Dentry::new(None, "ppoll-file".into(), Arc::clone(&inode));
    File::new(inode, dentry, OpenFlags::O_RDWR)
}

/// Install one fd with `ready` readiness and return its `struct pollfd` bytes.
fn one_fd(task: &Task, ready: u32) -> (i32, [u8; 8]) {
    let fdt = Arc::new(FdTable::new());
    let fd = fdt.alloc(mk_file(ready)).unwrap();
    // SAFETY: freshly leaked test task is not scheduled and has no concurrent fd-table writer.
    unsafe { task.replace_fd_table(Some(fdt)); }
    let mut pfd = [0u8; 8];
    pfd[0..4].copy_from_slice(&fd.to_ne_bytes());
    pfd[4..6].copy_from_slice(&(vfs::POLL_IN as i16).to_ne_bytes());
    (fd, pfd)
}

fn ts(sec: i64, nsec: i64) -> [i64; 2] { [sec, nsec] }

fn args(pfd: &mut [u8; 8], nfds: u64, tsp: u64, ss: u64, sslen: u64) -> SyscallArgs {
    SyscallArgs { a0: pfd.as_mut_ptr() as u64, a1: nfds, a2: tsp, a3: ss, a4: sslen, a5: 0 }
}

const EINTR: i64 = -(Errno::Eintr.as_i32() as i32 as i64);
const EINVAL: i64 = -(Errno::Einval.as_i32() as i32 as i64);
const EFAULT: i64 = -(Errno::Efault.as_i32() as i32 as i64);

#[test]
fn a_signal_during_the_wait_keeps_the_temporary_mask_for_delivery() {
    let _g = begin();
    // Caller blocks SIGUSR1; ppoll's mask unblocks it for the duration of the
    // wait. The signal lands while parked.
    let task = install_task(SIGUSR1_BIT | SIGUSR2_BIT);
    let (_fd, mut pfd) = one_fd(task, 0);
    let mut new_mask: u64 = SIGUSR2_BIT;
    poll::poll_common::SIGNAL_ON_PARK.store(SIGUSR1_BIT, Ordering::SeqCst);

    let rv = production_ppoll::sys_ppoll(&args(&mut pfd, 1, 0,
                                               &mut new_mask as *mut u64 as u64, 8));

    assert_eq!(rv, EINTR);
    // Linux `restore_saved_sigmask_unless(ret == -ERESTARTNOHAND)`: the
    // temporary mask is STILL installed so the handler runs under it.
    assert_eq!(task.sigmask.load(Ordering::Acquire), SIGUSR2_BIT);
    assert!(task.restore_sigmask.load(Ordering::Acquire));
    assert_eq!(task.saved_sigmask.load(Ordering::Acquire), SIGUSR1_BIT | SIGUSR2_BIT);
    // …and the frame `rt_sigreturn` restores carries the caller's ORIGINAL
    // mask, which is the entire point of TIF_RESTORE_SIGMASK.
    assert_eq!(task.sigmask_to_save(), SIGUSR1_BIT | SIGUSR2_BIT);
    assert!(!task.restore_sigmask.load(Ordering::Acquire), "the flag is one-shot");
}

#[test]
fn an_uninterrupted_wait_restores_the_callers_mask_before_returning() {
    let _g = begin();
    let task = install_task(SIGUSR1_BIT);
    let (_fd, mut pfd) = one_fd(task, vfs::POLL_IN);
    let mut new_mask: u64 = SIGUSR2_BIT;

    let rv = production_ppoll::sys_ppoll(&args(&mut pfd, 1, 0,
                                               &mut new_mask as *mut u64 as u64, 8));

    assert_eq!(rv, 1);
    assert_eq!(task.sigmask.load(Ordering::Acquire), SIGUSR1_BIT);
    assert!(!task.restore_sigmask.load(Ordering::Acquire));
}

#[test]
fn a_null_sigmask_pointer_never_touches_the_mask() {
    let _g = begin();
    let task = install_task(SIGUSR1_BIT);
    let (_fd, mut pfd) = one_fd(task, vfs::POLL_IN);

    // NULL sigmask with a nonsense sigsetsize is still legal (Linux checks the
    // pointer first) and must leave the mask exactly as it was.
    assert_eq!(production_ppoll::sys_ppoll(&args(&mut pfd, 1, 0, 0, 999)), 1);
    assert_eq!(task.sigmask.load(Ordering::Acquire), SIGUSR1_BIT);
    assert!(!task.restore_sigmask.load(Ordering::Acquire));
}

#[test]
fn a_non_null_sigmask_demands_sizeof_sigset_t_and_installs_nothing_on_einval() {
    let _g = begin();
    let task = install_task(SIGUSR1_BIT);
    let (_fd, mut pfd) = one_fd(task, vfs::POLL_IN);
    let mut new_mask: u64 = SIGUSR2_BIT;
    let ss = &mut new_mask as *mut u64 as u64;

    for bad in [0u64, 4, 7, 9, 16] {
        assert_eq!(production_ppoll::sys_ppoll(&args(&mut pfd, 1, 0, ss, bad)), EINVAL);
        assert_eq!(task.sigmask.load(Ordering::Acquire), SIGUSR1_BIT);
        assert!(!task.restore_sigmask.load(Ordering::Acquire));
    }
    assert_eq!(poll::poll_common::SUBSCRIBES.load(Ordering::SeqCst), 0, "no wait was entered");
}

#[test]
fn the_timespec_is_validated_before_any_mask_is_installed() {
    let _g = begin();
    let task = install_task(SIGUSR1_BIT);
    let (_fd, mut pfd) = one_fd(task, vfs::POLL_IN);
    let mut new_mask: u64 = SIGUSR2_BIT;
    let ss = &mut new_mask as *mut u64 as u64;

    for bad in [ts(0, 1_000_000_000), ts(0, -1), ts(-1, 0)] {
        let mut t = bad;
        let rv = production_ppoll::sys_ppoll(&args(&mut pfd, 1, t.as_mut_ptr() as u64, ss, 8));
        assert_eq!(rv, EINVAL, "timespec {bad:?}");
        assert_eq!(task.sigmask.load(Ordering::Acquire), SIGUSR1_BIT);
        assert!(!task.restore_sigmask.load(Ordering::Acquire));
    }
    // A faulting timespec is EFAULT, still before the mask install.
    assert_eq!(production_ppoll::sys_ppoll(&args(&mut pfd, 1, BAD_PTR, ss, 8)), EFAULT);
    assert_eq!(task.sigmask.load(Ordering::Acquire), SIGUSR1_BIT);
}

#[test]
fn null_timeout_blocks_while_a_zero_timeout_polls_once_without_parking() {
    let _g = begin();
    let task = install_task(0);
    let (_fd, mut pfd) = one_fd(task, 0);

    let mut zero = ts(0, 0);
    assert_eq!(production_ppoll::sys_ppoll(&args(&mut pfd, 1, zero.as_mut_ptr() as u64, 0, 0)), 0);
    assert_eq!(poll::poll_common::PARK_CALLS.load(Ordering::SeqCst), 0);

    // NULL timespec = wait indefinitely: the call parks and only a signal ends it.
    poll::poll_common::SIGNAL_ON_PARK.store(SIGUSR1_BIT, Ordering::SeqCst);
    assert_eq!(production_ppoll::sys_ppoll(&args(&mut pfd, 1, 0, 0, 0)), EINTR);
    assert_eq!(poll::poll_common::PARK_CALLS.load(Ordering::SeqCst), 1);
}

#[test]
fn a_zero_timeout_with_a_deliverable_signal_is_eintr_not_zero() {
    let _g = begin();
    let task = install_task(0);
    let (_fd, mut pfd) = one_fd(task, 0);
    task.sigpending.fetch_or(SIGUSR1_BIT, Ordering::Release);

    // Linux `do_poll`: `count = -ERESTARTNOHAND` is assigned before the
    // `if (count || timed_out) break`, so the signal outranks the timeout.
    let mut zero = ts(0, 0);
    assert_eq!(production_ppoll::sys_ppoll(&args(&mut pfd, 1, zero.as_mut_ptr() as u64, 0, 0)), EINTR);
    assert_eq!(poll::poll_common::PARK_CALLS.load(Ordering::SeqCst), 0);
}

#[test]
fn the_remaining_time_is_written_back_for_a_nonzero_timeout() {
    let _g = begin();
    let task = install_task(0);
    let (_fd, mut pfd) = one_fd(task, vfs::POLL_IN);
    ADVANCE_ON_POLL.store(2_000_000_000, Ordering::SeqCst);
    let mut t = ts(5, 0);

    assert_eq!(production_ppoll::sys_ppoll(&args(&mut pfd, 1, t.as_mut_ptr() as u64, 0, 0)), 1);
    // The RAW syscall updates the caller's timespec (glibc's wrapper hides it
    // behind a local copy); 5 s requested, 2 s consumed.
    assert_eq!(t, ts(3, 0));
}

#[test]
fn a_zero_timeout_leaves_the_callers_timespec_untouched() {
    let _g = begin();
    let task = install_task(0);
    let (_fd, mut pfd) = one_fd(task, vfs::POLL_IN);
    ADVANCE_ON_POLL.store(2_000_000_000, Ordering::SeqCst);
    let mut t = ts(0, 0);

    assert_eq!(production_ppoll::sys_ppoll(&args(&mut pfd, 1, t.as_mut_ptr() as u64, 0, 0)), 1);
    assert_eq!(t, ts(0, 0), "Linux: no update for zero timeout");
}

#[test]
fn a_sticky_timeouts_persona_suppresses_the_writeback() {
    let _g = begin();
    let task = install_task(0);
    task.personality.store(sched::personality::STICKY_TIMEOUTS, Ordering::Release);
    let (_fd, mut pfd) = one_fd(task, vfs::POLL_IN);
    ADVANCE_ON_POLL.store(2_000_000_000, Ordering::SeqCst);
    let mut t = ts(5, 0);

    assert_eq!(production_ppoll::sys_ppoll(&args(&mut pfd, 1, t.as_mut_ptr() as u64, 0, 0)), 1);
    assert_eq!(t, ts(5, 0));
}

#[test]
fn an_expired_deadline_reports_a_zero_remainder_never_a_negative_one() {
    let _g = begin();
    let task = install_task(0);
    let (_fd, mut pfd) = one_fd(task, vfs::POLL_IN);
    ADVANCE_ON_POLL.store(9_000_000_000, Ordering::SeqCst);
    let mut t = ts(1, 0);

    assert_eq!(production_ppoll::sys_ppoll(&args(&mut pfd, 1, t.as_mut_ptr() as u64, 0, 0)), 1);
    assert_eq!(t, ts(0, 0));
}

#[test]
fn every_waiter_registers_before_the_first_readiness_scan() {
    let _g = begin();
    let task = install_task(0);
    let (_fd, mut pfd) = one_fd(task, vfs::POLL_IN);

    assert_eq!(production_ppoll::sys_ppoll(&args(&mut pfd, 1, 0, 0, 0)), 1);
    // Register-then-recheck, half one: the subscription is in place before the
    // scan that could otherwise miss a concurrent readiness transition.
    assert_eq!(poll::poll_common::SUBSCRIBES_AT_FIRST_POLL.load(Ordering::SeqCst), 1);
}

#[test]
fn a_notification_inside_the_scan_to_park_gap_is_not_lost() {
    let _g = begin();
    let task = install_task(0);
    let (_fd, mut pfd) = one_fd(task, 0);
    NOTIFY_ON_POLL.store(1, Ordering::SeqCst);
    poll::poll_common::SIGNAL_ON_PARK.store(SIGUSR1_BIT, Ordering::SeqCst);

    assert_eq!(production_ppoll::sys_ppoll(&args(&mut pfd, 1, 0, 0, 0)), EINTR);
    // Register-then-recheck, half two: the generation handed to `park_until`
    // was snapshot BEFORE the scan, so a notification raised during the scan
    // makes `observed != current` and the park cannot swallow the wakeup.
    let observed = poll::poll_common::PARK_OBSERVED.load(Ordering::SeqCst);
    assert_eq!(observed, 0);
    assert_ne!(observed, poll::poll_common::GENERATION.load(Ordering::SeqCst));
}

#[test]
fn the_real_waiter_publishes_sleeping_before_it_rechecks_the_generation() {
    // The production `PollWaiter::park_until` is kernel-gated, so its ordering
    // is asserted on the source: park (publish Sleeping) THEN compare the
    // snapshot, never the reverse — check-then-park loses wakeups.
    let src = include_str!("../src/poll_common.rs");
    let park = src.find("park_with_deadline(deadline_ns)").expect("park call");
    let recheck = src.find("if self.generation.load(Ordering::Acquire) != observed").expect("recheck");
    let yield_at = src.find("sched::live::park_yield()").expect("yield");
    assert!(park < recheck && recheck < yield_at);
}
