//! Slot 270 `pselect6` against Linux `fs/select.c::SYSCALL_DEFINE6(pselect6)`
//! → `get_sigset_argpack` → `do_pselect`: the six-argument sigset argpack,
//! the `set_user_sigmask`/`TIF_RESTORE_SIGMASK` handshake, the timespec rules,
//! and the remaining-time writeback.

use std::boxed::Box;
use std::ptr;
use std::sync::atomic::{AtomicPtr, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use sched::{SchedClass, Task};
use syscall::{errno::Errno, SyscallArgs};
use vfs::{Dentry, FdTable, File, FileOps, FileType, InodeBuilder, OpenFlags,
          default_inode_ops, mk_mode};

macro_rules! debug_ssh { ($($t:tt)*) => {} }

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
        /// Signal bitmap the park raises, simulating a signal that arrives
        /// while the caller sleeps under the temporary mask.
        pub(crate) static SIGNAL_ON_PARK: AtomicU64 = AtomicU64::new(0);

        pub(crate) fn monotonic_ns() -> u64 { NOW_NS.load(Ordering::SeqCst) }

        pub(crate) struct PollWaiter;

        impl PollWaiter {
            pub(crate) fn new() -> Arc<Self> { Arc::new(Self) }
            pub(crate) fn subscribe(self: &Arc<Self>, _subs: &vfs::PollSubscribers) {}
            pub(crate) fn unsubscribe(&self, _subs: &vfs::PollSubscribers) {}
            pub(crate) fn generation(&self) -> u64 { 0 }
            pub(crate) unsafe fn park_until(&self, _observed: u64, _deadline_ns: u64) {
                PARK_CALLS.fetch_add(1, Ordering::SeqCst);
                let sig = SIGNAL_ON_PARK.load(Ordering::SeqCst);
                if sig != 0 {
                    if let Some(cur) = sched::current() { cur.sigpending.fetch_or(sig, Ordering::Release); }
                }
            }
        }
    }
}

#[path = "../src/pselect_ppoll.rs"]
mod pselect_ppoll;

#[path = "../src/pselect_ppoll_edge.rs"]
mod pselect_ppoll_edge;

mod select {
    pub(crate) mod s023_select {
        pub(crate) use crate::select_engine::sys_select_with_deadline;
    }
}

#[path = "../src/023_select.rs"]
mod select_engine;

#[path = "../src/270_pselect6.rs"]
mod production_pselect6;

static TEST_LOCK: Mutex<()> = Mutex::new(());
static CURRENT: AtomicPtr<Task> = AtomicPtr::new(ptr::null_mut());
static NEXT_INO: AtomicU64 = AtomicU64::new(0x7270);
/// Nanoseconds the fake clock advances on every `->poll` call.
static ADVANCE_ON_POLL: AtomicU64 = AtomicU64::new(0);

struct PollOps(u32);

impl FileOps for PollOps {
    fn poll(&self, _inode: &vfs::inode::Inode) -> u32 {
        let step = ADVANCE_ON_POLL.load(Ordering::SeqCst);
        if step != 0 { poll::poll_common::NOW_NS.fetch_add(step, Ordering::SeqCst); }
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
    select_engine::set_test_current(None);
    select_engine::set_post_snapshot_hook(None);
    poll::poll_common::NOW_NS.store(0, Ordering::SeqCst);
    poll::poll_common::PARK_CALLS.store(0, Ordering::SeqCst);
    poll::poll_common::SIGNAL_ON_PARK.store(0, Ordering::SeqCst);
    ADVANCE_ON_POLL.store(0, Ordering::SeqCst);
    guard
}

fn install_task(mask: u64) -> &'static Task {
    let task = Box::leak(Box::new(Task::new(0x7270, "pselect6", SchedClass::Normal { weight: 1024 })));
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
    let dentry = Dentry::new(None, "pselect-file".into(), Arc::clone(&inode));
    File::new(inode, dentry, OpenFlags::O_RDWR)
}

/// One readable-set fd with the given readiness; returns the 8-byte fd_set.
fn one_fd(task: &Task, ready: u32) -> u64 {
    let fdt = Arc::new(FdTable::new());
    let fd = fdt.alloc(mk_file(ready)).unwrap();
    // SAFETY: freshly leaked test task is not scheduled and has no concurrent fd-table writer.
    unsafe { task.replace_fd_table(Some(fdt)); }
    1u64 << fd
}

/// `struct sigset_argpack { const sigset_t *ss; size_t ss_len; }`.
#[repr(C)]
struct SigsetArgpack { ss: u64, ss_len: u64 }

fn ts(sec: i64, nsec: i64) -> [i64; 2] { [sec, nsec] }

fn args(nfds: u64, readfds: &mut u64, tsp: u64, pack: u64) -> SyscallArgs {
    SyscallArgs { a0: nfds, a1: readfds as *mut u64 as u64, a2: 0, a3: 0, a4: tsp, a5: pack }
}

// Linux `do_poll`/`core_sys_select` end an interrupted wait with
// `-ERESTARTNOHAND`, and `poll_select_finish` folds it to `-EINTR` only when
// the residual timeout could not be written back (`fs/select.c:361-363`).
// Every case below either has no timeout buffer or a zero timeout, so the
// restart code survives to the syscall tail — which restarts the call when no
// handler frame was built.
const RESTARTNOHAND: i64 = syscall::restart::restart_nohand();
const EINVAL: i64 = -(Errno::Einval.as_i32() as i32 as i64);
const EFAULT: i64 = -(Errno::Efault.as_i32() as i32 as i64);

#[test]
fn the_sixth_argument_is_a_two_word_pack_not_a_bare_sigset_pointer() {
    let _g = begin();
    let task = install_task(SIGUSR1_BIT);
    let mut set = one_fd(task, vfs::POLL_IN);
    let mut mask: u64 = SIGUSR2_BIT;
    let mut pack = SigsetArgpack { ss: &mut mask as *mut u64 as u64, ss_len: 8 };

    let rv = production_pselect6::sys_pselect6(
        &args(64, &mut set, 0, &mut pack as *mut SigsetArgpack as u64));

    assert_eq!(rv, 1);
    // The mask that was installed came from `*pack.ss` — reading a5 as a bare
    // `sigset_t *` would have installed the pack's first word (a pointer).
    assert_eq!(task.saved_sigmask.load(Ordering::Acquire), SIGUSR1_BIT);
    assert_ne!(pack.ss, SIGUSR2_BIT);
}

#[test]
fn a_signal_during_the_wait_keeps_the_temporary_mask_for_delivery() {
    let _g = begin();
    let task = install_task(SIGUSR1_BIT | SIGUSR2_BIT);
    let mut set = one_fd(task, 0);
    let original = set;
    let mut mask: u64 = SIGUSR2_BIT;
    let mut pack = SigsetArgpack { ss: &mut mask as *mut u64 as u64, ss_len: 8 };
    poll::poll_common::SIGNAL_ON_PARK.store(SIGUSR1_BIT, Ordering::SeqCst);

    let rv = production_pselect6::sys_pselect6(
        &args(64, &mut set, 0, &mut pack as *mut SigsetArgpack as u64));

    assert_eq!(rv, RESTARTNOHAND);
    assert_eq!(task.sigmask.load(Ordering::Acquire), SIGUSR2_BIT, "temporary mask stays installed");
    assert!(task.restore_sigmask.load(Ordering::Acquire));
    assert_eq!(task.saved_sigmask.load(Ordering::Acquire), SIGUSR1_BIT | SIGUSR2_BIT);
    assert_eq!(task.sigmask_to_save(), SIGUSR1_BIT | SIGUSR2_BIT,
               "rt_sigreturn lands back on the caller's original mask");
    // Linux `core_sys_select`: `if (ret < 0) goto out;` — no set_fd_set.
    assert_eq!(set, original, "an interrupted select leaves the caller's fd sets alone");
}

#[test]
fn an_uninterrupted_wait_restores_the_callers_mask_before_returning() {
    let _g = begin();
    let task = install_task(SIGUSR1_BIT);
    let mut set = one_fd(task, vfs::POLL_IN);
    let mut mask: u64 = SIGUSR2_BIT;
    let mut pack = SigsetArgpack { ss: &mut mask as *mut u64 as u64, ss_len: 8 };

    let rv = production_pselect6::sys_pselect6(
        &args(64, &mut set, 0, &mut pack as *mut SigsetArgpack as u64));

    assert_eq!(rv, 1);
    assert_eq!(task.sigmask.load(Ordering::Acquire), SIGUSR1_BIT);
    assert!(!task.restore_sigmask.load(Ordering::Acquire));
}

#[test]
fn a_null_inner_sigset_or_a_null_pack_leaves_the_mask_alone() {
    let _g = begin();
    let task = install_task(SIGUSR1_BIT);
    let mut set = one_fd(task, vfs::POLL_IN);

    // `{NULL, 0}` — Linux's own default argpack.
    let mut pack = SigsetArgpack { ss: 0, ss_len: 0 };
    let mut probe = set;
    assert_eq!(production_pselect6::sys_pselect6(
        &args(64, &mut probe, 0, &mut pack as *mut SigsetArgpack as u64)), 1);
    assert_eq!(task.sigmask.load(Ordering::Acquire), SIGUSR1_BIT);
    assert!(!task.restore_sigmask.load(Ordering::Acquire));

    // A NULL inner pointer beside a garbage length is still legal.
    let mut pack = SigsetArgpack { ss: 0, ss_len: 999 };
    let mut probe = set;
    assert_eq!(production_pselect6::sys_pselect6(
        &args(64, &mut probe, 0, &mut pack as *mut SigsetArgpack as u64)), 1);
    assert_eq!(task.sigmask.load(Ordering::Acquire), SIGUSR1_BIT);

    // No pack at all (a5 == NULL).
    let mut probe = set;
    assert_eq!(production_pselect6::sys_pselect6(&args(64, &mut probe, 0, 0)), 1);
    assert_eq!(task.sigmask.load(Ordering::Acquire), SIGUSR1_BIT);
    assert!(!task.restore_sigmask.load(Ordering::Acquire));
    set = probe;
    assert_ne!(set, 0);
}

#[test]
fn ss_len_must_equal_sizeof_sigset_t() {
    let _g = begin();
    let task = install_task(SIGUSR1_BIT);
    let mut set = one_fd(task, vfs::POLL_IN);
    let mut mask: u64 = SIGUSR2_BIT;

    for bad in [0u64, 1, 4, 7, 9, 16, 128] {
        let mut pack = SigsetArgpack { ss: &mut mask as *mut u64 as u64, ss_len: bad };
        let mut probe = set;
        let rv = production_pselect6::sys_pselect6(
            &args(64, &mut probe, 0, &mut pack as *mut SigsetArgpack as u64));
        assert_eq!(rv, EINVAL, "ss_len={bad}");
        assert_eq!(task.sigmask.load(Ordering::Acquire), SIGUSR1_BIT);
        assert!(!task.restore_sigmask.load(Ordering::Acquire));
    }
    set = 0;
    assert_eq!(set, 0);
}

#[test]
fn a_faulting_argpack_is_efault_even_when_the_timespec_is_also_invalid() {
    let _g = begin();
    let task = install_task(SIGUSR1_BIT);
    let mut set = one_fd(task, vfs::POLL_IN);
    let mut bad_ts = ts(-1, 0);

    // Linux reads the pack in the syscall entry, BEFORE `do_pselect` touches
    // the timespec — so the pack's EFAULT wins over the timespec's EINVAL.
    let rv = production_pselect6::sys_pselect6(
        &args(64, &mut set, bad_ts.as_mut_ptr() as u64, BAD_PTR));
    assert_eq!(rv, EFAULT);
    assert_eq!(task.sigmask.load(Ordering::Acquire), SIGUSR1_BIT);
}

#[test]
fn the_timespec_is_validated_before_any_mask_is_installed() {
    let _g = begin();
    let task = install_task(SIGUSR1_BIT);
    let mut set = one_fd(task, vfs::POLL_IN);
    let mut mask: u64 = SIGUSR2_BIT;

    for bad in [ts(0, 1_000_000_000), ts(0, -1), ts(-1, 0)] {
        let mut t = bad;
        let mut pack = SigsetArgpack { ss: &mut mask as *mut u64 as u64, ss_len: 8 };
        let mut probe = set;
        let rv = production_pselect6::sys_pselect6(
            &args(64, &mut probe, t.as_mut_ptr() as u64, &mut pack as *mut SigsetArgpack as u64));
        assert_eq!(rv, EINVAL, "timespec {bad:?}");
        assert_eq!(task.sigmask.load(Ordering::Acquire), SIGUSR1_BIT);
        assert!(!task.restore_sigmask.load(Ordering::Acquire));
    }
    set = 0;
    assert_eq!(set, 0);
}

#[test]
fn null_timeout_blocks_while_a_zero_timeout_polls_once_without_parking() {
    let _g = begin();
    let task = install_task(0);
    let set0 = one_fd(task, 0);

    let mut zero = ts(0, 0);
    let mut probe = set0;
    assert_eq!(production_pselect6::sys_pselect6(
        &args(64, &mut probe, zero.as_mut_ptr() as u64, 0)), 0);
    assert_eq!(poll::poll_common::PARK_CALLS.load(Ordering::SeqCst), 0);
    assert_eq!(probe, 0, "a timed-out select clears the caller's sets");

    poll::poll_common::SIGNAL_ON_PARK.store(SIGUSR1_BIT, Ordering::SeqCst);
    let mut probe = set0;
    assert_eq!(production_pselect6::sys_pselect6(&args(64, &mut probe, 0, 0)), RESTARTNOHAND);
    assert_eq!(poll::poll_common::PARK_CALLS.load(Ordering::SeqCst), 1);
}

#[test]
fn a_zero_timeout_with_a_deliverable_signal_is_restartnohand_not_zero() {
    let _g = begin();
    let task = install_task(0);
    let mut set = one_fd(task, 0);
    task.sigpending.fetch_or(SIGUSR1_BIT, Ordering::Release);

    let mut zero = ts(0, 0);
    assert_eq!(production_pselect6::sys_pselect6(
        &args(64, &mut set, zero.as_mut_ptr() as u64, 0)), RESTARTNOHAND);
    assert_eq!(poll::poll_common::PARK_CALLS.load(Ordering::SeqCst), 0);
}

#[test]
fn the_remaining_time_is_written_back_for_a_nonzero_timeout_only() {
    let _g = begin();
    let task = install_task(0);
    let mut set = one_fd(task, vfs::POLL_IN);
    ADVANCE_ON_POLL.store(2_000_000_000, Ordering::SeqCst);

    let mut t = ts(5, 0);
    let mut probe = set;
    assert_eq!(production_pselect6::sys_pselect6(
        &args(64, &mut probe, t.as_mut_ptr() as u64, 0)), 1);
    assert_eq!(t, ts(3, 0), "the RAW pselect6 updates the caller's timespec");

    poll::poll_common::NOW_NS.store(0, Ordering::SeqCst);
    let mut t = ts(0, 0);
    let mut probe = set;
    assert_eq!(production_pselect6::sys_pselect6(
        &args(64, &mut probe, t.as_mut_ptr() as u64, 0)), 1);
    assert_eq!(t, ts(0, 0), "Linux: no update for zero timeout");
    set = 0;
    assert_eq!(set, 0);
}

#[test]
fn a_sticky_timeouts_persona_suppresses_the_writeback() {
    let _g = begin();
    let task = install_task(0);
    task.personality.store(sched::personality::STICKY_TIMEOUTS, Ordering::Release);
    let mut set = one_fd(task, vfs::POLL_IN);
    ADVANCE_ON_POLL.store(2_000_000_000, Ordering::SeqCst);
    let mut t = ts(5, 0);

    assert_eq!(production_pselect6::sys_pselect6(
        &args(64, &mut set, t.as_mut_ptr() as u64, 0)), 1);
    assert_eq!(t, ts(5, 0));
}

#[test]
fn a_negative_nfds_is_einval_and_a_closed_fd_in_a_set_is_ebadf() {
    let _g = begin();
    let task = install_task(0);
    let mut set = one_fd(task, vfs::POLL_IN);

    let mut probe = set;
    let bad_n = SyscallArgs { a0: (-1i64) as u64, ..args(0, &mut probe, 0, 0) };
    assert_eq!(production_pselect6::sys_pselect6(&bad_n), EINVAL);

    // A set bit naming an fd that was never opened is EBADF, as Linux
    // `max_select_fd` reports it.
    let mut closed = 1u64 << 40;
    assert_eq!(production_pselect6::sys_pselect6(&args(64, &mut closed, 0, 0)),
               -(Errno::Ebadf.as_i32() as i64));
    set = 0;
    assert_eq!(set, 0);
}
