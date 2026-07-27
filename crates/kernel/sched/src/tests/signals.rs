// Hosted coverage for the signal state the `rt_*` syscalls stand on:
// per-signal queue depth policy, the thread-private vs process-directed
// pending union + claim, and the `sigsuspend` saved-mask handshake.

extern crate alloc;

use alloc::sync::Arc;
use core::sync::atomic::Ordering;

use crate::live::sigpend;
use crate::signum::{self, Signum};
use crate::task::{SchedClass, SigInfo, Task, RT_QUEUE_CAP};

const SIGUSR1: u32 = Signum::Sigusr1 as u32;
const SIGCHLD: u32 = Signum::Sigchld as u32;
const SIGRTMIN: u32 = signum::RT_SIGNAL_MIN;

fn task(tid: u32) -> Arc<Task> {
    Arc::new(Task::new(tid, "sig", SchedClass::Normal { weight: 1024 }))
}

/// A leader plus one sibling thread sharing its `ThreadGroup`, as `clone(2)`
/// with CLONE_THREAD builds them.
fn thread_group() -> (Arc<Task>, Arc<Task>) {
    let leader = task(1);
    leader.pid.attach(&leader);
    let mut worker = Task::new(2, "sig-worker", SchedClass::Normal { weight: 1024 });
    worker.join_thread_group(Arc::clone(&leader.thread_group));
    let worker = Arc::new(worker);
    worker.pid.attach(&worker);
    (leader, worker)
}

fn info(signo: u32, code: i32, value: u64) -> SigInfo {
    SigInfo { signo, code, pid: 7, uid: 0, value }
}

// --- queue depth policy (Linux `legacy_queue` vs POSIX RT) -------------------

#[test]
fn standard_signals_keep_one_queued_record_like_legacy_queue() {
    let t = task(10);
    t.sigq_reserve(SIGUSR1);
    assert!(t.sigq_push(info(SIGUSR1, signum::SI_QUEUE, 0xaa)));
    assert!(!t.sigq_push(info(SIGUSR1, signum::SI_QUEUE, 0xbb)),
            "a second standard-signal record is dropped, not queued");
    let (rec, empty) = t.sigq_pop(SIGUSR1);
    assert_eq!(rec.map(|r| r.value), Some(0xaa));
    assert!(empty);
}

#[test]
fn realtime_signals_queue_multiple_records_in_arrival_order() {
    let t = task(11);
    t.sigq_reserve(SIGRTMIN);
    for n in 0..3u64 { assert!(t.sigq_push(info(SIGRTMIN, signum::SI_QUEUE, n))); }
    for n in 0..3u64 {
        let (rec, empty) = t.sigq_pop(SIGRTMIN);
        assert_eq!(rec.map(|r| r.value), Some(n));
        assert_eq!(empty, n == 2);
    }
}

#[test]
fn realtime_queue_is_capped_and_drops_the_overflow() {
    let t = task(12);
    t.sigq_reserve(SIGRTMIN);
    for n in 0..RT_QUEUE_CAP as u64 { assert!(t.sigq_push(info(SIGRTMIN, signum::SI_QUEUE, n))); }
    assert!(!t.sigq_push(info(SIGRTMIN, signum::SI_QUEUE, 999)));
}

#[test]
fn sigchld_has_no_slot_so_child_sigq_stays_the_only_owner() {
    assert_eq!(signum::sigq_index(SIGCHLD), None);
    let t = task(13);
    assert!(!t.sigq_push(info(SIGCHLD, 0, 1)), "SIGCHLD must not reach the shared array");
    t.child_sigq_push(info(SIGCHLD, 1, 0x1234));
    let (rec, empty) = t.dequeue_siginfo(SIGCHLD);
    assert_eq!(rec.map(|r| r.value), Some(0x1234));
    assert!(empty);
}

#[test]
fn sigq_index_covers_every_signal_but_sigchld() {
    assert_eq!(signum::sigq_index(0), None);
    assert_eq!(signum::sigq_index(65), None);
    for sig in 1..=64u32 {
        let want = if sig == SIGCHLD { None } else { Some((sig - 1) as usize) };
        assert_eq!(signum::sigq_index(sig), want, "sig={sig}");
    }
}

#[test]
fn dequeue_siginfo_clears_a_standard_signal_but_holds_a_draining_rt_queue() {
    let t = task(14);
    t.sigq_reserve(SIGUSR1);
    t.sigq_push(info(SIGUSR1, signum::SI_QUEUE, 1));
    assert_eq!(t.dequeue_siginfo(SIGUSR1).1, true, "standard signals clear on take");
    t.sigq_reserve(SIGRTMIN);
    t.sigq_push(info(SIGRTMIN, signum::SI_QUEUE, 1));
    t.sigq_push(info(SIGRTMIN, signum::SI_QUEUE, 2));
    assert_eq!(t.dequeue_siginfo(SIGRTMIN).1, false, "RT bit stays set while records remain");
    assert_eq!(t.dequeue_siginfo(SIGRTMIN).1, true);
}

#[test]
fn flush_pending_signal_drops_the_queued_record_too() {
    let t = task(15);
    t.sigq_reserve(SIGUSR1);
    t.sigq_push(info(SIGUSR1, signum::SI_QUEUE, 1));
    t.sigpending.fetch_or(Signum::Sigusr1.bit(), Ordering::Release);
    t.flush_pending_signal(SIGUSR1 as usize);
    assert_eq!(t.sigpending.load(Ordering::Acquire) & Signum::Sigusr1.bit(), 0);
    assert_eq!(t.sigq_pop(SIGUSR1).0, None);
}

// --- thread-private vs process-directed pending -----------------------------

#[test]
fn a_group_leader_has_no_separate_shared_pending_set() {
    let (leader, _worker) = thread_group();
    leader.sigpending.fetch_or(Signum::Sigusr1.bit(), Ordering::Release);
    assert_eq!(sigpend::group_signal_target(&leader).map(|t| t.tid), None);
    assert_eq!(sigpend::shared_pending(&leader), 0, "no double-count for the leader");
    assert_eq!(sigpend::all_pending(&leader), Signum::Sigusr1.bit());
}

#[test]
fn a_worker_thread_sees_process_directed_pending_signals() {
    let (leader, worker) = thread_group();
    // `kill(getpid(), SIGUSR1)` resolves the tgid to the leader and posts there.
    leader.sigpending.fetch_or(Signum::Sigusr1.bit(), Ordering::Release);
    assert_eq!(worker.sigpending.load(Ordering::Acquire), 0, "not thread-private");
    assert_eq!(sigpend::shared_pending(&worker), Signum::Sigusr1.bit());
    assert_eq!(sigpend::all_pending(&worker), Signum::Sigusr1.bit(),
               "sigwaitinfo in a worker thread must see it, or it hangs forever");
}

#[test]
fn all_pending_unions_both_sets() {
    let (leader, worker) = thread_group();
    leader.sigpending.fetch_or(Signum::Sigusr1.bit(), Ordering::Release);
    worker.sigpending.fetch_or(Signum::Sigusr2.bit(), Ordering::Release);
    assert_eq!(sigpend::all_pending(&worker), Signum::Sigusr1.bit() | Signum::Sigusr2.bit());
}

#[test]
fn dequeue_signal_prefers_the_thread_private_record() {
    let (leader, worker) = thread_group();
    worker.sigq_reserve(SIGRTMIN);
    worker.sigq_push(info(SIGRTMIN, signum::SI_QUEUE, 0x11));
    worker.sigpending.fetch_or(1 << (SIGRTMIN - 1), Ordering::Release);
    leader.sigq_reserve(SIGRTMIN);
    leader.sigq_push(info(SIGRTMIN, signum::SI_QUEUE, 0x22));
    leader.sigpending.fetch_or(1 << (SIGRTMIN - 1), Ordering::Release);
    let got = sigpend::dequeue_signal(&worker, SIGRTMIN).flatten();
    assert_eq!(got.map(|r| r.value), Some(0x11), "private queue first, like __dequeue_signal");
}

#[test]
fn dequeue_signal_falls_back_to_the_process_directed_set_and_consumes_it() {
    let (leader, worker) = thread_group();
    leader.sigpending.fetch_or(Signum::Sigusr1.bit(), Ordering::Release);
    assert_eq!(sigpend::dequeue_signal(&worker, SIGUSR1), Some(None),
               "bitmap-only signal claimed with a synthesised siginfo");
    assert_eq!(leader.sigpending.load(Ordering::Acquire) & Signum::Sigusr1.bit(), 0,
               "consumed, not merely observed");
}

#[test]
fn a_bitmap_only_signal_is_claimed_by_exactly_one_consumer() {
    let (leader, worker) = thread_group();
    leader.sigpending.fetch_or(Signum::Sigusr1.bit(), Ordering::Release);
    assert!(sigpend::dequeue_signal(&worker, SIGUSR1).is_some());
    assert!(sigpend::dequeue_signal(&leader, SIGUSR1).is_none(),
            "the loser of the claim gets nothing, never a duplicate delivery");
}

#[test]
fn dequeue_signal_reports_nothing_when_the_signal_is_not_pending() {
    let (_leader, worker) = thread_group();
    assert_eq!(sigpend::dequeue_signal(&worker, SIGUSR1), None);
    assert_eq!(sigpend::dequeue_signal(&worker, 0), None);
    assert_eq!(sigpend::dequeue_signal(&worker, 65), None);
}

// --- rt_sigsuspend saved-mask handshake -------------------------------------

#[test]
fn arm_saved_sigmask_installs_the_new_mask_and_remembers_the_old() {
    let t = task(20);
    t.set_current_blocked(Signum::Sigusr1.bit());
    t.arm_saved_sigmask(Signum::Sigusr2.bit());
    assert_eq!(t.sigmask.load(Ordering::Acquire), Signum::Sigusr2.bit(),
               "the suspend mask is live while parked");
    assert_eq!(t.saved_sigmask.load(Ordering::Acquire), Signum::Sigusr1.bit());
    assert!(t.restore_sigmask.load(Ordering::Acquire));
}

#[test]
fn sigmask_to_save_hands_the_frame_the_pre_suspend_mask() {
    let t = task(21);
    t.set_current_blocked(Signum::Sigusr1.bit());
    t.arm_saved_sigmask(Signum::Sigusr2.bit());
    assert_eq!(t.sigmask_to_save(), Signum::Sigusr1.bit(),
               "rt_sigreturn must land on the caller's original mask");
    assert_eq!(t.sigmask.load(Ordering::Acquire), Signum::Sigusr2.bit(),
               "the handler still runs under the suspend mask");
}

#[test]
fn sigmask_to_save_is_one_shot_and_falls_back_to_the_live_mask() {
    let t = task(22);
    t.set_current_blocked(Signum::Sigusr1.bit());
    t.arm_saved_sigmask(Signum::Sigusr2.bit());
    assert_eq!(t.sigmask_to_save(), Signum::Sigusr1.bit());
    assert_eq!(t.sigmask_to_save(), Signum::Sigusr2.bit(), "flag consumed exactly once");
}

#[test]
fn restore_saved_sigmask_puts_the_old_mask_back_when_no_handler_runs() {
    let t = task(23);
    t.set_current_blocked(Signum::Sigusr1.bit());
    t.arm_saved_sigmask(Signum::Sigusr2.bit());
    t.restore_saved_sigmask();
    assert_eq!(t.sigmask.load(Ordering::Acquire), Signum::Sigusr1.bit());
    assert!(!t.restore_sigmask.load(Ordering::Acquire));
}

#[test]
fn restore_saved_sigmask_is_a_noop_once_a_frame_consumed_the_flag() {
    let t = task(24);
    t.set_current_blocked(Signum::Sigusr1.bit());
    t.arm_saved_sigmask(Signum::Sigusr2.bit());
    assert_eq!(t.sigmask_to_save(), Signum::Sigusr1.bit()); // handler delivery
    t.restore_saved_sigmask();
    assert_eq!(t.sigmask.load(Ordering::Acquire), Signum::Sigusr2.bit(),
               "the handler keeps the suspend mask; only rt_sigreturn restores");
}

#[test]
fn restore_saved_sigmask_does_nothing_when_never_armed() {
    let t = task(25);
    t.set_current_blocked(Signum::Sigusr1.bit());
    t.restore_saved_sigmask();
    assert_eq!(t.sigmask.load(Ordering::Acquire), Signum::Sigusr1.bit());
}

#[test]
fn an_armed_suspend_mask_can_never_block_sigkill_or_sigstop() {
    let t = task(26);
    t.arm_saved_sigmask(u64::MAX);
    let live = t.sigmask.load(Ordering::Acquire);
    assert_eq!(live & (Signum::Sigkill.bit() | Signum::Sigstop.bit()), 0);
}

// --- sigaltstack task state -------------------------------------------------

#[test]
fn altstack_round_trips_through_the_task_atomics() {
    use crate::sigaltstack::{AltStack, SS_AUTODISARM};
    let t = task(30);
    let a = AltStack { sp: 0x7000, size: 64 * 1024, flags: SS_AUTODISARM };
    t.set_altstack(a);
    assert_eq!(t.altstack(), a);
    t.set_altstack(crate::sigaltstack::reset());
    assert_eq!(t.altstack(), crate::sigaltstack::reset());
}

// --- rt_sigqueueinfo forgery gate -------------------------------------------

#[test]
fn forged_si_codes_are_rejected_at_any_target_but_the_callers_own_thread() {
    use signum::sigqueueinfo_forgery_rejected as gate;
    for code in [signum::SI_USER, 1, signum::SI_KERNEL, signum::SI_TKILL] {
        assert!(gate(code, 100, 200), "si_code={code} at another pid must EPERM");
        assert!(!gate(code, 100, 100), "si_code={code} at self is allowed");
        assert!(gate(code, 100, 0), "pid 0 is never 'self'");
        assert!(gate(code, 100, -1), "a negative pid is never 'self'");
    }
}

#[test]
fn app_supplied_negative_si_codes_are_always_allowed() {
    use signum::sigqueueinfo_forgery_rejected as gate;
    for code in [signum::SI_QUEUE, -2, -3, -4, -5, -7, i32::MIN] {
        assert!(!gate(code, 100, 200), "si_code={code} is the app's to set");
    }
}
