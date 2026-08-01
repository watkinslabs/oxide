// Hosted OUTCOME tests for PI futexes and the robust-list exit walk (B1633).
//
// `ipc::live` is `#![cfg(target_os = "oxide-kernel")]`-gated, so the real PI
// source never compiles under a plain `cargo test`. This binary `#[path]`-
// includes the production files directly and shadows `sched`/`hal`/`hal_x86_64`
// with a minimal mock — the same technique `futex_core_hosted.rs` uses — so the
// assertions below run the SAME code the kernel does.
//
// What these prove is the OUTCOME, not that a flag was set: a real OS thread
// parks in `lock_pi`, another thread unlocks or dies, and the test asserts the
// parked thread actually returned owning the mutex with the right bits in the
// user word. `sched::pi_prio` and `sched::live::pi_boost` are the REAL files
// too, so the priority-inheritance assertions exercise production logic.

#![allow(dead_code)]
extern crate alloc;
extern crate self as hal;
extern crate self as hal_x86_64;
extern crate self as sched;

use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicU8, Ordering};
use std::sync::mpsc;
use std::time::Duration;

#[path = "futex_pi/harness.rs"] mod harness;
pub use harness::*;

// ---------------------------------------------------------------------------
// The REAL production files under test.
// ---------------------------------------------------------------------------
mod futex_pi;

#[path = "../src/futex_restart.rs"] pub mod futex_restart;
#[path = "../src/futex_pi_rules.rs"] pub mod futex_pi_rules;
#[path = "../src/robust_decode.rs"] pub mod robust_decode;

use futex_pi::core::FUTEX_PRIVATE_FLAG;
use futex_pi_rules::{FUTEX_OWNER_DIED, FUTEX_TID_MASK, FUTEX_WAITERS};

const FUTEX_WAKE: u32 = 1;

fn eagain() -> i64 { -(syscall::errno::Errno::Eagain.as_i32() as i64) }
fn edeadlk() -> i64 { -(syscall::errno::Errno::Edeadlk.as_i32() as i64) }
fn einval() -> i64 { -(syscall::errno::Errno::Einval.as_i32() as i64) }
fn eperm() -> i64 { -(syscall::errno::Errno::Eperm.as_i32() as i64) }
fn esrch() -> i64 { -(syscall::errno::Errno::Esrch.as_i32() as i64) }

/// Each test uses a distinct `mm_root` so their private futex keys cannot
/// collide across the shared global PI table when tests run in parallel.
fn word_addr(w: &AtomicU32) -> u64 { w as *const AtomicU32 as u64 }

// ---------------------------------------------------------------------------
// LOCK_PI / UNLOCK_PI, uncontended
// ---------------------------------------------------------------------------

#[test]
fn an_uncontended_lock_pi_takes_the_word_and_never_blocks() {
    static W: AtomicU32 = AtomicU32::new(0);
    let ua = word_addr(&W);
    live::set_current(Arc::new(Task::new(1001, 0x1000)));
    assert_eq!(futex_pi::pi::lock_pi(ua, true, 0, false), 0);
    assert_eq!(W.load(Ordering::SeqCst) & FUTEX_TID_MASK, 1001,
               "an uncontended take must write the caller's TID into the word");
    assert_eq!(W.load(Ordering::SeqCst) & FUTEX_WAITERS, 0,
               "no kernel state exists, so nothing should force the slow path");
}

#[test]
fn taking_over_a_dead_owners_futex_preserves_owner_died() {
    static W: AtomicU32 = AtomicU32::new(FUTEX_OWNER_DIED);
    let ua = word_addr(&W);
    live::set_current(Arc::new(Task::new(1002, 0x2000)));
    assert_eq!(futex_pi::pi::lock_pi(ua, true, 0, false), 0);
    let w = W.load(Ordering::SeqCst);
    assert_eq!(w & FUTEX_TID_MASK, 1002);
    assert_ne!(w & FUTEX_OWNER_DIED, 0,
               "the new owner must still see EOWNERDEAD and run its consistency handler");
}

#[test]
fn relocking_a_futex_this_thread_owns_is_edeadlk() {
    static W: AtomicU32 = AtomicU32::new(1003);
    let ua = word_addr(&W);
    live::set_current(Arc::new(Task::new(1003, 0x3000)));
    assert_eq!(futex_pi::pi::lock_pi(ua, true, 0, false), edeadlk());
}

#[test]
fn unlocking_a_futex_this_thread_does_not_own_is_eperm() {
    static W: AtomicU32 = AtomicU32::new(9999);
    let ua = word_addr(&W);
    live::set_current(Arc::new(Task::new(1004, 0x4000)));
    assert_eq!(futex_pi::pi::unlock_pi(ua, true), eperm());
    assert_eq!(W.load(Ordering::SeqCst), 9999, "a refused unlock must not touch the word");
}

#[test]
fn locking_a_futex_owned_by_a_tid_that_does_not_exist_is_esrch() {
    // 0x3ff0 names no registered task, so the owner attach fails outright
    // rather than parking behind an owner that will never unlock.
    static W: AtomicU32 = AtomicU32::new(0x3ff0);
    let ua = word_addr(&W);
    live::set_current(Arc::new(Task::new(1005, 0x5000)));
    assert_eq!(futex_pi::pi::lock_pi(ua, true, 0, false), esrch());
}

#[test]
fn unlocking_an_uncontended_futex_clears_the_word() {
    static W: AtomicU32 = AtomicU32::new(0);
    let ua = word_addr(&W);
    live::set_current(Arc::new(Task::new(1006, 0x6000)));
    assert_eq!(futex_pi::pi::lock_pi(ua, true, 0, false), 0);
    assert_eq!(futex_pi::pi::unlock_pi(ua, true), 0);
    assert_eq!(W.load(Ordering::SeqCst), 0, "an uncontended release leaves the futex plainly free");
}

// ---------------------------------------------------------------------------
// Contended: the ownership handoff, end to end
// ---------------------------------------------------------------------------

/// Spawn a thread that locks `ua` as `tid` and reports the return value.
fn spawn_locker(ua: u64, tid: u32, mm: u64, class: SchedClass)
    -> (Arc<Task>, mpsc::Receiver<i64>, std::thread::JoinHandle<()>)
{
    let t = Arc::new(Task::with_class(tid, mm, class));
    let watch = t.clone();
    let (tx, rx) = mpsc::channel();
    let h = std::thread::spawn(move || {
        live::set_current(t);
        tx.send(futex_pi::pi::lock_pi(ua, true, 0, false)).unwrap();
    });
    (watch, rx, h)
}

#[test]
fn unlock_pi_hands_the_mutex_to_the_waiter_which_returns_owning_it() {
    static W: AtomicU32 = AtomicU32::new(0);
    let ua = word_addr(&W);
    const MM: u64 = 0x7000;
    let owner = Arc::new(Task::new(1101, MM));
    live::set_current(owner.clone());
    assert_eq!(futex_pi::pi::lock_pi(ua, true, 0, false), 0);

    let (waiter, rx, h) = spawn_locker(ua, 1102, MM, SchedClass::Normal { weight: 1024 });
    wait_until_parked(&waiter);
    assert_ne!(W.load(Ordering::SeqCst) & FUTEX_WAITERS, 0,
               "a blocked waiter must publish FUTEX_WAITERS so the owner cannot unlock in userspace");
    assert!(rx.try_recv().is_err(), "the waiter must still be blocked while the owner holds the lock");

    live::set_current(owner);
    assert_eq!(futex_pi::pi::unlock_pi(ua, true), 0);

    let rv = rx.recv_timeout(Duration::from_secs(5))
        .expect("the handed-off waiter must wake — a hang here is a lost PI handoff");
    assert_eq!(rv, 0, "the waiter returns owning the mutex, not with an error");
    let w = W.load(Ordering::SeqCst);
    assert_eq!(w & FUTEX_TID_MASK, 1102, "the word must name the NEW owner before it is woken");
    assert_ne!(w & FUTEX_WAITERS, 0, "PI state still exists, so the word keeps FUTEX_WAITERS");
    assert_eq!(w & FUTEX_OWNER_DIED, 0, "a live owner's handoff must not claim the owner died");
    h.join().unwrap();
}

#[test]
fn trylock_pi_on_a_contended_futex_is_eagain_and_leaves_the_owner_alone() {
    static W: AtomicU32 = AtomicU32::new(0);
    let ua = word_addr(&W);
    const MM: u64 = 0x8000;
    let owner = Arc::new(Task::new(1201, MM));
    live::set_current(owner);
    assert_eq!(futex_pi::pi::lock_pi(ua, true, 0, false), 0);

    live::set_current(Arc::new(Task::new(1202, MM)));
    assert_eq!(futex_pi::pi::lock_pi(ua, true, 0, true), eagain(),
               "a failed trylock is EWOULDBLOCK/EAGAIN, never a silent success");
    assert_eq!(W.load(Ordering::SeqCst) & FUTEX_TID_MASK, 1201,
               "a failed trylock must not steal ownership");
}

// ---------------------------------------------------------------------------
// OWNER DEATH — the outcome that makes robust/PI futexes worth having
// ---------------------------------------------------------------------------

#[test]
fn an_owners_death_hands_the_mutex_to_the_waiter_with_futex_owner_died() {
    static W: AtomicU32 = AtomicU32::new(0);
    let ua = word_addr(&W);
    const MM: u64 = 0x9000;
    let owner = Arc::new(Task::new(1301, MM));
    live::set_current(owner.clone());
    assert_eq!(futex_pi::pi::lock_pi(ua, true, 0, false), 0);

    let (waiter, rx, h) = spawn_locker(ua, 1302, MM, SchedClass::Normal { weight: 1024 });
    wait_until_parked(&waiter);

    // The owner dies WITHOUT unlocking — exactly what the exit path must
    // recover from. This is the production `exit_pi_state_list`.
    futex_pi::pi::exit_pi_state_list(1301);

    let rv = rx.recv_timeout(Duration::from_secs(5))
        .expect("a waiter behind a dead owner must be released — a hang here is the whole defect");
    assert_eq!(rv, 0, "the waiter takes ownership; the death is reported through the WORD, not an errno");
    let w = W.load(Ordering::SeqCst);
    assert_eq!(w & FUTEX_TID_MASK, 1302, "the dead owner's mutex must name the new owner");
    assert_ne!(w & FUTEX_OWNER_DIED, 0,
               "FUTEX_OWNER_DIED is what turns into EOWNERDEAD in pthread_mutex_lock");
    assert_ne!(w & FUTEX_WAITERS, 0);
    h.join().unwrap();
}

#[test]
fn a_dead_owner_with_no_kernel_pi_state_is_left_for_the_robust_list() {
    static W: AtomicU32 = AtomicU32::new(0);
    let ua = word_addr(&W);
    const MM: u64 = 0xa000;
    live::set_current(Arc::new(Task::new(1401, MM)));
    assert_eq!(futex_pi::pi::lock_pi(ua, true, 0, false), 0);

    // No waiter ever contended it, so no kernel PI record exists — exactly as
    // in Linux, where `pi_state` is created by the first waiter and dropped
    // with the last. The exit walk therefore has nothing to hand over and must
    // not invent state; recovering THIS mutex is the robust list's job, which
    // is why glibc registers robust PI mutexes on both mechanisms.
    futex_pi::pi::exit_pi_state_list(1401);
    assert_eq!(W.load(Ordering::SeqCst) & FUTEX_TID_MASK, 1401);
    assert_eq!(W.load(Ordering::SeqCst) & FUTEX_OWNER_DIED, 0,
               "the PI exit walk must not touch a futex it holds no ownership record for");
}

// ---------------------------------------------------------------------------
// Priority inheritance — the boost is applied and then given back
// ---------------------------------------------------------------------------

#[test]
fn a_realtime_waiter_boosts_the_owner_and_the_boost_is_returned_at_unlock() {
    static W: AtomicU32 = AtomicU32::new(0);
    let ua = word_addr(&W);
    const MM: u64 = 0xb000;
    let owner = Arc::new(Task::with_class(1501, MM, SchedClass::Normal { weight: 1024 }));
    live::set_current(owner.clone());
    assert_eq!(futex_pi::pi::lock_pi(ua, true, 0, false), 0);
    assert_eq!(owner.sched_class(), SchedClass::Normal { weight: 1024 });

    let (waiter, rx, h) =
        spawn_locker(ua, 1502, MM, SchedClass::Rt { prio: 70, policy: SchedPolicy::Fifo });
    wait_until_parked(&waiter);

    assert_eq!(owner.sched_class(), SchedClass::Rt { prio: 70, policy: SchedPolicy::Fifo },
               "a fair-class owner blocking an RT waiter MUST inherit its priority, or a \
                mid-priority third task preempts the owner and the RT waiter is stalled \
                indefinitely — unbounded priority inversion");

    live::set_current(owner.clone());
    assert_eq!(futex_pi::pi::unlock_pi(ua, true), 0);
    assert_eq!(rx.recv_timeout(Duration::from_secs(5)).expect("handed off"), 0);
    assert_eq!(owner.sched_class(), SchedClass::Normal { weight: 1024 },
               "the borrowed priority must be returned at unlock, not kept forever");
    h.join().unwrap();
}

#[test]
fn a_departing_waiter_lowers_the_owners_boost_to_the_next_highest() {
    static W: AtomicU32 = AtomicU32::new(0);
    let ua = word_addr(&W);
    const MM: u64 = 0xc000;
    let owner = Arc::new(Task::with_class(1601, MM, SchedClass::Normal { weight: 1024 }));
    live::set_current(owner.clone());
    assert_eq!(futex_pi::pi::lock_pi(ua, true, 0, false), 0);

    let (mid, rx_mid, h_mid) =
        spawn_locker(ua, 1602, MM, SchedClass::Rt { prio: 50, policy: SchedPolicy::Fifo });
    wait_until_parked(&mid);
    let (hi, rx_hi, h_hi) =
        spawn_locker(ua, 1603, MM, SchedClass::Rt { prio: 80, policy: SchedPolicy::Fifo });
    wait_until_parked(&hi);
    assert_eq!(owner.sched_class(), SchedClass::Rt { prio: 80, policy: SchedPolicy::Fifo },
               "the owner inherits from the HIGHEST waiter, not the first one");

    // The top waiter abandons the wait (a signal). Its priority goes with it.
    hi.set_signal_pending(true);
    // SAFETY: test-only mock wake, standing in for signal delivery's ttwu.
    unsafe { live::try_to_wake_up(hi.clone()); }
    assert!(rx_hi.recv_timeout(Duration::from_secs(5)).expect("interrupted waiter returns") < 0,
            "an interrupted PI lock attempt reports a restart, never a fake success");
    assert_eq!(owner.sched_class(), SchedClass::Rt { prio: 50, policy: SchedPolicy::Fifo },
               "a departing waiter must LOWER the boost; keeping the highest-ever priority \
                would leave the owner permanently elevated for a waiter that is long gone");

    live::set_current(owner.clone());
    assert_eq!(futex_pi::pi::unlock_pi(ua, true), 0);
    assert_eq!(rx_mid.recv_timeout(Duration::from_secs(5)).expect("remaining waiter woken"), 0);
    assert_eq!(owner.sched_class(), SchedClass::Normal { weight: 1024 },
               "the last waiter gone, the owner is back to its own class");
    h_hi.join().unwrap();
    h_mid.join().unwrap();
}

// ---------------------------------------------------------------------------
// Robust-list exit walk — the real walk, over a real list, with a real waiter
// ---------------------------------------------------------------------------

/// `struct robust_list_head { void *list; long futex_offset; void *list_op_pending; }`
/// followed by one `struct robust_list { void *next; }` node, laid out in host
/// memory exactly as glibc lays it out in a thread's TLS.
#[repr(C)]
struct RobustFixture {
    head_next: u64,
    futex_offset: i64,
    list_op_pending: u64,
    node_next: u64,
    lock_word: AtomicU32,
    _pad: u32,
}

#[test]
fn the_robust_walk_sets_owner_died_and_wakes_a_waiter_on_the_dead_owners_mutex() {
    const MM: u64 = 0xd000;
    const OWNER: u32 = 1701;
    let mut fx = Box::new(RobustFixture {
        head_next: 0, futex_offset: 0, list_op_pending: 0,
        node_next: 0, lock_word: AtomicU32::new(FUTEX_WAITERS | OWNER), _pad: 0,
    });
    let base = &mut *fx as *mut RobustFixture as u64;
    let node = base + core::mem::offset_of!(RobustFixture, node_next) as u64;
    let lock = base + core::mem::offset_of!(RobustFixture, lock_word) as u64;
    // A single-entry circular list, and a futex_offset that points from the
    // node to the lock word — the indirection glibc uses so the kernel need not
    // know the mutex layout.
    // SAFETY: `fx` is a live, uniquely-owned Box; these writes target its own
    // fields through the same allocation.
    unsafe {
        core::ptr::write_volatile(base as *mut u64, node);
        core::ptr::write_volatile((base + 8) as *mut i64, (lock as i64) - (node as i64));
        core::ptr::write_volatile(node as *mut u64, base);
    }

    // A real waiter parked on the dead owner's mutex word, through the real
    // non-PI wait path (glibc's robust mutexes are not PI unless asked).
    let waiter = Arc::new(Task::new(1702, MM));
    let watch = waiter.clone();
    let (tx, rx) = mpsc::channel();
    let h = std::thread::spawn(move || {
        let val = FUTEX_WAITERS | OWNER;
        live::set_current(waiter);
        tx.send(futex_pi::wait::dispatch(lock, FUTEX_PRIVATE_FLAG, val)).unwrap();
    });
    wait_until_parked(&watch);

    // The owner dies. This is the production walk.
    live::set_current(Arc::new(Task::new(OWNER, MM)));
    futex_pi::robust::exit_robust_list(base, OWNER);

    let rv = rx.recv_timeout(Duration::from_secs(5))
        .expect("a waiter on a dead owner's robust mutex must be woken — otherwise it blocks forever");
    assert_eq!(rv, 0);
    let w = fx.lock_word.load(Ordering::SeqCst);
    assert_ne!(w & FUTEX_OWNER_DIED, 0,
               "the walk must mark the mutex owner-died so the woken waiter reports EOWNERDEAD");
    assert_eq!(w & FUTEX_TID_MASK, 0, "the dead owner's TID must be cleared from the word");
    h.join().unwrap();
}

#[test]
fn the_robust_walk_leaves_a_mutex_owned_by_someone_else_untouched() {
    const OWNER: u32 = 1801;
    const OTHER: u32 = 1802;
    let mut fx = Box::new(RobustFixture {
        head_next: 0, futex_offset: 0, list_op_pending: 0,
        node_next: 0, lock_word: AtomicU32::new(OTHER), _pad: 0,
    });
    let base = &mut *fx as *mut RobustFixture as u64;
    let node = base + core::mem::offset_of!(RobustFixture, node_next) as u64;
    let lock = base + core::mem::offset_of!(RobustFixture, lock_word) as u64;
    // SAFETY: same uniquely-owned Box as above; field writes within it.
    unsafe {
        core::ptr::write_volatile(base as *mut u64, node);
        core::ptr::write_volatile((base + 8) as *mut i64, (lock as i64) - (node as i64));
        core::ptr::write_volatile(node as *mut u64, base);
    }
    live::set_current(Arc::new(Task::new(OWNER, 0xe000)));
    futex_pi::robust::exit_robust_list(base, OWNER);
    assert_eq!(fx.lock_word.load(Ordering::SeqCst), OTHER,
               "a mutex the dying thread does not own must be left exactly as it was");
}

// ---------------------------------------------------------------------------
// requeue-PI pairing
// ---------------------------------------------------------------------------

#[test]
fn wait_requeue_pi_rejects_the_same_address_for_both_futexes() {
    static W: AtomicU32 = AtomicU32::new(0);
    let ua = word_addr(&W);
    live::set_current(Arc::new(Task::new(1901, 0xf000)));
    assert_eq!(futex_pi::pi::wait_requeue_pi(ua, 0, u32::MAX, ua, true, 0), einval());
}

#[test]
fn cmp_requeue_pi_refuses_to_wake_more_than_one_waiter() {
    static A: AtomicU32 = AtomicU32::new(0);
    static B: AtomicU32 = AtomicU32::new(0);
    live::set_current(Arc::new(Task::new(1902, 0xf100)));
    assert_eq!(futex_pi::pi::cmp_requeue_pi(word_addr(&A), word_addr(&B), 2, 1, 0, true), einval(),
               "only the one waiter the requeue can acquire the PI mutex for may be woken");
    assert_eq!(futex_pi::pi::cmp_requeue_pi(word_addr(&A), word_addr(&B), 1, -1, 0, true), einval());
}

#[test]
fn a_plain_wake_cannot_release_a_requeue_pi_waiter() {
    static SRC: AtomicU32 = AtomicU32::new(0);
    static DST: AtomicU32 = AtomicU32::new(0);
    let (src, dst) = (word_addr(&SRC), word_addr(&DST));
    const MM: u64 = 0xf200;
    let w = Arc::new(Task::new(1903, MM));
    let watch = w.clone();
    let (tx, rx) = mpsc::channel();
    let h = std::thread::spawn(move || {
        live::set_current(w);
        tx.send(futex_pi::pi::wait_requeue_pi(src, 0, u32::MAX, dst, true, 0)).unwrap();
    });
    wait_until_parked(&watch);

    live::set_current(Arc::new(Task::new(1904, MM)));
    assert_eq!(futex_pi::wait::dispatch(src, FUTEX_WAKE | FUTEX_PRIVATE_FLAG, 1), einval(),
               "releasing a requeue-pi waiter through a plain wake would return it to userspace \
                believing it owns a mutex nobody handed it");
    assert!(rx.try_recv().is_err(), "the waiter must still be parked");

    // Release it the only legal way, so the thread can join.
    assert_eq!(futex_pi::pi::cmp_requeue_pi(src, dst, 1, 0, 0, true), 1);
    assert_eq!(rx.recv_timeout(Duration::from_secs(5)).expect("requeue-pi wake"), 0);
    assert_eq!(DST.load(Ordering::SeqCst) & FUTEX_TID_MASK, 1903,
               "the requeue acquires the PI mutex on the woken waiter's behalf");
    h.join().unwrap();
}
