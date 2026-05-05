// Hosted unit tests covering invariants 6 (RT preempts Normal) and 7
// (idle uniqueness) plus runqueue insert/pick/remove correctness.

extern crate alloc;
use super::*;
use crate::cfs::CfsRunqueue;
use crate::rt::{RtRunqueue, RT_PRIO_COUNT};
use crate::runqueue::RunqueueInner;
use crate::task::{SchedClass, SchedPolicy, Task, TaskState};

use alloc::sync::Arc;
use core::sync::atomic::Ordering;

fn rt(tid: u32, prio: u8) -> Arc<Task> {
    Arc::new(Task::new(tid, "rt", SchedClass::Rt { prio, policy: SchedPolicy::Fifo }))
}

fn normal(tid: u32, vruntime: u64, weight: u32) -> Arc<Task> {
    let t = Arc::new(Task::new(tid, "normal", SchedClass::Normal { weight }));
    t.vruntime.store(vruntime, Ordering::Release);
    t
}

fn idle(tid: u32) -> Arc<Task> {
    Arc::new(Task::new(tid, "idle", SchedClass::Idle))
}

// ---------------------------------------------------------------------------
// RT runqueue
// ---------------------------------------------------------------------------

#[test]
fn rt_empty() {
    let q = RtRunqueue::new();
    assert!(!q.has_runnable());
    assert_eq!(q.nr_running(), 0);
}

#[test]
fn rt_pick_highest_priority_first() {
    let mut q = RtRunqueue::new();
    q.enqueue(rt(1, 10));
    q.enqueue(rt(2, 99));
    q.enqueue(rt(3, 50));
    let t = q.pick_highest().unwrap();
    assert_eq!(t.tid, 2);
    let t = q.pick_highest().unwrap();
    assert_eq!(t.tid, 3);
    let t = q.pick_highest().unwrap();
    assert_eq!(t.tid, 1);
    assert!(q.pick_highest().is_none());
}

#[test]
fn rt_fifo_within_priority() {
    let mut q = RtRunqueue::new();
    q.enqueue(rt(10, 50));
    q.enqueue(rt(11, 50));
    q.enqueue(rt(12, 50));
    assert_eq!(q.pick_highest().unwrap().tid, 10);
    assert_eq!(q.pick_highest().unwrap().tid, 11);
    assert_eq!(q.pick_highest().unwrap().tid, 12);
}

#[test]
fn rt_remove_by_tid() {
    let mut q = RtRunqueue::new();
    q.enqueue(rt(1, 30));
    q.enqueue(rt(2, 30));
    q.enqueue(rt(3, 60));
    let t = q.remove(2).unwrap();
    assert_eq!(t.tid, 2);
    assert_eq!(q.nr_running(), 2);
    assert_eq!(q.pick_highest().unwrap().tid, 3);
    assert_eq!(q.pick_highest().unwrap().tid, 1);
}

#[test]
fn rt_remove_clears_bitmap_when_bucket_empty() {
    let mut q = RtRunqueue::new();
    q.enqueue(rt(1, 50));
    q.remove(1).unwrap();
    // Bucket 50 is now empty; nothing should pick.
    assert!(!q.has_runnable());
}

#[test]
fn rt_peek_does_not_remove() {
    let mut q = RtRunqueue::new();
    q.enqueue(rt(1, 99));
    let peek_tid = q.peek_highest().unwrap().tid;
    assert_eq!(peek_tid, 1);
    assert_eq!(q.nr_running(), 1);
}

#[test]
fn rt_priority_constant_matches_spec() {
    // `13§3`: RT prio 1..=99 ⇒ slot count 100 (with 0 unused).
    assert_eq!(RT_PRIO_COUNT, 100);
}

// ---------------------------------------------------------------------------
// CFS runqueue
// ---------------------------------------------------------------------------

#[test]
fn cfs_pick_leftmost_lowest_vruntime() {
    let mut q = CfsRunqueue::new();
    q.enqueue(normal(1, 100, 1024));
    q.enqueue(normal(2,  50, 1024));
    q.enqueue(normal(3, 200, 1024));
    assert_eq!(q.pick_leftmost().unwrap().tid, 2);
    assert_eq!(q.pick_leftmost().unwrap().tid, 1);
    assert_eq!(q.pick_leftmost().unwrap().tid, 3);
    assert!(q.pick_leftmost().is_none());
}

#[test]
fn cfs_min_vruntime_tracks_leftmost() {
    let mut q = CfsRunqueue::new();
    q.enqueue(normal(1, 100, 1024));
    q.enqueue(normal(2,  50, 1024));
    assert_eq!(q.min_vruntime(), 50);
    q.pick_leftmost().unwrap();
    assert_eq!(q.min_vruntime(), 100);
    q.pick_leftmost().unwrap();
    assert_eq!(q.min_vruntime(), 0); // empty
}

#[test]
fn cfs_ties_disambiguated_by_tid() {
    let mut q = CfsRunqueue::new();
    q.enqueue(normal(7, 100, 1024));
    q.enqueue(normal(3, 100, 1024));
    q.enqueue(normal(5, 100, 1024));
    // Same vruntime ⇒ key tie broken by tid; lower tid leftmost.
    assert_eq!(q.pick_leftmost().unwrap().tid, 3);
    assert_eq!(q.pick_leftmost().unwrap().tid, 5);
    assert_eq!(q.pick_leftmost().unwrap().tid, 7);
}

#[test]
fn cfs_remove_by_tid() {
    let mut q = CfsRunqueue::new();
    q.enqueue(normal(1, 10, 1024));
    q.enqueue(normal(2, 20, 1024));
    let t = q.remove(2).unwrap();
    assert_eq!(t.tid, 2);
    assert_eq!(q.nr_running(), 1);
    assert_eq!(q.pick_leftmost().unwrap().tid, 1);
}

// ---------------------------------------------------------------------------
// Runqueue
// ---------------------------------------------------------------------------

#[test]
fn rq_idle_picked_when_empty() {
    let id = idle(0);
    let mut rq = RunqueueInner::new(0, Arc::clone(&id));
    let pick = rq.pick_next_task();
    assert_eq!(pick.tid, id.tid);
    // Re-pick still yields idle (idle uniqueness, `13§2` inv 7).
    let pick = rq.pick_next_task();
    assert_eq!(pick.tid, id.tid);
}

#[test]
fn rq_rt_preempts_normal_invariant_6() {
    let mut rq = RunqueueInner::new(0, idle(0));
    rq.enqueue(normal(10, 0, 1024));
    rq.enqueue(rt(20, 50));
    // Even though Normal was enqueued first, RT must pick first.
    let pick = rq.pick_next_task();
    assert_eq!(pick.tid, 20);
    // Then Normal.
    let pick = rq.pick_next_task();
    assert_eq!(pick.tid, 10);
}

#[test]
fn rq_idle_only_when_no_runnable_invariant_7() {
    let id = idle(0);
    let mut rq = RunqueueInner::new(0, Arc::clone(&id));
    rq.enqueue(normal(1, 5, 1024));
    let pick = rq.pick_next_task();
    assert_eq!(pick.tid, 1);
    // Now the only runnable is gone ⇒ idle picked.
    let pick = rq.pick_next_task();
    assert_eq!(pick.tid, id.tid);
}

#[test]
fn rq_enqueue_idle_panics() {
    let mut rq = RunqueueInner::new(0, idle(0));
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        rq.enqueue(idle(99));
    }));
    assert!(result.is_err(), "enqueueing an Idle-class task must panic");
}

#[test]
fn rq_remove_finds_in_either_class() {
    let mut rq = RunqueueInner::new(0, idle(0));
    rq.enqueue(rt(1, 20));
    rq.enqueue(normal(2, 100, 1024));
    let a = rq.remove(2).unwrap();
    assert_eq!(a.tid, 2);
    let b = rq.remove(1).unwrap();
    assert_eq!(b.tid, 1);
    assert!(rq.remove(99).is_none());
}

#[test]
fn rq_peek_does_not_drain() {
    let mut rq = RunqueueInner::new(0, idle(0));
    rq.enqueue(rt(7, 80));
    let p = rq.peek_next_task();
    assert_eq!(p.tid, 7);
    assert_eq!(rq.nr_running(), 1);
    let pick = rq.pick_next_task();
    assert_eq!(pick.tid, 7);
    assert_eq!(rq.nr_running(), 0);
}

// ---------------------------------------------------------------------------
// Task state CAS
// ---------------------------------------------------------------------------

#[test]
fn task_cas_state_transitions() {
    let t = Task::new(1, "t", SchedClass::Normal { weight: 1024 });
    assert_eq!(t.state(), TaskState::Runnable);
    t.cas_state(TaskState::Runnable, TaskState::Sleeping).unwrap();
    assert_eq!(t.state(), TaskState::Sleeping);
    // Wrong-from CAS fails without changing state.
    let err = t.cas_state(TaskState::Runnable, TaskState::Zombie).unwrap_err();
    assert_eq!(err, TaskState::Sleeping);
    assert_eq!(t.state(), TaskState::Sleeping);
    t.cas_state(TaskState::Sleeping, TaskState::Runnable).unwrap();
    assert_eq!(t.state(), TaskState::Runnable);
}

#[test]
fn task_lift_vruntime_respects_floor() {
    let t = Task::new(1, "t", SchedClass::Normal { weight: 1024 });
    t.vruntime.store(50, Ordering::Release);
    t.lift_vruntime(100);
    assert_eq!(t.vruntime.load(Ordering::Acquire), 100);
    // Lifting below current is a no-op.
    t.lift_vruntime(20);
    assert_eq!(t.vruntime.load(Ordering::Acquire), 100);
}

#[test]
fn task_kernel_stack_starts_null() {
    let t = Task::new(1, "t", SchedClass::Normal { weight: 1024 });
    assert!(t.kernel_stack.load(Ordering::Acquire).is_null());
}

#[test]
fn task_arch_ctx_buffer_is_zero_initialised() {
    let t = Task::new(1, "t", SchedClass::Normal { weight: 1024 });
    // SAFETY: hosted test; we are the sole accessor of `t.arch_ctx`.
    let buf = unsafe { &*t.arch_ctx.get() };
    assert!(buf.0.iter().all(|&b| b == 0));
    assert_eq!(buf.0.len(), crate::ARCH_CTX_SIZE);
}

#[test]
fn task_arch_ctx_ptr_round_trips() {
    // `arch_ctx_ptr::<C>()` aliases the buffer; writing through
    // it then reading via the buffer view yields the same bytes.
    #[repr(C)]
    struct FakeCtx { rsp: u64, marker: u64 }
    let t = Task::new(1, "t", SchedClass::Normal { weight: 1024 });
    // SAFETY: hosted test; we are the sole accessor of `t.arch_ctx`; FakeCtx is 16 B which fits ARCH_CTX_SIZE.
    unsafe {
        let p = t.arch_ctx_ptr::<FakeCtx>();
        (*p).rsp = 0xdead_b000_dead_b000;
        (*p).marker = 0xfeedface;
    }
    // Read back via the byte buffer.
    // SAFETY: hosted test; sole accessor; reading the same storage.
    let buf = unsafe { &*t.arch_ctx.get() };
    let rsp = u64::from_ne_bytes(buf.0[0..8].try_into().unwrap());
    let marker = u64::from_ne_bytes(buf.0[8..16].try_into().unwrap());
    assert_eq!(rsp,    0xdead_b000_dead_b000);
    assert_eq!(marker, 0xfeedface);
}

#[test]
fn task_kthread_has_no_mm() {
    // `Task::new` is the kthread constructor (per `13§5` field list,
    // kernel threads have no `mm`).
    let t = Task::new(1, "kt", SchedClass::Normal { weight: 1024 });
    // SAFETY: hosted test; single-threaded.
    assert!(unsafe { t.mm_ref() }.is_none(), "kthread Task must not carry an mm");
}

#[test]
fn task_user_carries_mm() {
    // User tasks per `13§5` carry `Arc<AddressSpace>`. The Arc is
    // shared (CLONE_VM siblings get a clone of the same Arc).
    let mm = vmm::AddressSpace::new(0).expect("AddressSpace::new should succeed");
    let t1 = Task::new_user(10, "u1", SchedClass::Normal { weight: 1024 }, alloc::sync::Arc::clone(&mm));
    let t2 = Task::new_user(11, "u2", SchedClass::Normal { weight: 1024 }, alloc::sync::Arc::clone(&mm));

    // SAFETY: hosted test; single-threaded; no concurrent writer.
    let m1 = unsafe { t1.mm_ref() }.expect("u1 mm");
    // SAFETY: same as above.
    let m2 = unsafe { t2.mm_ref() }.expect("u2 mm");
    assert!(alloc::sync::Arc::ptr_eq(m1, m2), "CLONE_VM siblings must share the same AS instance");
    // The original handle plus two task clones = 3 strong refs.
    assert_eq!(alloc::sync::Arc::strong_count(&mm), 3);
}

// ---------------------------------------------------------------------------
// argv_to_cmdline — `/proc/<pid>/cmdline` byte sequence per `19§4`
// ---------------------------------------------------------------------------

#[test]
fn cmdline_empty_argv_is_empty_string() {
    assert_eq!(crate::argv_to_cmdline(&[]).as_bytes(), b"");
}

#[test]
fn cmdline_single_arg_has_trailing_nul() {
    let argv: &[&[u8]] = &[b"/init"];
    assert_eq!(crate::argv_to_cmdline(argv).as_bytes(), b"/init\0");
}

#[test]
fn cmdline_multiple_args_nul_separated() {
    let argv: &[&[u8]] = &[b"sh", b"-c", b"echo hi"];
    assert_eq!(
        crate::argv_to_cmdline(argv).as_bytes(),
        b"sh\0-c\0echo hi\0",
    );
}

#[test]
fn cmdline_drops_non_ascii_bytes() {
    // Lossy UTF-8: bytes >= 0x80 are dropped (not replaced) per the
    // single-byte ASCII contract. NUL separators are still emitted.
    let argv: &[&[u8]] = &[b"a\xC3\xA9b"]; // "a" 0xC3 0xA9 "b"
    assert_eq!(crate::argv_to_cmdline(argv).as_bytes(), b"ab\0");
}

#[test]
fn cmdline_preserves_internal_spaces() {
    let argv: &[&[u8]] = &[b"hello world"];
    assert_eq!(crate::argv_to_cmdline(argv).as_bytes(), b"hello world\0");
}

// ---------------------------------------------------------------------------
// Tid registry — `19§4` per-pid procfs needs Weak-decaying tid → Task lookup
// ---------------------------------------------------------------------------

// Registry is a process-global; serialise the registry tests so parallel
// cargo-test execution doesn't observe each other's clear_for_tests().
fn registry_test_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

#[test]
fn registry_insert_and_lookup() {
    let _g = registry_test_lock();
    crate::registry::clear_for_tests();
    let t = alloc::sync::Arc::new(Task::new(123, "t", SchedClass::Normal { weight: 1024 }));
    crate::registry::insert(&t);
    let got = crate::registry::lookup(123).expect("tid 123 should be live");
    assert!(alloc::sync::Arc::ptr_eq(&t, &got));
}

#[test]
fn registry_lookup_unknown_returns_none() {
    let _g = registry_test_lock();
    crate::registry::clear_for_tests();
    assert!(crate::registry::lookup(9999).is_none());
}

#[test]
fn registry_decays_when_arc_dropped() {
    let _g = registry_test_lock();
    crate::registry::clear_for_tests();
    {
        let t = alloc::sync::Arc::new(Task::new(7, "t", SchedClass::Normal { weight: 1024 }));
        crate::registry::insert(&t);
        assert!(crate::registry::lookup(7).is_some());
    }
    assert!(crate::registry::lookup(7).is_none(),
            "Weak<Task> upgrade must fail after the last Arc is dropped");
}

#[test]
fn registry_live_tids_prunes_decayed() {
    let _g = registry_test_lock();
    crate::registry::clear_for_tests();
    let live = alloc::sync::Arc::new(Task::new(1, "live", SchedClass::Normal { weight: 1024 }));
    crate::registry::insert(&live);
    {
        let dead = alloc::sync::Arc::new(Task::new(2, "dead", SchedClass::Normal { weight: 1024 }));
        crate::registry::insert(&dead);
    } // dead drops here
    let tids = crate::registry::live_tids();
    assert_eq!(tids, alloc::vec![1u32]);
}

#[test]
fn registry_insert_idempotent_overwrites_stale_slot() {
    let _g = registry_test_lock();
    crate::registry::clear_for_tests();
    let a = alloc::sync::Arc::new(Task::new(42, "a", SchedClass::Normal { weight: 1024 }));
    crate::registry::insert(&a);
    let b = alloc::sync::Arc::new(Task::new(42, "b", SchedClass::Normal { weight: 1024 }));
    crate::registry::insert(&b);
    let got = crate::registry::lookup(42).unwrap();
    assert!(alloc::sync::Arc::ptr_eq(&b, &got));
    assert_eq!(crate::registry::live_tids().len(), 1);
}

// ---------------------------------------------------------------------------
// pgid / sid — POSIX setpgid(2) + setsid(2) state per `28§4`
// ---------------------------------------------------------------------------

#[test]
fn task_pgid_and_sid_default_to_tid() {
    use core::sync::atomic::Ordering;
    let t = Task::new(42, "t", SchedClass::Normal { weight: 1024 });
    assert_eq!(t.pgid.load(Ordering::Acquire), 42);
    assert_eq!(t.sid .load(Ordering::Acquire), 42);
}

#[test]
fn task_pgid_can_be_updated() {
    use core::sync::atomic::Ordering;
    let t = Task::new(7, "t", SchedClass::Normal { weight: 1024 });
    t.pgid.store(99, Ordering::Release);
    assert_eq!(t.pgid.load(Ordering::Acquire), 99);
    // sid is independent of pgid.
    assert_eq!(t.sid.load(Ordering::Acquire), 7);
}

#[test]
fn registry_tasks_in_pgrp_filters_by_pgid() {
    use core::sync::atomic::Ordering;
    let _g = registry_test_lock();
    crate::registry::clear_for_tests();
    let a = alloc::sync::Arc::new(Task::new(10, "a", SchedClass::Normal { weight: 1024 }));
    let b = alloc::sync::Arc::new(Task::new(11, "b", SchedClass::Normal { weight: 1024 }));
    let c = alloc::sync::Arc::new(Task::new(12, "c", SchedClass::Normal { weight: 1024 }));
    a.pgid.store(99, Ordering::Release);
    b.pgid.store(99, Ordering::Release);
    c.pgid.store(50, Ordering::Release);
    crate::registry::insert(&a);
    crate::registry::insert(&b);
    crate::registry::insert(&c);
    let in_99 = crate::registry::tasks_in_pgrp(99);
    assert_eq!(in_99.len(), 2);
    let tids: alloc::vec::Vec<u32> = in_99.iter().map(|t| t.tid).collect();
    assert!(tids.contains(&10) && tids.contains(&11) && !tids.contains(&12));
    let in_50 = crate::registry::tasks_in_pgrp(50);
    assert_eq!(in_50.len(), 1);
    assert_eq!(in_50[0].tid, 12);
    let in_none = crate::registry::tasks_in_pgrp(7777);
    assert!(in_none.is_empty());
}

#[test]
fn try_wake_stopped_flips_only_stopped_tasks() {
    let t = Task::new(1, "t", SchedClass::Normal { weight: 1024 });
    assert_eq!(t.state(), TaskState::Runnable);
    // No-op when already Runnable.
    assert!(!crate::registry::try_wake_stopped(&t));
    assert_eq!(t.state(), TaskState::Runnable);
    // Flip Stopped → Runnable.
    t.set_state(TaskState::Stopped);
    assert!(crate::registry::try_wake_stopped(&t));
    assert_eq!(t.state(), TaskState::Runnable);
    // Repeat: now Runnable, returns false again.
    assert!(!crate::registry::try_wake_stopped(&t));
}

#[test]
fn try_wake_stopped_ignores_zombie() {
    let t = Task::new(2, "t", SchedClass::Normal { weight: 1024 });
    t.set_state(TaskState::Zombie);
    // SIGCONT must not resurrect a Zombie.
    assert!(!crate::registry::try_wake_stopped(&t));
    assert_eq!(t.state(), TaskState::Zombie);
}

// ---------------------------------------------------------------------------
// rlimit clamping + format helpers
// ---------------------------------------------------------------------------

#[test]
fn rlimit_clamp_pair_accepts_cur_le_max() {
    use crate::rlimit::clamp_pair;
    assert_eq!(clamp_pair(0,    100), Some((0, 100)));
    assert_eq!(clamp_pair(50,   100), Some((50, 100)));
    assert_eq!(clamp_pair(100,  100), Some((100, 100)));
    assert_eq!(clamp_pair(0,    0),   Some((0, 0)));
}

#[test]
fn rlimit_clamp_pair_rejects_cur_above_max() {
    use crate::rlimit::clamp_pair;
    assert_eq!(clamp_pair(101, 100), None);
    assert_eq!(clamp_pair(1,   0),   None);
}

#[test]
fn rlimit_validate_setrlimit_round_trip() {
    use crate::rlimit::validate_setrlimit;
    let old = (10, 100);
    assert_eq!(validate_setrlimit(old, (5,   50)),  Ok((5,   50)));
    assert_eq!(validate_setrlimit(old, (50,  200)), Ok((50,  200)));
    assert_eq!(validate_setrlimit(old, (51,  50)),  Err(()));
}

#[test]
fn rlimit_format_unlimited() {
    use crate::rlimit::{format_rlim, INFINITY};
    let mut b = [0u8; 16];
    let n = format_rlim(&mut b, INFINITY).unwrap();
    assert_eq!(&b[..n], b"unlimited");
}

#[test]
fn rlimit_format_decimal() {
    use crate::rlimit::format_rlim;
    let mut b = [0u8; 16];
    assert_eq!(format_rlim(&mut b, 0).unwrap(), 1);
    assert_eq!(&b[..1], b"0");
    let n = format_rlim(&mut b, 1024).unwrap();
    assert_eq!(&b[..n], b"1024");
    let n = format_rlim(&mut b, 8388608).unwrap();
    assert_eq!(&b[..n], b"8388608");
}

#[test]
fn rlimit_format_buf_too_small_returns_none() {
    use crate::rlimit::{format_rlim, INFINITY};
    let mut b = [0u8; 3];
    assert_eq!(format_rlim(&mut b, INFINITY), None); // "unlimited" is 9
    assert_eq!(format_rlim(&mut b, 99999),     None); // 5 digits won't fit
}

#[test]
fn rlimit_indices_match_linux_layout() {
    use crate::rlimit::rlim;
    assert_eq!(rlim::CPU, 0);
    assert_eq!(rlim::NOFILE, 7);
    assert_eq!(rlim::AS, 9);
    assert_eq!(rlim::NICE, 13);
    assert_eq!(rlim::COUNT, 16);
}

#[test]
fn clamp_nice_saturates_below_minus_20() {
    use crate::rlimit::clamp_nice;
    assert_eq!(clamp_nice(-100), -20);
    assert_eq!(clamp_nice(-21),  -20);
}

#[test]
fn clamp_nice_saturates_above_19() {
    use crate::rlimit::clamp_nice;
    assert_eq!(clamp_nice(20), 19);
    assert_eq!(clamp_nice(100), 19);
}

#[test]
fn clamp_nice_passes_through_in_range() {
    use crate::rlimit::clamp_nice;
    assert_eq!(clamp_nice(-20), -20);
    assert_eq!(clamp_nice(0),    0);
    assert_eq!(clamp_nice(19),  19);
}

#[test]
fn task_state_linux_char() {
    assert_eq!(TaskState::Runnable.linux_char(), b'R');
    assert_eq!(TaskState::Sleeping.linux_char(), b'S');
    assert_eq!(TaskState::Stopped .linux_char(), b'T');
    assert_eq!(TaskState::Zombie  .linux_char(), b'Z');
}

#[test]
fn task_state_linux_status_label() {
    assert_eq!(TaskState::Runnable.linux_status_label(), "R (running)");
    assert_eq!(TaskState::Stopped .linux_status_label(), "T (stopped)");
    assert_eq!(TaskState::Zombie  .linux_status_label(), "Z (zombie)");
}

#[test]
fn settimeofday_offset_satisfies_apply() {
    use crate::clock::{settimeofday_offset, apply_offset};
    let mono = 1_000_000_000u64; // 1 second of uptime
    let target = 1_700_000_000_000_000_000u64; // wall-clock ns
    let off = settimeofday_offset(mono, target);
    assert_eq!(apply_offset(mono, off), target);
}

#[test]
fn settimeofday_offset_zero_when_target_eq_mono() {
    use crate::clock::settimeofday_offset;
    assert_eq!(settimeofday_offset(42, 42), 0);
}

#[test]
fn settimeofday_offset_wraps_when_target_below_mono() {
    use crate::clock::{settimeofday_offset, apply_offset};
    // target < mono: offset wraps via two's complement; apply still inverts.
    let mono = 1_000u64;
    let target = 100u64;
    let off = settimeofday_offset(mono, target);
    assert_eq!(apply_offset(mono, off), target);
}

#[test]
fn ns_to_clk_tck_100hz() {
    use crate::clock::ns_to_clk_tck;
    assert_eq!(ns_to_clk_tck(0),                    0);
    assert_eq!(ns_to_clk_tck(10_000_000),           1);   // 10 ms = 1 tick
    assert_eq!(ns_to_clk_tck(1_000_000_000),      100);   // 1 s
    assert_eq!(ns_to_clk_tck(1_234_567_890),      123);   // truncates
}

#[test]
fn ns_to_timespec_split() {
    use crate::clock::ns_to_timespec;
    assert_eq!(ns_to_timespec(0),               (0, 0));
    assert_eq!(ns_to_timespec(1_500_000_000),   (1, 500_000_000));
    assert_eq!(ns_to_timespec(999_999_999),     (0, 999_999_999));
}

#[test]
fn ns_to_timeval_split() {
    use crate::clock::ns_to_timeval;
    assert_eq!(ns_to_timeval(0),                (0, 0));
    assert_eq!(ns_to_timeval(1_500_000_000),    (1, 500_000));
    assert_eq!(ns_to_timeval(1_999_999),        (0, 1_999));
}
