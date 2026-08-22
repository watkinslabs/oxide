use super::*;
use core::sync::atomic::AtomicBool;
use std::sync::Arc as StdArc;

// Tests share process-global RCU state; serialize them.
static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());
fn guard() -> std::sync::MutexGuard<'static, ()> {
    let g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    _test_reset();
    g
}

#[test]
fn quiescent_state_table_uses_canonical_cpu_bound() {
    assert_eq!(CPU_QS.len(), hal::MAX_CPUS);
    assert_eq!(CPU_MASK_WORDS, hal::MAX_CPUS.div_ceil(u64::BITS as usize));
}

#[test]
fn callback_runs_only_after_a_grace_period() {
    let _g = guard();
    let ran = StdArc::new(AtomicBool::new(false));
    let r2 = ran.clone();
    call_rcu(Box::new(move || r2.store(true, Ordering::Release)));
    rcu_process_callbacks();
    assert!(!ran.load(Ordering::Acquire), "callback ran before any QS");
    assert_eq!(pending_callbacks(), 1);
    for _ in 0..6 { note_qs(); rcu_process_callbacks(); }
    assert!(ran.load(Ordering::Acquire), "callback must run after a grace period");
    assert_eq!(pending_callbacks(), 0, "no leak: callback dequeued");
}

#[test]
fn synchronize_rcu_waits_for_a_full_period() {
    let _g = guard();
    let seq0 = GP_SEQ.load(Ordering::Acquire);
    synchronize_rcu();
    assert!(GP_SEQ.load(Ordering::Acquire) > seq0, "synchronize_rcu advanced a grace period");
}

#[test]
fn rcu_barrier_flushes_all_pending() {
    let _g = guard();
    let n = StdArc::new(AtomicUsize::new(0));
    for _ in 0..10 {
        let nn = n.clone();
        call_rcu(Box::new(move || { nn.fetch_add(1, Ordering::AcqRel); }));
    }
    assert_eq!(pending_callbacks(), 10);
    rcu_barrier();
    assert_eq!(n.load(Ordering::Acquire), 10, "every queued callback ran");
    assert_eq!(pending_callbacks(), 0, "no leak after barrier");
}

#[test]
fn barrier_excludes_callbacks_queued_after_its_entry() {
    let _g = guard();
    let early = StdArc::new(AtomicBool::new(false));
    let late = StdArc::new(AtomicBool::new(false));
    let early_done = early.clone();
    let late_queued = late.clone();
    call_rcu(Box::new(move || {
        early_done.store(true, Ordering::Release);
        call_rcu(Box::new(move || late_queued.store(true, Ordering::Release)));
    }));
    rcu_barrier();
    assert!(early.load(Ordering::Acquire), "pre-barrier callback must retire");
    assert!(!late.load(Ordering::Acquire), "late callback must not extend this barrier");
    rcu_barrier();
    assert!(late.load(Ordering::Acquire));
}

#[test]
fn callback_backlog_remains_deferred_until_a_grace_period() {
    let _g = guard();
    let ran = StdArc::new(AtomicUsize::new(0));
    const CALLBACKS: usize = 64;
    for _ in 0..CALLBACKS {
        let r = ran.clone();
        call_rcu(Box::new(move || { r.fetch_add(1, Ordering::AcqRel); }));
    }
    rcu_process_callbacks();
    assert_eq!(ran.load(Ordering::Acquire), 0, "callbacks cannot bypass a grace period");
    assert_eq!(pending_callbacks(), CALLBACKS);
    rcu_barrier();
    assert_eq!(ran.load(Ordering::Acquire), CALLBACKS);
}

#[test]
fn stalled_period_retains_callbacks_until_the_missing_cpu_quiesces() {
    let _g = guard();
    let ran = StdArc::new(AtomicBool::new(false));
    let r2 = ran.clone();
    call_rcu(Box::new(move || r2.store(true, Ordering::Release)));
    for _ in 0..4 { drain_once(); }
    assert!(!ran.load(Ordering::Acquire), "a stalled CPU keeps its protected callback alive");
    assert_eq!(pending_callbacks(), 1);
    for _ in 0..2 { note_qs(); drain_once(); }
    assert!(ran.load(Ordering::Acquire));
    assert_eq!(pending_callbacks(), 0);
}

#[test]
fn grace_period_includes_an_online_cpu_above_the_first_mask_word() {
    let _g = guard();
    let cpu = u64::BITS as usize + 2;
    let mut online = [0u64; CPU_MASK_WORDS];
    online[cpu / u64::BITS as usize] = 1u64 << (cpu % u64::BITS as usize);
    let snap = [0u64; MAX_CPUS];
    assert!(!all_quiesced(&snap, online));
    CPU_QS[cpu].0.store(1, Ordering::Release);
    assert!(all_quiesced(&snap, online));
}
