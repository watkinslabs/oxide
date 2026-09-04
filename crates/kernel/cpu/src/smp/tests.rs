use super::*;
extern crate std;
use std::sync::{Arc, Barrier, Mutex, MutexGuard};

static SMP_TESTS: Mutex<()> = Mutex::new(());

fn reset_locked() {
    BOOT_CPU_ID.store(u64::MAX, Ordering::Release);
    BOOT_LOGICAL_ID.store(u32::MAX, Ordering::Release);
    HOTPLUG_OWNER.store(NO_HOTPLUG_OWNER, Ordering::Release);
    ONLINE.store(0, Ordering::Release);
    ONLINE_MASK.clear();
    CAPACITY_MASK.clear();
    ACTIVE_MASK.clear();
    CALLABLE_MASK.clear();
    FROZEN.clear();
    for state in &HOTPLUG { state.store(HP_IDLE, Ordering::Release); }
}

fn reset() -> MutexGuard<'static, ()> {
    let guard = SMP_TESTS.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    reset_locked();
    guard
}

#[test]
fn empty_topology_yields_no_aps() {
    let _serial = reset();
    // SAFETY: hosted test single-thread invariant; sole writer for BOOT_CPU_ID.
    unsafe { set_boot_cpu_id(0); }
    let aps = enumerate_aps();
    assert!(!aps.contains(&0));
}

#[test]
fn online_transitions_are_idempotent_and_reversible() {
    let _serial = reset();
    // SAFETY: hosted-test single-thread invariant; sole writer.
    unsafe { set_boot_cpu_id(0); }
    assert_eq!(online_count(), 1);
    // SAFETY: test owns CPU 1's lifecycle transition.
    unsafe { mark_online(1); mark_online(1); }
    assert_eq!(online_count(), 2);
    // SAFETY: test owns CPU 1's lifecycle transition.
    assert!(unsafe { mark_offline(1) });
    // SAFETY: test still exclusively owns CPU 1's lifecycle state.
    assert!(!unsafe { mark_offline(1) });
    assert_eq!(online_count(), 2, "capacity removal must retain transport reachability");
    assert_eq!(online_count(), online_cpumask().count_ones());
    assert!(online_cpumask().contains(1));
    assert!(!capacity_cpumask().contains(1));
    finish_offline(1);
    assert_eq!(online_count(), 1);
    assert_eq!(online_count(), online_cpumask().count_ones());
}

#[test]
fn online_set_is_published_through_the_canonical_cpumask() {
    let _serial = reset();
    // SAFETY: hosted-test single-thread invariant; each logical bit has one writer.
    unsafe { mark_online(0); mark_online(crate::MAX_CPUS as u32 - 1); }
    let online = online_cpumask();
    assert!(online.contains(0));
    assert!(online.contains(crate::MAX_CPUS - 1));
}

#[test]
fn failed_partial_thaw_retains_only_the_unrestored_cpu() {
    let _serial = reset();
    // SAFETY: hosted test owns these logical lifecycle transitions.
    unsafe { set_boot_cpu_id(0); mark_online(1); mark_online(2); mark_offline(1); mark_offline(2); }
    finish_offline(1); finish_offline(2);
    // SAFETY: CPU 1's simulated restart owns its online transition.
    unsafe { mark_online(1); }
    finish_thaw_cpu(1, true);
    finish_thaw_cpu(2, false);
    let frozen = frozen_cpumask();
    assert!(!frozen.contains(1));
    assert!(frozen.contains(2), "failed CPU-up must retain frozen ownership");
    assert!(!begin_freeze(), "a partial thaw must block a new down transaction");
}

#[test]
fn target_refusal_never_enters_the_frozen_set() {
    let _serial = reset();
    // SAFETY: hosted test owns the topology lifecycle.
    unsafe { set_boot_cpu_id(0); mark_online(1); }
    assert!(request_offline(1));
    reject_offline(1);
    assert_eq!(offline_result(1), Some(false));
    assert!(online_cpumask().contains(1));
    assert!(!frozen_cpumask().contains(1));
    cancel_offline(1);
    assert!(accepts_work(1), "refused target must resume scheduler admission");
}

#[test]
fn cpu_down_reaches_play_dead_only_from_the_irq_tail_state() {
    let _serial = reset();
    // SAFETY: hosted test owns the topology lifecycle.
    unsafe { set_boot_cpu_id(0); mark_online(1); }
    assert!(request_offline(1));
    // SAFETY: test owns the serialized capacity transition.
    assert!(unsafe { mark_offline(1) });
    assert!(deactivate(1));
    assert!(!offline_tail_requested(1));
    assert!(request_offline_tail(1));
    assert!(offline_tail_requested(1));
    assert_eq!(offline_result(1), None);
    assert!(!request_offline_tail(1), "call-function admission transfers once");
    reject_offline(1);
    assert_eq!(offline_result(1), Some(false));
    cancel_offline(1);
    assert!(accepts_work(1));
}

#[test]
fn old_active_selector_publishes_before_deactivation_grace_completes() {
    let _serial = reset();
    // SAFETY: hosted test owns both logical lifecycle transitions.
    unsafe { mark_online(0); mark_online(1); }
    assert!(request_offline(1));
    let sampled_active = is_active(1);
    // SAFETY: test owns the serialized capacity transition.
    assert!(unsafe { mark_offline(1) });
    let mut published = false;
    let mut grace_done = false;
    assert!(deactivate_with(1, || {
        assert!(!is_active(1), "active bit must clear before grace starts");
        assert!(sampled_active);
        published = true;
        assert!(!grace_done, "old selector published after grace completion");
    }));
    grace_done = true;
    assert!(published && grace_done);
}

#[test]
fn cancellation_restores_capacity_active_and_transport_sets() {
    let _serial = reset();
    // SAFETY: hosted test owns both logical lifecycle transitions.
    unsafe { mark_online(0); mark_online(1); }
    assert!(request_offline(1));
    // SAFETY: test owns the serialized capacity transition.
    assert!(unsafe { mark_offline(1) });
    assert!(deactivate(1));
    assert!(online_cpumask().contains(1));
    assert!(!capacity_cpumask().contains(1));
    assert!(!active_cpumask().contains(1));
    assert!(live_cpumask().contains(1));
    reject_offline(1);
    cancel_offline(1);
    assert!(online_cpumask().contains(1));
    assert!(capacity_cpumask().contains(1));
    assert!(active_cpumask().contains(1));
    assert!(live_cpumask().contains(1));
}

#[test]
fn cancellation_wins_before_the_target_claims_play_dead() {
    let _serial = reset();
    // SAFETY: hosted test owns both logical lifecycle transitions.
    unsafe { mark_online(0); mark_online(1); }
    assert!(request_offline(1));
    // SAFETY: test owns the serialized capacity transition.
    assert!(unsafe { mark_offline(1) });
    assert!(deactivate(1));
    assert!(request_offline_tail(1));
    cancel_offline(1);
    assert!(!claim_offline_commit(1));
    assert!(online_cpumask().contains(1));
    assert!(active_cpumask().contains(1));
}

#[test]
fn play_dead_claim_wins_before_late_cancellation() {
    let _serial = reset();
    // SAFETY: hosted test owns both logical lifecycle transitions.
    unsafe { mark_online(0); mark_online(1); }
    assert!(request_offline(1));
    // SAFETY: test owns the serialized capacity transition.
    assert!(unsafe { mark_offline(1) });
    assert!(deactivate(1));
    assert!(request_offline_tail(1));
    assert!(claim_offline_commit(1));
    finish_offline(1);
    cancel_offline(1);
    assert_eq!(offline_result(1), Some(true));
    assert!(!active_cpumask().contains(1));
    assert!(!live_cpumask().contains(1));
}

#[test]
fn boot_and_last_active_cpu_are_never_offline_targets() {
    let _serial = reset();
    // SAFETY: hosted test owns boot publication.
    unsafe { set_boot_cpu_id(0); }
    assert!(!request_offline(0));
    // SAFETY: hosted test owns CPU 1 lifecycle.
    unsafe { mark_online(1); }
    assert!(request_offline(1));
    cancel_offline(1);
    let _ = ACTIVE_MASK.clear_cpu(0, Ordering::AcqRel);
    assert!(!request_offline(1), "last active CPU must retain a migration destination");
}

#[test]
fn cpu_hotplug_writer_serializes_last_active_admission() {
    let _serial = reset();
    unsafe { set_boot_cpu_id(0); mark_online(0); mark_online(1); mark_online(2); }
    let start = Arc::new(Barrier::new(3));
    let one_start = Arc::clone(&start);
    let one = std::thread::spawn(move || { one_start.wait(); request_offline(1) });
    let two_start = Arc::clone(&start);
    let two = std::thread::spawn(move || { two_start.wait(); request_offline(2) });
    start.wait();
    let one_won = one.join().unwrap();
    let two_won = two.join().unwrap();
    assert_ne!(one_won, two_won, "exactly one synchronized topology writer must win");
    let (winner, loser) = if one_won { (1, 2) } else { (2, 1) };
    cancel_offline(winner);
    assert!(request_offline(loser), "cancellation releases the topology writer");
    cancel_offline(loser);
}

#[test]
fn sparse_boot_hardware_id_is_never_reinterpreted_as_logical() {
    let _serial = reset();
    let sparse = u64::MAX - 1;
    // SAFETY: hosted test is the sole boot-ID publisher.
    unsafe { set_boot_cpu_id(sparse); mark_online(1); }
    assert_eq!(boot_cpu_id(), sparse);
    assert_eq!(boot_logical_id(), Some(0));
    assert!(!request_offline(0),
        "the persisted boot logical ID must win even without a topology reverse map");
    assert!(request_offline(1));
}

#[test]
fn repeated_hosted_reset_restores_every_smp_global() {
    let _serial = reset();
    for _ in 0..64 {
        // SAFETY: serialized hosted test owns both lifecycle records.
        unsafe { set_boot_cpu_id(u64::MAX - 1); mark_online(1); mark_offline(1); }
        assert!(request_offline(1));
        reject_offline(1);
        let _ = FROZEN.set(1, Ordering::Release);
        reset_locked();
        assert_eq!(boot_cpu_id(), u64::MAX);
        assert_eq!(boot_logical_id(), None);
        assert_eq!(online_count(), 0);
        assert!(online_cpumask().is_empty());
        assert!(capacity_cpumask().is_empty());
        assert!(active_cpumask().is_empty());
        assert!(callable_cpumask().is_empty());
        assert!(frozen_cpumask().is_empty());
        assert!(HOTPLUG.iter().all(|state| state.load(Ordering::Acquire) == HP_IDLE));
    }
}

#[test]
fn delayed_reject_cannot_overwrite_completed_cancellation() {
    let _serial = reset();
    // SAFETY: hosted test owns both logical lifecycle transitions.
    unsafe { mark_online(0); mark_online(1); }
    assert!(request_offline(1));
    // SAFETY: test owns the capacity transition.
    assert!(unsafe { mark_offline(1) });
    assert!(deactivate(1));
    cancel_offline(1);
    reject_offline(1);
    assert_eq!(offline_result(1), None);
    assert!(active_cpumask().contains(1));
    assert!(capacity_cpumask().contains(1));
}

#[test]
fn callfn_publication_closes_only_at_terminal_grace() {
    let _serial = reset();
    // SAFETY: hosted test owns both logical lifecycle transitions.
    unsafe { mark_online(0); mark_online(1); }
    assert!(request_offline(1));
    // SAFETY: test owns capacity transition.
    assert!(unsafe { mark_offline(1) });
    assert!(deactivate(1));
    assert!(callable_cpumask().contains(1),
        "deactivated but executing CPU must still receive TLB/membarrier calls");
    assert!(request_offline_tail(1));
    let sampled_callable = true;
    let mut old_reader_published = false;
    assert!(begin_callfn_shutdown_with(1, || {
        assert!(!callable_cpumask().contains(1));
        assert!(online_cpumask().contains(1),
            "transport membership must survive terminal publication closure");
        if sampled_callable { old_reader_published = true; }
    }));
    assert!(old_reader_published, "pre-clear reader publishes before grace completes");
    assert!(!callable_cpumask().contains(1));
    assert!(online_cpumask().contains(1),
        "positive control: ONLINE alone would admit the final-empty race");
}

#[test]
fn refusal_restores_hardware_before_software_publication() {
    let _serial = reset();
    // SAFETY: hosted test owns both logical lifecycle transitions.
    unsafe { mark_online(0); mark_online(1); }
    assert!(request_offline(1));
    // SAFETY: hosted test owns capacity transition.
    assert!(unsafe { mark_offline(1) });
    assert!(deactivate(1));
    assert!(request_offline_tail(1));
    assert!(begin_callfn_shutdown_with(1, || {}));
    assert!(claim_offline_commit(1));
    finish_offline(1);
    let mut local_restored = false;
    // SAFETY: test models firmware returning on the target CPU.
    unsafe { restore_offline_refusal_with(1, || {
        assert!(!active_cpumask().contains(1));
        assert!(!callable_cpumask().contains(1));
        local_restored = true;
    }); }
    assert!(local_restored);
    assert!(active_cpumask().contains(1));
    assert!(callable_cpumask().contains(1));
    assert!(online_cpumask().contains(1));
    assert_eq!(offline_result(1), Some(false));
}
