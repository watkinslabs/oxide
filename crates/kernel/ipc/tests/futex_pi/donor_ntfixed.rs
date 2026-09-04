use super::*;

const fn nt(level: u8) -> SchedClass { SchedClass::NtFixed { level, quantum: 3 } }

#[test]
fn higher_nt_fixed_donor_replaces_lower_then_deboosts_through_it() {
    static W: AtomicU32 = AtomicU32::new(0);
    let ua = word_addr(&W);
    let owner = Arc::new(Task::with_class(1701, 0xcc00,
        SchedClass::Normal { weight: 1024 }));
    live::set_current(Arc::clone(&owner));
    assert_eq!(futex_pi::pi::lock_pi(ua, true, 0, false), 0);

    let (low, low_rx, low_join) = spawn_locker(ua, 1702, 0xcc00, nt(5));
    wait_until_parked(&low);
    assert_eq!(owner.sched_class(), nt(5));
    assert!(Arc::ptr_eq(&owner.pi_top_task_unlocked().unwrap(), &low));

    let (high, high_rx, high_join) = spawn_locker(ua, 1703, 0xcc00, nt(24));
    wait_until_parked(&high);
    assert_eq!(owner.sched_class(), nt(24));
    assert!(Arc::ptr_eq(&owner.pi_top_task_unlocked().unwrap(), &high));

    high.set_signal_pending(true);
    // SAFETY: hosted wake only unparks this test-owned waiter thread.
    unsafe { live::try_to_wake_up(Arc::clone(&high)); }
    assert!(high_rx.recv_timeout(Duration::from_secs(5)).unwrap() < 0);
    assert_eq!(owner.sched_class(), nt(5));
    assert!(Arc::ptr_eq(&owner.pi_top_task_unlocked().unwrap(), &low));

    low.set_signal_pending(true);
    // SAFETY: hosted wake only unparks this test-owned waiter thread.
    unsafe { live::try_to_wake_up(Arc::clone(&low)); }
    assert!(low_rx.recv_timeout(Duration::from_secs(5)).unwrap() < 0);
    assert_eq!(owner.sched_class(), SchedClass::Normal { weight: 1024 });
    assert!(!owner.sched_is_boosted());
    high_join.join().unwrap();
    low_join.join().unwrap();
    live::set_current(owner);
    assert_eq!(futex_pi::pi::unlock_pi(ua, true), 0);
}
