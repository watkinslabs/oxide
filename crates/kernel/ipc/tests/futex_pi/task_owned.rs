use super::*;

#[test]
fn owner_tree_has_one_top_waiter_per_owned_lock_and_blocked_edges_clear() {
    static LOW_LOCK: AtomicU32 = AtomicU32::new(0);
    static HIGH_LOCK: AtomicU32 = AtomicU32::new(0);
    let low_addr = word_addr(&LOW_LOCK);
    let high_addr = word_addr(&HIGH_LOCK);
    const MM: u64 = 0xfeed_1000;
    let owner = Arc::new(Task::new(21_001, MM));
    live::set_current(Arc::clone(&owner));
    assert_eq!(futex_pi::pi::lock_pi(low_addr, true, 0, false), 0);
    assert_eq!(futex_pi::pi::lock_pi(high_addr, true, 0, false), 0);

    let (low, low_rx, low_join) = spawn_locker(low_addr, 21_002, MM,
        SchedClass::Rt { prio: 10, policy: SchedPolicy::Fifo });
    wait_until_parked(&low);
    let (high, high_rx, high_join) = spawn_locker(high_addr, 21_003, MM,
        SchedClass::Rt { prio: 80, policy: SchedPolicy::Fifo });
    wait_until_parked(&high);

    let low_edge = low.pi_lock.lock().blocked_on().expect("low waiter publishes pi_blocked_on");
    let high_edge = high.pi_lock.lock().blocked_on().expect("high waiter publishes pi_blocked_on");
    assert_ne!(low_edge.lock_id, high_edge.lock_id,
        "positive control: the two futex wait trees have distinct identities");
    assert_eq!(owner.pi_lock.lock().waiter_count(), 2,
        "owner PI tree contains one top waiter from each owned futex");
    assert!(Arc::ptr_eq(&owner.pi_top_task_unlocked().unwrap(), &high));

    live::set_current(Arc::clone(&owner));
    assert_eq!(futex_pi::pi::unlock_pi(high_addr, true), 0);
    assert_eq!(high_rx.recv_timeout(Duration::from_secs(5)).unwrap(), 0);
    high_join.join().unwrap();
    assert!(high.pi_lock.lock().blocked_on().is_none(),
        "handoff clears the granted task's blocked-on edge before wake");
    assert_eq!(owner.pi_lock.lock().waiter_count(), 1);
    assert!(Arc::ptr_eq(&owner.pi_top_task_unlocked().unwrap(), &low));

    live::set_current(Arc::clone(&owner));
    assert_eq!(futex_pi::pi::unlock_pi(low_addr, true), 0);
    assert_eq!(low_rx.recv_timeout(Duration::from_secs(5)).unwrap(), 0);
    low_join.join().unwrap();
    assert_eq!(owner.pi_lock.lock().waiter_count(), 0);
    assert!(owner.pi_top_task_unlocked().is_none());

    live::set_current(high);
    assert_eq!(futex_pi::pi::unlock_pi(high_addr, true), 0);
    live::set_current(low);
    assert_eq!(futex_pi::pi::unlock_pi(low_addr, true), 0);
}
