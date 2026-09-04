use super::*;

#[test]
fn pi_wait_lock_nests_between_registry_and_task_pi() {
    use sync::LockClass;
    assert!(sync::TaskList::rank() < sync::RtMutexWait::rank());
    assert!(sync::RtMutexWait::rank() < sync::TaskPi::rank());
    assert!(sync::TaskPi::rank() < sync::Runqueue::rank());
}

#[test]
fn waiter_hook_initialization_waits_until_publication_is_ready() {
    let state = Arc::new(core::sync::atomic::AtomicU8::new(0));
    let installs = Arc::new(AtomicU32::new(0));
    let entered = Arc::new(std::sync::Barrier::new(2));
    let release = Arc::new(std::sync::Barrier::new(2));
    let (observed_tx, observed_rx) = mpsc::channel();
    let (done_tx, done_rx) = mpsc::channel();

    let s = Arc::clone(&state);
    let n = Arc::clone(&installs);
    let e = Arc::clone(&entered);
    let r = Arc::clone(&release);
    let winner = std::thread::spawn(move || futex_pi::pi::state::ensure_hook_for_test(&s,
        || { n.fetch_add(1, Ordering::AcqRel); e.wait(); r.wait(); }, std::hint::spin_loop));
    entered.wait();

    let s = Arc::clone(&state);
    let n = Arc::clone(&installs);
    let loser = std::thread::spawn(move || {
        let mut observed = Some(observed_tx);
        futex_pi::pi::state::ensure_hook_for_test(&s,
            || { n.fetch_add(1, Ordering::AcqRel); },
            || {
                if let Some(tx) = observed.take() { tx.send(()).unwrap(); }
                std::thread::yield_now();
            });
        done_tx.send(()).unwrap();
    });
    observed_rx.recv_timeout(Duration::from_secs(5)).expect("loser saw INSTALLING");
    assert!(done_rx.try_recv().is_err(), "an INSTALLING observer returned before READY");
    release.wait();
    winner.join().unwrap();
    loser.join().unwrap();
    done_rx.recv_timeout(Duration::from_secs(5)).expect("loser observed READY");
    assert_eq!(state.load(Ordering::Acquire), 2);
    assert_eq!(installs.load(Ordering::Acquire), 1,
        "only the UNINIT-to-INSTALLING winner may publish the singleton hook");
}

#[test]
fn an_exiting_futex_owner_is_retryable_not_attachable() {
    let owner = Arc::new(Task::new(1599, 0xc000));
    live::set_current(Arc::clone(&owner));
    owner.exiting.store(true, Ordering::Release);
    let (lookup, pinned) = futex_pi::pi::lock::classify_owner(1599);
    assert_eq!(lookup, futex_pi_rules::OwnerLookup::Exiting);
    assert!(Arc::ptr_eq(&owner, &pinned.expect("exiting owner remains pinned")));
}

#[test]
fn owner_exit_uaccess_failure_releases_waiters_with_efault() {
    static W: AtomicU32 = AtomicU32::new(0);
    let ua = word_addr(&W);
    const MM: u64 = 0xbfff;
    let owner = Arc::new(Task::new(1598, MM));
    live::set_current(Arc::clone(&owner));
    assert_eq!(futex_pi::pi::lock_pi(ua, true, 0, false), 0);
    let (waiter, rx, join) = spawn_locker(ua, 1597, MM,
        SchedClass::Rt { prio: 70, policy: SchedPolicy::Fifo });
    wait_until_parked(&waiter);
    useraccess::fault_read_on_call(ua, 1);
    futex_pi::pi::exit_pi_state_list(&owner);
    assert_eq!(rx.recv_timeout(Duration::from_secs(5)).expect("faulted exit wake"),
        -(syscall::errno::Errno::Efault.as_i32() as i64));
    assert!(!owner.sched_is_boosted());
    join.join().unwrap();
    W.store(0, Ordering::SeqCst);
}

#[test]
fn timed_out_top_waiter_is_removed_and_deboosts_the_owner() {
    let _clock = fake_clock();
    static W: AtomicU32 = AtomicU32::new(0);
    let ua = word_addr(&W);
    let owner = Arc::new(Task::new(1596, 0xbffe));
    live::set_current(Arc::clone(&owner));
    assert_eq!(futex_pi::pi::lock_pi(ua, true, 0, false), 0);
    let waiter = Arc::new(Task::with_class(1595, 0xbffe,
        SchedClass::Rt { prio: 80, policy: SchedPolicy::Fifo }));
    let watch = Arc::clone(&waiter);
    let (tx, rx) = mpsc::channel();
    let join = std::thread::spawn(move || {
        live::set_current(waiter);
        tx.send(futex_pi::pi::lock_pi(ua, true, 100, false)).unwrap();
    });
    wait_until_parked(&watch);
    assert_eq!(owner.sched_class(), SchedClass::Rt { prio: 80, policy: SchedPolicy::Fifo });
    FAKE_NOW_NS.store(100, Ordering::SeqCst);
    // SAFETY: hosted wake only unparks this test-owned waiter thread.
    unsafe { live::try_to_wake_up(watch); }
    assert_eq!(rx.recv_timeout(Duration::from_secs(5)).unwrap(),
        -(syscall::errno::Errno::Etimedout.as_i32() as i64));
    join.join().unwrap();
    assert_eq!(owner.sched_class(), SchedClass::Normal { weight: 1024 });
    live::set_current(owner);
    assert_eq!(futex_pi::pi::unlock_pi(ua, true), 0);
}

#[test]
fn allocation_failure_precedes_pi_table_and_user_word_publication() {
    static W: AtomicU32 = AtomicU32::new(0);
    let ua = word_addr(&W);
    live::set_current(Arc::new(Task::new(1600, 0xc001)));
    futex_pi::pi::state::fail_next_reservation(ua);

    assert_eq!(futex_pi::pi::lock_pi(ua, true, 0, false),
        -(syscall::errno::Errno::Enomem.as_i32() as i64));
    assert_eq!(W.load(Ordering::SeqCst), 0,
        "ENOMEM must not publish either ownership or FUTEX_WAITERS");
}

#[test]
fn pi_waiter_publication_allocates_and_frees_only_outside_wait_lock() {
    crate::alloc_guard::reset();
    {
        let _table = futex_pi::pi::state::PI_TABLE.lock();
        let mut positive = Vec::<u8>::with_capacity(8);
        positive.push(1);
        std::hint::black_box(&positive);
    }
    assert!(crate::alloc_guard::violations() >= 2,
        "positive control did not observe allocation and free under RtMutexWait");

    crate::alloc_guard::reset();
    static W: AtomicU32 = AtomicU32::new(0);
    let ua = word_addr(&W);
    let owner = Arc::new(Task::new(1601, 0xc002));
    live::set_current(Arc::clone(&owner));
    assert_eq!(futex_pi::pi::lock_pi(ua, true, 0, false), 0);
    let (waiter, rx, join) = spawn_locker(ua, 1602, 0xc002,
        SchedClass::Rt { prio: 50, policy: SchedPolicy::Fifo });
    wait_until_parked(&waiter);
    waiter.set_signal_pending(true);
    // SAFETY: hosted wake only unparks this test-owned waiter thread.
    unsafe { live::try_to_wake_up(Arc::clone(&waiter)); }
    assert!(rx.recv_timeout(Duration::from_secs(5)).unwrap() < 0);
    join.join().unwrap();
    assert_eq!(crate::alloc_guard::violations(), 0,
        "PI waiter publication or removal reached the allocator under RtMutexWait");
}

#[test]
fn deadline_waiter_lends_identity_and_deadline_to_fair_owner() {
    static W: AtomicU32 = AtomicU32::new(0);
    let ua = word_addr(&W);
    let owner = Arc::new(Task::with_class(1611, 0xc100, SchedClass::Normal { weight: 1024 }));
    live::set_current(Arc::clone(&owner));
    assert_eq!(futex_pi::pi::lock_pi(ua, true, 0, false), 0);
    let donor = Arc::new(Task::with_class(1612, 0xc100, SchedClass::Deadline));
    donor.set_deadline(200);
    let (waiter, rx, join) = spawn_existing_locker(ua, Arc::clone(&donor));
    wait_until_parked(&waiter);
    assert_eq!((owner.sched_class(), owner.effective_dl_deadline()), (SchedClass::Deadline, 200));
    assert!(Arc::ptr_eq(&owner.pi_top_task_unlocked().unwrap(), &donor));
    live::set_current(Arc::clone(&owner));
    assert_eq!(futex_pi::pi::unlock_pi(ua, true), 0);
    assert_eq!(rx.recv_timeout(Duration::from_secs(5)).unwrap(), 0);
    assert_eq!(owner.sched_class(), SchedClass::Normal { weight: 1024 });
    assert!(!owner.sched_is_boosted());
    join.join().unwrap();
}

#[test]
fn earlier_deadline_waiter_replaces_then_restores_owner_deadline() {
    static W: AtomicU32 = AtomicU32::new(0);
    let ua = word_addr(&W);
    let owner = Arc::new(Task::with_class(1621, 0xc200, SchedClass::Deadline));
    owner.set_deadline(800);
    live::set_current(Arc::clone(&owner));
    assert_eq!(futex_pi::pi::lock_pi(ua, true, 0, false), 0);
    let donor = Arc::new(Task::with_class(1622, 0xc200, SchedClass::Deadline));
    donor.set_deadline(300);
    let (waiter, rx, join) = spawn_existing_locker(ua, donor);
    wait_until_parked(&waiter);
    assert_eq!(owner.effective_dl_deadline(), 300);
    live::set_current(Arc::clone(&owner));
    assert_eq!(futex_pi::pi::unlock_pi(ua, true), 0);
    assert_eq!(rx.recv_timeout(Duration::from_secs(5)).unwrap(), 0);
    assert_eq!(owner.effective_dl_deadline(), 800);
    assert!(!owner.sched_is_boosted());
    join.join().unwrap();
}

#[test]
fn ordinary_fair_waiter_does_not_donate_nice_weight() {
    static W: AtomicU32 = AtomicU32::new(0);
    let ua = word_addr(&W);
    let owner = Arc::new(Task::with_class(1631, 0xc300, SchedClass::Normal { weight: 15 }));
    live::set_current(Arc::clone(&owner));
    assert_eq!(futex_pi::pi::lock_pi(ua, true, 0, false), 0);
    let (waiter, rx, join) = spawn_locker(ua, 1632, 0xc300,
        SchedClass::Normal { weight: 88_761 });
    wait_until_parked(&waiter);
    assert_eq!(owner.sched_class(), SchedClass::Normal { weight: 15 });
    live::set_current(Arc::clone(&owner));
    assert_eq!(futex_pi::pi::unlock_pi(ua, true), 0);
    assert_eq!(rx.recv_timeout(Duration::from_secs(5)).unwrap(), 0);
    assert_eq!(owner.sched_class(), SchedClass::Normal { weight: 15 });
    join.join().unwrap();
}

#[test]
fn stale_snapshot_positive_control_can_overwrite_the_real_top_donor() {
    let owner = Arc::new(Task::with_class(1641, 0xc400, SchedClass::Normal { weight: 1024 }));
    let low = Arc::new(Task::with_class(1642, 0xc400,
        SchedClass::Rt { prio: 50, policy: SchedPolicy::Fifo }));
    let high = Arc::new(Task::with_class(1643, 0xc400,
        SchedClass::Rt { prio: 80, policy: SchedPolicy::Fifo }));
    live::pi_boost::apply_boost(&owner, Some(high));
    live::pi_boost::apply_boost(&owner, Some(Arc::clone(&low)));
    assert_eq!(owner.sched_class(), SchedClass::Rt { prio: 50, policy: SchedPolicy::Fifo });
    assert!(Arc::ptr_eq(&owner.pi_top_task_unlocked().unwrap(), &low));
}

#[test]
fn concurrent_waiter_publications_cannot_leave_the_stale_donor() {
    static W: AtomicU32 = AtomicU32::new(0);
    let ua = word_addr(&W);
    let owner = Arc::new(Task::with_class(1651, 0xc500, SchedClass::Normal { weight: 1024 }));
    live::set_current(Arc::clone(&owner));
    assert_eq!(futex_pi::pi::lock_pi(ua, true, 0, false), 0);

    let entered = Arc::new(std::sync::Barrier::new(2));
    let release = Arc::new(std::sync::Barrier::new(2));
    futex_pi::pi::state::arm_reboost_gate(owner.tid, Arc::clone(&entered), Arc::clone(&release));
    let low = Arc::new(Task::with_class(1652, 0xc500,
        SchedClass::Rt { prio: 50, policy: SchedPolicy::Fifo }));
    let (low_waiter, low_rx, low_join) = spawn_existing_locker(ua, Arc::clone(&low));
    entered.wait();

    let high = Arc::new(Task::with_class(1653, 0xc500,
        SchedClass::Rt { prio: 80, policy: SchedPolicy::Fifo }));
    let (started_tx, started_rx) = mpsc::channel();
    let (high_tx, high_rx) = mpsc::channel();
    let high_waiter = Arc::clone(&high);
    let high_join = std::thread::spawn(move || {
        live::set_current(high);
        started_tx.send(()).unwrap();
        high_tx.send(futex_pi::pi::lock_pi(ua, true, 0, false)).unwrap();
    });
    started_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    for _ in 0..1_000 { std::thread::yield_now(); }
    release.wait();
    wait_until_parked(&low_waiter);
    wait_until_parked(&high_waiter);

    assert_eq!(owner.sched_class(), SchedClass::Rt { prio: 80, policy: SchedPolicy::Fifo });
    assert!(Arc::ptr_eq(&owner.pi_top_task_unlocked().unwrap(), &high_waiter));

    high_waiter.set_signal_pending(true);
    // SAFETY: hosted wake only unparks this test-owned waiter thread.
    unsafe { live::try_to_wake_up(Arc::clone(&high_waiter)); }
    assert!(high_rx.recv_timeout(Duration::from_secs(5)).unwrap() < 0);
    assert_eq!(owner.sched_class(), SchedClass::Rt { prio: 50, policy: SchedPolicy::Fifo });
    low_waiter.set_signal_pending(true);
    // SAFETY: hosted wake only unparks this test-owned waiter thread.
    unsafe { live::try_to_wake_up(Arc::clone(&low_waiter)); }
    assert!(low_rx.recv_timeout(Duration::from_secs(5)).unwrap() < 0);
    assert_eq!(owner.sched_class(), SchedClass::Normal { weight: 1024 });
    high_join.join().unwrap();
    low_join.join().unwrap();
}

#[test]
fn waiter_priority_change_callback_immediately_rekeys_the_owner() {
    static W: AtomicU32 = AtomicU32::new(0);
    let ua = word_addr(&W);
    let owner = Arc::new(Task::with_class(1661, 0xc600, SchedClass::Normal { weight: 1024 }));
    live::set_current(Arc::clone(&owner));
    assert_eq!(futex_pi::pi::lock_pi(ua, true, 0, false), 0);
    let donor = Arc::new(Task::with_class(1662, 0xc600,
        SchedClass::Rt { prio: 50, policy: SchedPolicy::Fifo }));
    let (changed, changed_rx, changed_join) = spawn_existing_locker(ua, Arc::clone(&donor));
    wait_until_parked(&changed);
    assert_eq!(owner.sched_class(), SchedClass::Rt { prio: 50, policy: SchedPolicy::Fifo });

    donor.set_normal_sched_class(SchedClass::Rt { prio: 80, policy: SchedPolicy::Fifo });
    assert_eq!(owner.sched_class(), SchedClass::Rt { prio: 50, policy: SchedPolicy::Fifo },
        "positive control: changing the waiter alone cannot publish into its owner's PI state");
    live::pi_boost::set_base_class(&donor,
        SchedClass::Rt { prio: 80, policy: SchedPolicy::Fifo });
    assert_eq!(owner.sched_class(), SchedClass::Rt { prio: 80, policy: SchedPolicy::Fifo });
    assert!(Arc::ptr_eq(&owner.pi_top_task_unlocked().unwrap(), &donor));

    let (peer, peer_rx, peer_join) = spawn_locker(ua, 1663, 0xc600,
        SchedClass::Rt { prio: 40, policy: SchedPolicy::Fifo });
    wait_until_parked(&peer);
    assert_eq!(owner.sched_class(), SchedClass::Rt { prio: 80, policy: SchedPolicy::Fifo });
    assert!(Arc::ptr_eq(&owner.pi_top_task_unlocked().unwrap(), &donor));

    changed.set_signal_pending(true);
    // SAFETY: hosted wake only unparks this test-owned waiter thread.
    unsafe { live::try_to_wake_up(Arc::clone(&changed)); }
    assert!(changed_rx.recv_timeout(Duration::from_secs(5)).unwrap() < 0);
    peer.set_signal_pending(true);
    // SAFETY: hosted wake only unparks this test-owned waiter thread.
    unsafe { live::try_to_wake_up(Arc::clone(&peer)); }
    assert!(peer_rx.recv_timeout(Duration::from_secs(5)).unwrap() < 0);
    assert_eq!(owner.sched_class(), SchedClass::Normal { weight: 1024 });
    changed_join.join().unwrap();
    peer_join.join().unwrap();
}

#[test]
fn deadline_change_propagates_through_a_blocked_owner_chain_without_relocking_table() {
    static A_LOCK: AtomicU32 = AtomicU32::new(0);
    static B_LOCK: AtomicU32 = AtomicU32::new(0);
    let (a_lock, b_lock) = (word_addr(&A_LOCK), word_addr(&B_LOCK));
    const MM: u64 = 0xc650;
    let b = Arc::new(Task::with_class(1664, MM, SchedClass::Normal { weight: 1024 }));
    live::set_current(Arc::clone(&b));
    assert_eq!(futex_pi::pi::lock_pi(b_lock, true, 0, false), 0);

    let a = Arc::new(Task::with_class(1665, MM, SchedClass::Normal { weight: 1024 }));
    let blocked_a = Arc::clone(&a);
    let a_thread = Arc::clone(&a);
    let (owned_tx, owned_rx) = mpsc::channel();
    let (a_tx, a_rx) = mpsc::channel();
    let a_join = std::thread::spawn(move || {
        live::set_current(a_thread);
        assert_eq!(futex_pi::pi::lock_pi(a_lock, true, 0, false), 0);
        owned_tx.send(()).unwrap();
        a_tx.send(futex_pi::pi::lock_pi(b_lock, true, 0, false)).unwrap();
    });
    owned_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    wait_until_parked(&blocked_a);

    let donor = Arc::new(Task::with_class(1666, MM, SchedClass::Deadline));
    donor.set_deadline(500);
    let (blocked_donor, donor_rx, donor_join) =
        spawn_existing_locker(a_lock, Arc::clone(&donor));
    wait_until_parked(&blocked_donor);
    assert_eq!((a.effective_dl_deadline(), b.effective_dl_deadline()), (500, 500));

    donor.set_deadline_raw(300);
    assert_eq!((a.effective_dl_deadline(), b.effective_dl_deadline()), (500, 500),
        "positive control: a raw deadline write cannot rekey a published waiter node");
    donor.set_deadline(100);
    assert_eq!((a.effective_dl_deadline(), b.effective_dl_deadline()), (100, 100),
        "the waiter node, direct owner, and transitive owner must rekey in one table walk");
    assert_eq!((a.sched_class(), b.sched_class()),
        (SchedClass::Deadline, SchedClass::Deadline));

    blocked_donor.set_signal_pending(true);
    // SAFETY: hosted wake unparks this test-owned donor.
    unsafe { live::try_to_wake_up(Arc::clone(&blocked_donor)); }
    assert!(donor_rx.recv_timeout(Duration::from_secs(5)).unwrap() < 0);
    assert_eq!(b.sched_class(), SchedClass::Normal { weight: 1024 });
    live::set_current(Arc::clone(&b));
    assert_eq!(futex_pi::pi::unlock_pi(b_lock, true), 0);
    assert_eq!(a_rx.recv_timeout(Duration::from_secs(5)).unwrap(), 0);
    donor_join.join().unwrap();
    a_join.join().unwrap();
}

#[test]
fn equal_rt_donors_keep_global_waiter_fifo_across_owned_futexes() {
    static A: AtomicU32 = AtomicU32::new(0);
    static B: AtomicU32 = AtomicU32::new(0);
    let ua = word_addr(&A);
    let ub = word_addr(&B);
    let owner = Arc::new(Task::with_class(1671, 0xc700, SchedClass::Normal { weight: 1024 }));
    live::set_current(Arc::clone(&owner));
    assert_eq!(futex_pi::pi::lock_pi(ua, true, 0, false), 0);
    assert_eq!(futex_pi::pi::lock_pi(ub, true, 0, false), 0);
    let (low, low_rx, low_join) = spawn_locker(ua, 1672, 0xc700,
        SchedClass::Rt { prio: 10, policy: SchedPolicy::Fifo });
    wait_until_parked(&low);
    let (first, first_rx, first_join) = spawn_locker(ub, 1673, 0xc700,
        SchedClass::Rt { prio: 50, policy: SchedPolicy::Fifo });
    wait_until_parked(&first);
    let (second, second_rx, second_join) = spawn_locker(ua, 1674, 0xc700,
        SchedClass::Rt { prio: 50, policy: SchedPolicy::Fifo });
    wait_until_parked(&second);
    assert!(Arc::ptr_eq(&owner.pi_top_task_unlocked().unwrap(), &first));

    for (waiter, rx) in [(&first, &first_rx), (&second, &second_rx), (&low, &low_rx)] {
        waiter.set_signal_pending(true);
        // SAFETY: hosted wake only unparks this test-owned waiter thread.
        unsafe { live::try_to_wake_up(Arc::clone(waiter)); }
        assert!(rx.recv_timeout(Duration::from_secs(5)).unwrap() < 0);
    }
    assert_eq!(owner.sched_class(), SchedClass::Normal { weight: 1024 });
    first_join.join().unwrap();
    second_join.join().unwrap();
    low_join.join().unwrap();
}

#[test]
fn futex_words_and_handoffs_use_namespace_visible_thread_ids() {
    static W: AtomicU32 = AtomicU32::new(0);
    let ua = word_addr(&W);
    let owner = Arc::new(Task::new(1681, 0xc800));
    owner.set_visible_tid(81);
    live::set_current(Arc::clone(&owner));
    let lock_rv = futex_pi::pi::lock_pi(ua, true, 0, false);
    let owner_word = W.load(Ordering::SeqCst) & FUTEX_TID_MASK;

    let donor = Arc::new(Task::with_class(1682, 0xc800,
        SchedClass::Rt { prio: 70, policy: SchedPolicy::Fifo }));
    donor.set_visible_tid(82);
    let (waiter, rx, join) = spawn_existing_locker(ua, Arc::clone(&donor));
    wait_until_parked(&waiter);
    live::set_current(Arc::clone(&owner));
    let unlock_rv = futex_pi::pi::unlock_pi(ua, true);
    let handoff_word = W.load(Ordering::SeqCst) & FUTEX_TID_MASK;
    let waiter_rv = rx.recv_timeout(Duration::from_secs(5)).unwrap();
    join.join().unwrap();
    live::set_current(Arc::clone(&donor));
    let final_unlock = futex_pi::pi::unlock_pi(ua, true);

    assert_eq!((lock_rv, unlock_rv, waiter_rv, final_unlock), (0, 0, 0, 0));
    assert_eq!((owner_word, handoff_word), (81, 82));
}

#[test]
fn a_two_owner_pi_cycle_is_rejected_before_the_waiter_is_published() {
    static A_LOCK: AtomicU32 = AtomicU32::new(0);
    static B_LOCK: AtomicU32 = AtomicU32::new(0);
    let (a_lock, b_lock) = (word_addr(&A_LOCK), word_addr(&B_LOCK));
    let a = Arc::new(Task::new(1691, 0xc900));
    let b = Arc::new(Task::new(1692, 0xc900));
    live::set_current(Arc::clone(&a));
    assert_eq!(futex_pi::pi::lock_pi(a_lock, true, 0, false), 0);
    live::set_current(Arc::clone(&b));
    assert_eq!(futex_pi::pi::lock_pi(b_lock, true, 0, false), 0);

    let (blocked_a, a_rx, a_join) = spawn_existing_locker(b_lock, Arc::clone(&a));
    wait_until_parked(&blocked_a);
    live::set_current(Arc::clone(&b));
    let cycle_rv = futex_pi::pi::lock_pi(a_lock, true, 0, true);

    blocked_a.set_signal_pending(true);
    // SAFETY: hosted wake only unparks this test-owned waiter thread.
    unsafe { live::try_to_wake_up(Arc::clone(&blocked_a)); }
    assert!(a_rx.recv_timeout(Duration::from_secs(5)).unwrap() < 0);
    a_join.join().unwrap();
    live::set_current(Arc::clone(&b));
    assert_eq!(futex_pi::pi::unlock_pi(b_lock, true), 0);
    live::set_current(Arc::clone(&a));
    assert_eq!(futex_pi::pi::unlock_pi(a_lock, true), 0);

    assert_eq!(cycle_rv, -(syscall::errno::Errno::Edeadlk.as_i32() as i64));
}

#[test]
fn a_special_deadline_donor_is_borrowed_even_with_a_later_deadline() {
    static W: AtomicU32 = AtomicU32::new(0);
    let ua = word_addr(&W);
    let owner = Arc::new(Task::with_class(1693, 0xca00, SchedClass::Deadline));
    owner.set_deadline(100);
    live::set_current(Arc::clone(&owner));
    assert_eq!(futex_pi::pi::lock_pi(ua, true, 0, false), 0);
    let donor = Arc::new(Task::with_class(1694, 0xca00, SchedClass::Deadline));
    donor.set_deadline(900);
    donor.set_deadline_special(true);
    let (waiter, rx, join) = spawn_existing_locker(ua, Arc::clone(&donor));
    wait_until_parked(&waiter);
    let borrowed = (owner.effective_dl_deadline(), owner.effective_dl_special());
    live::set_current(Arc::clone(&owner));
    assert_eq!(futex_pi::pi::unlock_pi(ua, true), 0);
    assert_eq!(rx.recv_timeout(Duration::from_secs(5)).unwrap(), 0);
    join.join().unwrap();
    live::set_current(donor);
    assert_eq!(futex_pi::pi::unlock_pi(ua, true), 0);
    assert_eq!(borrowed, (900, true));
}

#[test]
fn transient_cmpxchg_contention_is_retried_past_the_old_fixed_limit() {
    static W: AtomicU32 = AtomicU32::new(0);
    let ua = word_addr(&W);
    let owner = Arc::new(Task::new(1695, 0xcb00));
    live::set_current(Arc::clone(&owner));
    useraccess::cmpxchg_eagain_for(ua, 80);
    let rv = futex_pi::pi::lock_pi(ua, true, 0, false);
    let calls = useraccess::cmpxchg_calls();
    if rv == 0 { assert_eq!(futex_pi::pi::unlock_pi(ua, true), 0); }
    assert_eq!(rv, 0);
    assert!(calls > 64, "positive control did not cross the removed retry ceiling");
}
