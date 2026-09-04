use super::*;

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
        "a plain wake must not release a requeue-PI waiter without mutex ownership");
    assert!(rx.try_recv().is_err(), "the waiter must still be parked");
    assert_eq!(futex_pi::pi::cmp_requeue_pi(src, dst, 1, 0, 0, true), 1);
    assert_eq!(rx.recv_timeout(Duration::from_secs(5)).expect("requeue-pi wake"), 0);
    assert_eq!(DST.load(Ordering::SeqCst) & FUTEX_TID_MASK, 1903);
    h.join().unwrap();
}

#[test]
fn uncontended_requeue_records_the_proxy_owner_before_attaching_more_waiters() {
    static SRC: AtomicU32 = AtomicU32::new(0);
    static DST: AtomicU32 = AtomicU32::new(0);
    let (src, dst) = (word_addr(&SRC), word_addr(&DST));
    const MM: u64 = 0xf280;
    let first = Arc::new(Task::new(1905, MM));
    let first_watch = Arc::clone(&first);
    let (tx1, rx1) = mpsc::channel();
    let h1 = std::thread::spawn(move || {
        live::set_current(first);
        tx1.send(futex_pi::pi::wait_requeue_pi(src, 0, u32::MAX, dst, true, 0)).unwrap();
    });
    wait_until_parked(&first_watch);

    let second = Arc::new(Task::with_class(1906, MM,
        SchedClass::Rt { prio: 70, policy: SchedPolicy::Fifo }));
    let second_watch = Arc::clone(&second);
    let (tx2, rx2) = mpsc::channel();
    let h2 = std::thread::spawn(move || {
        live::set_current(second);
        tx2.send(futex_pi::pi::wait_requeue_pi(src, 0, u32::MAX, dst, true, 0)).unwrap();
    });
    wait_until_parked(&second_watch);

    live::set_current(Arc::new(Task::new(1907, MM)));
    assert_eq!(futex_pi::pi::cmp_requeue_pi(src, dst, 1, 1, 0, true), 2);
    assert_eq!(rx2.recv_timeout(Duration::from_secs(5)).expect("RT proxy owner wake"), 0);
    assert_eq!(DST.load(Ordering::SeqCst) & FUTEX_TID_MASK, 1906,
        "the highest-priority source waiter must receive proxy ownership");
    assert!(rx1.try_recv().is_err(), "the earlier normal waiter remains queued behind RT");

    live::set_current(Arc::clone(&second_watch));
    assert_eq!(futex_pi::pi::unlock_pi(dst, true), 0);
    assert_eq!(rx1.recv_timeout(Duration::from_secs(5)).expect("normal waiter handoff"), 0);
    assert_eq!(DST.load(Ordering::SeqCst) & FUTEX_TID_MASK, 1905);
    live::set_current(Arc::clone(&first_watch));
    assert_eq!(futex_pi::pi::unlock_pi(dst, true), 0);
    h1.join().unwrap();
    h2.join().unwrap();
}

#[test]
fn equal_priority_requeue_waiters_receive_proxy_ownership_fifo() {
    static SRC: AtomicU32 = AtomicU32::new(0);
    static DST: AtomicU32 = AtomicU32::new(0);
    let (src, dst) = (word_addr(&SRC), word_addr(&DST));
    const MM: u64 = 0xf281;
    let class = SchedClass::Rt { prio: 71, policy: SchedPolicy::Fifo };
    let first = Arc::new(Task::with_class(1951, MM, class));
    let first_watch = Arc::clone(&first);
    let (tx1, rx1) = mpsc::channel();
    let h1 = std::thread::spawn(move || {
        live::set_current(first);
        tx1.send(futex_pi::pi::wait_requeue_pi(src, 0, u32::MAX, dst, true, 0)).unwrap();
    });
    wait_until_parked(&first_watch);
    let second = Arc::new(Task::with_class(1952, MM, class));
    let second_watch = Arc::clone(&second);
    let (tx2, rx2) = mpsc::channel();
    let h2 = std::thread::spawn(move || {
        live::set_current(second);
        tx2.send(futex_pi::pi::wait_requeue_pi(src, 0, u32::MAX, dst, true, 0)).unwrap();
    });
    wait_until_parked(&second_watch);

    live::set_current(Arc::new(Task::new(1953, MM)));
    assert_eq!(futex_pi::pi::cmp_requeue_pi(src, dst, 1, 1, 0, true), 2);
    assert_eq!(rx1.recv_timeout(Duration::from_secs(5)).expect("FIFO proxy owner"), 0);
    assert_eq!(DST.load(Ordering::SeqCst) & FUTEX_TID_MASK, 1951);
    assert!(rx2.try_recv().is_err());
    live::set_current(Arc::clone(&first_watch));
    assert_eq!(futex_pi::pi::unlock_pi(dst, true), 0);
    assert_eq!(rx2.recv_timeout(Duration::from_secs(5)).expect("second FIFO waiter"), 0);
    live::set_current(Arc::clone(&second_watch));
    assert_eq!(futex_pi::pi::unlock_pi(dst, true), 0);
    h1.join().unwrap();
    h2.join().unwrap();
}

#[test]
fn requeue_pi_rejects_an_ordinary_pi_source_before_destination_lookup() {
    static SRC: AtomicU32 = AtomicU32::new(0);
    static DST: AtomicU32 = AtomicU32::new(0);
    let (src, dst) = (word_addr(&SRC), word_addr(&DST));
    const MM: u64 = 0xf282;
    let owner = Arc::new(Task::new(1961, MM));
    live::set_current(Arc::clone(&owner));
    assert_eq!(futex_pi::pi::lock_pi(src, true, 0, false), 0);
    let waiter = Arc::new(Task::new(1962, MM));
    let (watch, rx, join) = spawn_existing_locker(src, waiter);
    wait_until_parked(&watch);
    DST.store(0x00ff_fffe, Ordering::SeqCst);
    let cmp = SRC.load(Ordering::SeqCst);
    assert_eq!(futex_pi::pi::cmp_requeue_pi(src, dst, 1, 1, cmp, true), einval(),
        "source operation mismatch precedes invalid destination-owner lookup");
    assert_eq!(DST.load(Ordering::SeqCst), 0x00ff_fffe);
    DST.store(0, Ordering::SeqCst);
    live::set_current(Arc::clone(&owner));
    assert_eq!(futex_pi::pi::unlock_pi(src, true), 0);
    assert_eq!(rx.recv_timeout(Duration::from_secs(5)).expect("ordinary PI waiter"), 0);
    live::set_current(Arc::clone(&watch));
    assert_eq!(futex_pi::pi::unlock_pi(src, true), 0);
    join.join().unwrap();
}

#[test]
fn requeue_pi_rejects_mixed_destination_keys_without_moving_waiters() {
    static SRC: AtomicU32 = AtomicU32::new(0);
    static DST_A: AtomicU32 = AtomicU32::new(0);
    static DST_B: AtomicU32 = AtomicU32::new(0);
    let (src, dst_a, dst_b) = (word_addr(&SRC), word_addr(&DST_A), word_addr(&DST_B));
    const MM: u64 = 0xf283;
    let first = Arc::new(Task::new(1971, MM));
    let first_watch = Arc::clone(&first);
    let (tx1, rx1) = mpsc::channel();
    let h1 = std::thread::spawn(move || {
        live::set_current(first);
        tx1.send(futex_pi::pi::wait_requeue_pi(src, 0, u32::MAX, dst_a, true, 0)).unwrap();
    });
    wait_until_parked(&first_watch);
    let second = Arc::new(Task::new(1972, MM));
    let second_watch = Arc::clone(&second);
    let (tx2, rx2) = mpsc::channel();
    let h2 = std::thread::spawn(move || {
        live::set_current(second);
        tx2.send(futex_pi::pi::wait_requeue_pi(src, 0, u32::MAX, dst_b, true, 0)).unwrap();
    });
    wait_until_parked(&second_watch);

    live::set_current(Arc::new(Task::new(1973, MM)));
    assert_eq!(futex_pi::pi::cmp_requeue_pi(src, dst_a, 1, 1, 0, true), einval());
    assert_eq!(DST_A.load(Ordering::SeqCst), 0);
    assert!(rx1.try_recv().is_err());
    assert!(rx2.try_recv().is_err());
    for waiter in [&first_watch, &second_watch] {
        waiter.set_signal_pending(true);
        // SAFETY: hosted wake only unparks this test-owned waiter thread.
        unsafe { live::try_to_wake_up(Arc::clone(waiter)); }
    }
    assert!(rx1.recv_timeout(Duration::from_secs(5)).unwrap() < 0);
    assert!(rx2.recv_timeout(Duration::from_secs(5)).unwrap() < 0);
    h1.join().unwrap();
    h2.join().unwrap();
}

#[test]
fn requeued_waiter_timeout_removes_destination_donation() {
    let _clock = fake_clock();
    static SRC: AtomicU32 = AtomicU32::new(0);
    static DST: AtomicU32 = AtomicU32::new(0);
    let (src, dst) = (word_addr(&SRC), word_addr(&DST));
    const MM: u64 = 0xf290;
    let owner = Arc::new(Task::new(1908, MM));
    live::set_current(Arc::clone(&owner));
    assert_eq!(futex_pi::pi::lock_pi(dst, true, 0, false), 0);
    let waiter = Arc::new(Task::with_class(1909, MM,
        SchedClass::Rt { prio: 75, policy: SchedPolicy::Fifo }));
    let watch = Arc::clone(&waiter);
    let (tx, rx) = mpsc::channel();
    let join = std::thread::spawn(move || {
        live::set_current(waiter);
        tx.send(futex_pi::pi::wait_requeue_pi(src, 0, u32::MAX, dst, true, 100)).unwrap();
    });
    wait_until_parked(&watch);
    assert_eq!(futex_pi::pi::cmp_requeue_pi(src, dst, 1, 1, 0, true), 1);
    assert_eq!(owner.sched_class(),
        SchedClass::Rt { prio: 75, policy: SchedPolicy::Fifo });
    FAKE_NOW_NS.store(100, Ordering::SeqCst);
    // SAFETY: hosted wake only unparks this test-owned waiter thread.
    unsafe { live::try_to_wake_up(watch); }
    assert_eq!(rx.recv_timeout(Duration::from_secs(5)).unwrap(),
        -(syscall::errno::Errno::Etimedout.as_i32() as i64));
    join.join().unwrap();
    assert_eq!(owner.sched_class(), SchedClass::Normal { weight: 1024 });
    live::set_current(owner);
    assert_eq!(futex_pi::pi::unlock_pi(dst, true), 0);
}

#[test]
fn requeue_rejects_a_cycle_before_moving_the_waiter() {
    static A_LOCK: AtomicU32 = AtomicU32::new(0);
    static B_LOCK: AtomicU32 = AtomicU32::new(0);
    static SRC: AtomicU32 = AtomicU32::new(0);
    let (a_lock, b_lock, src) = (word_addr(&A_LOCK), word_addr(&B_LOCK), word_addr(&SRC));
    const MM: u64 = 0xf2a0;
    let a = Arc::new(Task::new(1913, MM));
    let b = Arc::new(Task::new(1914, MM));
    live::set_current(Arc::clone(&a));
    assert_eq!(futex_pi::pi::lock_pi(a_lock, true, 0, false), 0);
    live::set_current(Arc::clone(&b));
    assert_eq!(futex_pi::pi::lock_pi(b_lock, true, 0, false), 0);

    let (blocked_a, a_rx, a_join) = spawn_existing_locker(b_lock, Arc::clone(&a));
    wait_until_parked(&blocked_a);
    let blocked_b = Arc::clone(&b);
    let b_watch = Arc::clone(&b);
    let (b_tx, b_rx) = mpsc::channel();
    let b_join = std::thread::spawn(move || {
        live::set_current(blocked_b);
        b_tx.send(futex_pi::pi::wait_requeue_pi(src, 0, u32::MAX, a_lock, true, 0)).unwrap();
    });
    wait_until_parked(&b_watch);

    live::set_current(Arc::new(Task::new(1915, MM)));
    assert_eq!(futex_pi::pi::cmp_requeue_pi(src, a_lock, 1, 1, 0, true),
        -(syscall::errno::Errno::Edeadlk.as_i32() as i64));
    b_watch.set_signal_pending(true);
    // SAFETY: hosted wake only unparks this test-owned waiter thread.
    unsafe { live::try_to_wake_up(Arc::clone(&b_watch)); }
    assert!(b_rx.recv_timeout(Duration::from_secs(5)).unwrap() < 0);
    b_join.join().unwrap();

    live::set_current(Arc::clone(&b));
    assert_eq!(futex_pi::pi::unlock_pi(b_lock, true), 0);
    assert_eq!(a_rx.recv_timeout(Duration::from_secs(5)).unwrap(), 0);
    a_join.join().unwrap();
    live::set_current(a);
    assert_eq!(futex_pi::pi::unlock_pi(a_lock, true), 0);
}

#[test]
fn wait_requeue_pi_retries_an_inatomic_source_read_fault_outside_table() {
    static SRC: AtomicU32 = AtomicU32::new(0);
    static DST: AtomicU32 = AtomicU32::new(0);
    let (src, dst) = (word_addr(&SRC), word_addr(&DST));
    let waiter = Arc::new(Task::new(1911, 0xf300));
    let watch = Arc::clone(&waiter);
    let (tx, rx) = mpsc::channel();
    useraccess::fault_read_on_call(src, 2);
    let join = std::thread::spawn(move || {
        live::set_current(waiter);
        tx.send(futex_pi::pi::wait_requeue_pi(src, 0, u32::MAX, dst, true, 0)).unwrap();
    });
    wait_until_parked(&watch);
    live::set_current(Arc::new(Task::new(1912, 0xf300)));
    assert_eq!(futex_pi::pi::cmp_requeue_pi(src, dst, 1, 0, 0, true), 1);
    assert_eq!(rx.recv_timeout(Duration::from_secs(5)).unwrap(), 0);
    join.join().unwrap();
}

#[test]
fn cmp_requeue_pi_retries_an_inatomic_destination_cmpxchg_fault() {
    static SRC: AtomicU32 = AtomicU32::new(0);
    static DST: AtomicU32 = AtomicU32::new(0);
    let (src, dst) = (word_addr(&SRC), word_addr(&DST));
    let waiter = Arc::new(Task::new(1921, 0xf400));
    let watch = Arc::clone(&waiter);
    let (tx, rx) = mpsc::channel();
    let join = std::thread::spawn(move || {
        live::set_current(waiter);
        tx.send(futex_pi::pi::wait_requeue_pi(src, 0, u32::MAX, dst, true, 0)).unwrap();
    });
    wait_until_parked(&watch);
    live::set_current(Arc::new(Task::new(1922, 0xf400)));
    useraccess::fault_cmpxchg_on_call(dst, 2);
    assert_eq!(futex_pi::pi::cmp_requeue_pi(src, dst, 1, 0, 0, true), 1);
    assert!(useraccess::cmpxchg_calls() >= 4);
    assert_eq!(rx.recv_timeout(Duration::from_secs(5)).unwrap(), 0);
    join.join().unwrap();
}

#[test]
fn cmp_requeue_pi_retries_a_lost_destination_cmpxchg() {
    static SRC: AtomicU32 = AtomicU32::new(0);
    static DST: AtomicU32 = AtomicU32::new(0);
    let (src, dst) = (word_addr(&SRC), word_addr(&DST));
    let waiter = Arc::new(Task::new(1931, 0xf500));
    let watch = Arc::clone(&waiter);
    let (tx, rx) = mpsc::channel();
    let join = std::thread::spawn(move || {
        live::set_current(waiter);
        tx.send(futex_pi::pi::wait_requeue_pi(src, 0, u32::MAX, dst, true, 0)).unwrap();
    });
    wait_until_parked(&watch);
    live::set_current(Arc::new(Task::new(1932, 0xf500)));
    useraccess::mismatch_cmpxchg_on_call(dst, 2);
    let moved = futex_pi::pi::cmp_requeue_pi(src, dst, 1, 0, 0, true);
    if moved != 1 {
        watch.set_signal_pending(true);
        // SAFETY: hosted wake only unparks this test-owned waiter thread.
        unsafe { live::try_to_wake_up(Arc::clone(&watch)); }
    }
    let waiter_result = rx.recv_timeout(Duration::from_secs(5)).unwrap();
    join.join().unwrap();
    assert_eq!(moved, 1, "a changed destination value must restart the requeue transaction");
    assert_eq!(waiter_result, 0);
    assert!(useraccess::mismatch_cmpxchg_calls() >= 4,
        "positive control did not force one lost compare-exchange followed by a retry");
    assert_eq!(DST.load(Ordering::SeqCst) & FUTEX_TID_MASK, 1931);
}

#[test]
fn contended_destination_transfers_one_waiter_when_nr_requeue_is_zero() {
    static SRC: AtomicU32 = AtomicU32::new(0);
    static DST: AtomicU32 = AtomicU32::new(0);
    let (src, dst) = (word_addr(&SRC), word_addr(&DST));
    const MM: u64 = 0xf600;
    let owner = Arc::new(Task::new(1941, MM));
    live::set_current(Arc::clone(&owner));
    assert_eq!(futex_pi::pi::lock_pi(dst, true, 0, false), 0);

    let waiter = Arc::new(Task::with_class(1942, MM,
        SchedClass::Rt { prio: 85, policy: SchedPolicy::Fifo }));
    let watch = Arc::clone(&waiter);
    let (tx, rx) = mpsc::channel();
    let join = std::thread::spawn(move || {
        live::set_current(waiter);
        tx.send(futex_pi::pi::wait_requeue_pi(src, 0, u32::MAX, dst, true, 0)).unwrap();
    });
    wait_until_parked(&watch);

    live::set_current(Arc::new(Task::new(1943, MM)));
    let moved = futex_pi::pi::cmp_requeue_pi(src, dst, 1, 0, 0, true);
    let waiter_result = if moved == 1 {
        assert_ne!(DST.load(Ordering::SeqCst) & FUTEX_WAITERS, 0,
            "destination owner must be forced through PI unlock after transfer");
        assert_eq!(owner.sched_class(),
            SchedClass::Rt { prio: 85, policy: SchedPolicy::Fifo });
        live::set_current(Arc::clone(&owner));
        assert_eq!(futex_pi::pi::unlock_pi(dst, true), 0);
        rx.recv_timeout(Duration::from_secs(5)).unwrap()
    } else {
        watch.set_signal_pending(true);
        // SAFETY: hosted wake only unparks this test-owned waiter thread.
        unsafe { live::try_to_wake_up(Arc::clone(&watch)); }
        let result = rx.recv_timeout(Duration::from_secs(5)).unwrap();
        live::set_current(owner);
        assert_eq!(futex_pi::pi::unlock_pi(dst, true), 0);
        result
    };
    join.join().unwrap();
    assert_eq!(moved, 1,
        "the mandatory wake slot becomes one queued transfer when proxy acquisition blocks");
    assert_eq!(waiter_result, 0);
    live::set_current(watch);
    assert_eq!(futex_pi::pi::unlock_pi(dst, true), 0);
}
