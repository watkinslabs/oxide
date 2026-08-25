use super::*;

fn eagain() -> i64 { -(syscall::errno::Errno::Eagain.as_i32() as i64) }
fn einval() -> i64 { -(syscall::errno::Errno::Einval.as_i32() as i64) }
fn enosys() -> i64 { -(syscall::errno::Errno::Enosys.as_i32() as i64) }
fn etimedout() -> i64 { -(syscall::errno::Errno::Etimedout.as_i32() as i64) }
fn eintr() -> i64 { -(syscall::errno::Errno::Eintr.as_i32() as i64) }

// ---------------------------------------------------------------------------
// EAGAIN / EINVAL — synchronous, no task/thread needed (the checks run
// before `current()` is ever consulted).
// ---------------------------------------------------------------------------

#[test]
fn wait_returns_eagain_when_word_does_not_match() {
    let word = AtomicU32::new(42);
    let uaddr = &word as *const AtomicU32 as u64;
    let rv = futex::wait::dispatch_timed(
        uaddr, FUTEX_WAIT | FUTEX_PRIVATE_FLAG, 999, FUTEX_BITSET_MATCH_ANY, 0);
    assert_eq!(rv, eagain());
}

#[test]
fn wait_returns_einval_on_misaligned_uaddr() {
    // Alignment is checked before any dereference — a bogus-but-nonzero,
    // never-actually-read address is fine here.
    let rv = futex::wait::dispatch_timed(
        0x1001, FUTEX_WAIT | FUTEX_PRIVATE_FLAG, 0, FUTEX_BITSET_MATCH_ANY, 0);
    assert_eq!(rv, einval());
}

#[test]
fn wake_returns_einval_on_misaligned_uaddr() {
    let rv = futex::wait::dispatch(0x2002, FUTEX_WAKE | FUTEX_PRIVATE_FLAG, 1);
    assert_eq!(rv, einval());
}

#[test]
fn wait_bitset_zero_is_einval_not_success() {
    let word = AtomicU32::new(1);
    let uaddr = &word as *const AtomicU32 as u64;
    let rv = futex::wait::dispatch_timed(
        uaddr, FUTEX_WAIT_BITSET | FUTEX_PRIVATE_FLAG, 1, 0, 0);
    assert_eq!(rv, einval(), "Linux __futex_wait: `if (!bitset) return -EINVAL;`");
}

#[test]
fn wake_bitset_zero_is_einval_not_success() {
    let word = AtomicU32::new(1);
    let uaddr = &word as *const AtomicU32 as u64;
    let rv = futex::wait::dispatch_timed(
        uaddr, FUTEX_WAKE_BITSET | FUTEX_PRIVATE_FLAG, 1, 0, 0);
    assert_eq!(rv, einval(), "Linux futex_wake: `if (!bitset) return -EINVAL;`");
}

#[test]
fn robust_wake_releases_word_before_waking() {
    let word = AtomicU32::new(0x1234_5678);
    let pending = AtomicU64::new(u64::MAX);
    let uaddr = &word as *const AtomicU32 as u64;
    live::set_current(Arc::new(Task::new(113, SHARED_MM + 0x11)));

    let rv = futex::wait::dispatch_timed_pending(
        uaddr,
        FUTEX_WAKE | FUTEX_PRIVATE_FLAG | FUTEX_ROBUST_UNLOCK,
        1,
        FUTEX_BITSET_MATCH_ANY,
        0,
        &pending as *const AtomicU64 as u64,
    );

    assert_eq!(rv, 0);
    assert_eq!(word.load(Ordering::SeqCst), 0, "robust wake must release the user word");
    assert_eq!(pending.load(Ordering::SeqCst), 0, "robust wake must clear list_op_pending");
}

#[test]
fn robust_wake_list32_clears_only_the_compat_pointer() {
    let word = AtomicU32::new(9);
    let pending = AtomicU64::new(u64::MAX);
    let uaddr = &word as *const AtomicU32 as u64;
    live::set_current(Arc::new(Task::new(114, SHARED_MM + 0x12)));

    let rv = futex::wait::dispatch_timed_pending(
        uaddr,
        FUTEX_WAKE | FUTEX_PRIVATE_FLAG | FUTEX_ROBUST_UNLOCK | FUTEX_ROBUST_LIST32,
        1,
        FUTEX_BITSET_MATCH_ANY,
        0,
        &pending as *const AtomicU64 as u64,
    );

    assert_eq!(rv, 0);
    assert_eq!(word.load(Ordering::SeqCst), 0);
    assert_eq!(pending.load(Ordering::SeqCst), 0xffff_ffff_0000_0000);
}

#[test]
fn robust_modifier_refuses_non_unlock_commands_before_user_access() {
    let rv = futex::wait::dispatch_timed_pending(
        0,
        FUTEX_WAIT | FUTEX_ROBUST_UNLOCK,
        0,
        FUTEX_BITSET_MATCH_ANY,
        0,
        0,
    );
    assert_eq!(rv, enosys());
}

#[test]
fn robust_wake_pending_fault_leaves_word_released_and_wakes_nobody() {
    let word = AtomicU32::new(17);
    let uaddr = &word as *const AtomicU32 as u64;
    live::set_current(Arc::new(Task::new(115, SHARED_MM + 0x13)));

    let rv = futex::wait::dispatch_timed_pending(
        uaddr,
        FUTEX_WAKE | FUTEX_PRIVATE_FLAG | FUTEX_ROBUST_UNLOCK,
        1,
        FUTEX_BITSET_MATCH_ANY,
        0,
        0,
    );

    assert_eq!(rv, -(syscall::errno::Errno::Efault.as_i32() as i64));
    assert_eq!(word.load(Ordering::SeqCst), 0, "Linux releases before the failing pending clear");
}

#[test]
fn robust_pi_unlock_clears_pending_after_the_owned_word() {
    let word = AtomicU32::new(116);
    let pending = AtomicU64::new(u64::MAX);
    let uaddr = &word as *const AtomicU32 as u64;
    live::set_current(Arc::new(Task::new(116, SHARED_MM + 0x14)));

    let rv = futex::wait::dispatch_timed_pending(
        uaddr,
        FUTEX_UNLOCK_PI | FUTEX_PRIVATE_FLAG | FUTEX_ROBUST_UNLOCK,
        0,
        FUTEX_BITSET_MATCH_ANY,
        0,
        &pending as *const AtomicU64 as u64,
    );

    assert_eq!(rv, 0);
    assert_eq!(word.load(Ordering::SeqCst), 0);
    assert_eq!(pending.load(Ordering::SeqCst), 0);
}

// ---------------------------------------------------------------------------
// Unimplemented ops: honest ENOSYS, never the old silent `0`.
// ---------------------------------------------------------------------------

#[test]
fn unimplemented_ops_return_enosys_never_zero() {
    let word = AtomicU32::new(0);
    let uaddr = &word as *const AtomicU32 as u64;
    // The PI commands are implemented (see `futex_pi_hosted.rs`); what remains
    // ENOSYS is `FUTEX_FD`, which Linux removed, and any unknown command.
    for op in [FUTEX_FD, /* genuinely unknown cmd */ 200] {
        let rv = futex::wait::dispatch(uaddr, op | FUTEX_PRIVATE_FLAG, 0);
        assert_eq!(rv, enosys(), "op {op} must return -ENOSYS, not silent success");
        assert_ne!(rv, 0, "op {op} must never silently report success");
    }
}

// ---------------------------------------------------------------------------
// Real concurrency: two OS threads standing in for two kernel tasks sharing
// one address space (`mm_root`), synchronized only through the production
// `WAITERS` spinlock + double-checked value (the lost-wakeup-window fix).
// ---------------------------------------------------------------------------

const SHARED_MM: u64 = 0x9000;

#[test]
fn futex_wake_reliably_releases_a_concurrently_enqueued_waiter() {
    static WORD: AtomicU32 = AtomicU32::new(7);
    let uaddr = &WORD as *const AtomicU32 as u64;
    let (tx, rx) = mpsc::channel();
    let waiter = Arc::new(Task::new(101, SHARED_MM));
    let waiter_watch = waiter.clone();
    let h = std::thread::spawn(move || {
        live::set_current(waiter);
        let rv = futex::wait::dispatch_timed(
            uaddr, FUTEX_WAIT | FUTEX_PRIVATE_FLAG, 7, FUTEX_BITSET_MATCH_ANY, 0);
        tx.send(rv).unwrap();
    });

    wait_until_parked(&waiter_watch);

    // Waker: distinct task, SAME mm_root (same "process", per-thread private
    // futex keying is (mm_root, va)). Retries are bounded and only cover the
    // test's own thread-startup race, not a correctness gap in the wake
    // path — a real bug here would make this loop exhaust its deadline.
    let waker = Arc::new(Task::new(102, SHARED_MM));
    live::set_current(waker);
    let mut woke = -1i64;
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while std::time::Instant::now() < deadline {
        woke = futex::wait::dispatch(uaddr, FUTEX_WAKE | FUTEX_PRIVATE_FLAG, 1);
        if woke == 1 { break; }
        std::thread::sleep(Duration::from_millis(1));
    }
    assert_eq!(woke, 1, "FUTEX_WAKE must find and wake the concurrently-parked waiter");

    let rv = rx.recv_timeout(Duration::from_secs(5))
        .expect("a real FUTEX_WAKE match must return promptly, never hang");
    assert_eq!(rv, 0, "a real wake takes priority and always reports success");
    h.join().unwrap();
}

#[test]
fn wake_bitset_only_wakes_matching_waiters() {
    static WORD: AtomicU32 = AtomicU32::new(3);
    let uaddr = &WORD as *const AtomicU32 as u64;
    let (tx, rx) = mpsc::channel();
    let waiter = Arc::new(Task::new(111, SHARED_MM + 0x10));
    let waiter_watch = waiter.clone();
    let h = std::thread::spawn(move || {
        live::set_current(waiter);
        // Registers with bitset 0b01 only.
        let rv = futex::wait::dispatch_timed(
            uaddr, FUTEX_WAIT_BITSET | FUTEX_PRIVATE_FLAG, 3, 0b01, 0);
        tx.send(rv).unwrap();
    });
    wait_until_parked(&waiter_watch);

    let waker = Arc::new(Task::new(112, SHARED_MM + 0x10));
    live::set_current(waker);

    // Disjoint bitset: must not match, waiter stays parked.
    let woke = futex::wait::dispatch_timed(
        uaddr, FUTEX_WAKE_BITSET | FUTEX_PRIVATE_FLAG, 1, 0b10, 0);
    assert_eq!(woke, 0, "non-overlapping bitset must not wake the waiter");
    assert!(rx.try_recv().is_err(), "waiter must still be parked");

    // Overlapping bitset: must match and wake it.
    let woke2 = futex::wait::dispatch_timed(
        uaddr, FUTEX_WAKE_BITSET | FUTEX_PRIVATE_FLAG, 1, 0b11, 0);
    assert_eq!(woke2, 1, "overlapping bitset must wake the waiter");
    let rv = rx.recv_timeout(Duration::from_secs(5)).expect("must not hang");
    assert_eq!(rv, 0);
    h.join().unwrap();
}

#[test]
fn wait_timeout_returns_etimedout_not_a_fake_success() {
    // Held for the whole test: the waiter thread below reads this clock too.
    let _clock = fake_clock();
    static WORD: AtomicU32 = AtomicU32::new(9);
    let uaddr = &WORD as *const AtomicU32 as u64;
    let (tx, rx) = mpsc::channel();
    let waiter = Arc::new(Task::new(121, SHARED_MM + 0x20));
    let waiter_watch = waiter.clone();
    let deadline_ns: u64 = 1_000;
    let h = std::thread::spawn(move || {
        live::set_current(waiter);
        let rv = futex::wait::dispatch_timed(
            uaddr, FUTEX_WAIT | FUTEX_PRIVATE_FLAG, 9, FUTEX_BITSET_MATCH_ANY, deadline_ns);
        tx.send(rv).unwrap();
    });
    wait_until_parked(&waiter_watch);

    // Simulate the deadline scanner (`tick_wake_expired`): advance the fake
    // clock past the deadline and wake the task WITHOUT going through
    // `FUTEX_WAKE` (`ttwu_deferred` never touches `WAITERS`, exactly like the
    // real scanner).
    FAKE_NOW_NS.store(deadline_ns + 1, Ordering::SeqCst);
    unsafe { live::try_to_wake_up(waiter_watch.clone()); }

    let rv = rx.recv_timeout(Duration::from_secs(5)).expect("must not hang");
    assert_eq!(rv, etimedout());
    h.join().unwrap();
}

#[test]
fn untimed_wait_returns_erestartsys_on_signal_not_a_fake_success_or_timeout() {
    static WORD: AtomicU32 = AtomicU32::new(5);
    let uaddr = &WORD as *const AtomicU32 as u64;
    let (tx, rx) = mpsc::channel();
    let waiter = Arc::new(Task::new(131, SHARED_MM + 0x30));
    let waiter_watch = waiter.clone();
    // No deadline armed — before the fix this fell through to a bare `0`
    // (fake success) once woken by anything other than FUTEX_WAKE.
    let h = std::thread::spawn(move || {
        live::set_current(waiter);
        let rv = futex::wait::dispatch(uaddr, FUTEX_WAIT | FUTEX_PRIVATE_FLAG, 5);
        tx.send(rv).unwrap();
    });
    wait_until_parked(&waiter_watch);

    // Mimic `signal_wake_up`: mark a signal pending, then wake through the
    // SAME generic ttwu path signal delivery uses — never through
    // `FUTEX_WAKE`/`wake_key`.
    waiter_watch.set_signal_pending(true);
    unsafe { live::try_to_wake_up(waiter_watch.clone()); }

    let rv = rx.recv_timeout(Duration::from_secs(5)).expect("must not hang");
    // No timeout, so `-ERESTARTSYS`
    // reaches the syscall tail untouched and an SA_RESTART handler restarts
    // the wait. A bare EINTR here loses that restart.
    assert_eq!(rv, syscall::restart::restart_sys());
    assert_ne!(rv, eintr());
    assert_eq!(waiter_watch.restart_block.kind(), 0, "an untimed wait arms no block");
    h.join().unwrap();
}

#[test]
fn timed_wait_arms_futex_wait_restart_with_the_same_absolute_deadline() {
    // Held for the whole test: the waiter thread below reads this clock too.
    let _clock = fake_clock();
    static WORD: AtomicU32 = AtomicU32::new(7);
    let uaddr = &WORD as *const AtomicU32 as u64;
    let (tx, rx) = mpsc::channel();
    let waiter = Arc::new(Task::new(132, SHARED_MM + 0x40));
    let waiter_watch = waiter.clone();
    FAKE_NOW_NS.store(1_000, Ordering::SeqCst);
    let deadline = 9_000_000u64;
    let op = FUTEX_WAIT_BITSET | FUTEX_PRIVATE_FLAG;
    let h = std::thread::spawn(move || {
        live::set_current(waiter);
        let rv = futex::wait::dispatch_timed(uaddr, op, 7, FUTEX_BITSET_MATCH_ANY, deadline);
        tx.send(rv).unwrap();
    });
    wait_until_parked(&waiter_watch);
    waiter_watch.set_signal_pending(true);
    unsafe { live::try_to_wake_up(waiter_watch.clone()); }

    let rv = rx.recv_timeout(Duration::from_secs(5)).expect("must not hang");
    // Any timeout arms the wait's own restart function and
    // `set_restart_fn` returns -ERESTART_RESTARTBLOCK.
    assert_eq!(rv, syscall::restart::restart_block());
    assert_eq!(waiter_watch.restart_block.kind(), task::restart::RESTART_FUTEX);
    let a = waiter_watch.restart_block.args();
    assert_eq!(a[0], uaddr);
    assert_eq!(a[1], op as u64);
    assert_eq!(a[2], 7);
    assert_eq!(a[3], FUTEX_BITSET_MATCH_ANY as u64);
    // The ABSOLUTE deadline, verbatim — resuming must run out the REMAINING
    // timeout, never a fresh full one.
    assert_eq!(a[4], deadline);
    h.join().unwrap();
}

#[test]
fn wait_timeout_beats_signal_when_deadline_already_elapsed() {
    // Held for the whole test: the waiter thread below reads this clock too.
    let _clock = fake_clock();
    // Linux `__futex_wait`: `to->task == NULL` (deadline fired) is checked
    // BEFORE `signal_pending`. Mirror that ordering: arm a deadline, let it
    // elapse, ALSO mark a signal pending, then wake — must report
    // ETIMEDOUT, not EINTR.
    static WORD: AtomicU32 = AtomicU32::new(4);
    let uaddr = &WORD as *const AtomicU32 as u64;
    let (tx, rx) = mpsc::channel();
    let waiter = Arc::new(Task::new(141, SHARED_MM + 0x40));
    let waiter_watch = waiter.clone();
    let deadline_ns: u64 = 500;
    let h = std::thread::spawn(move || {
        live::set_current(waiter);
        let rv = futex::wait::dispatch_timed(
            uaddr, FUTEX_WAIT | FUTEX_PRIVATE_FLAG, 4, FUTEX_BITSET_MATCH_ANY, deadline_ns);
        tx.send(rv).unwrap();
    });
    wait_until_parked(&waiter_watch);

    FAKE_NOW_NS.store(deadline_ns + 1, Ordering::SeqCst);
    waiter_watch.set_signal_pending(true);
    unsafe { live::try_to_wake_up(waiter_watch.clone()); }

    let rv = rx.recv_timeout(Duration::from_secs(5)).expect("must not hang");
    assert_eq!(rv, etimedout());
    h.join().unwrap();
}

// ---------------------------------------------------------------------------
// FUTEX_WAKE_OP oparg/cmparg sign-extension fix.
// ---------------------------------------------------------------------------

#[test]
fn wake_op_sign_extends_oparg_for_negative_add() {
    static WORD1: AtomicU32 = AtomicU32::new(0);
    static WORD2: AtomicU32 = AtomicU32::new(10);
    let uaddr1 = &WORD1 as *const AtomicU32 as u64;
    let uaddr2 = &WORD2 as *const AtomicU32 as u64;
    let task = Arc::new(Task::new(151, SHARED_MM + 0x50));
    live::set_current(task);

    // op=ADD(1) cmp=EQ(0, unused, cmparg=0, no wake2) oparg=-1 as a 12-bit
    // two's complement immediate (0xFFF), matching Linux's
    // `sign_extend32(oparg, 11)`. Before the fix, this was read as +4095.
    let encoded: u32 = (1u32 << 28) | (0xFFFu32 << 12);
    let rv = futex::ops::wake_op(uaddr1, uaddr2, 0, 0, encoded, true);
    assert!(rv >= 0, "wake_op must not error on a plain ADD");
    assert_eq!(WORD2.load(Ordering::SeqCst), 9,
        "ADD with sign-extended oparg -1 must decrement 10 -> 9, not wrap to 10+4095");
}

#[test]
fn wake_op_sign_extends_cmparg_for_negative_compare() {
    // Proves the cmparg fix, not just oparg: a waiter parked on uaddr2 only
    // wakes if `oldval == cmparg` after sign-extension. `oldval` is -1; the
    // encoded cmparg field is 0xFFF, which is -1 sign-extended but +4095
    // zero-extended (the pre-fix bug). If cmparg were still read as +4095,
    // the comparison would fail, wake2 would never fire, and the waiter
    // below would time out instead of waking.
    static WORD1: AtomicU32 = AtomicU32::new(0);
    static WORD2: AtomicU32 = AtomicU32::new((-1i32) as u32);
    let uaddr1 = &WORD1 as *const AtomicU32 as u64;
    let uaddr2 = &WORD2 as *const AtomicU32 as u64;

    let (tx, rx) = mpsc::channel();
    let waiter = Arc::new(Task::new(152, SHARED_MM + 0x60));
    let waiter_watch = waiter.clone();
    let h = std::thread::spawn(move || {
        live::set_current(waiter);
        let rv = futex::wait::dispatch_timed(
            uaddr2, FUTEX_WAIT | FUTEX_PRIVATE_FLAG, (-1i32) as u32, FUTEX_BITSET_MATCH_ANY, 0);
        tx.send(rv).unwrap();
    });
    wait_until_parked(&waiter_watch);

    let waker = Arc::new(Task::new(153, SHARED_MM + 0x60));
    live::set_current(waker);
    // op=SET(0) oparg=0 (uaddr2 <- 0, harmless); cmp=EQ(0) cmparg=0xFFF
    // (-1 sign-extended) against oldval(-1) -> must satisfy wake2.
    let encoded: u32 = 0xFFFu32;
    let woken = futex::ops::wake_op(uaddr1, uaddr2, 0, 5, encoded, true);
    assert_eq!(woken, 1, "sign-extended cmparg(-1) must match oldval(-1) and wake the waiter");

    let rv = rx.recv_timeout(Duration::from_secs(5))
        .expect("cmparg sign-extension bug would leave this waiter parked forever");
    assert_eq!(rv, 0);
    assert_eq!(WORD2.load(Ordering::SeqCst), 0, "SET must still apply oparg=0");
    h.join().unwrap();
}

/// The clock guard does the two things the hang needed: it excludes a
/// concurrent driver, and it hands each test a known starting time.
///
/// Without the first, one test rewrites another's notion of "now" and a
/// deadline reads as not-yet-elapsed, sending the wait loop down the
/// reference's genuine spurious-wakeup retry with nothing left to wake it.
/// Without the second, a test inherits whatever time ran last.
#[test]
fn the_fake_clock_guard_excludes_and_resets() {
    let guard = fake_clock();
    assert_eq!(FAKE_NOW_NS.load(Ordering::SeqCst), 0, "acquire resets the clock");
    FAKE_NOW_NS.store(9_999, Ordering::SeqCst);

    // A second acquirer must not get in while the first holds it.
    let entered = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let flag = entered.clone();
    // Read the clock INSIDE the second acquirer's guard. Reading it here after
    // the join would read it with no guard held at all, so whichever test
    // acquired next is what the assertion would see.
    let at_acquire = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(u64::MAX));
    let observed = at_acquire.clone();
    let waiter = std::thread::spawn(move || {
        let _g = fake_clock();
        observed.store(FAKE_NOW_NS.load(Ordering::SeqCst), Ordering::SeqCst);
        flag.store(true, Ordering::SeqCst);
    });
    std::thread::sleep(std::time::Duration::from_millis(50));
    assert!(!entered.load(Ordering::SeqCst), "the clock is held exclusively");
    assert_eq!(FAKE_NOW_NS.load(Ordering::SeqCst), 9_999,
        "nobody else rewrote the clock while it was held");

    drop(guard);
    waiter.join().expect("the second acquirer proceeds once released");
    assert!(entered.load(Ordering::SeqCst));
    assert_eq!(at_acquire.load(Ordering::SeqCst), 0, "and it reset on its acquire too");
}
