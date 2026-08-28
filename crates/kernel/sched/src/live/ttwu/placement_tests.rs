use super::*;

#[test]
fn wake_of_settled_local_sleeper_enqueues_once() {
    const ME: u32 = 20;
    const OTHER: u32 = 21;
    let cpus = Cpus::new(&[ME, OTHER]);
    let t = settled_sleeper(2001, ME);
    assert!(t.claim_wake());

    place_runnable_with(&|c| cpus.get(c), ME, Arc::clone(&t), false);

    assert_eq!(cpus.trees_holding(2001), 1, "settled local wake must enqueue exactly once");
    assert!(t.on_rq.load(Ordering::Acquire));
}

/// THE BUG. A `wait4` parent claimed by a child exiting on another CPU is
/// still `on_cpu` on its own. Placement must be deferred to the owner's
/// wake-list (Linux `ttwu_queue_wakelist` under
/// `smp_load_acquire(&p->on_cpu)`), never enqueued into the waker's tree.
#[test]
fn wake_of_task_still_on_cpu_elsewhere_is_deferred_not_enqueued() {
    const ME: u32 = 22;
    const OWNER: u32 = 23;
    let cpus = Cpus::new(&[ME, OWNER]);
    let t = parked_but_still_running(2002, OWNER);
    assert!(t.claim_wake(), "the waker legitimately wins the Sleeping->Runnable claim");

    place_runnable_with(&|c| cpus.get(c), ME, Arc::clone(&t), false);

    assert_eq!(cpus.trees_holding(2002), 0,
        "an executing task (on_cpu) was enqueued into a runqueue tree");
    let deferred = wake_list_drain(OWNER);
    assert_eq!(deferred.len(), 1, "wake was not deferred to the owner CPU's wake list");
    assert_eq!(deferred[0].tid, 2002);
}

/// Deterministic reproduction of the boot panic. Runs the pre-fix
/// `wake_wait4_parent` body verbatim — claim the wake, then enqueue on the
/// CALLER's runqueue — and then the exact sequence `schedule()` performs:
/// `pick_next_task` followed by the `on_cpu` compare-exchange whose failure is
/// `hal::kassert!(..., "schedule selected task already owned by another CPU")`.
#[test]
fn prefix_local_enqueue_makes_the_next_pick_fail_the_on_cpu_cas() {
    const ME: u32 = 24;
    const OWNER: u32 = 25;
    let cpus = Cpus::new(&[ME, OWNER]);
    let t = parked_but_still_running(2003, OWNER);
    assert!(t.claim_wake());

    // Pre-fix body, in effect: no on_cpu handshake, no select_task_rq.
    let caller = cpus.get(ME).expect("test cpu installed");
    {
        let mut inner = caller.inner.lock();
        inner.enqueue(Arc::clone(&t));
        caller.nr_running.store(inner.nr_running(), Ordering::Release);
    }
    assert_eq!(cpus.trees_holding(2003), 1, "probe failed to see the local enqueue");

    // ... and now the caller CPU schedules.
    let picked = caller.inner.lock().pick_next_task();
    assert_eq!(picked.tid, 2003, "the pre-fix enqueue is what the next pick selects");
    assert!(picked.on_cpu
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err(),
        "the on_cpu CAS must reject a task another CPU still owns — this is the \
         assertion that panics the boot");
}

/// The same setup routed through the real placement path leaves the caller's
/// tree empty, so its next pick is the idle task and the CAS succeeds.
#[test]
fn deferred_wake_leaves_the_next_pick_cas_clean() {
    const ME: u32 = 26;
    const OWNER: u32 = 27;
    let cpus = Cpus::new(&[ME, OWNER]);
    let t = parked_but_still_running(2004, OWNER);
    assert!(t.claim_wake());

    place_runnable_with(&|c| cpus.get(c), ME, Arc::clone(&t), false);

    let caller = cpus.get(ME).expect("test cpu installed");
    let picked = caller.inner.lock().pick_next_task();
    assert!(matches!(picked.sched_class(), SchedClass::Idle),
        "caller must fall through to idle, not to a task owned by another CPU");
    assert!(picked.on_cpu
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_ok());
    let _ = wake_list_drain(OWNER);
}

/// A settled sleeper whose selected CPU is remote is also deferred — a waker
/// must never take a peer's rq lock (Linux `ttwu_queue_wakelist`).
#[test]
fn wake_selecting_a_remote_cpu_is_deferred_through_its_wake_list() {
    const ME: u32 = 28;
    const REMOTE: u32 = 29;
    let cpus = Cpus::new(&[ME, REMOTE]);
    let t = settled_sleeper(2005, REMOTE);
    // Pin it to REMOTE so select_task_rq cannot choose the local CPU.
    t.cpus_allowed.store(cpu::CpuMask::of(REMOTE as usize), Ordering::Release);
    assert!(t.claim_wake());

    place_runnable_with(&|c| cpus.get(c), ME, Arc::clone(&t), false);

    assert_eq!(cpus.trees_holding(2005), 0, "a waker enqueued onto a peer's runqueue");
    let deferred = wake_list_drain(REMOTE);
    assert_eq!(deferred.len(), 1);
    assert_eq!(deferred[0].tid, 2005);
}

/// `force_defer` (the interrupt-context contract: never touch an rq lock from
/// a context that may have interrupted its owner) defers even a settled,
/// local wake.
#[test]
fn force_defer_never_takes_the_local_runqueue_lock() {
    const ME: u32 = 30;
    const OTHER: u32 = 31;
    let cpus = Cpus::new(&[ME, OTHER]);
    let t = settled_sleeper(2006, ME);
    assert!(t.claim_wake());

    place_runnable_with(&|c| cpus.get(c), ME, Arc::clone(&t), true);

    assert_eq!(cpus.trees_holding(2006), 0);
    let deferred = wake_list_drain(ME);
    assert_eq!(deferred.len(), 1);
    assert_eq!(deferred[0].tid, 2006);
}

/// Ordinary WaitList wakes from hard IRQ use the deferred path, while the
/// softirq tail may take the local rq lock with IRQs saved. This is the Linux
/// `irq_exit` distinction: block completion delivery happens after the
/// hard-IRQ field has been dropped, so it must not pay an extra wake-list hop.
#[test]
fn interrupt_context_requires_deferred_wake_placement() {
    crate::preempt::_test_reset();
    assert!(!wake_context_requires_defer());

    crate::preempt::irq_enter();
    assert!(wake_context_requires_defer(),
        "hardirq wake must use the lock-free wake list");
    crate::preempt::irq_exit();

    crate::preempt::preempt_count_add(crate::preempt::SOFTIRQ_OFFSET);
    assert!(!wake_context_requires_defer(),
        "softirq wake may use the local rq lock after irq_exit");
    crate::preempt::preempt_count_sub(crate::preempt::SOFTIRQ_OFFSET);
    crate::preempt::_test_reset();
}

/// The wake-list drain re-defers a task that is STILL `on_cpu` when its owner
/// gets round to it, rather than enqueuing it (Linux `sched_ttwu_pending`
/// runs after `finish_task_switch` has cleared `on_cpu`).
#[test]
fn drained_wake_of_a_still_running_task_is_re_deferred() {
    const OWNER: u32 = 32;
    let t = parked_but_still_running(2007, OWNER);
    assert!(t.claim_wake());
    assert!(matches!(t.pending_wake(core::ptr::null_mut()), PendingWake::Defer),
        "a task still executing elsewhere must not be reported ready to enqueue");

    t.on_cpu.store(false, Ordering::Release);
    assert!(matches!(t.pending_wake(core::ptr::null_mut()), PendingWake::Ready),
        "once switched off it becomes enqueueable");
}

#[test]
fn on_cpu_handoff_requeues_without_spinning_in_the_irq_tail() {
    const CPU: u32 = 61;
    let cpus = Cpus::new(&[CPU]);
    let rq = cpus.get(CPU).unwrap();
    let t = parked_but_still_running(2010, CPU);
    assert!(t.claim_wake());
    assert!(wake_list_push(CPU, Arc::clone(&t)));
    assert!(!sched_ttwu_pending(CPU, core::ptr::null_mut(), rq));
    assert!(t.on_wake_list.load(Ordering::Acquire),
        "unfinished switch ownership must remain on a wake list");
    assert!(rq.inner.try_lock().is_some(),
        "IRQ-tail wake deferral must not wait while owning the runqueue");

    t.on_cpu.store(false, Ordering::Release);
    assert!(sched_ttwu_pending(CPU, core::ptr::null_mut(), rq));
    assert!(t.on_rq.load(Ordering::Acquire));
}

/// A deferred wake is deliberately shown as unlinked between the lock-free
/// list drain and destination activation.  `on_wake_list` names list
/// membership, not wake ownership: the `Waking` state retains that ownership
/// until `RunqueueInner::enqueue` commits the task.  Keep this transient
/// explicit so a task dump does not turn it into evidence of a lost wake.
#[test]
fn drained_waking_task_is_unlinked_until_destination_activation() {
    const CPU: u32 = 60;
    let cpus = Cpus::new(&[CPU]);
    let rq = cpus.get(CPU).expect("test cpu installed");
    let t = settled_sleeper(2009, CPU);
    assert!(t.claim_wake());
    wake_list_push(CPU, Arc::clone(&t));
    #[cfg(feature = "debug-watchdog")]
    assert_eq!(crate::task::WakeDiagPhase::from_u8(t.wake_diag_phase.load(Ordering::Acquire)),
        crate::task::WakeDiagPhase::Listed);

    let mut drained = wake_list_drain(CPU);
    assert_eq!(drained.len(), 1);
    assert_eq!(t.state(), TaskState::Waking);
    assert!(!t.on_rq.load(Ordering::Acquire));
    assert!(!t.on_cpu.load(Ordering::Acquire));
    assert!(!t.on_wake_list.load(Ordering::Acquire),
        "the drain releases list membership before the destination rq lock");
    #[cfg(feature = "debug-watchdog")]
    assert_eq!(crate::task::WakeDiagPhase::from_u8(t.wake_diag_phase.load(Ordering::Acquire)),
        crate::task::WakeDiagPhase::Drained);

    wake_list_push(CPU, drained.pop().expect("one drained wake"));
    let current = rq.current.load(Ordering::Acquire);
    assert!(sched_ttwu_pending(CPU, current, rq));
    assert_eq!(t.state(), TaskState::Runnable,
        "destination activation must complete the retained wake claim");
    assert!(t.on_rq.load(Ordering::Acquire));
    assert!(!t.on_wake_list.load(Ordering::Acquire));
    #[cfg(feature = "debug-watchdog")]
    assert_eq!(crate::task::WakeDiagPhase::from_u8(t.wake_diag_phase.load(Ordering::Acquire)),
        crate::task::WakeDiagPhase::None);
}

/// The IRQ/idle wrapper must retain the same target-side activation rule as
/// the raw list drainer.  Architecture dispatchers use this wrapper so an
/// interrupt-triggered wake never reaches the task-stack switch tail.
#[test]
fn target_service_wrapper_activates_a_claimed_wake() {
    const CPU: u32 = 62;
    let cpus = Cpus::new(&[CPU]);
    let rq = cpus.get(CPU).expect("test cpu installed");
    let t = settled_sleeper(2011, CPU);

    assert!(t.claim_wake());
    wake_list_push(CPU, Arc::clone(&t));

    assert!(service_pending_on(rq));
    assert_eq!(t.state(), TaskState::Runnable);
    assert!(t.on_rq.load(Ordering::Acquire));
    assert!(!t.on_wake_list.load(Ordering::Acquire));
}

/// `sched_ttwu_pending` consumes the target's claimed wake list; it must not
/// wait for the producer-side wake lock after unlinking it.  The old shape
/// acquired `task_wake_lock` between `wake_list_drain` and activation, so this
/// exact handoff left a Waking task detached indefinitely whenever the waker
/// was delayed while still holding its publication lock.  Linux walks the
/// claimed llist under the target rq lock without reacquiring `p->pi_lock`.
#[test]
fn target_drain_activates_a_claimed_wake_while_producer_lock_is_held() {
    const CPU: u32 = 61;
    let cpus = Cpus::new(&[CPU]);
    let rq = cpus.get(CPU).expect("test cpu installed");
    let t = settled_sleeper(2010, CPU);

    // Model the producer between claiming/listing the wake and dropping its
    // task-side serialization lock.  A pre-fix target drain self-spins here.
    let _producer = t.task_wake_lock.lock_irqsave::<RqIrq>();
    assert!(t.claim_wake());
    wake_list_push(CPU, Arc::clone(&t));

    let current = rq.current.load(Ordering::Acquire);
    assert!(sched_ttwu_pending(CPU, current, rq),
        "the target must activate the claimed list without waiting on its producer");
    assert_eq!(t.state(), TaskState::Runnable);
    assert!(t.on_rq.load(Ordering::Acquire));
    assert!(!t.on_wake_list.load(Ordering::Acquire));
    assert_eq!(cpus.trees_holding(t.tid), 1, "the wake must activate exactly once");
}


/// `select_task_rq_with` honours `cpus_allowed`; a mask that excludes the
/// caller must not resolve to the caller.
#[test]
fn select_task_rq_honours_the_affinity_mask() {
    const ME: u32 = 33;
    const ALLOWED: u32 = 34;
    let cpus = Cpus::new(&[ME, ALLOWED]);
    let t = settled_sleeper(2008, ALLOWED);
    t.cpus_allowed.store(cpu::CpuMask::of(ALLOWED as usize), Ordering::Release);

    assert_eq!(select_task_rq_with(&|c| cpus.get(c), ME, &t), ALLOWED);
}
