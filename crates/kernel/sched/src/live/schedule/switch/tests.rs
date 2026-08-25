    use super::*;
    use super::handoff::finish_lock_switch_pending;
    use super::round::restore_saved_irqs;

    #[test]
    fn pending_switch_handoff_releases_forgotten_rq_guard_once() {
        let idle = Arc::new(Task::new(9000, "idle", SchedClass::Idle));
        let rq = Runqueue::new(0, idle);
        let outgoing = Arc::new(Task::new(
            9001,
            "outgoing",
            SchedClass::Normal { weight: 1024 },
        ));
        outgoing.on_cpu.store(true, Ordering::Release);
        rq.switched_from.store(Arc::as_ptr(&outgoing) as *mut Task, Ordering::Release);

        let guard = rq.inner.lock();
        core::mem::forget(guard);
        assert!(rq.inner.try_lock().is_none(), "test did not retain the rq guard");

        // SAFETY: the test installed the exact non-null handoff token and
        // matching forgotten guard required by the helper.
        assert!(unsafe { finish_lock_switch_pending(&rq) });
        assert!(!outgoing.on_cpu.load(Ordering::Acquire));
        assert!(rq.switched_from.load(Ordering::Acquire).is_null());
        assert!(rq.inner.try_lock().is_some(), "pending handoff left rq locked");

        // SAFETY: no pending token remains; this must be a no-op.
        assert!(!unsafe { finish_lock_switch_pending(&rq) },
            "handoff was consumable more than once");
    }

    #[test]
    fn irq_return_keeps_the_inner_irq_save_masked() {
        assert!(!restore_saved_irqs(true));
        assert!(restore_saved_irqs(false));
    }
