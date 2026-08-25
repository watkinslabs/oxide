    use super::*;
    use crate::linux_block::core;
    use alloc::boxed::Box;
    use ::core::sync::atomic::{AtomicBool, Ordering};

    static DRAINED: AtomicBool = AtomicBool::new(false);

    #[test]
    fn a_frozen_queue_rejects_new_users_until_the_last_unfreeze() {
        let _modules = crate::test_serial::claim();
        let q = core::blk_alloc_queue(0);
        assert!(!q.is_null());
        // SAFETY: q is the fresh queue allocation owned by this test.
        unsafe {
            bump_depth(q, true);
            assert!(!queue_begin_use(q));
            drop_depth(q, true);
            assert!(queue_begin_use(q));
            queue_end_use(q);
            core::blk_cleanup_queue(q);
        }
    }

    #[test]
    fn freeze_wait_returns_only_after_an_existing_queue_user_releases() {
        let _modules = crate::test_serial::claim();
        DRAINED.store(false, Ordering::Release);
        let q = core::blk_alloc_queue(0);
        assert!(!q.is_null());
        // SAFETY: q is fresh and this test retains the use reference until the worker is joined.
        unsafe {
            assert!(queue_begin_use(q));
            bump_depth(q, true);
        }
        let q_addr = q as usize;
        let waiter = std::thread::spawn(move || {
            // SAFETY: q_addr remains owned by the test until this worker has returned from freeze_wait.
            unsafe { freeze_wait(q_addr as *mut LinuxRequestQueue); }
            DRAINED.store(true, Ordering::Release);
        });
        for _ in 0..1_000 {
            if DRAINED.load(Ordering::Acquire) { break; }
            std::thread::yield_now();
        }
        assert!(!DRAINED.load(Ordering::Acquire));
        // SAFETY: this releases the one admitted use that freeze_wait is waiting to drain.
        unsafe { queue_end_use(q); }
        waiter.join().expect("freeze waiter joins after the final queue user drains");
        assert!(DRAINED.load(Ordering::Acquire));
        // SAFETY: q is still frozen but has no users, so cleanup's nested freeze/wait and reclaim are safe.
        unsafe { core::blk_cleanup_queue(q); }
    }

    #[test]
    fn timed_freeze_wait_returns_the_unchanged_timeout_when_already_drained() {
        let _modules = crate::test_serial::claim();
        let q = core::blk_alloc_queue(0);
        assert!(!q.is_null());
        // SAFETY: q has no queue users, so the timed wait observes its ready predicate before sleeping.
        let remaining = unsafe { blk_mq_freeze_queue_wait_timeout(q, 17) };
        assert_eq!(remaining, 17);
        // SAFETY: q has no users and is owned solely by this test.
        unsafe { core::blk_cleanup_queue(q); }
    }

    #[test]
    fn quiesce_waits_for_tagset_dispatch_and_rejects_later_dispatches() {
        let _modules = crate::test_serial::claim();
        DRAINED.store(false, Ordering::Release);
        // SAFETY: LinuxBlkMqTagSet is a plain C-layout owner supplied by the driver; zero is a valid initial
        // state for its scalar/raw-pointer fields and this test initializes its lifecycle before attaching q.
        let mut set: LinuxBlkMqTagSet = unsafe { ::core::mem::zeroed() };
        set.srcu = Box::into_raw(Box::new(LinuxTagSetLifecycle::new()));
        // SAFETY: the initialized tag set and default limits are owned by this test for q's full lifetime.
        let q = unsafe { blk_mq_alloc_queue(&mut set, ::core::ptr::null(), ::core::ptr::null_mut()) };
        assert!(!q.is_null());
        // SAFETY: q is attached to set and is not frozen/quiesced, so it admits one dispatch to drain later.
        assert!(unsafe { queue_begin_dispatch(q) });
        let q_addr = q as usize;
        let waiter = std::thread::spawn(move || {
            // SAFETY: q remains attached and retained by the dispatch reference until this thread returns.
            unsafe { blk_mq_quiesce_queue(q_addr as *mut LinuxRequestQueue); }
            DRAINED.store(true, Ordering::Release);
        });
        for _ in 0..1_000 {
            if DRAINED.load(Ordering::Acquire) { break; }
            std::thread::yield_now();
        }
        assert!(!DRAINED.load(Ordering::Acquire));
        // SAFETY: q is quiesced while the first dispatch is still counted, so later dispatch admission fails.
        assert!(!unsafe { queue_begin_dispatch(q) });
        // SAFETY: release the first and only dispatch, waking the tag-set drain waiter.
        unsafe { queue_end_dispatch(q); }
        waiter.join().expect("quiesce completes after the in-flight dispatch drains");
        assert!(DRAINED.load(Ordering::Acquire));
        // SAFETY: this reverses the quiesce depth and then tears down the detached queue/tag-set allocations.
        unsafe {
            blk_mq_unquiesce_queue(q);
            assert!(queue_begin_dispatch(q));
            queue_end_dispatch(q);
            core::blk_cleanup_queue(q);
            drop(Box::from_raw(set.srcu));
        }
    }

    #[test]
    fn completion_drain_waits_until_the_tagset_has_no_completed_requests() {
        let _modules = crate::test_serial::claim();
        DRAINED.store(false, Ordering::Release);
        // SAFETY: the test owns this zero-initialized driver tag-set and initializes its lifecycle first.
        let mut set: LinuxBlkMqTagSet = unsafe { ::core::mem::zeroed() };
        set.srcu = Box::into_raw(Box::new(LinuxTagSetLifecycle::new()));
        // SAFETY: q is attached to the initialized tag set and remains owned until the waiter has joined.
        let q = unsafe { blk_mq_alloc_queue(&mut set, ::core::ptr::null(), ::core::ptr::null_mut()) };
        assert!(!q.is_null());
        // SAFETY: q is attached to set; this models one request that has reached MQ_RQ_COMPLETE.
        unsafe { request_mark_complete(q); }
        let set_addr = (&mut set as *mut LinuxBlkMqTagSet) as usize;
        let waiter = std::thread::spawn(move || {
            // SAFETY: set remains valid and owns the completion predicate until this wait returns.
            unsafe { blk_mq_tagset_wait_completed_request(set_addr as *mut LinuxBlkMqTagSet); }
            DRAINED.store(true, Ordering::Release);
        });
        for _ in 0..1_000 {
            if DRAINED.load(Ordering::Acquire) { break; }
            std::thread::yield_now();
        }
        assert!(!DRAINED.load(Ordering::Acquire));
        // SAFETY: this withdraws the sole complete-state request and wakes the drain waiter.
        unsafe { request_unmark_complete(q); }
        waiter.join().expect("completion drain waiter joins after completed request is released");
        assert!(DRAINED.load(Ordering::Acquire));
        // SAFETY: q is detached before its tag-set lifecycle allocation is reclaimed.
        unsafe {
            core::blk_cleanup_queue(q);
            drop(Box::from_raw(set.srcu));
        }
    }
