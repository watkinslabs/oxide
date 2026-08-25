    use super::*;

    /// A `BhGate` that counts disable/enable and reports whether bottom halves
    /// are currently off — enough to pin the ordering contract without the
    /// scheduler's real `preempt_count`.
    struct CountingBh;
    static BH_DEPTH: core::sync::atomic::AtomicI64 = core::sync::atomic::AtomicI64::new(0);
    static BH_CHECK_DEPTH: core::sync::atomic::AtomicI64 = core::sync::atomic::AtomicI64::new(0);
    /// Set by the fake "softirq" if it ever observes bottom halves enabled
    /// while the lock is still held — the exact bug `lock_bh` must prevent.
    static BH_REENTERED_HELD: AtomicBool = AtomicBool::new(false);

    impl BhGate for CountingBh {
        unsafe fn disable() { BH_DEPTH.fetch_add(1, Ordering::AcqRel); }
        fn check_enable() { BH_CHECK_DEPTH.store(BH_DEPTH.load(Ordering::Acquire), Ordering::Release); }
        unsafe fn enable()  { BH_DEPTH.fetch_sub(1, Ordering::AcqRel); }
    }

    fn bh_disabled() -> bool { BH_DEPTH.load(Ordering::Acquire) > 0 }

    /// A `lock_bh` section must be VISIBLE to the held-lock trace.
    ///
    /// Every sleep-while-atomic report inside one printed `held=[]` and named
    /// no lock, because this was the single acquisition that never joined the
    /// trace. The report exists to turn a count into a call site; blind to the
    /// bh path it could not.
    #[cfg(feature = "debug-preempt")]
    #[test]
    fn a_bh_section_is_visible_to_the_held_lock_trace() {
        let _serial = crate::test_serial::gate();
        let s: Spinlock<u32, Buddy> = Spinlock::new(0);
        let outside = crate::preempt_gate::held_trace().1;
        {
            let _g = s.lock_bh::<CountingBh>();
            let (rank, depth, _) = crate::preempt_gate::held_trace();
            assert_eq!(depth, outside + 1, "the bh section must appear in the trace");
            assert_eq!(rank, Buddy::rank(), "and name the class it locked");
        }
        assert_eq!(crate::preempt_gate::held_trace().1, outside, "and leave when it does");
    }

    /// ...while changing nothing beyond the canonical gate's own accounting.
    /// The trace helper must not add another credit beside the gate.
    #[test]
    fn joining_the_trace_does_not_change_the_bottom_half_accounting() {
        BH_DEPTH.store(0, Ordering::Release);
        let s: Spinlock<u32, Buddy> = Spinlock::new(0);
        {
            let _g = s.lock_bh::<CountingBh>();
            assert_eq!(BH_DEPTH.load(Ordering::Acquire), 1, "exactly one bh disable");
        }
        assert_eq!(BH_DEPTH.load(Ordering::Acquire), 0, "and exactly one enable");
    }

    #[test]
    fn lock_bh_excludes_softirqs_for_the_whole_critical_section() {
        BH_DEPTH.store(0, Ordering::Release);
        BH_REENTERED_HELD.store(false, Ordering::Release);
        let s: Spinlock<u32, Buddy> = Spinlock::new(0);
        assert!(!bh_disabled());
        {
            let mut g = s.lock_bh::<CountingBh>();
            // The whole critical section runs with bottom halves off; a softirq
            // that took this lock plainly could not run here.
            assert!(bh_disabled(), "spin_lock_bh must hold BH off across the section");
            *g = 7;
            assert!(bh_disabled());
        }
        // Balanced on drop, and re-enabled only after release.
        assert!(!bh_disabled(), "spin_unlock_bh must re-enable bottom halves");
        assert!(!BH_REENTERED_HELD.load(Ordering::Acquire));
        assert_eq!(*s.lock(), 7);
    }

    #[test]
    fn lock_bh_releases_before_reenabling_so_a_drain_can_take_the_lock() {
        // `local_bh_enable` drains inline, and a handler in that drain may take
        // the same lock. Model it: the gate's `enable` tries the lock and must
        // succeed, proving the release already happened.
        static TAKEN_IN_DRAIN: AtomicBool = AtomicBool::new(false);
        static LK: Spinlock<u32, Buddy> = Spinlock::new(0);
        struct DrainingBh;
        impl BhGate for DrainingBh {
            unsafe fn disable() {}
            unsafe fn enable() {
                // Stands in for a softirq handler run by the inline drain.
                TAKEN_IN_DRAIN.store(LK.try_lock().is_some(), Ordering::Release);
            }
        }
        {
            let mut g = LK.lock_bh::<DrainingBh>();
            *g = 1;
        }
        assert!(
            TAKEN_IN_DRAIN.load(Ordering::Acquire),
            "lock must be released before local_bh_enable drains, or the drain self-deadlocks"
        );
    }

    #[test]
    fn lock_bh_checks_the_pair_before_enabling() {
        let _serial = crate::test_serial::gate();
        BH_DEPTH.store(0, Ordering::Release);
        BH_CHECK_DEPTH.store(0, Ordering::Release);
        let lock = Spinlock::<(), Buddy>::new(());
        drop(lock.lock_bh::<CountingBh>());
        assert_eq!(BH_CHECK_DEPTH.load(Ordering::Acquire), 1,
            "diagnostic must observe the outstanding disable credit");
        assert_eq!(BH_DEPTH.load(Ordering::Acquire), 0);
    }

    #[test]
    fn noop_bh_gate_is_inert() {
        let s: Spinlock<u32, Buddy> = Spinlock::new(3);
        {
            let mut g = s.lock_bh::<NoopBh>();
            *g += 1;
        }
        assert_eq!(*s.lock(), 4);
    }

    #[test]
    fn lock_round_trip() {
        let s: Spinlock<u32, Buddy> = Spinlock::new(0);
        {
            let mut g = s.lock();
            *g = 42;
        }
        assert_eq!(*s.lock(), 42);
    }

    #[test]
    fn try_lock_fails_when_held() {
        let s: Spinlock<u32, Buddy> = Spinlock::new(7);
        let g = s.lock();
        assert!(s.try_lock().is_none());
        drop(g);
        assert!(s.try_lock().is_some());
    }

    #[test]
    fn irqsave_round_trip_noop() {
        let s: Spinlock<u32, Buddy> = Spinlock::new(0);
        let mut g = s.lock_irqsave::<NoopIrq>();
        *g = 99;
        drop(g);
        assert_eq!(*s.lock(), 99);
    }

    #[test]
    fn lock_classes_have_distinct_ranks() {
        assert!(Buddy::rank() < Slab::rank());
        assert!(Slab::rank() < PageTable::rank());
        // kernfs node locks sit strictly between Dentry and Superblock so a
        // pseudo-fs may hold its structural lock WHILE taking the SB icache
        // lock (iget) — ascending, deadlock-free. (inode D2 lock-rank reorder.)
        assert!(Dentry::rank() < Kernfs::rank());
        assert!(Kernfs::rank() < Superblock::rank());
    }

