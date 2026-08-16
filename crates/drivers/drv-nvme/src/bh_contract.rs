// The bottom-half contract for this driver's locks, checked on the source.
//
// The completion path runs in the shared block-completion SOFTIRQ. Every lock
// the driver holds is therefore shared between process context and a softirq
// that can land on the same CPU, and the reference's rule for that lock is
// `spin_lock_bh`: a plain process-context hold is a one-CPU self-deadlock the
// moment the softirq interrupts the owner and spins for what it interrupted.
//
// Measured before this contract existed, from a peer CPU's stall report:
//
//   [CPU-STALL] cpu=0 no heartbeat for 10s ... syscall=read
//   preempt_count=0x103 resched=1
//   held=[100@.../imp/request.rs:140 100@.../imp/request.rs:141
//         100@.../imp/request.rs:238]
//
// — the controller lock taken by `enqueue_or_post`, the request lock beside
// it, and then the SAME controller lock again from `take_completed`, with the
// softirq field of the count raised: the block-completion softirq landed on a
// CPU whose process context already owned the controller. The guest ran on
// past a login prompt with that CPU parked. The sibling AHCI driver took the
// same fault twice (B2007/B2008) and answered it the same way.
//
// `imp` is compiled only into the kernel target, so no hosted test can call
// this code. The property is still checkable: every acquisition in it must be
// the `lock_bh` form, and that is a fact about the source.

#[cfg(test)]
mod tests {
    const SOURCES: &[(&str, &str)] = &[
        ("imp/request.rs", include_str!("imp/request.rs")),
        ("imp/reset.rs", include_str!("imp/reset.rs")),
        ("imp/watchdog.rs", include_str!("imp/watchdog.rs")),
    ];

    /// No bare `.lock()` anywhere the completion softirq can reach — which,
    /// the drain being able to run on any CPU at any bh-enable point, is
    /// everywhere.
    #[test]
    fn every_acquisition_in_the_softirq_shared_driver_is_the_bottom_half_form() {
        for (name, src) in SOURCES {
            for (n, line) in src.lines().enumerate() {
                assert!(!line.contains(".lock()"),
                    "{name}:{}: a bare `.lock()` on a lock the block-completion \
                     softirq also takes self-deadlocks the CPU it interrupts; \
                     use `.lock_bh::<crate::imp::NvmeBh>()`\n  {}",
                    n + 1, line.trim());
            }
        }
    }

    /// ...and the bottom-half form is actually present, so the check above
    /// cannot pass merely because a file stopped locking anything.
    #[test]
    fn the_bottom_half_form_is_the_one_in_use() {
        let request = SOURCES[0].1;
        assert!(request.matches("lock_bh::<crate::imp::NvmeBh>()").count() >= 10,
            "the request path should still take its locks, in the bh form");
    }
}
