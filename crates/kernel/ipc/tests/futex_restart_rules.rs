use ipc::futex_restart::{FutexInterrupt, futex_interrupt};

#[test]
fn an_untimed_wait_takes_the_plain_erestartsys_arm() {
    assert_eq!(futex_interrupt(0), FutexInterrupt::RestartSys);
}

#[test]
fn any_timeout_arms_a_restart_block_absolute_or_relative_alike() {
    // `FUTEX_WAIT`'s relative timeout and `FUTEX_WAIT_BITSET`'s absolute
    // one both reach `futex_wait()` as an absolute deadline, so there is
    // no ABS/REL branch to test — only "has a deadline".
    for dl in [1u64, 1_000, u64::MAX] {
        assert_eq!(futex_interrupt(dl), FutexInterrupt::RestartBlock, "dl={dl}");
    }
}
