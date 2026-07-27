// getpriority(2) return bias, RLIMIT_NICE units, and the PROCESS-WIDE rlimit
// table (Linux `signal_struct.rlim`).

use alloc::sync::Arc;

use crate::rlimit::{
    nice_to_rlimit, prio_which, rlimit_to_nice, rlim, DEFAULT_RLIMITS, INFINITY, MAX_NICE, MIN_NICE,
};
use crate::{SchedClass, Task};

fn task(tid: u32) -> Task {
    Task::new(tid, "rlimit-prio", SchedClass::Normal { weight: 1024 })
}

/// THE getpriority detail that is most often wrong: the return is biased so it
/// can never look like a negative errno.
#[test]
fn getpriority_return_is_biased_by_20_minus_nice() {
    // Linux `nice_to_rlimit(nice) = MAX_NICE - nice + 1` = `20 - nice`.
    assert_eq!(nice_to_rlimit(0), 20);
    assert_eq!(nice_to_rlimit(MIN_NICE), 40, "highest priority → largest return");
    assert_eq!(nice_to_rlimit(MAX_NICE), 1, "lowest priority → smallest return");
    assert_eq!(nice_to_rlimit(-1), 21);
    assert_eq!(nice_to_rlimit(19), 1);
}

#[test]
fn the_bias_keeps_every_return_out_of_the_errno_range() {
    // An UNBIASED getpriority would return the raw nice value, and a task at
    // nice -3 would produce -3 — indistinguishable from -ESRCH at the libc
    // wrapper. With the bias the range is [1, 40]: never zero, never negative.
    for nice in MIN_NICE..=MAX_NICE {
        let rv = nice_to_rlimit(nice);
        assert!((1..=40).contains(&rv), "nice {nice} → {rv} outside [1,40]");
        assert!(rv > 0, "a biased getpriority return can never look like -errno");
    }
}

#[test]
fn nice_to_rlimit_round_trips_through_rlimit_to_nice() {
    for nice in MIN_NICE..=MAX_NICE {
        assert_eq!(rlimit_to_nice(nice_to_rlimit(nice)), nice);
    }
}

#[test]
fn lower_nice_yields_a_higher_getpriority_result() {
    // getpriority keeps the LARGEST `nice_to_rlimit` across the target set,
    // i.e. the highest-priority (lowest-nice) task.
    assert!(nice_to_rlimit(-5) > nice_to_rlimit(0));
    assert!(nice_to_rlimit(0) > nice_to_rlimit(10));
}

#[test]
fn rlimit_nice_is_expressed_in_the_same_biased_units() {
    // `can_nice` compares `nice_to_rlimit(new_nice)` against RLIMIT_NICE, so a
    // RLIMIT_NICE of 30 permits nice values down to -10 and no further.
    let allowed = 30i32;
    assert_eq!(rlimit_to_nice(allowed), -10);
    assert!(nice_to_rlimit(-10) <= allowed, "nice -10 is within a RLIMIT_NICE of 30");
    assert!(nice_to_rlimit(-11) > allowed, "nice -11 exceeds a RLIMIT_NICE of 30 → EACCES");
    // The default RLIMIT_NICE of 0 permits no reduction at all.
    assert!(nice_to_rlimit(MAX_NICE) > 0, "even nice 19 exceeds a RLIMIT_NICE of 0");
}

#[test]
fn prio_which_selectors_are_the_linux_values() {
    assert_eq!((prio_which::PROCESS, prio_which::PGRP, prio_which::USER), (0, 1, 2));
}

/// Linux keeps rlimits on `signal_struct`, so every thread of a process shares
/// ONE table: `setrlimit(2)` in one thread is immediately visible to a sibling.
#[test]
fn rlimits_are_process_wide_and_shared_across_a_thread_group() {
    let leader = task(9101);
    let mut sibling = task(9102);
    sibling.join_thread_group(Arc::clone(&leader.thread_group));

    assert_eq!(leader.rlimit(rlim::NOFILE), sibling.rlimit(rlim::NOFILE));
    sibling.set_rlimit(rlim::NOFILE, (8192, 16384));
    assert_eq!(leader.rlimit(rlim::NOFILE), (8192, 16384),
        "a sibling thread's setrlimit must be visible to the whole process");

    leader.set_rlimit(rlim::STACK, (1 << 20, INFINITY));
    assert_eq!(sibling.rlimit(rlim::STACK), (1 << 20, INFINITY));
}

/// A separate PROCESS (its own ThreadGroup) must NOT observe another process's
/// limits — the sharing is per thread group, not global.
#[test]
fn a_separate_thread_group_keeps_its_own_table() {
    let a = task(9103);
    let b = task(9104);
    a.set_rlimit(rlim::NOFILE, (64, 64));
    assert_eq!(b.rlimit(rlim::NOFILE), DEFAULT_RLIMITS[rlim::NOFILE],
        "an unrelated process keeps the init defaults");
    assert_ne!(a.rlimit(rlim::NOFILE), b.rlimit(rlim::NOFILE));
}

/// fork(2) (`copy_signal`) seeds the child's fresh table from the parent's.
#[test]
fn fork_inherits_the_whole_table_into_a_fresh_thread_group() {
    let parent = task(9105);
    parent.set_rlimit(rlim::NOFILE, (2048, 4096));
    parent.set_rlimit(rlim::CORE, (1 << 30, INFINITY));
    let child = task(9106);
    child.set_all_rlimits(parent.all_rlimits());
    assert_eq!(child.rlimit(rlim::NOFILE), (2048, 4096));
    assert_eq!(child.rlimit(rlim::CORE), (1 << 30, INFINITY));
    // The copy is a snapshot: a later parent change does not reach the child.
    parent.set_rlimit(rlim::NOFILE, (16, 16));
    assert_eq!(child.rlimit(rlim::NOFILE), (2048, 4096));
}

#[test]
fn every_resource_index_is_addressable_and_defaults_match_linux_init_rlimits() {
    let t = task(9107);
    for i in 0..rlim::COUNT { assert_eq!(t.rlimit(i), DEFAULT_RLIMITS[i]); }
    assert_eq!(t.rlimit(rlim::STACK), (8 * 1024 * 1024, INFINITY), "_STK_LIM");
    assert_eq!(t.rlimit(rlim::NOFILE), (1024, 4096), "NR_OPEN_DEFAULT");
    assert_eq!(t.rlimit(rlim::CORE), (0, INFINITY), "cores disabled by default");
    assert_eq!(t.rlimit(rlim::CPU), (INFINITY, INFINITY));
}
