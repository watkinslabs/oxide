// `RLIMIT_CPU` / `RLIMIT_RTTIME` enforcement against a real task + thread
// group — the wiring `crate::live::cpu_rlimit` performs, as opposed to the
// ladder arithmetic covered by `rlimit::cputime`'s own tests.

use core::sync::atomic::Ordering;

use super::common::normal;
use crate::live::cpu_rlimit::check_cpu_rlimits;
use crate::rlimit::cputime::{NS_PER_SEC, US_PER_SEC};
use crate::rlimit::{rlim, INFINITY};
use crate::signum::Signum;

/// One second of thread-group system time, the quantity `RLIMIT_CPU` bounds.
fn burn_cpu_secs(t: &crate::Task, secs: u64) {
    t.thread_group.charge_cpu(false, secs * NS_PER_SEC);
}

#[test]
fn an_unlimited_task_is_never_signalled() {
    let t = normal(1, 0, 1024);
    burn_cpu_secs(&t, 10_000);
    t.rt_timeout_ns.store(u64::MAX / 2, Ordering::Release);
    assert_eq!(check_cpu_rlimits(&t), 0);
}

#[test]
fn the_cpu_soft_limit_raises_sigxcpu_once_per_second() {
    let t = normal(2, 0, 1024);
    t.set_rlimit(rlim::CPU, (3, INFINITY));
    burn_cpu_secs(&t, 2);
    assert_eq!(check_cpu_rlimits(&t), 0, "under the limit");
    burn_cpu_secs(&t, 1);
    assert_eq!(check_cpu_rlimits(&t), Signum::Sigxcpu.bit());
    // Linux stores `soft + 1` back, which is what keeps the report at 1 Hz:
    // a second check at the same CPU total is silent.
    assert_eq!(t.rlimit(rlim::CPU), (4, INFINITY));
    assert_eq!(check_cpu_rlimits(&t), 0, "the bump suppresses the repeat");
    burn_cpu_secs(&t, 1);
    assert_eq!(check_cpu_rlimits(&t), Signum::Sigxcpu.bit());
    assert_eq!(t.rlimit(rlim::CPU), (5, INFINITY));
}

#[test]
fn the_cpu_hard_limit_kills_and_suppresses_the_soft_report() {
    let t = normal(3, 0, 1024);
    t.set_rlimit(rlim::CPU, (2, 4));
    burn_cpu_secs(&t, 4);
    assert_eq!(check_cpu_rlimits(&t), Signum::Sigkill.bit(),
        "the hard test runs first and returns");
    assert_eq!(t.rlimit(rlim::CPU), (2, 4), "a kill leaves the soft limit alone");
}

#[test]
fn an_infinite_cpu_soft_limit_disarms_the_hard_one() {
    let t = normal(4, 0, 1024);
    t.set_rlimit(rlim::CPU, (INFINITY, 1));
    burn_cpu_secs(&t, 1_000);
    assert_eq!(check_cpu_rlimits(&t), 0);
}

#[test]
fn rlimit_cpu_samples_the_whole_thread_group_not_one_thread() {
    // The limit is process-wide: time charged through the shared thread group
    // is what counts, and the per-thread utime a caller might reach for is not.
    let t = normal(5, 0, 1024);
    t.set_rlimit(rlim::CPU, (1, INFINITY));
    t.utime_ns.store(100 * NS_PER_SEC, Ordering::Release);
    assert_eq!(check_cpu_rlimits(&t), 0, "one thread's own utime is not the sample");
    burn_cpu_secs(&t, 1);
    assert_eq!(check_cpu_rlimits(&t), Signum::Sigxcpu.bit());
}

#[test]
fn rttime_is_per_thread_and_denominated_in_microseconds() {
    let t = normal(6, 0, 1024);
    t.set_rlimit(rlim::RTTIME, (US_PER_SEC, 3 * US_PER_SEC));
    t.rt_timeout_ns.store(NS_PER_SEC - 1_000, Ordering::Release);
    assert_eq!(check_cpu_rlimits(&t), 0);
    t.rt_timeout_ns.store(NS_PER_SEC, Ordering::Release);
    assert_eq!(check_cpu_rlimits(&t), Signum::Sigxcpu.bit());
    // The soft limit steps by one second, expressed in microseconds.
    assert_eq!(t.rlimit(rlim::RTTIME), (2 * US_PER_SEC, 3 * US_PER_SEC));
    t.rt_timeout_ns.store(3 * NS_PER_SEC, Ordering::Release);
    assert_eq!(check_cpu_rlimits(&t), Signum::Sigkill.bit());
}

#[test]
fn both_limits_can_fire_in_one_pass() {
    let t = normal(7, 0, 1024);
    t.set_rlimit(rlim::CPU, (1, INFINITY));
    t.set_rlimit(rlim::RTTIME, (US_PER_SEC, US_PER_SEC));
    burn_cpu_secs(&t, 1);
    t.rt_timeout_ns.store(NS_PER_SEC, Ordering::Release);
    assert_eq!(check_cpu_rlimits(&t), Signum::Sigxcpu.bit() | Signum::Sigkill.bit());
}
