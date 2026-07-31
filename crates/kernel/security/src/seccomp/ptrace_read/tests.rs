use super::*;
use sched::seccomp_filter::SeccompFilter;
use sched::task::{SchedClass, Task};
use core::sync::atomic::Ordering;

fn confined(tid: u32, chain: &[(&[u64], u64)]) -> Task {
    let t = Task::new(tid, "seccomp", SchedClass::Normal { weight: 1024 });
    t.seccomp_mode.store(SECCOMP_MODE_FILTER as u8, Ordering::Release);
    let mut g = t.seccomp_filters.lock();
    for (prog, flags) in chain { g.push(SeccompFilter::new(prog.to_vec(), *flags)); }
    drop(g);
    t
}

#[test]
fn a_caller_without_cap_sys_admin_is_eacces() {
    assert_eq!(filter_read_allowed(false), Err(Errno::Eacces));
}

#[test]
fn an_unconfined_capable_caller_is_allowed() {
    // `mode_of_current()` is DISABLED with no live task, which is the
    // unconfined case this gate admits.
    assert_eq!(filter_read_allowed(true), Ok(()));
}

#[test]
fn a_task_not_in_filter_mode_is_einval_not_enoent() {
    let t = Task::new(8001, "plain", SchedClass::Normal { weight: 1024 });
    assert_eq!(nth_filter(&t, 0), Err(Errno::Einval));
    // Even STRICT mode, whose chain is legitimately empty.
    t.seccomp_mode.store(SECCOMP_MODE_STRICT as u8, Ordering::Release);
    assert_eq!(nth_filter(&t, 0), Err(Errno::Einval));
}

#[test]
fn offset_zero_names_the_most_recently_installed_filter() {
    let t = confined(8002, &[(&[1, 2], 0), (&[3], 0), (&[4, 5, 6], 0)]);
    assert_eq!(nth_filter(&t, 0), Ok(alloc::vec![4, 5, 6]));
    assert_eq!(nth_filter(&t, 1), Ok(alloc::vec![3]));
    assert_eq!(nth_filter(&t, 2), Ok(alloc::vec![1, 2]));
}

#[test]
fn an_offset_past_the_end_is_enoent() {
    let t = confined(8003, &[(&[1], 0)]);
    assert_eq!(nth_filter(&t, 1), Err(Errno::Enoent));
    assert_eq!(nth_filter(&t, u64::MAX), Err(Errno::Enoent));
}

#[test]
fn metadata_reports_only_the_log_flag() {
    let t = confined(8004, &[
        (&[1], SECCOMP_FILTER_FLAG_LOG | super::super::flags::SECCOMP_FILTER_FLAG_TSYNC),
        (&[2], super::super::flags::SECCOMP_FILTER_FLAG_SPEC_ALLOW),
    ]);
    // Newest first: offset 0 is the SPEC_ALLOW one, which reports nothing.
    assert_eq!(nth_filter_flags(&t, 0), Ok(0));
    // The LOG bit survives; the TSYNC bit installed alongside it does not
    // reach userspace.
    assert_eq!(nth_filter_flags(&t, 1), Ok(SECCOMP_FILTER_FLAG_LOG));
}

#[test]
fn the_flags_travel_with_the_program_across_a_chain_clone() {
    let t = confined(8005, &[(&[9], SECCOMP_FILTER_FLAG_LOG)]);
    let copy: alloc::vec::Vec<SeccompFilter> = t.seccomp_filters.lock().clone();
    let u = Task::new(8006, "child", SchedClass::Normal { weight: 1024 });
    u.seccomp_mode.store(SECCOMP_MODE_FILTER as u8, Ordering::Release);
    *u.seccomp_filters.lock() = copy;
    assert_eq!(nth_filter_flags(&u, 0), Ok(SECCOMP_FILTER_FLAG_LOG));
    assert_eq!(nth_filter(&u, 0), Ok(alloc::vec![9]));
}
