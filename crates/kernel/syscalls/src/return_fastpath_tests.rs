#[test]
fn production_syscall_return_has_no_timer_walk_or_ungated_diag_ring() {
    let dispatch = include_str!("dispatch/core.rs");
    assert!(!dispatch.contains("fire_due_timers"));
    assert!(!dispatch.contains("service_current_timers"));
    assert!(dispatch.contains("#[cfg(any(feature = \"debug-taskdump\", feature = \"debug-polktrace\"))]\n    sched::diag::record_syscall"));
}

#[test]
fn disabled_syscall_tracepoints_stop_at_the_per_task_work_test() {
    let dispatch = include_str!("dispatch/core.rs");
    assert!(dispatch.contains(
        "if !sched::syscall_work::tracepoint_pending(task) { return; }\n    syscall::tracepoint::fire_sys_enter"));
    assert!(dispatch.contains(
        "if !sched::syscall_work::tracepoint_pending(task) { return; }\n    syscall::tracepoint::fire_sys_exit"));
    assert_eq!(dispatch.matches("syscall::tracepoint::fire_sys_enter").count(), 1,
        "entry firing has no bypass around the work-bit owner");
    assert_eq!(dispatch.matches("syscall::tracepoint::fire_sys_exit").count(), 1,
        "exit firing has no bypass around the work-bit owner");
}

#[test]
fn periodic_timer_rearm_is_owned_by_the_timer_mutation_path() {
    let runtime = include_str!("../../sched/src/timers/runtime.rs");
    assert!(!runtime.contains("pub fn fire_due_timers"));
    let rearm = runtime.split("pub fn posixtimer_rearm")
        .nth(1).expect("posixtimer_rearm exists")
        .split("fn cpu_clock_runs_for").next().expect("rearm body");
    assert!(rearm.contains("sync_wall_locked"));
    assert!(rearm.contains("reprogram_posix_timers"));
}

#[test]
fn syscost_profiler_does_not_enable_serial_workload_traces() {
    let manifest = include_str!("../../kmain/Cargo.toml");
    assert!(manifest.contains("debug-syscost = [\"syscalls/debug-syscost\"]"));
    assert!(manifest.contains("debug-syscost-trace = [\"fs/debug-syscost\", \"net/debug-syscost\"]"));
}
