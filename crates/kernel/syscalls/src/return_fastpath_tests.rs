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
    assert!(manifest.contains("debug-syscost-trace = [\"fs/debug-syscost\", \"net/debug-syscost\", \"syscalls/debug-syscost-trace\"]"));
    let poll = include_str!("007_poll.rs");
    assert!(poll.contains("#[cfg(feature = \"debug-syscost-trace\")]"));
    assert!(!poll.contains("#[cfg(feature = \"debug-syscost\")]"));
}

#[test]
fn syscall_process_irqs_close_before_return_work() {
    let dispatch = include_str!("dispatch/core.rs");
    let enable = dispatch.find("ProcessIrqs::enable()").expect("process IRQ guard");
    let route = dispatch.find("dispatch_route_a(nr, &args)").expect("syscall routes");
    let close = dispatch.rfind("drop(process_irqs);").expect("IRQ guard close");
    // Match the call by receiver and leading arguments, not its whole signature:
    // a parameter added to the tail must not read as a missing call site. The
    // prefix still excludes the prose above the call, which names the function
    // without opening an argument list.
    let exit = dispatch.find("exit_to_user_mode_loop(regs, Some(rv)").expect("return work");
    assert!(enable < route, "IRQs enabled before ordinary syscall work");
    assert!(route < close, "IRQs stay enabled through syscall work");
    assert!(close < exit, "IRQs masked before return-work flag checks");
    assert!(dispatch.contains("drop(process_irqs);\n        sched::cpustat::user_enter();\n        return rv;"),
        "early user-dispatch return closes the IRQ guard");
}

#[test]
fn process_fault_stubs_inherit_saved_irq_state() {
    let x86 = include_str!("../../../arch/hal-x86_64/src/fault/stubs.rs");
    let vector = x86.find("cmp  qword ptr [rsp + 0x78], 14").expect("#PF classifier");
    let saved_if = x86.find("test qword ptr [rsp + 0x98], 0x200").expect("saved IF test");
    let enable = x86[saved_if..].find("\"    sti\"").expect("process IRQ enable") + saved_if;
    let call = x86.find("call oxide_fault_print_rust").expect("fault dispatch");
    let mask = x86[call..].find("\"    cli\"").expect("exit IRQ mask") + call;
    assert!(vector < saved_if && saved_if < enable && enable < call && call < mask);

    let arm = include_str!("../../../arch/hal-aarch64/src/vbar/asm.rs");
    let classify = arm.find("cmp  x9, #0x20").expect("abort classifier");
    let saved_i = arm.find("tbnz x9, #7, 9f").expect("saved DAIF.I test");
    let enable = arm[saved_i..].find("msr  daifclr, #2").expect("process IRQ enable") + saved_i;
    let call = arm.find("bl   oxide_fault_print_rust").expect("fault dispatch");
    let mask = arm[call..].find("msr  daifset, #2").expect("exit IRQ mask") + call;
    assert!(classify < saved_i && saved_i < enable && enable < call && call < mask);
}
