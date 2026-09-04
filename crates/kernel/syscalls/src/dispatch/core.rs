#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use super::ptrace::ptrace_syscall_stop_if_armed;

/// Value a tracer sees in the ABI return register at a PTRACE_SYSCALL
/// *entry* stop. Linux stores `-ENOSYS` there before running the handler so a
/// tracer can distinguish entry from exit (`syscall_trace_enter`).
const ENOSYS_AT_ENTRY_STOP: u64 = (-(syscall::errno::Errno::Enosys.as_i32() as i64)) as u64;
use super::route_a::dispatch_route_a;
use super::route_b::dispatch_route_b;
use super::route_c::dispatch_route_c;

/// Linux `SYSCALL_WORK_SYSCALL_TRACEPOINT` entry side. The disabled path stops
/// at the current task's syscall-work word and never enters the AtomicPtr hook
/// wrapper. # C: O(1)
#[inline]
fn fire_sys_enter_if_armed(task: Option<&sched::Task>, nr: u32, args: &SyscallArgs) {
    if !sched::syscall_work::tracepoint_pending(task) { return; }
    syscall::tracepoint::fire_sys_enter(nr, args);
}

/// Linux `syscall_exit_work` tracepoint leg. Re-read the task word at exit: an
/// event may have been enabled or disabled while this syscall slept. # C: O(1)
#[inline]
fn fire_sys_exit_if_armed(task: Option<&sched::Task>, nr: u32, rv: i64, args: &SyscallArgs) {
    if !sched::syscall_work::tracepoint_pending(task) { return; }
    syscall::tracepoint::fire_sys_exit(nr, rv, args);
}

/// The pre-call entry work — `syscall_trace_enter`'s ptrace stop, the
/// post-stop number re-read, and the seccomp filter — in a frame of its own.
///
/// Returns `(skip_value, abi_syscall_number)`: `Some(rv)` means do not run the
/// call and send `rv` down the normal exit path; the number is the one to
/// dispatch on, which a tracer may have rewritten.
/// # C: O(1) plus the filter's own cost
#[inline(never)]
fn syscall_entry_work(orig_nr: u64, args: &SyscallArgs) -> (Option<u64>, u64) {
    let aborted = ptrace_syscall_stop_if_armed(ENOSYS_AT_ENTRY_STOP, true);
    let abi_nr = super::ptrace::syscall_nr_after_entry_stop(orig_nr);
    let outcome = crate::dispatch_entry_order::entry_work(
        aborted, abi_nr, ENOSYS_AT_ENTRY_STOP,
        |n| super::seccomp::seccomp_gate(n,
            &[args.a0, args.a1, args.a2, args.a3, args.a4, args.a5]));
    match outcome {
        crate::dispatch_entry_order::EntryOutcome::Skip(rv) => (Some(rv), abi_nr),
        crate::dispatch_entry_order::EntryOutcome::Run(nr)  => (None, nr),
    }
}

#[inline(never)]
fn dispatch_routed_syscall(entry: (Option<u64>, u64), nr: u64, args: &SyscallArgs) -> i64 {
    if let Some(rv) = entry.0 { return rv as i64; }
    // Real Wine win32u PE stubs use their generated raw ordinal namespace
    // rather than Oxide's tagged synthetic dispatcher entry. Only an NT task
    // may claim this otherwise-unreserved raw number.
    if sched::live::current().is_some_and(|task| task.is_nt_personality()) {
        if let Some(rv) = crate::nt_wine_window::dispatch_raw(nr, *args) { return rv as i64; }
    }
    // A tagged NT word is consumed before the Linux number tables. The common
    // syscall entry/return frame is retained, but no Linux handler can claim
    // an NT service selector; the adapter separately checks NT task state.
    if let Some(call) = crate::nt_dispatch::decode_entry(nr, *args) {
        if let Some(rv) = crate::nt_exec::dispatch(call) { return rv as i64; }
        return crate::nt_dispatch::dispatch(call) as i64;
    }
    if let Some(rv) = dispatch_route_a(nr, args) { return rv; }
    if let Some(rv) = dispatch_route_b(nr, args) { return rv; }
    if let Some(rv) = dispatch_route_c(nr, args) { return rv; }
    if let Some(rv) = sched::cred::cred_dispatch(nr, args) { return rv; }
    if let Some(rv) = sched::timers::timer_dispatch(nr, args) { return rv; }
    if let Some(rv) = crate::perms::perms_dispatch(nr, args) { return rv; }
    if let Some(rv) = ::fs::keyring::keyring_dispatch(nr, args) { return rv; }
    if let Some(rv) = sched::compat::try_compat(nr, args) { return rv; }
    -(syscall::Errno::Enosys.as_i32() as i64)
}

#[no_mangle]
pub unsafe extern "C" fn oxide_syscall_dispatch(
    nr: u64, a0: u64, a1: u64, a2: u64, a3: u64, a4: u64,
    #[cfg(target_arch = "aarch64")] entry_frame: *mut hal_aarch64::SvcFrame,
) -> u64 {
    if nr >> 32 == syscall::nt::NT_SERVICE_NAMESPACE >> 32 {
        klog::write_raw(b"[WINDOWS-PE-RAW-NT] nr="); klog::write_hex_u64(nr);
        klog::write_raw(b" service="); klog::write_hex_u64(nr & 0xffff_ffff);
        klog::write_raw(b" a0="); klog::write_hex_u64(a0);
        klog::write_raw(b" a1="); klog::write_hex_u64(a1);
        klog::write_raw(b" a2="); klog::write_hex_u64(a2); klog::write_raw(b"\n");
    }
    // Linux `vtime_user_exit`: the architectural syscall entry has crossed
    // into kernel mode; close the user interval before any dispatch work.
    sched::cpustat::user_exit();
    let dispatch_task = sched::current();
    // Linux hands `pt_regs *` from el0_svc directly to the syscall path. Bind
    // that same explicit entry argument to the task BEFORE opening IRQs. The
    // old order opened IRQs and then re-read a per-CPU cache; a switch to a
    // first-syscall task could replace it with zero in between.
    #[cfg(target_arch = "aarch64")]
    let process_irqs = crate::dispatch_frame_order::bind_then_enable(
        entry_frame,
        |frame| {
            if let Some(task) = dispatch_task {
                task.security.svc_frame.store(frame as u64, core::sync::atomic::Ordering::Release);
            }
        },
        super::process_irq::ProcessIrqs::enable,
    );
    // Architectural entry masks IRQs while it saves the user frame. Ordinary
    // syscall work is process context: timers, completion IRQs and wakeups
    // must run while it blocks. Dropping this guard restores the entry mask
    // before the return-to-user work loop starts its flag-check discipline.
    #[cfg(target_arch = "x86_64")]
    let process_irqs = super::process_irq::ProcessIrqs::enable();
    let orig_nr = nr;
    #[cfg(target_arch = "aarch64")]
    let nr = syscall::arm_abi::aarch64_nr_to_x86(nr);
    debug_ssh! { crate::signal_trace::dispatch_entry(orig_nr, nr); }
    // SAFETY: `syscall_a5` reads the sixth argument out of the per-CPU entry
    // save block, which the arch stub filled for THIS syscall before calling
    // here and which nothing else writes until the next entry.
    let a5 = unsafe { crate::syscall_a5::read() };
    let args = SyscallArgs { a0, a1, a2, a3, a4, a5 };
    let is_nt_entry = crate::nt_dispatch::decode_entry(nr, args).is_some();
    if let Some(task) = dispatch_task {
        task.record_syscall_snapshot(sched::SyscallSnapshot {
            nr: orig_nr as u32,
            args: [a0, a1, a2, a3, a4, a5],
            sp: crate::arch_frame::current_user_sp(),
            ip: crate::arch_frame::current_user_pc(),
        });
    }
    let entry = if is_nt_entry {
        (None, nr)
    } else {
    // Linux rseq syscall-entry work revokes a current slice grant before any
    // tracer, filter, or syscall body can observe this kernel entry.
    sched::rseq::slice_syscall_enter(nr);
    if let Some(c) = sched::current() {
        c.note_syscall(nr as u32);
        // Per-syscall checkpoint (state.md: stack-guard-wipe hunt) — `current_ref`
        // alone only checks at scheduler-internal touchpoints (~a dozen call
        // sites), giving a multi-second resolution window on when a hit
        // actually happened. Every syscall entry, for every task, gives
        // per-syscall resolution instead: a no-op when the guard is intact
        // (the common case), and on a hit, bisects the wipe to "between this
        // task's last two syscalls" rather than "somewhere in the last several
        // seconds of boot".
        c.debug_check_canary("syscall_entry");
    }
    #[cfg(feature = "debug-sshd")]
    trace_sshd_listener_enter(nr, &args);
    #[cfg(feature = "debug-swap")]
    trace_swapon_process(b"enter", nr, None);
    fire_sys_enter_if_armed(dispatch_task, nr as u32, &args);
    debug_syscall! { sched::trace::entry(nr, a0, a1, a2, a3); }
    debug_gnome_syscall! { sched::trace::entry(nr, a0, a1, a2, a3); }
    #[cfg(feature = "debug-desktop")]
    trace_mutter_syscall(b"enter", nr, a0, a1, a2, a3, a4, a5, None);
    // seccomp sees the syscall number AS THE CALLING ABI NUMBERS IT. This
    // dispatcher remaps aarch64's generic-ABI number onto the x86_64 numbering
    // it dispatches on (`aarch64_nr_to_x86` above), but that is an internal
    // detail: `seccomp_data.arch` reports AUDIT_ARCH_AARCH64, so
    // `seccomp_data.nr` must be the arm64 number the caller actually used.
    // Feeding the translated number instead makes every libseccomp filter
    // compiled for arm64 miss every `nr` comparison and fall through to its
    // default action — SCMP_ACT_KILL or a blanket errno — which kills or
    // corrupts any confined process on aarch64 while behaving on x86_64.
    // Syscall user dispatch runs FIRST — before ptrace and before seccomp.
    // A dispatched call's ABI is whatever foreign personality the userspace
    // handler emulates, so neither a tracer nor a cBPF filter compiled for
    // THIS ABI may be shown its arguments.
    if let Some(rv) = super::user_dispatch::user_dispatch_gate(orig_nr, a0) {
        drop(process_irqs);
        sched::cpustat::user_enter();
        return rv;
    }
    // The ptrace entry stop runs BEFORE seccomp, and the number is re-read
    // afterwards, so a tracer's rewrite is what the filter judges and what the
    // dispatcher runs. The reverse order let a tracer substitute a call the
    // filter had already approved under a different number.
    // Kept in its own non-inlined frame: its locals would otherwise sum into
    // this function's, which sits on the deepest aarch64 syscall chain the
    // stack gate measures. The entry work is a shallow sibling of the routes.
    syscall_entry_work(orig_nr, &args)
    };
    #[cfg(target_arch = "aarch64")]
    let nr = if entry.1 == orig_nr { nr } else { syscall::arm_abi::aarch64_nr_to_x86(entry.1) };
    #[cfg(not(target_arch = "aarch64"))]
    let nr = entry.1;
    #[cfg(feature = "debug-syscost")]
    let __syscost = crate::syscost::start();
    #[cfg(feature = "debug-startlat")]
    let __startlat = crate::startlat::start();
    // A skipped call does NOT return early: it falls through to the exit tail
    // below, so its syscall-exit stop and — for a `SECCOMP_RET_TRAP` SIGSYS —
    // its signal delivery happen before the return to userspace instead of
    // waiting for the next timer tick.
    let rv = dispatch_routed_syscall(entry, nr, &args);
    // rv is left un-normalized here (may still carry an internal restart
    // sentinel like -ERESTARTSYS) — the ignored-restart check below and
    // dispatch_pending() need the raw sentinel. normalize_user_return()
    // runs once, at the final return, per docs/38 restart ABI.
    #[cfg(feature = "debug-syscall-return")]
    let return_task = sched::live::current();
    if !is_nt_entry {
    #[cfg(feature = "debug-syscall-return")]
    if let Some(task) = return_task {
        sched::diag::syscall_return_stage(task, sched::diag::SYSCALL_RETURN_STAGE_AFTER_DISPATCH);
    }
    #[cfg(feature = "debug-swap")]
    trace_swapon_process(b"exit", nr, Some(rv));
    debug_syscall! { sched::trace::ret(nr, rv); }
    debug_gnome_syscall! { sched::trace::ret(nr, rv); }
    #[cfg(feature = "debug-desktop")]
    trace_mutter_syscall(b"exit", nr, a0, a1, a2, a3, a4, a5, Some(rv));
    fire_sys_exit_if_armed(dispatch_task, nr as u32, rv, &args);
    debug_sched! {
        klog::write_raw(b"[INFO]  syscall: nr=");
        klog::write_hex_u64(nr);
        klog::write_raw(b" rv=");
        klog::write_hex_u64(rv as u64);
        klog::write_raw(b"\n");
    }
    debug_ssh! { crate::signal_trace::syscall_nr_rv(nr, rv); }
    #[cfg(feature = "debug-sshd-detail")]
    trace_sshd_syscall(nr, rv);
    #[cfg(feature = "debug-sshd")]
    trace_sshd_listener_exit(nr, rv);
    #[cfg(feature = "debug-random-seed")]
    trace_random_seed_syscall(nr, rv);
    #[cfg(feature = "debug-zram-lifecycle")]
    crate::signal_trace::zram_lifecycle_syscall(nr, rv);
    #[cfg(feature = "debug-syscost")]
    crate::syscost::record(nr, __syscost);
    #[cfg(feature = "debug-startlat")]
    crate::startlat::record(nr, __startlat, rv);
    #[cfg(feature = "debug-boot")]
    trace_einval(nr, a0, a1, a2, a3, a4, a5, rv);
    #[cfg(any(feature = "debug-taskdump", feature = "debug-polktrace"))]
    sched::diag::record_syscall(nr as u32, rv);
    #[cfg(feature = "debug-syscall-return")]
    if let Some(task) = return_task {
        sched::diag::syscall_return_stage(task, sched::diag::SYSCALL_RETURN_STAGE_AFTER_DIAG);
    }
    crate::proc::rseq_writeback();
    #[cfg(feature = "debug-syscall-return")]
    if let Some(task) = return_task {
        sched::diag::syscall_return_stage(task, sched::diag::SYSCALL_RETURN_STAGE_AFTER_RSEQ);
    }
    // A syscall rolled back by user dispatch never reached the kernel's ABI,
    // so its exit-side tracer work is skipped for the same reason the entry
    // side was.
    if !super::user_dispatch::rolled_back_this_syscall() {
        ptrace_syscall_stop_if_armed(rv as u64, false);
    }
    #[cfg(feature = "debug-syscall-return")]
    if let Some(task) = return_task {
        sched::diag::syscall_return_stage(task, sched::diag::SYSCALL_RETURN_STAGE_AFTER_PTRACE);
    }
    }
    // Return-to-user work begins with IRQs masked, enables them only around a
    // work pass, then masks again before re-reading the pending-work flags.
    drop(process_irqs);
    // Linux `syscall_exit_to_user_mode_prepare` -> `exit_to_user_mode_loop`:
    // reschedule, deliver signals and apply the restart decision, LOOPING while
    // work remains. The SAME loop runs on the IRQ and exception return paths
    // (`sched::exit_to_user::hook`), which is what makes a signal reach a task
    // that never enters the kernel (B1471 / `wait-diff-open-items.md` W9).
    #[cfg(feature = "debug-syscall-return")]
    if let Some(task) = return_task {
        sched::diag::syscall_return_stage(task, sched::diag::SYSCALL_RETURN_STAGE_IN_EXIT_TO_USER);
    }
    let regs = crate::arch_frame::current_user_regs();
    // SAFETY: syscall-return tail on the running task's own kernel stack; the
    // entry frame is live and exclusively owned until the epilogue consumes it.
    let rv_out = unsafe { crate::exit_to_user::exit_to_user_mode_loop(regs, Some(rv), false) };
    #[cfg(feature = "debug-syscall-return")]
    if let Some(task) = return_task { sched::diag::syscall_return_clear(task); }
    // Diagnostic only: the ARM wait4(ECHILD) investigation needs to know
    // whether the kernel is about to ERET to a zero PC, or whether userspace
    // later branches through a zero link register.  The SVC frame is owned by
    // this task for the whole dispatch, including any schedule() above.
    #[cfg(all(target_arch = "aarch64", feature = "debug-smp"))]
    if nr == syscall::nrs::NR_WAIT4 {
        let frame = crate::arch_frame::current_svc_frame();
        if !frame.is_null() {
            // SAFETY: the task-owned frame is live until the assembly SVC
            // epilogue consumes it after this dispatcher returns.
            let frame = unsafe { &*frame };
            klog::write_raw(b"[WAIT4-RETURN tid=");
            klog::write_dec_u64(sched::live::current().map(|t| t.tid).unwrap_or(0) as u64);
            klog::write_raw(b" rv="); klog::write_hex_u64(rv as u64);
            klog::write_raw(b" elr="); klog::write_hex_u64(frame.elr_el1);
            klog::write_raw(b" lr="); klog::write_hex_u64(frame.x30);
            klog::write_raw(b" sp="); klog::write_hex_u64(frame.sp_el0);
            klog::write_raw(b"]\n");
        }
    }
    // Linux `vtime_user_enter`: all exit work is complete and the assembly
    // epilogue is about to resume userspace.
    sched::cpustat::user_enter();
    rv_out
}

/// Native NT personality entry. It is deliberately a separate symbol from
/// `oxide_syscall_dispatch`: NT service words are tagged and never pass
/// through Linux tracing, seccomp, or Linux-number routing.
#[no_mangle]
pub unsafe extern "C" fn oxide_nt_syscall_dispatch(
    entry: u64, a0: u64, a1: u64, a2: u64, a3: u64, a4: u64,
    #[cfg(target_arch = "aarch64")] _entry_frame: *mut hal_aarch64::SvcFrame,
) -> u64 {
    // SAFETY: `syscall_a5` reads the sixth argument saved by this
    // architecture's syscall entry stub before any nested call can replace it.
    let a5 = unsafe { crate::syscall_a5::read() };
    let args = SyscallArgs { a0, a1, a2, a3, a4, a5 };
    let Some(call) = crate::nt_dispatch::decode_entry(entry, args) else {
        return crate::nt_dispatch::STATUS_INVALID_PARAMETER;
    };
    crate::nt_dispatch::dispatch(call)
}

mod desktop_trace;
mod diagnostic_trace;

#[cfg(feature = "debug-desktop")]
use desktop_trace::trace_mutter_syscall;
#[cfg(feature = "debug-sshd-detail")]
use diagnostic_trace::trace_sshd_syscall;
#[cfg(feature = "debug-sshd")]
use diagnostic_trace::{trace_sshd_listener_enter, trace_sshd_listener_exit};
#[cfg(feature = "debug-swap")]
use diagnostic_trace::trace_swapon_process;
#[cfg(feature = "debug-random-seed")]
use diagnostic_trace::trace_random_seed_syscall;
#[cfg(feature = "debug-boot")]
use diagnostic_trace::trace_einval;
