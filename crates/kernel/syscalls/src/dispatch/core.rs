#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;

use super::ptrace::ptrace_syscall_stop_if_armed;
use super::route_a::dispatch_route_a;
use super::route_b::dispatch_route_b;
use super::route_c::dispatch_route_c;

#[no_mangle]
pub unsafe extern "C" fn oxide_syscall_dispatch(nr: u64, a0: u64, a1: u64, a2: u64, a3: u64, a4: u64) -> u64 {
    let orig_nr = nr;
    #[cfg(target_arch = "aarch64")]
    let nr = syscall::arm_abi::aarch64_nr_to_x86(nr);
    debug_ssh! { crate::signal_trace::dispatch_entry(orig_nr, nr); }
    let _ = orig_nr;
    #[cfg(target_arch = "aarch64")]
    if let Some(c) = sched::current() {
        c.svc_frame.store(hal_aarch64::current_svc_frame() as u64, core::sync::atomic::Ordering::Release);
    }
    let a5 = unsafe { crate::syscall_a5::read() };
    let args = SyscallArgs { a0, a1, a2, a3, a4, a5 };
    if let Some(c) = sched::current() { c.note_syscall(nr as u32); }
    #[cfg(feature = "debug-sshd")]
    trace_sshd_listener_enter(nr, &args);
    #[cfg(feature = "debug-swap")]
    trace_swapon_process(b"enter", nr, None);
    syscall::tracepoint::fire_sys_enter(nr as u32);
    debug_syscall! { sched::trace::entry(nr, a0, a1, a2, a3); }
    debug_gnome_syscall! { sched::trace::entry(nr, a0, a1, a2, a3); }
    if let Err(rv) = security::seccomp::check(nr, &[a0, a1, a2, a3, a4, a5]) { return rv as u64; }
    ptrace_syscall_stop_if_armed();
    #[cfg(feature = "debug-syscost")]
    let __syscost = crate::syscost::start();
    let rv = if let Some(rv) = dispatch_route_a(nr, &args) { rv }
    else if let Some(rv) = dispatch_route_b(nr, &args) { rv }
    else if let Some(rv) = dispatch_route_c(nr, &args) { rv }
    else if let Some(rv) = sched::cred::cred_dispatch(nr, &args) { rv }
    else if let Some(rv) = sched::timers::timer_dispatch(nr, &args) { rv }
    else if let Some(rv) = crate::perms::perms_dispatch(nr, &args) { rv }
    else if let Some(rv) = ::fs::keyring::keyring_dispatch(nr, &args) { rv }
    else if let Some(rv) = sched::compat::try_compat(nr, &args) { rv }
    // No modern route claimed this nr: honest ENOSYS. There is NO legacy
    // fallback table (docs/53 hollow-shell) — an unimplemented syscall must
    // report ENOSYS, never silently hit a stub with wrong semantics.
    else { -(syscall::Errno::Enosys.as_i32() as i64) };
    // rv is left un-normalized here (may still carry an internal restart
    // sentinel like -ERESTARTSYS) — the ignored-restart check below and
    // dispatch_pending() need the raw sentinel. normalize_user_return()
    // runs once, at the final return, per docs/38 restart ABI.
    #[cfg(feature = "debug-syscall-return")]
    let return_task = sched::live::current();
    #[cfg(feature = "debug-syscall-return")]
    if let Some(task) = return_task {
        sched::diag::syscall_return_stage(task, sched::diag::SYSCALL_RETURN_STAGE_AFTER_DISPATCH);
    }
    #[cfg(feature = "debug-swap")]
    trace_swapon_process(b"exit", nr, Some(rv));
    debug_syscall! { sched::trace::ret(nr, rv); }
    debug_gnome_syscall! { sched::trace::ret(nr, rv); }
    syscall::tracepoint::fire_sys_exit(nr as u32, rv);
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
    sched::diag::record_syscall(nr as u32, rv);
    #[cfg(feature = "debug-syscall-return")]
    if let Some(task) = return_task {
        sched::diag::syscall_return_stage(task, sched::diag::SYSCALL_RETURN_STAGE_AFTER_DIAG);
    }
    sched::timers::fire_due_timers();
    #[cfg(feature = "debug-syscall-return")]
    if let Some(task) = return_task {
        sched::diag::syscall_return_stage(task, sched::diag::SYSCALL_RETURN_STAGE_AFTER_TIMERS);
    }
    crate::proc::rseq_writeback();
    #[cfg(feature = "debug-syscall-return")]
    if let Some(task) = return_task {
        sched::diag::syscall_return_stage(task, sched::diag::SYSCALL_RETURN_STAGE_AFTER_RSEQ);
    }
    ptrace_syscall_stop_if_armed();
    #[cfg(feature = "debug-syscall-return")]
    if let Some(task) = return_task {
        sched::diag::syscall_return_stage(task, sched::diag::SYSCALL_RETURN_STAGE_AFTER_PTRACE);
    }
    if let Some(cur) = sched::live::current() {
        use core::sync::atomic::Ordering;
        use sched::live::sigpend::Signum;
        let deadline = cur.alarm_ns.load(Ordering::Acquire);
        if deadline != 0 {
            #[cfg(target_arch = "x86_64")]
            let now = { use hal::TimerOps; hal_x86_64::X86TimerOps::monotonic_ns().0 };
            #[cfg(target_arch = "aarch64")]
            let now = { use hal::TimerOps; hal_aarch64::ArmTimerOps::monotonic_ns().0 };
            if now >= deadline {
                let interval = cur.alarm_interval_ns.load(Ordering::Acquire);
                cur.alarm_ns.store(if interval != 0 { now.saturating_add(interval) } else { 0 }, Ordering::Release);
                cur.sigpending.fetch_or(Signum::Sigalrm.bit(), Ordering::Release);
            }
        }
        let u = cur.utime_ns.load(Ordering::Acquire);
        let s = cur.stime_ns.load(Ordering::Acquire);
        let vdl = cur.itimer_virtual_ns.load(Ordering::Acquire);
        if vdl != 0 && u >= vdl {
            let interval = cur.itimer_virtual_interval_ns.load(Ordering::Acquire);
            cur.itimer_virtual_ns.store(if interval != 0 { u.saturating_add(interval) } else { 0 }, Ordering::Release);
            cur.sigpending.fetch_or(Signum::Sigvtalrm.bit(), Ordering::Release);
        }
        let pdl = cur.itimer_prof_ns.load(Ordering::Acquire);
        let cpu = u.saturating_add(s);
        if pdl != 0 && cpu >= pdl {
            let interval = cur.itimer_prof_interval_ns.load(Ordering::Acquire);
            cur.itimer_prof_ns.store(if interval != 0 { cpu.saturating_add(interval) } else { 0 }, Ordering::Release);
            cur.sigpending.fetch_or(Signum::Sigprof.bit(), Ordering::Release);
        }
    }
    if sched::preempt::preempt_count() == 0 && sched::preempt::take_need_resched() {
        unsafe { sched::live::schedule(); }
    }
    if let Some(p) = crate::signal::take_lowest_pending() {
        debug_ssh! { crate::signal_trace::deliver_taken(&p); }
        #[cfg(feature = "debug-zram-lifecycle")]
        crate::signal_trace::zram_lifecycle_deliver(&p);
        if matches!(p.sig, 19) || (matches!(p.sig, 20 | 21 | 22) && p.handler == 0) {
            sched::live::stop::stop_until_cont_sig(p.sig as u8);
            return rv as u64;
        }
        let ignored_restart = syscall::restart::is_restart_sys(rv)
            && crate::signal::disposition_ignores(&p);
        let sig_rv = unsafe { crate::signal_dispatch::dispatch_pending(&p, rv as u64, &|sa| crate::s060_exit::sys_exit(sa)) };
        if sig_rv != 0 {
            #[cfg(feature = "debug-syscall-return")]
            if let Some(task) = return_task { sched::diag::syscall_return_clear(task); }
            return sig_rv;
        }
        if ignored_restart {
            #[cfg(feature = "debug-syscall-return")]
            if let Some(task) = return_task { sched::diag::syscall_return_clear(task); }
            #[cfg(target_arch = "aarch64")]
            {
                if let Some(cur) = sched::live::current() {
                    let frame = cur.svc_frame.load(core::sync::atomic::Ordering::Acquire) as *mut hal_aarch64::SvcFrame;
                    if !frame.is_null() {
                        // SAFETY: syscall-return tail exclusively owns the current task's SVC frame.
                        return unsafe { hal_aarch64::restart_ignored_syscall(frame) };
                    }
                }
            }
            #[cfg(target_arch = "x86_64")]
            {
                // SAFETY: syscall-return tail exclusively owns the current task's syscall-save frame.
                return unsafe { hal_x86_64::restart_ignored_syscall() };
            }
        }
    } else {
        debug_ssh! { crate::signal_trace::deliver_blocked(); }
    }
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
    syscall::restart::normalize_user_return(rv) as u64
}

/// Retained executable-scoped syscall trace for the OpenSSH daemon. The
/// startup path uses this instead of the global SSH trace so generator fanout
/// keeps production timing while a no-banner daemon remains diagnosable.
/// # C: O(executable-path length)
#[cfg(feature = "debug-sshd-detail")]
fn trace_sshd_syscall(nr: u64, rv: i64) {
    let Some(task) = sched::current() else { return; };
    // SAFETY: current task is the sole writer of its executable-path mirror.
    let is_sshd = unsafe {
        (*task.exe_path.get()).as_ref().is_some_and(|path| path.ends_with("/sshd"))
    };
    if !is_sshd { return; }
    klog::write_raw(b"[SSHD] tid=");
    klog::write_dec_u64(task.tid as u64);
    klog::write_raw(b" nr=");
    klog::write_dec_u64(nr);
    klog::write_raw(b" rv=");
    klog::write_hex_u64(rv as u64);
    klog::write_raw(b"\n");
}

/// Retained feature-gated listener lifecycle trace for the OpenSSH daemon.
/// # C: O(executable-path length)
#[cfg(feature = "debug-sshd")]
fn trace_sshd_listener_enter(nr: u64, args: &SyscallArgs) {
    if !is_sshd_listener_syscall(nr) { return; }
    let Some(tid) = sshd_tid() else { return; };
    klog::write_raw(b"[SSHD-LISTEN] enter tid=");
    klog::write_dec_u64(tid as u64);
    klog::write_raw(b" nr=");
    klog::write_dec_u64(nr);
    klog::write_raw(b" a0=");
    klog::write_hex_u64(args.a0);
    klog::write_raw(b" a1=");
    klog::write_hex_u64(args.a1);
    klog::write_raw(b" a2=");
    klog::write_hex_u64(args.a2);
    klog::write_raw(b" a3=");
    klog::write_hex_u64(args.a3);
    klog::write_raw(b"\n");
}

/// Retained feature-gated listener lifecycle return trace for OpenSSH.
/// # C: O(executable-path length)
#[cfg(feature = "debug-sshd")]
fn trace_sshd_listener_exit(nr: u64, rv: i64) {
    if !is_sshd_listener_syscall(nr) { return; }
    let Some(tid) = sshd_tid() else { return; };
    klog::write_raw(b"[SSHD-LISTEN] exit tid=");
    klog::write_dec_u64(tid as u64);
    klog::write_raw(b" nr=");
    klog::write_dec_u64(nr);
    klog::write_raw(b" rv=");
    klog::write_hex_u64(rv as u64);
    klog::write_raw(b"\n");
}

#[cfg(feature = "debug-sshd")]
fn is_sshd_listener_syscall(nr: u64) -> bool {
    matches!(nr,
        syscall::nrs::NR_SOCKET |
        syscall::nrs::NR_BIND |
        syscall::nrs::NR_LISTEN |
        syscall::nrs::NR_ACCEPT4)
}

#[cfg(feature = "debug-sshd")]
fn sshd_tid() -> Option<u32> {
    let task = sched::current()?;
    // SAFETY: current task is the sole writer of its executable-path mirror.
    unsafe { (*task.exe_path.get()).as_ref().is_some_and(|path| path.ends_with("/sshd")) }.then_some(task.tid)
}

/// Retained, feature-gated syscall trace for systemd's random-seed helper.
/// It locates an early-boot entropy or persistence stall without changing the
/// production path or flooding the serial console with unrelated service I/O.
/// # C: O(executable-path length)
#[cfg(feature = "debug-random-seed")]
fn trace_random_seed_syscall(nr: u64, rv: i64) {
    let Some(task) = sched::current() else { return; };
    // SAFETY: the running task is the sole writer of its executable-path mirror.
    let is_random_seed = unsafe {
        (*task.exe_path.get())
            .as_ref()
            .is_some_and(|path| path.ends_with("/systemd-random-seed"))
    };
    if !is_random_seed { return; }
    klog::write_raw(b"[RSEED] nr=");
    klog::write_dec_u64(nr);
    klog::write_raw(b" rv=");
    klog::write_hex_u64(rv as u64);
    klog::write_raw(b"\n");
}

/// Retained, feature-gated syscall boundary trace for `/sbin/swapon` only.
/// It identifies an ABI failure before the final `swapon(2)` request without
/// perturbing any other userspace process.
/// # C: O(executable-path length)
#[cfg(feature = "debug-swap")]
fn trace_swapon_process(phase: &[u8], nr: u64, result: Option<i64>) {
    let Some(task) = sched::current() else { return; };
    // SAFETY: the running task is the sole writer of its executable-path mirror.
    let is_swapon = unsafe {
        (*task.exe_path.get())
            .as_ref()
            .is_some_and(|path| path.ends_with("/swapon"))
    };
    if !is_swapon { return; }
    klog::write_raw(b"[SWAPON] ");
    klog::write_raw(phase);
    klog::write_raw(b" nr=");
    klog::write_dec_u64(nr);
    if let Some(result) = result {
        klog::write_raw(b" rv=");
        klog::write_hex_u64(result as u64);
    }
    klog::write_raw(b"\n");
}
