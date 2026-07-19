#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;

use super::ptrace::ptrace_syscall_stop_if_armed;
use super::route_a::dispatch_route_a;
use super::route_b::dispatch_route_b;
use super::route_c::dispatch_route_c;

/// Emit a focused syscall ledger for the compositor while diagnosing display
/// bring-up.  This is deliberately narrower than `debug-syscall`: the latter
/// makes a full desktop boot too slow to preserve the ordering at the KMS
/// boundary.  Keeping this feature-gated trace permanent lets future display
/// regressions distinguish an absent DRM request from a syscall that returned
/// an errno before it reached DRM.
#[cfg(feature = "debug-boot")]
fn trace_mutter_syscall(phase: &'static [u8], nr: u64, a0: u64, a1: u64, a2: u64, rv: Option<i64>) {
    // The KMS ABI itself crosses ioctl: CREATE_DUMB/MAP_DUMB/ADDFB/SETCRTC
    // all appear there.  mmap is much too hot during Mesa startup to include
    // in an always-available boot trace; DRM's own MAP_DUMB ioctl record
    // identifies the cookie before that mapping.  This keeps diagnostics from
    // changing a desktop service's startup timing.
    if nr != 16 { return; }
    let is_mutter = sched::live::current()
        .and_then(|c| unsafe { (*c.exe_path.get()).as_ref().map(|s| {
            s.contains("gnome-shell") || s.contains("mutter")
        }) })
        .unwrap_or(false);
    if !is_mutter { return; }
    klog::write_raw(b"[MUTTERSYS ");
    klog::write_raw(phase);
    klog::write_raw(b" tid=");
    klog::write_dec_u64(sched::live::current().map(|c| c.tid as u64).unwrap_or(0));
    klog::write_raw(b" nr=");
    klog::write_dec_u64(nr);
    klog::write_raw(b" fd=");
    klog::write_dec_u64(a0);
    klog::write_raw(b" req=");
    klog::write_hex_u64(a1);
    klog::write_raw(b" arg=");
    klog::write_hex_u64(a2);
    if let Some(rv) = rv {
        klog::write_raw(b" rv=");
        if rv < 0 { klog::write_raw(b"-"); klog::write_dec_u64(rv.wrapping_neg() as u64); }
        else { klog::write_dec_u64(rv as u64); }
    }
    klog::write_raw(b"]\n");
}

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
    syscall::tracepoint::fire_sys_enter(nr as u32);
    debug_syscall! { sched::trace::entry(nr, a0, a1, a2, a3); }
    #[cfg(feature = "debug-boot")]
    trace_mutter_syscall(b"enter", nr, a0, a1, a2, None);
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
    let rv = syscall::restart::normalize_user_return(rv);
    debug_syscall! { sched::trace::ret(nr, rv); }
    #[cfg(feature = "debug-boot")]
    trace_mutter_syscall(b"exit", nr, a0, a1, a2, Some(rv));
    syscall::tracepoint::fire_sys_exit(nr as u32, rv);
    debug_sched! {
        klog::write_raw(b"[INFO]  syscall: nr=");
        klog::write_hex_u64(nr);
        klog::write_raw(b" rv=");
        klog::write_hex_u64(rv as u64);
        klog::write_raw(b"\n");
    }
    debug_ssh! { crate::signal_trace::syscall_nr_rv(nr, rv); }
    #[cfg(feature = "debug-syscost")]
    crate::syscost::record(nr, __syscost);
    sched::diag::record_syscall(nr as u32, rv);
    sched::timers::fire_due_timers();
    crate::proc::rseq_writeback();
    ptrace_syscall_stop_if_armed();
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
        if matches!(p.sig, 19) || (matches!(p.sig, 20 | 21 | 22) && p.handler == 0) {
            sched::live::stop::stop_until_cont_sig(p.sig as u8);
            return rv as u64;
        }
        let sig_rv = unsafe { crate::signal_dispatch::dispatch_pending(&p, rv as u64, &|sa| crate::s060_exit::sys_exit(sa)) };
        if sig_rv != 0 { return sig_rv; }
    } else {
        debug_ssh! { crate::signal_trace::deliver_blocked(); }
    }
    rv as u64
}
