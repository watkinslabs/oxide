// sys_wait4 — extracted from mod.rs to honor the 1000-line cap.
// Implements POSIX wait4(2) including WNOHANG / WUNTRACED / WCONTINUED.

#![cfg(target_os = "oxide-kernel")]

use syscall::errno::Errno;
use syscall::SyscallArgs;
use syscall::wait::{wait4_options_valid, WCONTINUED, WNOHANG, WUNTRACED};
use sched::registry::WaitChildSnapshot;

/// `sys_wait4(pid, wstatus, options, rusage)`.
/// # C: O(N_loop × N_children)
pub fn sys_wait4(args: &SyscallArgs) -> i64 {
    let pid     = args.a0 as i32;
    let wstatus = args.a1;
    let options = args.a2;
    let rusage  = args.a3;

    if !wait4_options_valid(options) { return -(Errno::Einval.as_i32() as i64); }
    if pid == i32::MIN { return -(Errno::Esrch.as_i32() as i64); }
    wait4_with_status_sink(pid, options, |wstat| write_wstatus(wstatus, wstat), |child| write_rusage(rusage, child))
}

/// Shared wait engine. Syscall `wait4` passes a user-copy sink; internal
/// callers such as `waitid` pass a kernel-local sink.
/// # C: O(N_loop × N_children)
pub(crate) fn wait4_with_status_sink<F, R>(pid: i32, options: u64, mut write_status: F, mut write_usage: R) -> i64
where
    F: FnMut(i32) -> Result<(), i64>,
    R: FnMut(WaitChildSnapshot) -> Result<(), i64>,
{
    let (parent_tid, parent_tgid, parent_pgid) = match sched::live::current() {
        Some(c) => (
            c.tid,
            c.tgid.load(core::sync::atomic::Ordering::Acquire),
            c.pgid(),
        ),
        None    => return -(Errno::Einval.as_i32() as i64),
    };
    let want_stop = (options & WUNTRACED)  != 0;
    let want_cont = (options & WCONTINUED) != 0;
    loop {
        if want_stop || want_cont {
            if let Some((child, kind, sig)) = sched::live::registry::take_child_stop_event(
                parent_tid, parent_tgid, pid, parent_pgid, options, want_stop, want_cont)
            {
                let wstat: i32 = if kind == 1 { ((sig as i32) << 8) | 0x7f } else { 0xffff };
                if let Err(rv) = write_status(wstat) { return rv; }
                if let Err(rv) = write_usage(child) { return rv; }
                return child.vpid as i64;
            }
        }
        if let Some((child, code)) = sched::live::reap_one(parent_tid, parent_tgid, pid, parent_pgid, options) {
            let wstat: i32 = if code & 0x100 != 0 { code & 0x7f } else { (code & 0xff) << 8 };
            if let Err(rv) = write_status(wstat) { return rv; }
            if let Err(rv) = write_usage(child) { return rv; }
            // F237: if no more zombies for this parent, clear the
            // SIGCHLD pending bit. Without this, the bit stays set
            // and signal_dispatch fires a SIGCHLD handler AFTER
            // wait4 already reaped — the shell's handler then
            // calls waitpid(-1, WNOHANG) which returns -1/ECHILD
            // and corrupts the shell's $? to 255.
            if !sched::live::has_wait_zombies(parent_tid, parent_tgid, pid, parent_pgid, options) {
                use core::sync::atomic::Ordering;
                if let Some(cur) = sched::live::current() {
                    let bit = sched::live::sigpend::Signum::Sigchld.bit();
                    cur.sigpending.fetch_and(!bit, Ordering::Release);
                }
            }
            debug_sched! { klog::write_raw(b"[INFO]  sys_wait4: reaped\n"); }
            debug_ssh! {
                klog::write_raw(b"[INFO]  ssh-trace: wait4 reaped tid=");
                klog::write_dec_u64(child.vpid as u64);
                klog::write_raw(b" parent=");
                klog::write_dec_u64(parent_tid as u64);
                klog::write_raw(b"\n");
            }
            return child.vpid as i64;
        }
        if !sched::live::registry::has_wait_children(parent_tid, parent_tgid, pid, parent_pgid, options) {
            #[cfg(feature = "debug-boot")]
            {
                klog::write_raw(b"[wait4 ECHILD] parent="); klog::write_dec_u64(parent_tid as u64);
                klog::write_raw(b" reqpid="); klog::write_hex_u64(pid as u32 as u64);
                // exe of the caller — names WHICH process holds the garbage pid
                // (generator post-exec vs systemd vs a pre-exec fork child).
                if let Some(c) = sched::live::current() {
                    c.with_exe_path(|p| if let Some(p) = p {
                        klog::write_raw(b" exe="); klog::write_raw(p.as_bytes());
                    });
                }
                klog::write_raw(b"\n");
            }
            debug_ssh! {
                klog::write_raw(b"[INFO]  ssh-trace: wait4 ECHILD parent=");
                klog::write_dec_u64(parent_tid as u64);
                klog::write_raw(b"\n");
            }
            return -(Errno::Echild.as_i32() as i64);
        }
        if (options & WNOHANG) != 0 { return 0; }
        // Interruptible wait: Linux `do_wait` runs at TASK_INTERRUPTIBLE.
        // A deliverable (unmasked) signal — and ALWAYS SIGKILL/SIGSTOP
        // regardless of mask, since signal(7) makes both unblockable —
        // aborts the blocking wait with -EINTR. The syscall-return tail
        // (dispatch.rs `take_lowest_pending`) then runs the fatal-signal
        // default action (SIG_DFL terminate). Ordered AFTER reap_one above
        // (Linux reaps an available zombie even with a signal pending) and
        // BEFORE park: without it a task parked here is unkillable —
        // kill() wakes it (wake_if_sleeping) but it just re-parks, never
        // returning to the dispatch tail that converts SIGKILL→terminate.
        if let Some(cur) = sched::live::current() {
            use core::sync::atomic::Ordering;
            use sched::live::sigpend::Signum;
            let forced  = Signum::Sigkill.bit() | Signum::Sigstop.bit();
            let pending = cur.sigpending.load(Ordering::Acquire);
            let masked  = cur.sigmask.load(Ordering::Acquire);
            let deliver = (pending & !masked) | (pending & forced);
            if deliver != 0 { return syscall::restart::restart_sys(); }
        }
        // SAFETY: process ctx; runqueue installed; preempt-off; park+schedule per `13§8`.
        unsafe { sched::live::park_for_wait4(); }
        // F143: post-park reap recheck closes the missed-wakeup race
        // where a child sys_exit between the reap_one above and
        // park_for_wait4 fires wake_wait4_parent while WAITERS is
        // empty — losing the wake. If the child has Zombied since,
        // unpark + return its status without going through schedule().
        if let Some((child, code)) = sched::live::reap_one(parent_tid, parent_tgid, pid, parent_pgid, options) {
            sched::live::unpark_self_from_wait4();
            let wstat: i32 = if code & 0x100 != 0 { code & 0x7f } else { (code & 0xff) << 8 };
            if let Err(rv) = write_status(wstat) { return rv; }
            if let Err(rv) = write_usage(child) { return rv; }
            return child.vpid as i64;
        }
        // SAFETY: process ctx; runqueue installed; preempt-off.
        unsafe { sched::live::schedule(); }
    }
}

pub(crate) fn write_rusage(ptr: u64, child: WaitChildSnapshot) -> Result<(), i64> {
    const RUSAGE_BYTES: u64 = 144;
    if ptr == 0 { return Ok(()); }
    crate::userbuf::validate_user_buf_writable(ptr, RUSAGE_BYTES, 1)?;
    let (u_sec, u_usec) = sched::clock::ns_to_timeval(child.utime_ns);
    let (s_sec, s_usec) = sched::clock::ns_to_timeval(child.stime_ns);
    // SAFETY: full rusage byte range validated writable; Linux copyout accepts unaligned storage.
    unsafe {
        core::ptr::write_unaligned( ptr       as *mut u64, u_sec);
        core::ptr::write_unaligned((ptr + 8)  as *mut u64, u_usec);
        core::ptr::write_unaligned((ptr + 16) as *mut u64, s_sec);
        core::ptr::write_unaligned((ptr + 24) as *mut u64, s_usec);
        for off in (32..RUSAGE_BYTES).step_by(8) {
            core::ptr::write_unaligned((ptr + off) as *mut u64, 0);
        }
    }
    Ok(())
}

#[inline]
fn write_wstatus(ptr: u64, val: i32) -> Result<(), i64> {
    if ptr == 0 { return Ok(()); }
    crate::userbuf::validate_user_buf_writable(ptr, 4, 1)?;
    // SAFETY: exact writable user byte range validated; Linux copyout accepts unaligned int storage.
    unsafe { core::ptr::write_unaligned(ptr as *mut i32, val); }
    Ok(())
}
