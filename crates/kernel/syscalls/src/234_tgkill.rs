// 234 tgkill — one syscall, one file (docs/53 §0). Moved verbatim from signal.rs.
#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use crate::signal_common::*;

/// `sys_tgkill(tgid, tid, sig)` — slot 234. Validates that the
/// target tid belongs to the named tgid before delivering.
/// # C: O(N_tasks) lookup
pub fn sys_tgkill(args: &SyscallArgs) -> i64 {
    use core::sync::atomic::Ordering;
    use syscall::errno::Errno;
    use sched::Signum;
    let tgid = args.a0 as i32;
    let tid  = args.a1 as i32;
    let sig  = args.a2 as i32;
    if tgid <= 0 || tid <= 0 { return -(Errno::Esrch.as_i32() as i64); }
    if !(0..=64).contains(&sig) { return -(Errno::Einval.as_i32() as i64); }
    let cur = match sched::live::current() {
        Some(c) => c, None => return -(Errno::Esrch.as_i32() as i64),
    };
    let want_tgid = tgid as u32;
    let want_tid = tid as u32;
    let namespace = match cur.namespace_owner(namespace_identity::NamespaceKind::Pid) {
        Some(namespace) => namespace,
        None => return -(Errno::Esrch.as_i32() as i64),
    };
    // F109: in non-init pid_ns, `tid` is a vtid in caller's NS.
    match sched::registry::lookup_in_namespace(&namespace, want_tid) {
        Some(t) => {
            let leader_tid = t.tgid.load(Ordering::Acquire);
            let same_group = sched::live::registry::lookup(leader_tid)
                .is_some_and(|leader| leader.pid.visible_tid(&namespace) == Some(want_tgid)
                    && alloc::sync::Arc::ptr_eq(&leader.thread_group, &t.thread_group));
            if !same_group {
                return -(Errno::Esrch.as_i32() as i64);
            }
            if !sig_perm_check(cur, &t, sig) {
                return -(Errno::Eperm.as_i32() as i64);
            }
            if sig != 0 {
                // Queue a siginfo carrying the SENDER's pid/uid with
                // si_code = SI_TKILL, so an SA_SIGINFO handler sees a real
                // siginfo instead of a zeroed one. glibc's
                // __nptl_setxid_sighandler (SIGSETXID=33) validates
                // `si_pid == getpid()` before applying the setxid and
                // acknowledging; a zeroed si_pid=0 made it silently return
                // without acking, so setgid()/setresgid() in a multithreaded
                // process (gdm-session-worker dropping to the session user)
                // hung forever in __nptl_setxid → no greeter.
                //
                // EVERY signal, not just the real-time range: Linux `do_tkill`
                // stamps SI_TKILL unconditionally, and glibc's SIGCANCEL
                // (pthread_cancel) is signal 32 — one below the old
                // `is_realtime` gate, so its handler saw si_code 0.
                let spid = cur.vtgid.load(Ordering::Acquire);
                let spid = if spid != 0 { spid } else { cur.tgid.load(Ordering::Acquire) };
                t.sigq_reserve(sig as u32);
                t.sigq_push(sched::SigInfo {
                    signo: sig as u32,
                    code: sched::signum::SI_TKILL,
                    pid: spid,
                    uid: cur.creds.euid.load(Ordering::Relaxed),
                    value: 0,
                });
                t.sigpending.fetch_or(1u64 << (sig - 1), Ordering::Release);
                if sig == Signum::Sigcont as i32 { sched::live::registry::wake_if_stopped(&t); }
                sched::live::signal_wake_up(&t);
            }
            #[cfg(feature = "debug-displaystack")]
            if sig >= 32 {
                let is_gdm = cur.with_exe_path(|p| p.map(|s| s.contains("gdm-session")).unwrap_or(false));
                if is_gdm {
                    klog::write_raw(b"[TGKILL from="); klog::write_dec_u64(cur.tid as u64);
                    klog::write_raw(b" to_vtid="); klog::write_dec_u64(want_tid as u64);
                    klog::write_raw(b" tgt_tid="); klog::write_dec_u64(t.tid as u64);
                    klog::write_raw(b" sig="); klog::write_dec_u64(sig as u64);
                    klog::write_raw(b" tgtmask="); klog::write_hex_u64(t.sigmask.load(Ordering::Acquire));
                    klog::write_raw(b"]\n");
                }
            }
            0
        }
        None => {
            #[cfg(feature = "debug-displaystack")]
            if sig >= 32 {
                let is_gdm = cur.with_exe_path(|p| p.map(|s| s.contains("gdm-session")).unwrap_or(false));
                if is_gdm {
                    klog::write_raw(b"[TGKILL from="); klog::write_dec_u64(cur.tid as u64);
                    klog::write_raw(b" to_vtid="); klog::write_dec_u64(want_tid as u64);
                    klog::write_raw(b" sig="); klog::write_dec_u64(sig as u64);
                    klog::write_raw(b" NOTFOUND]\n");
                }
            }
            -(Errno::Esrch.as_i32() as i64)
        }
    }
}
