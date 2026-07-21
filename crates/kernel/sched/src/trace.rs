// F151 per-syscall entry trace. Gated by the `debug-syscall` cargo
// feature so call sites are absent in production builds (per
// `04§3 R05`). Used to bisect Linux-compat gaps when bringing up
// off-the-shelf userspace (coreutils / bash / util-linux).
//
// Format: `[SYS] pid=<tid> nr=<dec> a0=<hex> a1=<hex> a2=<hex> a3=<hex>`.
// Four args keeps lines bounded while still exposing flags/options for
// waitid/openat-like boot debugging.

#![cfg(feature = "debug-syscall")]

/// Print one entry line for the syscall about to be dispatched.
/// # C: O(1) per call (write_raw is a UART byte-emit)
pub fn entry(nr: u64, a0: u64, a1: u64, a2: u64, a3: u64) {
    #[cfg(feature = "debug-syscall")]
    {
        // Focused proc/signal/wait/futex/epoll set across ALL tasks, so the
        // PID1<->child exit/reap handshake is visible without drowning in
        // the manager's unit-load traffic. nr set (x86_64): clone/fork/vfork
        // /execve/exit/wait4/kill, rt_sig*, futex, exit_group, waitid,
        // epoll_*, tgkill, signalfd*, poll/ppoll, clone3, pidfd*.
        let (pid, vpid) = match crate::live::current() {
            Some(t) => (t.tid, t.vtgid.load(core::sync::atomic::Ordering::Relaxed)),
            None => return,
        };
        // PID1 (vpid==1): focused proc/signal/wait set, to see the
        // fork/reap handshake. Late executor children (vpid>=20): FULL
        // trace, to catch where the wedging executor blocks after execve.
        // Everything else (early children 2..19, already known-good): skip.
        // FUTEX-deadlock debugging set: futex ops + sched_yield + proc
        // lifecycle, all tasks, low volume. Pinpoints a stuck futex waiter
        // (and the op/uaddr) while a peer spins on sched_yield.
        let interesting = matches!(nr,
            24 | 41..=55 | 56 | 57 | 58 | 435 | 59 | 60 | 61
            | 202 | 231 | 247 | 449 | 454 | 455 | 456
            | 112 | 116 | 117 | 119 | 126 | 157 | 248 | 249 | 250 | 272 | 302 | 308);   // yield/proc lifecycle/wait/futex + PAM keyring/ns/cred
        if !interesting { return; }
        klog::write_raw(b"[SYS] vpid=");
        klog::write_dec_u64(vpid as u64);
        klog::write_raw(b" pid=");
        klog::write_dec_u64(pid as u64);
        klog::write_raw(b" nr=");
        klog::write_dec_u64(nr);
        klog::write_raw(b" a0=");
        klog::write_hex_u64(a0);
        klog::write_raw(b" a1=");
        klog::write_hex_u64(a1);
        klog::write_raw(b" a2=");
        klog::write_hex_u64(a2);
        klog::write_raw(b" a3=");
        klog::write_hex_u64(a3);
        klog::write_raw(b"\n");
    }
}

/// Print selected syscall returns for boot-stall debugging.
/// # C: O(1) for uninteresting syscalls; UART emit for selected ones.
pub fn ret(nr: u64, rv: i64) {
    #[cfg(feature = "debug-syscall")]
    {
        // Same focused set as entry(): proc/signal/wait/futex/epoll, all tasks.
        let (pid, vpid) = match crate::live::current() {
            Some(t) => (t.tid, t.vtgid.load(core::sync::atomic::Ordering::Relaxed)),
            None => return,
        };
        let interesting = matches!(nr,
            24 | 41..=55 | 56 | 57 | 58 | 435 | 59 | 60 | 61
            | 202 | 231 | 247 | 449 | 454 | 455 | 456
            | 112 | 116 | 117 | 119 | 126 | 157 | 248 | 249 | 250 | 272 | 302 | 308);   // yield/proc lifecycle/wait/futex + PAM keyring/ns/cred
        // Also surface ANY syscall returning EPERM (rv==-1) or EINTR (rv==-4)
        // across all tasks —
        // the errno behind synthetic failures like the user@UID.service step-PAM
        // "Operation not permitted". Rare, so no boot slowdown; tagged [RETERR].
        if !interesting && !matches!(rv, -1 | -4) { return; }
        klog::write_raw(if interesting { b"[RET] vpid=" } else { b"[RETERR] vpid=" });
        klog::write_dec_u64(vpid as u64);
        klog::write_raw(b" pid=");
        klog::write_dec_u64(pid as u64);
        klog::write_raw(b" nr=");
        klog::write_dec_u64(nr);
        klog::write_raw(b" rv=");
        if rv < 0 {
            klog::write_raw(b"-");
            klog::write_dec_u64(rv.wrapping_neg() as u64);
        } else {
            klog::write_dec_u64(rv as u64);
        }
        klog::write_raw(b"\n");
    }
}
