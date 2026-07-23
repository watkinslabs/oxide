// F151 per-syscall entry trace. Gated by the `debug-syscall` cargo
// feature so call sites are absent in production builds (per
// `04§3 R05`). Used to bisect Linux-compat gaps when bringing up
// off-the-shelf userspace (coreutils / bash / util-linux).
//
// Format: `[SYS] pid=<tid> nr=<dec> a0=<hex> a1=<hex> a2=<hex> a3=<hex>`.
// Four args keeps lines bounded while still exposing flags/options for
// waitid/openat-like boot debugging.

#![cfg(any(feature = "debug-syscall", feature = "debug-gnome-syscall"))]

use core::sync::atomic::{AtomicU32, Ordering};

// A complete desktop-session trace is finite and actionable. Keep this
// separate from the broad boot-interest set below: PID 1 otherwise consumes
// the UART budget before the manager or compositor is exec'd. The bound
// protects a genuinely looping desktop process from wedging a diagnostic boot.
const DESKTOP_TRACE_MAX: u32 = 16_384;
static DESKTOP_TRACE_N: AtomicU32 = AtomicU32::new(0);

fn trace_desktop_session(t: &crate::Task) -> bool {
    let desktop_process = t.with_exe_path(|path| path.is_some_and(|path|
        path.contains("gnome-shell")
            // `user@.service` executes this binary as the login user. Do not
            // select PID 1 or a fixed account ID: the executable plus the
            // non-root credential is the Linux process identity we need.
            || (path == "/usr/lib/systemd/systemd"
                && t.creds.euid.load(Ordering::Relaxed) != 0)));
    desktop_process && DESKTOP_TRACE_N.fetch_add(1, Ordering::Relaxed) < DESKTOP_TRACE_MAX
}

/// Print one entry line for the syscall about to be dispatched.
/// # C: O(1) per call (write_raw is a UART byte-emit)
pub fn entry(nr: u64, a0: u64, a1: u64, a2: u64, a3: u64) {
    #[cfg(any(feature = "debug-syscall", feature = "debug-gnome-syscall"))]
    {
        // Focused proc/signal/wait/futex/epoll set across ALL tasks, so the
        // PID1<->child exit/reap handshake is visible without drowning in
        // the manager's unit-load traffic. nr set (x86_64): clone/fork/vfork
        // /execve/exit/wait4/kill, rt_sig*, futex, exit_group, waitid,
        // epoll_*, tgkill, signalfd*, poll/ppoll, clone3, pidfd*.
        let t = match crate::live::current() {
            Some(t) => t,
            None => return,
        };
        let (pid, vpid) = (t.tid, t.vtgid.load(core::sync::atomic::Ordering::Relaxed));
        // Keep capability-transition tracing permanently available without
        // reintroducing the thousands of unrelated PRCTL probes emitted by
        // desktop services. These are precisely the operations that change
        // securebits or the ambient set.
        let capability_prctl = nr == syscall::nrs::NR_PRCTL
            && (matches!(a0, crate::prctl::PR_SET_KEEPCAPS | crate::prctl::PR_SET_SECUREBITS)
                || (a0 == crate::prctl::PR_CAP_AMBIENT
                    && a1 != crate::prctl::PR_CAP_AMBIENT_IS_SET));
        // GNOME Shell is traced in full. PID1 (vpid==1): focused proc/signal/wait set, to see the
        // fork/reap handshake. Late executor children (vpid>=20): FULL
        // trace, to catch where the wedging executor blocks after execve.
        // Everything else (early children 2..19, already known-good): skip.
        // FUTEX-deadlock debugging set: futex ops + sched_yield + proc
        // lifecycle, all tasks, low volume. Pinpoints a stuck futex waiter
        // (and the op/uaddr) while a peer spins on sched_yield.
        let interesting = capability_prctl || matches!(nr,
            24 | 41..=55 | 56 | 57 | 58 | 435 | 59 | 60 | 61
            | 202 | 231 | 247 | 449 | 454 | 455 | 456
            | 112 | 116 | 117 | 119 | 126 | 248 | 249 | 250 | 272 | 302 | 308);   // yield/proc lifecycle/wait/futex + PAM keyring/ns/cred
        let full_desktop = trace_desktop_session(t);
        if !full_desktop && !(cfg!(feature = "debug-syscall") && interesting) { return; }
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
    #[cfg(any(feature = "debug-syscall", feature = "debug-gnome-syscall"))]
    {
        // Same focused set as entry(): proc/signal/wait/futex/epoll, all tasks.
        let t = match crate::live::current() {
            Some(t) => t,
            None => return,
        };
        let (pid, vpid) = (t.tid, t.vtgid.load(core::sync::atomic::Ordering::Relaxed));
        let interesting = matches!(nr,
            24 | 41..=55 | 56 | 57 | 58 | 435 | 59 | 60 | 61
            | 202 | 231 | 247 | 449 | 454 | 455 | 456
            | 112 | 116 | 117 | 119 | 126 | 157 | 248 | 249 | 250 | 272 | 302 | 308);   // yield/proc lifecycle/wait/futex + PAM keyring/ns/cred/prctl
        // Also surface EPROTO across all tasks. This retains a direct mapping
        // from user-space's "Protocol error" message to its kernel syscall
        // without flooding the UART with expected ENOTTY feature probes.
        let full_desktop = trace_desktop_session(t);
        let eproto = rv == -(syscall::Errno::Eproto.as_i32() as i64);
        if !full_desktop && !(cfg!(feature = "debug-syscall") && (interesting || eproto)) { return; }
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
