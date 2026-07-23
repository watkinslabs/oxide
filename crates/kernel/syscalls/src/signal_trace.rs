// F205 SSH-relay diagnostic helpers. Targeted klog inside the
// signal-delivery path. Split out of `signal.rs` per `08§7`
// file-length cap. Bodies are wrapped in `debug_ssh!` so the
// klog call sites are absent from the binary when the feature
// is off (R06 ungated-klog gate).

#![cfg(target_os = "oxide-kernel")]

use crate::signal::PendingSignal;

#[allow(dead_code)]
fn pending() -> Option<(u32, u64, u64)> {
    use core::sync::atomic::Ordering;
    sched::live::current().map(|c| (c.tid,
        c.sigpending.load(Ordering::Acquire),
        c.sigmask.load(Ordering::Acquire)))
}

/// # C: O(1)
pub fn sigaction(tid: u32, sig: u64, h: u64, f: u64, r: u64) {
    let _ = (tid, sig, h, f, r);
    debug_ssh! {
        klog::write_raw(b"[INFO]  ssh-trace: rt_sigaction tid=");
        klog::write_dec_u64(tid as u64);
        klog::write_raw(b" sig="); klog::write_dec_u64(sig);
        klog::write_raw(b" handler="); klog::write_hex_u64(h);
        klog::write_raw(b" flags="); klog::write_hex_u64(f);
        klog::write_raw(b" restorer="); klog::write_hex_u64(r);
        klog::write_raw(b"\n");
    }
}

/// # C: O(1)
pub fn sigprocmask(tid: u32, how: u64, prior: u64, new: u64) {
    let _ = (tid, how, prior, new);
    debug_ssh! {
        let saved_pc: u64 = {
            #[cfg(target_arch = "aarch64")]
            {
                let p = hal_aarch64::current_svc_frame();
                if p.is_null() { 0 } else {
                    // SAFETY: live SvcFrame on running task's kernel stack per single-mutator invariant.
                    unsafe { (*p).elr_el1 }
                }
            }
            #[cfg(not(target_arch = "aarch64"))]
            { 0 }
        };
        klog::write_raw(b"[INFO]  ssh-trace: rt_sigprocmask tid=");
        klog::write_dec_u64(tid as u64);
        klog::write_raw(b" how="); klog::write_dec_u64(how);
        klog::write_raw(b" prior="); klog::write_hex_u64(prior);
        klog::write_raw(b" new="); klog::write_hex_u64(new);
        klog::write_raw(b" caller_pc="); klog::write_hex_u64(saved_pc);
        klog::write_raw(b"\n");
    }
}

/// # C: O(1)
pub fn deliver_taken(p: &PendingSignal) {
    let _ = p;
    debug_ssh! {
        if let Some((tid, pend, mask)) = pending() {
            klog::write_raw(b"[INFO]  ssh-trace: deliver tid=");
            klog::write_dec_u64(tid as u64);
            klog::write_raw(b" sig="); klog::write_dec_u64(p.sig as u64);
            klog::write_raw(b" handler="); klog::write_hex_u64(p.handler);
            klog::write_raw(b" pending="); klog::write_hex_u64(pend);
            klog::write_raw(b" mask="); klog::write_hex_u64(mask);
            klog::write_raw(b"\n");
        }
    }
}

/// # C: O(1)
pub fn dispatch_entry(orig_nr: u64, mapped_nr: u64) {
    let _ = (orig_nr, mapped_nr);
    debug_ssh! {
        if orig_nr == 139 || mapped_nr == 15 {
            klog::write_raw(b"[INFO]  ssh-trace: dispatch-entry orig_nr=");
            klog::write_dec_u64(orig_nr);
            klog::write_raw(b" mapped_nr="); klog::write_dec_u64(mapped_nr);
            klog::write_raw(b"\n");
        }
    }
}

/// Filter-and-log per-syscall (nr, rv) under the SSH-only gate.
/// Excludes the highest-frequency callers so PL011 doesn't drown
/// on aarch64. Anything that prints here is a candidate for the
/// SIGCHLD-detection mechanism dropbear-aarch64 actually uses.
/// # C: O(1)
pub fn syscall_nr_rv(nr: u64, rv: i64) {
    let _ = (nr, rv);
    debug_ssh! {
        let always = matches!(nr, 15);
        let noisy = matches!(nr,
            72 | 23 | 35 | 230 | 113 | 228 | 233 | 232 | 96);
        if always || !noisy {
            let tid = sched::live::current().map(|c| c.tid).unwrap_or(0);
            klog::write_raw(b"[INFO]  ssh-trace: syscall tid=");
            klog::write_dec_u64(tid as u64);
            klog::write_raw(b" nr=");
            klog::write_dec_u64(nr);
            klog::write_raw(b" rv=");
            klog::write_hex_u64(rv as u64);
            klog::write_raw(b"\n");
        }
    }
}

/// # C: O(1)
pub fn deliver_blocked() {
    debug_ssh! {
        if let Some((tid, pend, mask)) = pending() {
            if pend & !mask != 0 {
                klog::write_raw(b"[INFO]  ssh-trace: deliver-none tid=");
            } else if pend != 0 {
                klog::write_raw(b"[INFO]  ssh-trace: deliver-masked tid=");
            } else { return; }
            klog::write_dec_u64(tid as u64);
            klog::write_raw(b" pending="); klog::write_hex_u64(pend);
            klog::write_raw(b" mask="); klog::write_hex_u64(mask);
            klog::write_raw(b"\n");
        }
    }
}

/// Retained, executable-scoped trace for the injected ZRAM lifecycle binary.
/// # C: O(executable-path length)
#[cfg(feature = "debug-zram-lifecycle")]
fn is_zram_lifecycle() -> bool {
    let Some(task) = sched::current() else { return false; };
    task.with_exe_path(|p| p.is_some_and(|p| p.ends_with("/oxide-conformance-t_zram_lifecycle")))
}

/// Emit the exact lifecycle binary's syscall boundary without tracing PID 1.
/// # C: O(executable-path length)
#[cfg(feature = "debug-zram-lifecycle")]
pub fn zram_lifecycle_syscall(nr: u64, rv: i64) {
    if !is_zram_lifecycle() { return; }
    klog::write_raw(b"[ZRAM-TEST] syscall nr=");
    klog::write_dec_u64(nr);
    klog::write_raw(b" rv=");
    klog::write_hex_u64(rv as u64);
    klog::write_raw(b"\n");
}

/// Emit a pending openat path for the lifecycle binary before VFS resolution.
/// # C: O(executable-path length + path length)
#[cfg(feature = "debug-zram-lifecycle")]
pub fn zram_lifecycle_openat(path: &str, flags: u32) {
    if !is_zram_lifecycle() { return; }
    klog::write_raw(b"[ZRAM-TEST] openat flags=");
    klog::write_hex_u64(flags as u64);
    klog::write_raw(b" path=");
    klog::write_raw(path.as_bytes());
    klog::write_raw(b"\n");
}

/// Emit a named lifecycle checkpoint around a potentially blocking work path.
/// # C: O(executable-path length + checkpoint length)
#[cfg(feature = "debug-zram-lifecycle")]
pub fn zram_lifecycle_stage(stage: &'static [u8]) {
    if !is_zram_lifecycle() { return; }
    klog::write_raw(b"[ZRAM-TEST] stage=");
    klog::write_raw(stage);
    klog::write_raw(b"\n");
}

/// Emit delivery before the AArch64 frame rewrite for the lifecycle binary.
/// # C: O(executable-path length)
#[cfg(feature = "debug-zram-lifecycle")]
pub fn zram_lifecycle_deliver(p: &PendingSignal) {
    if !is_zram_lifecycle() { return; }
    klog::write_raw(b"[ZRAM-TEST] deliver sig=");
    klog::write_dec_u64(p.sig as u64);
    klog::write_raw(b" handler=");
    klog::write_hex_u64(p.handler);
    klog::write_raw(b"\n");
}

/// Emit the selected AArch64 restorer for the lifecycle binary.
/// # C: O(executable-path length)
#[cfg(feature = "debug-zram-lifecycle")]
pub fn zram_lifecycle_signal_frame(p: &PendingSignal, restorer: u64) {
    if !is_zram_lifecycle() { return; }
    klog::write_raw(b"[ZRAM-TEST] signal-frame sig=");
    klog::write_dec_u64(p.sig as u64);
    klog::write_raw(b" handler=");
    klog::write_hex_u64(p.handler);
    klog::write_raw(b" restorer=");
    klog::write_hex_u64(restorer);
    klog::write_raw(b"\n");
}
