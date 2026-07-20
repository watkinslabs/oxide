// Signal/namespace/ptrace/kill family extracted from
// syscall_glue_proc.rs to keep that file under the 1000-line cap
// per `08§7`. The dispatch in `syscall_glue.rs` calls into this
// module by name; everything here is single-mutator-per-active-CPU.
//
// docs/53 §0: individual syscall handlers split into per-file modules
// (013_rt_sigaction.rs, 062_kill.rs, …). Shared helpers live in
// signal_common.rs. This file retains only the signal-delivery
// primitives (PendingSignal / take_lowest_pending) used by the
// dispatch tail, plus a re-export of sig_perm_check for pidfd.rs.

#![cfg(target_os = "oxide-kernel")]

pub(crate) use crate::signal_common::sig_perm_check;

/// SIG_DFL sentinel (Linux uapi sa_handler convention). NEVER inline as a
/// bare 0 at call sites (`07§5`); mirrors the const in signal_dispatch.rs.
const SIG_DFL: u64 = 0;
/// Linux `SIG_IGN` disposition sentinel.  Kept beside `SIG_DFL` so syscall
/// restart policy never recreates signal-action encoding at call sites.
const SIG_IGN: u64 = 1;

/// One signal ready for delivery.
#[derive(Copy, Clone, Debug)]
pub struct PendingSignal {
    pub sig:      u32,
    pub handler:  u64,
    pub flags:    u64,
    pub restorer: u64,
    /// B117: extra siginfo_t fields for an SA_SIGINFO handler. For
    /// SIGCHLD this carries the dequeued child-exit event
    /// (si_code / si_pid / si_uid / si_status); `None` ⇒ deliver a
    /// signo-only siginfo (the prior behaviour, correct for signals
    /// with no associated data).
    pub info:     Option<sched::SigInfo>,
}

/// Whether a dequeued signal has an ignored disposition, including Linux's
/// default-ignore set (SIGCHLD, SIGURG, SIGWINCH).
/// # C: O(1)
pub fn disposition_ignores(p: &PendingSignal) -> bool {
    p.handler == SIG_IGN
        || (p.handler == SIG_DFL && sched::signum::default_action(p.sig) == sched::signum::DefaultAction::Ign)
}

/// Inspect `current.sigpending & !current.sigmask`; if non-zero,
/// take the lowest pending. For RT signals (33..=64) also pop one
/// siginfo from the per-signal queue and only clear the bitmap bit
/// when the queue drains (POSIX RT semantics — bit stays set while
/// records remain). Standard signals always clear the bit on take.
/// # C: O(1)
pub fn take_lowest_pending() -> Option<PendingSignal> {
    use core::sync::atomic::Ordering;
    let cur = sched::live::current()?;
    let pending = cur.sigpending.load(Ordering::Acquire);
    let masked  = cur.sigmask.load(Ordering::Acquire);
    // signal(7): SIGKILL/SIGSTOP bypass the mask, so a masked fatal signal can
    // never wedge a task unkillable; everything else honours the mask. Lowest
    // pending wins (Linux next_signal).
    let sig = sched::signum::next_deliverable(pending, masked)?;
    let mut info: Option<sched::SigInfo> = None;
    if sched::signum::is_realtime(sig) {
        let (rec, empty) = cur.rt_pop(sig);
        info = rec;
        if empty {
            cur.sigpending.fetch_and(!(1u64 << (sig - 1)), Ordering::Release);
        }
    } else {
        // B117: SIGCHLD (standard signal) carries a child-exit
        // siginfo. Pop one queued child event so the SA_SIGINFO
        // handler reads the right si_pid (child VPID) / si_status /
        // si_code. The pending bit stays set only if more child
        // events remain queued (Linux re-raises SIGCHLD per child),
        // so a reaper handling N exits sees N deliveries.
        if sig == sched::live::sigpend::Signum::Sigchld as u32 {
            let mut q = cur.child_sigq.lock();
            info = q.pop_front();
            let more = !q.is_empty();
            drop(q);
            if !more {
                cur.sigpending.fetch_and(!(1u64 << (sig - 1)), Ordering::Release);
            }
        } else {
            cur.sigpending.fetch_and(!(1u64 << (sig - 1)), Ordering::Release);
        }
    }
    let h = cur.sigactions_ref().get(sig);
    // SIGKILL/SIGSTOP can never be caught or ignored (signal(7)): force SIG_DFL
    // so a stale/buggy handler-table slot can't intercept them. rt_sigaction
    // (013) already rejects installing a disposition for them — defense in depth.
    let (handler, flags, restorer) = if sched::signum::is_unblockable(sig) {
        (SIG_DFL, 0, 0)
    } else {
        (h.handler, h.flags, h.restorer)
    };
    #[cfg(feature = "debug-boot")]
    if sig >= 32 {
        let is_gdm = unsafe { (*cur.exe_path.get()).as_ref().map(|s| s.contains("gdm-session")) }.unwrap_or(false);
        if is_gdm {
            klog::write_raw(b"[SIGDELIV tid="); klog::write_dec_u64(cur.tid as u64);
            klog::write_raw(b" sig="); klog::write_dec_u64(sig as u64);
            klog::write_raw(b" handler="); klog::write_hex_u64(handler);
            klog::write_raw(b"]\n");
        }
    }
    Some(PendingSignal { sig, handler, flags, restorer, info })
}
