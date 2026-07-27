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
    /// `sa_mask` — additional signals Linux `signal_delivered` blocks for the
    /// duration of the handler, on top of the signal itself (unless
    /// SA_NODEFER). Without it a handler is re-entered by exactly the signals
    /// `sigaction(2)` promised to hold off.
    pub mask:     u64,
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

/// Whether delivering `p` builds a user handler frame — Linux's
/// `get_signal()` returning a caught signal to `handle_signal`. SIG_DFL
/// (ignore, continue, stop, terminate) and SIG_IGN all take the
/// `arch_do_signal_or_restart` no-handler arm instead, which restarts an
/// interrupted syscall rather than reporting EINTR.
/// # C: O(1)
pub fn runs_user_handler(p: &PendingSignal) -> bool {
    p.handler != SIG_DFL && p.handler != SIG_IGN
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
    // One owner for "which queue backs this signal, and when does its pending
    // bit clear" (`Task::dequeue_siginfo`): RT signals keep the bit while
    // records remain, SIGCHLD does the same over its child-event queue so a
    // reaper handling N exits sees N deliveries, standard signals clear on
    // take but still surrender the single `legacy_queue` record an
    // SA_SIGINFO handler reads (si_code / si_pid / si_value).
    let (info, empty) = cur.dequeue_siginfo(sig);
    if empty {
        cur.sigpending.fetch_and(!(1u64 << (sig - 1)), Ordering::Release);
    }
    let h = cur.sigactions_ref().get(sig);
    // SIGKILL/SIGSTOP can never be caught or ignored (signal(7)): force SIG_DFL
    // so a stale/buggy handler-table slot can't intercept them. rt_sigaction
    // (013) already rejects installing a disposition for them — defense in depth.
    let (handler, flags, restorer, mask) = if sched::signum::is_unblockable(sig) {
        (SIG_DFL, 0, 0, 0)
    } else {
        (h.handler, h.flags, h.restorer, h.mask)
    };
    #[cfg(feature = "debug-boot")]
    {
        let is_gdm = cur.with_exe_path(|p| p.map(|s| s.contains("gdm-session")).unwrap_or(false));
        if is_gdm {
            klog::write_raw(b"[SIGDELIV tid="); klog::write_dec_u64(cur.tid as u64);
            klog::write_raw(b" sig="); klog::write_dec_u64(sig as u64);
            klog::write_raw(b" handler="); klog::write_hex_u64(handler);
            klog::write_raw(b" flags="); klog::write_hex_u64(flags);
            klog::write_raw(b"]\n");
        }
    }
    Some(PendingSignal { sig, handler, flags, restorer, mask, info })
}
