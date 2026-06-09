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

/// One signal ready for delivery.
#[derive(Copy, Clone, Debug)]
pub struct PendingSignal {
    pub sig:      u32,
    pub handler:  u64,
    pub flags:    u64,
    pub restorer: u64,
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
    let deliver = pending & !masked;
    if deliver == 0 { return None; }
    let sig = deliver.trailing_zeros() + 1;
    if sig >= 33 && sig <= 64 {
        let (_info, empty) = cur.rt_pop(sig);
        if empty {
            cur.sigpending.fetch_and(!(1u64 << (sig - 1)), Ordering::Release);
        }
    } else {
        cur.sigpending.fetch_and(!(1u64 << (sig - 1)), Ordering::Release);
    }
    // SAFETY: running task on this CPU; preempt-off; sole reader of sigactions slot per single-mutator invariant in `13§5`.
    let table = unsafe { &*cur.sigactions.get() };
    let h = table[(sig - 1) as usize];
    Some(PendingSignal { sig, handler: h.handler, flags: h.flags, restorer: h.restorer })
}
