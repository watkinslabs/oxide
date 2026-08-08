// Private-expedited membarrier decision logic — NO target gate, so every rule
// below is host-unit-tested. The work fns in the parent module bind these
// answers to real mm state and real IPIs; nothing here touches either.

use syscall::errno::Errno;

/// Linux `MEMBARRIER_FLAG_SYNC_CORE`.
pub const FLAG_SYNC_CORE: u32 = 1 << 0;
/// Linux `MEMBARRIER_FLAG_RSEQ`.
pub const FLAG_RSEQ: u32 = 1 << 1;

/// What an in-flight expedited round asks each target CPU to do on top of the
/// full memory barrier every round already carries.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Kind {
    /// Plain barrier. Linux `ipi_mb`.
    Mb,
    /// Barrier + a core-serializing instruction, so a thread that prefetched
    /// code the caller has since rewritten cannot execute the stale copy.
    /// Linux `ipi_sync_core`.
    SyncCore,
    /// Barrier + abort of any rseq critical section the target is inside, so a
    /// restartable sequence cannot straddle the barrier. Linux `ipi_rseq`.
    Rseq,
}

impl Kind {
    /// The internal flag word the command switch carries selects the kind.
    /// # C: O(1)
    pub fn from_flags(flags: u32) -> Kind {
        match flags {
            FLAG_SYNC_CORE => Kind::SyncCore,
            FLAG_RSEQ      => Kind::Rseq,
            _              => Kind::Mb,
        }
    }

    /// Round-trip encoding for the cross-CPU round descriptor, which must be a
    /// plain integer because targets read it from an atomic in IRQ context.
    /// # C: O(1)
    pub fn as_u32(self) -> u32 {
        match self { Kind::Mb => 0, Kind::SyncCore => 1, Kind::Rseq => 2 }
    }

    /// Inverse of `as_u32`. An unknown encoding degrades to the plain barrier,
    /// which is the safe direction: a round is never weaker than `Mb`.
    /// # C: O(1)
    pub fn from_u32(v: u32) -> Kind {
        match v { 1 => Kind::SyncCore, 2 => Kind::Rseq, _ => Kind::Mb }
    }
}

/// The mm's `_READY` registration bits, one per expedited private command.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Default)]
pub struct Ready {
    /// `MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED` has run.
    pub private: bool,
    /// `MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_SYNC_CORE` has run.
    pub sync_core: bool,
    /// `MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_RSEQ` has run.
    pub rseq: bool,
}

/// Registration gate. Each expedited private command consults its OWN `_READY`
/// bit and answers `EPERM` when it is clear — registering one kind never
/// licenses another, which is the whole point of having three bits.
/// # C: O(1)
pub fn admit(kind: Kind, r: Ready) -> Result<(), Errno> {
    let ok = match kind {
        Kind::Mb       => r.private,
        Kind::SyncCore => r.sync_core,
        Kind::Rseq     => r.rseq,
    };
    if ok { Ok(()) } else { Err(Errno::Eperm) }
}

/// Whether the whole IPI round can be skipped as a no-op success.
///
/// A single-user mm or a single online CPU means no OTHER CPU can be running a
/// thread of this mm, so the barrier is already implied by the syscall itself
/// — EXCEPT for SYNC_CORE, which owes the CALLING CPU a serializing
/// instruction regardless of how many threads exist: the caller is precisely
/// the thread that just rewrote the code it is about to execute.
/// # C: O(1)
pub fn may_skip_round(kind: Kind, single_user: bool, single_cpu: bool) -> bool {
    kind != Kind::SyncCore && (single_user || single_cpu)
}

/// Whether the calling CPU is itself a target of the round.
///
/// The plain and RSEQ rounds skip it: the caller executes a full barrier
/// inline, and user code may not issue a syscall from inside an rseq critical
/// section, so the caller cannot be in one. SYNC_CORE cannot skip it — if the
/// caller migrates and is replaced by another thread of the same mm around the
/// barrier, that thread would resume without ever having serialized.
/// # C: O(1)
pub fn includes_self(kind: Kind) -> bool { kind == Kind::SyncCore }

/// Whether a `cpu_id` narrowing request names a CPU this kernel can target.
/// Linux answers a plain success for an out-of-range or offline CPU rather
/// than an error, so a racing hotplug is not an ABI-visible failure.
/// # C: O(1)
pub fn cpu_id_targetable(cpu_id: i32, max_cpus: usize) -> bool {
    cpu_id >= 0 && (cpu_id as usize) < max_cpus
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_command_consults_only_its_own_ready_bit() {
        // Registering PRIVATE_EXPEDITED must not license SYNC_CORE or RSEQ,
        // and vice versa. A regression that collapsed these to one bit would
        // hand userspace a core-serialization guarantee it never asked the
        // kernel to start honouring.
        let only_private = Ready { private: true, ..Default::default() };
        assert_eq!(admit(Kind::Mb, only_private), Ok(()));
        assert_eq!(admit(Kind::SyncCore, only_private), Err(Errno::Eperm));
        assert_eq!(admit(Kind::Rseq, only_private), Err(Errno::Eperm));

        let only_sync = Ready { sync_core: true, ..Default::default() };
        assert_eq!(admit(Kind::SyncCore, only_sync), Ok(()));
        assert_eq!(admit(Kind::Mb, only_sync), Err(Errno::Eperm));
        assert_eq!(admit(Kind::Rseq, only_sync), Err(Errno::Eperm));

        let only_rseq = Ready { rseq: true, ..Default::default() };
        assert_eq!(admit(Kind::Rseq, only_rseq), Ok(()));
        assert_eq!(admit(Kind::Mb, only_rseq), Err(Errno::Eperm));
        assert_eq!(admit(Kind::SyncCore, only_rseq), Err(Errno::Eperm));
    }

    #[test]
    fn unregistered_is_eperm_not_einval() {
        // EINVAL means "this kernel does not have the command"; EPERM means
        // "register first". Both arches build the command in, so an
        // unregistered caller must always see EPERM — a userspace runtime that
        // probes with EINVAL would permanently disable its fast path.
        for k in [Kind::Mb, Kind::SyncCore, Kind::Rseq] {
            assert_eq!(admit(k, Ready::default()), Err(Errno::Eperm));
        }
    }

    #[test]
    fn sync_core_never_skips_the_round() {
        // The single-user / single-CPU shortcut is legal for the plain and
        // RSEQ barriers but never for SYNC_CORE: the caller itself still owes
        // a serializing instruction before it re-executes the code it patched.
        for (single_user, single_cpu) in [(true, true), (true, false), (false, true)] {
            assert!(may_skip_round(Kind::Mb, single_user, single_cpu));
            assert!(may_skip_round(Kind::Rseq, single_user, single_cpu));
            assert!(!may_skip_round(Kind::SyncCore, single_user, single_cpu));
        }
        // Multi-user, multi-CPU: nobody skips.
        assert!(!may_skip_round(Kind::Mb, false, false));
        assert!(!may_skip_round(Kind::Rseq, false, false));
        assert!(!may_skip_round(Kind::SyncCore, false, false));
    }

    #[test]
    fn only_sync_core_targets_the_calling_cpu() {
        assert!(includes_self(Kind::SyncCore));
        assert!(!includes_self(Kind::Mb));
        assert!(!includes_self(Kind::Rseq));
    }

    #[test]
    fn kind_selection_and_encoding_round_trip() {
        assert_eq!(Kind::from_flags(0), Kind::Mb);
        assert_eq!(Kind::from_flags(FLAG_SYNC_CORE), Kind::SyncCore);
        assert_eq!(Kind::from_flags(FLAG_RSEQ), Kind::Rseq);
        for k in [Kind::Mb, Kind::SyncCore, Kind::Rseq] {
            assert_eq!(Kind::from_u32(k.as_u32()), k);
        }
        // An encoding no sender writes must degrade to the strongest-ordering
        // safe default rather than silently skipping a target's barrier.
        assert_eq!(Kind::from_u32(7), Kind::Mb);
    }

    #[test]
    fn out_of_range_cpu_id_is_not_targetable() {
        assert!(cpu_id_targetable(0, 64));
        assert!(cpu_id_targetable(63, 64));
        assert!(!cpu_id_targetable(64, 64));
        assert!(!cpu_id_targetable(-1, 64));
        assert!(!cpu_id_targetable(i32::MAX, 64));
    }
}
