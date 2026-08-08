// Per-mm `membarrier(2)` registration state.
//
// The state belongs to the ADDRESS SPACE, not the task or the thread group:
// Linux's contract is that `CLONE_VM`-without-`CLONE_THREAD` siblings share
// one registration, since threads belonging to different thread groups can
// share the same mm. Keeping it here is the only place
// that fact is representable without a shadow registry.
//
// `execve` builds a FRESH `AddressSpace` over a fresh page-table root
// (`059_execve/{x86_64,aarch64}.rs`), so the state starts at zero on exec —
// that is this kernel's `membarrier_exec_mmap`, with no extra hook to keep
// in sync.
//
// All eight state bits exist, with Linux's numbering. The SYNC_CORE pair
// additionally drives the return-to-user core-serialization hook: a thread of
// this mm that was NOT running when the barrier was issued still owes a
// core-serializing instruction before it resumes user mode, and the only
// place that fact can live is the mm every such thread shares.

use core::sync::atomic::{AtomicU32, Ordering};

/// Linux `MEMBARRIER_STATE_PRIVATE_EXPEDITED` — intent recorded.
const STATE_PRIVATE_EXPEDITED: u32 = 1 << 1;
/// Linux `MEMBARRIER_STATE_PRIVATE_EXPEDITED_READY` — intent visible to
/// every CPU that may run this mm, so the command may now be issued.
const STATE_PRIVATE_EXPEDITED_READY: u32 = 1 << 0;
/// Linux `MEMBARRIER_STATE_GLOBAL_EXPEDITED`.
const STATE_GLOBAL_EXPEDITED: u32 = 1 << 3;
/// Linux `MEMBARRIER_STATE_GLOBAL_EXPEDITED_READY`.
const STATE_GLOBAL_EXPEDITED_READY: u32 = 1 << 2;
/// Linux `MEMBARRIER_STATE_PRIVATE_EXPEDITED_SYNC_CORE_READY`.
const STATE_PRIVATE_EXPEDITED_SYNC_CORE_READY: u32 = 1 << 4;
/// Linux `MEMBARRIER_STATE_PRIVATE_EXPEDITED_SYNC_CORE` — the bit the
/// return-to-user path consults, so a thread of this mm that was descheduled
/// across the barrier still serializes before resuming user code.
const STATE_PRIVATE_EXPEDITED_SYNC_CORE: u32 = 1 << 5;
/// Linux `MEMBARRIER_STATE_PRIVATE_EXPEDITED_RSEQ_READY`.
const STATE_PRIVATE_EXPEDITED_RSEQ_READY: u32 = 1 << 6;
/// Linux `MEMBARRIER_STATE_PRIVATE_EXPEDITED_RSEQ`.
const STATE_PRIVATE_EXPEDITED_RSEQ: u32 = 1 << 7;

/// Registration word. Set-only for the lifetime of the mm (Linux never
/// clears a bit outside `membarrier_exec_mmap`, which for us is a new mm).
pub(super) struct MembarrierState {
    bits: AtomicU32,
}

impl MembarrierState {
    /// # C: O(1)
    pub(super) fn new() -> Self { Self { bits: AtomicU32::new(0) } }

    /// `fork` inherits the parent's registration. Linux gets this by
    /// construction — `dup_mm` `memcpy`s the whole `mm_struct` and `mm_init`
    /// resets many fields but never `membarrier_state` — so a forked child may
    /// issue `MEMBARRIER_CMD_PRIVATE_EXPEDITED` without re-registering.
    /// (`execve` is the opposite case and gets a fresh mm; see module head.)
    /// # C: O(1)
    pub(super) fn forked_from(parent: &Self) -> Self {
        Self { bits: AtomicU32::new(parent.bits.load(Ordering::Acquire)) }
    }
}

impl super::AddressSpace {
    /// True once `MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED` has run against
    /// this mm. `MEMBARRIER_CMD_PRIVATE_EXPEDITED` is `EPERM` until then.
    /// # C: O(1)
    pub fn membarrier_private_expedited_ready(&self) -> bool {
        self.membarrier.bits.load(Ordering::Acquire) & STATE_PRIVATE_EXPEDITED_READY != 0
    }

    /// True once `MEMBARRIER_CMD_REGISTER_GLOBAL_EXPEDITED` has run against
    /// this mm. Reported by `MEMBARRIER_CMD_GET_REGISTRATIONS`; it does NOT
    /// gate `MEMBARRIER_CMD_GLOBAL_EXPEDITED`, which Linux explicitly allows
    /// from a non-registered process.
    /// # C: O(1)
    pub fn membarrier_global_expedited_ready(&self) -> bool {
        self.membarrier.bits.load(Ordering::Acquire) & STATE_GLOBAL_EXPEDITED_READY != 0
    }

    /// `membarrier_register_private_expedited`. Idempotent.
    ///
    /// Linux publishes the intent bit, runs `sync_runqueues_membarrier_state`
    /// so every runqueue that may schedule this mm observes it, and only then
    /// sets `_READY`. Our expedited path derives its target set from
    /// `mm_cpumask` + the online mask at send time rather than from a cached
    /// per-runqueue word, so there is no second copy to synchronize; the
    /// `AcqRel` publish is the whole ordering requirement.
    /// # C: O(1)
    pub fn membarrier_register_private_expedited(&self) {
        self.membarrier.bits.fetch_or(
            STATE_PRIVATE_EXPEDITED | STATE_PRIVATE_EXPEDITED_READY,
            Ordering::AcqRel,
        );
    }

    /// `membarrier_register_global_expedited`. Idempotent.
    /// # C: O(1)
    pub fn membarrier_register_global_expedited(&self) {
        self.membarrier.bits.fetch_or(
            STATE_GLOBAL_EXPEDITED | STATE_GLOBAL_EXPEDITED_READY,
            Ordering::AcqRel,
        );
    }

    /// True once `MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_SYNC_CORE` has run
    /// against this mm. `..._PRIVATE_EXPEDITED_SYNC_CORE` is `EPERM` until then.
    /// # C: O(1)
    pub fn membarrier_private_expedited_sync_core_ready(&self) -> bool {
        self.membarrier.bits.load(Ordering::Acquire) & STATE_PRIVATE_EXPEDITED_SYNC_CORE_READY != 0
    }

    /// True once `MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_RSEQ` has run
    /// against this mm. `..._PRIVATE_EXPEDITED_RSEQ` is `EPERM` until then.
    /// # C: O(1)
    pub fn membarrier_private_expedited_rseq_ready(&self) -> bool {
        self.membarrier.bits.load(Ordering::Acquire) & STATE_PRIVATE_EXPEDITED_RSEQ_READY != 0
    }

    /// Whether a thread of this mm owes a core-serializing instruction before
    /// it resumes user mode. Read on the context-switch tail: the expedited
    /// round only reaches CPUs that were RUNNING this mm, so a thread that was
    /// off-CPU at barrier time is covered here instead.
    /// # C: O(1)
    pub fn membarrier_sync_core_before_usermode(&self) -> bool {
        self.membarrier.bits.load(Ordering::Acquire) & STATE_PRIVATE_EXPEDITED_SYNC_CORE != 0
    }

    /// `membarrier_register_private_expedited` with the SYNC_CORE flag.
    /// Idempotent.
    /// # C: O(1)
    pub fn membarrier_register_private_expedited_sync_core(&self) {
        self.membarrier.bits.fetch_or(
            STATE_PRIVATE_EXPEDITED | STATE_PRIVATE_EXPEDITED_SYNC_CORE
                | STATE_PRIVATE_EXPEDITED_SYNC_CORE_READY,
            Ordering::AcqRel,
        );
    }

    /// `membarrier_register_private_expedited` with the RSEQ flag. Idempotent.
    /// # C: O(1)
    pub fn membarrier_register_private_expedited_rseq(&self) {
        self.membarrier.bits.fetch_or(
            STATE_PRIVATE_EXPEDITED | STATE_PRIVATE_EXPEDITED_RSEQ
                | STATE_PRIVATE_EXPEDITED_RSEQ_READY,
            Ordering::AcqRel,
        );
    }

    /// `MEMBARRIER_CMD_GET_REGISTRATIONS` view: `(global, private, sync_core,
    /// rseq)`, one flag per `MEMBARRIER_CMD_REGISTER_*` command.
    ///
    /// A command is reported when EITHER bit of its intent/ready pair is set,
    /// which is NOT the same test that gates `EPERM`. Registering SYNC_CORE or
    /// RSEQ sets the shared `PRIVATE_EXPEDITED` intent bit without its `_READY`
    /// bit, so `GET_REGISTRATIONS` then also reports
    /// `REGISTER_PRIVATE_EXPEDITED` even though plain
    /// `MEMBARRIER_CMD_PRIVATE_EXPEDITED` still answers `EPERM`.
    /// # C: O(1)
    pub fn membarrier_registrations(&self) -> (bool, bool, bool, bool) {
        let b = self.membarrier.bits.load(Ordering::Acquire);
        (
            b & (STATE_GLOBAL_EXPEDITED | STATE_GLOBAL_EXPEDITED_READY) != 0,
            b & (STATE_PRIVATE_EXPEDITED | STATE_PRIVATE_EXPEDITED_READY) != 0,
            b & (STATE_PRIVATE_EXPEDITED_SYNC_CORE | STATE_PRIVATE_EXPEDITED_SYNC_CORE_READY) != 0,
            b & (STATE_PRIVATE_EXPEDITED_RSEQ | STATE_PRIVATE_EXPEDITED_RSEQ_READY) != 0,
        )
    }
}

#[cfg(test)]
mod tests {
    use crate::AddressSpace;

    #[test]
    fn fresh_mm_has_no_registration() {
        let mm = AddressSpace::new(0).expect("AS::new");
        assert!(!mm.membarrier_private_expedited_ready());
        assert!(!mm.membarrier_global_expedited_ready());
    }

    #[test]
    fn registration_is_per_kind_and_idempotent() {
        let mm = AddressSpace::new(0).expect("AS::new");
        mm.membarrier_register_private_expedited();
        assert!(mm.membarrier_private_expedited_ready());
        // Registering PRIVATE must not imply GLOBAL: GET_REGISTRATIONS
        // reports them separately and userspace branches on that.
        assert!(!mm.membarrier_global_expedited_ready());
        mm.membarrier_register_private_expedited();
        assert!(mm.membarrier_private_expedited_ready());
        mm.membarrier_register_global_expedited();
        assert!(mm.membarrier_private_expedited_ready());
        assert!(mm.membarrier_global_expedited_ready());
    }

    #[test]
    fn sync_core_registration_does_not_grant_plain_private_expedited() {
        // The intent bit is shared, the READY bit is not. Registering only
        // SYNC_CORE must leave plain PRIVATE_EXPEDITED at EPERM, while
        // GET_REGISTRATIONS still reports BOTH register commands because it
        // tests either bit of each pair.
        let mm = AddressSpace::new(0).expect("AS::new");
        mm.membarrier_register_private_expedited_sync_core();
        assert!(mm.membarrier_private_expedited_sync_core_ready());
        assert!(!mm.membarrier_private_expedited_ready());
        assert!(!mm.membarrier_private_expedited_rseq_ready());
        assert_eq!(mm.membarrier_registrations(), (false, true, true, false));
    }

    #[test]
    fn rseq_registration_does_not_grant_plain_private_expedited() {
        let mm = AddressSpace::new(0).expect("AS::new");
        mm.membarrier_register_private_expedited_rseq();
        assert!(mm.membarrier_private_expedited_rseq_ready());
        assert!(!mm.membarrier_private_expedited_ready());
        assert!(!mm.membarrier_private_expedited_sync_core_ready());
        assert_eq!(mm.membarrier_registrations(), (false, true, false, true));
    }

    #[test]
    fn sync_core_before_usermode_tracks_only_sync_core_registration() {
        // The return-to-user hook must fire for a mm that registered
        // SYNC_CORE and for no other registration — a false positive costs a
        // serializing instruction on every switch, a false negative loses the
        // guarantee for a thread that was off-CPU at barrier time.
        let mm = AddressSpace::new(0).expect("AS::new");
        assert!(!mm.membarrier_sync_core_before_usermode());
        mm.membarrier_register_private_expedited();
        mm.membarrier_register_global_expedited();
        mm.membarrier_register_private_expedited_rseq();
        assert!(!mm.membarrier_sync_core_before_usermode());
        mm.membarrier_register_private_expedited_sync_core();
        assert!(mm.membarrier_sync_core_before_usermode());
    }

    #[test]
    fn registrations_are_inherited_by_fork() {
        // CLONE_VM siblings share one registration; a forked child must not
        // have to re-register before issuing the expedited commands.
        let mm = AddressSpace::new(0).expect("AS::new");
        mm.membarrier_register_private_expedited_sync_core();
        mm.membarrier_register_private_expedited_rseq();
        let child = super::MembarrierState::forked_from(&mm.membarrier);
        let fresh = AddressSpace::new(0).expect("AS::new");
        // Swap the fresh mm's state for the forked copy to observe it through
        // the same accessors userspace reaches.
        fresh.membarrier.bits.store(
            child.bits.load(core::sync::atomic::Ordering::Acquire),
            core::sync::atomic::Ordering::Release,
        );
        assert!(fresh.membarrier_private_expedited_sync_core_ready());
        assert!(fresh.membarrier_private_expedited_rseq_ready());
        assert!(fresh.membarrier_sync_core_before_usermode());
    }
}
