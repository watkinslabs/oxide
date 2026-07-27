// Per-mm `membarrier(2)` registration state — Linux
// `mm_struct::membarrier_state` (`include/linux/sched/mm.h`) driven by
// `kernel/sched/membarrier.c`.
//
// The state belongs to the ADDRESS SPACE, not the task or the thread group:
// Linux's contract is that `CLONE_VM`-without-`CLONE_THREAD` siblings share
// one registration ("We need to consider threads belonging to different
// thread groups, which use the same mm"). Keeping it here is the only place
// that fact is representable without a shadow registry.
//
// `execve` builds a FRESH `AddressSpace` over a fresh page-table root
// (`059_execve/{x86_64,aarch64}.rs`), so the state starts at zero on exec —
// that is this kernel's `membarrier_exec_mmap`, with no extra hook to keep
// in sync.
//
// Only the four bits behind a real implementation exist. Linux's
// `MEMBARRIER_STATE_PRIVATE_EXPEDITED_SYNC_CORE{,_READY}` and
// `..._RSEQ{,_READY}` are absent because their commands are refused at the
// ABI boundary (see `syscalls::membarrier`), so no code path could ever set
// them and a bit that can only read back zero is a lie in a bitmask.

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
}
