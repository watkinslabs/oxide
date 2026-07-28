// `task_struct::mempolicy` accessors — the per-THREAD NUMA policy
// `set_mempolicy(2)` installs and `get_mempolicy(2)` reports back.
//
// Stored as three atomics rather than behind a lock because the only writer is
// the owning thread (`do_set_mempolicy` holds `task_lock(current)` purely
// against `/proc` readers, and every field is written together).

use core::sync::atomic::Ordering;

use vmm::mempolicy::MemPolicy;

use crate::Task;

impl Task {
    /// `current->mempolicy`. `None` is Linux's NULL policy — allocation falls
    /// back to the system default and `get_mempolicy` reports `MPOL_DEFAULT`.
    /// # C: O(1)
    pub fn mempolicy(&self) -> Option<MemPolicy> {
        MemPolicy::from_words([
            self.mempolicy[0].load(Ordering::Acquire),
            self.mempolicy[1].load(Ordering::Acquire),
            self.mempolicy[2].load(Ordering::Acquire),
        ])
    }

    /// `do_set_mempolicy`'s install step. Word 0 is written LAST on install
    /// and FIRST on clear, so a concurrent `/proc` reader never sees a
    /// non-zero presence word paired with a stale nodemask.
    /// # C: O(1)
    pub fn set_mempolicy(&self, pol: Option<MemPolicy>) {
        match pol {
            None => {
                self.mempolicy[0].store(0, Ordering::Release);
                self.mempolicy[1].store(0, Ordering::Release);
                self.mempolicy[2].store(0, Ordering::Release);
            }
            Some(p) => {
                let w = p.to_words();
                self.mempolicy[1].store(w[1], Ordering::Release);
                self.mempolicy[2].store(w[2], Ordering::Release);
                self.mempolicy[0].store(w[0], Ordering::Release);
            }
        }
    }
}
