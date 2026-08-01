// Small per-mm layout fields split from `address_space.rs`.

use super::AddressSpace;

impl AddressSpace {
    /// Linux `arch_pick_mmap_layout`: install this mm's arena anchor AND the
    /// direction `get_unmapped_area` searches from it, in one step. Anchor and
    /// direction are never set apart — a legacy floor searched top-down would
    /// walk straight out of the arena.
    ///
    /// `top_down` is Linux's `MMF_TOPDOWN`. With it, `base` is the CEILING
    /// (`mm->mmap_base`, `stack_top - rlim_stack - GAP`); without it, `base` is
    /// the FLOOR (`mm->mmap_legacy_base`, `TASK_UNMAPPED_BASE + rnd`). Zero is
    /// the uninitialised sentinel in both directions.
    /// # C: O(1)
    pub fn set_mmap_layout(&self, base: u64, top_down: bool) {
        self.mmap_topdown.store(top_down, core::sync::atomic::Ordering::Release);
        self.mmap_base.store(base, core::sync::atomic::Ordering::Release);
    }

    /// # C: O(1)
    pub fn mmap_base(&self) -> u64 {
        self.mmap_base.load(core::sync::atomic::Ordering::Acquire)
    }

    /// Linux `mm_flags_test(MMF_TOPDOWN, mm)`. # C: O(1)
    pub fn mmap_topdown(&self) -> bool {
        self.mmap_topdown.load(core::sync::atomic::Ordering::Acquire)
    }

    /// Publish the mapped vDSO `__kernel_rt_sigreturn` entry for this mm.
    /// Zero means the mm has not yet completed execve vDSO installation.
    /// # C: O(1)
    pub fn set_vdso_rt_sigreturn(&self, addr: u64) {
        self.vdso_rt_sigreturn.store(addr, core::sync::atomic::Ordering::Release);
    }

    /// Return the mapped vDSO `__kernel_rt_sigreturn` entry for this mm.
    /// # C: O(1)
    pub fn vdso_rt_sigreturn(&self) -> u64 {
        self.vdso_rt_sigreturn.load(core::sync::atomic::Ordering::Acquire)
    }
}
