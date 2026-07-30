// Small per-mm layout fields split from `address_space.rs`.

use super::AddressSpace;

impl AddressSpace {
    /// Per-AS mmap arena top per Linux `mm_struct::mmap_base`.
    /// `execve` computes this from RLIMIT_STACK + a fixed GAP per
    /// `arch_pick_mmap_base`. Zero is the uninitialised sentinel.
    /// # C: O(1)
    pub fn set_mmap_base(&self, base: u64) {
        self.mmap_base.store(base, core::sync::atomic::Ordering::Release);
    }

    /// # C: O(1)
    pub fn mmap_base(&self) -> u64 {
        self.mmap_base.load(core::sync::atomic::Ordering::Acquire)
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
