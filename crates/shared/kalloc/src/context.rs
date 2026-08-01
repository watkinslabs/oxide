// Allocation-domain (memcg) ownership: the per-CPU context slot, its RAII
// scopes, and the global-allocator entry points the scheduler uses.

use core::sync::atomic::Ordering;

use crate::limits::NO_MEMCG_CONTEXT;
use crate::state::{KAlloc, GLOBAL_ALLOC};

/// Explicit owner for heap growth. Context is CPU-local and nestable; a
/// nested scope restores its exact predecessor on drop. KAlloc remains
/// cgroup-independent; its PMM growth callback owns typed accounting.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct AllocationContext { memcg: u64 }

impl AllocationContext {
    /// Intentionally uncharged boot/global allocation domain. # C: O(1)
    pub const UNCHARGED: Self = Self { memcg: NO_MEMCG_CONTEXT };
    /// Build an explicit cgroup-owned allocation domain. # C: O(1)
    pub const fn memcg(memcg: u64) -> Self { Self { memcg } }
    /// Cgroup identity carried to PMM growth. # C: O(1)
    pub const fn memcg_id(self) -> u64 { self.memcg }
}

/// RAII allocation-domain scope. The caller keeps preemption disabled until
/// drop, pinning the CPU whose context slot is restored.
pub struct AllocationScope<'a> {
    alloc: &'a KAlloc,
    cpu: usize,
    prior: u64,
}

/// Scope for the kernel's canonical global allocator.
pub struct GlobalAllocationScope { _scope: AllocationScope<'static> }

impl Drop for AllocationScope<'_> {
    fn drop(&mut self) { self.alloc.contexts[self.cpu].store(self.prior, Ordering::Release); }
}

impl KAlloc {
    /// Enter explicit CPU-local allocation domain. Nested scopes restore the
    /// exact prior owner. # C: O(1)
    /// # Ctx: preempt-disabled until the returned scope drops
    pub fn enter_context(&self, context: AllocationContext) -> AllocationScope<'_> {
        let cpu = self.context_cpu();
        let prior = self.contexts[cpu].swap(context.memcg_id(), Ordering::AcqRel);
        AllocationScope { alloc: self, cpu, prior }
    }

    /// Current CPU's growth owner, or no owner for pre-init/global work.
    /// # C: O(1)
    pub fn active_memcg(&self) -> u64 { self.contexts[self.context_cpu()].load(Ordering::Acquire) }
}

/// Enter the sole installed kernel allocator's explicit context. `None` is
/// permitted only before allocator publication during boot. # C: O(1)
pub fn enter_global_context(context: AllocationContext) -> Option<GlobalAllocationScope> {
    let raw = GLOBAL_ALLOC.load(Ordering::Acquire);
    if raw == 0 { return None; }
    // SAFETY: install_global accepts only a kernel-lifetime static allocator.
    let alloc = unsafe { &*(raw as *const KAlloc) };
    Some(GlobalAllocationScope { _scope: alloc.enter_context(context) })
}

/// Replace the scheduler-installed context for this CPU. # C: O(1)
/// # Ctx: preempt-disabled task-switch boundary
pub fn replace_global_context(context: AllocationContext) -> bool {
    let raw = GLOBAL_ALLOC.load(Ordering::Acquire);
    if raw == 0 { return false; }
    // SAFETY: install_global accepts only a kernel-lifetime static allocator.
    let alloc = unsafe { &*(raw as *const KAlloc) };
    let cpu = alloc.context_cpu();
    alloc.contexts[cpu].store(context.memcg_id(), Ordering::Release);
    true
}
