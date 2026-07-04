use alloc::sync::Arc;

use vmm::AddressSpace;

use super::Task;

/// Linux `struct sigaction` core fields per `27§3`.
#[repr(C, align(8))]
#[derive(Copy, Clone, Debug, Default)]
pub struct SaHandler {
    /// Handler entry. `0` = SIG_DFL (default disposition); `1` =
    /// SIG_IGN (ignore). Anything else = user fn pointer.
    pub handler:   u64,
    /// `SA_*` flags (Linux: SA_SIGINFO=0x4, SA_RESTART=0x10000000,
    /// SA_NOCLDSTOP, SA_NODEFER, etc.).
    pub flags:     u64,
    /// Optional return-trampoline (sa_restorer). musl + glibc set
    /// this to a libc-private stub that issues `rt_sigreturn`.
    pub restorer:  u64,
    /// Per-handler additional mask applied during dispatch.
    pub mask:      u64,
}

impl Task {
    /// Borrow `mm` (the `Arc<AddressSpace>` if set). Read-only;
    /// callers must observe the single-mutator invariant per the
    /// `mm` field doc.
    /// # SAFETY: caller is in IRQ-off / preempt-off context, OR
    /// holds a guarantee that no concurrent execve runs against
    /// this task on another CPU.
    /// # C: O(1)
    pub unsafe fn mm_ref(&self) -> Option<&Arc<AddressSpace>> {
        // SAFETY: caller asserts no concurrent writer; UnsafeCell::get is the supported deref pattern for shared interior mutability under documented external synchronization.
        unsafe { (&*self.mm.get()).as_ref() }
    }

    /// Soft `RLIMIT_NOFILE` — the per-task fd ceiling the fd-alloc path
    /// enforces (Linux `rlimit(RLIMIT_NOFILE)`); fd installs beyond it
    /// → EMFILE. Source for every `FdTable::alloc_limit` call site.
    /// # C: O(1)
    pub fn nofile_soft(&self) -> usize {
        // SAFETY: rlimits is single-mutator per the running task on this CPU (same invariant as `mm`); reads one (cur,max) slot only.
        unsafe { (*self.rlimits.get())[crate::rlimit::rlim::NOFILE].0 as usize }
    }

    /// Atomically replace `mm` with `new`. The displaced Arc is NOT dropped
    /// here — it is parked in this CPU's `active_mm` slot (Linux `exit_mm`
    /// keeps `active_mm`+`mm_count`; `mmdrop` runs after the next switch):
    /// on exit/signal-death the caller clears `mm` BEFORE the final
    /// `schedule()`, so an in-place drop of the last Arc would free the
    /// page-table root while it is still live in CR3/TTBR0 (GAP-2
    /// use-after-free → random exec/ld.so corruption). `execve` is safe by
    /// ordering (it `activate`s the new root BEFORE calling this) but parks
    /// through the same choke-point.
    /// # SAFETY: caller is the running task on its CPU OR holds
    /// the runqueue invariant for this task; preempt-off. Not safe
    /// to call on an actively-scheduled task from another CPU.
    /// # C: O(1)
    pub unsafe fn replace_mm(&self, new: Option<Arc<AddressSpace>>) {
        // SAFETY: see fn-level contract; single-mutator on this CPU.
        let old = unsafe { core::mem::replace(&mut *self.mm.get(), new) };
        #[cfg(target_os = "oxide-kernel")]
        if let Some(m) = old { crate::live::schedule::park_active_mm(m); }
        #[cfg(not(target_os = "oxide-kernel"))]
        drop(old); // hosted: no live CR3 to protect
    }
}
