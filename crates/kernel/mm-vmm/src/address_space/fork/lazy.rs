// VMA-tree-only fork: the child inherits the mappings and demand-faults every
// page. No page is copied and no leaf is installed.

use alloc::sync::Arc;

use sync::Spinlock;

use crate::tree::VmaTree;
use crate::{Error, KResult};

use super::super::AddressSpace;
use super::shared::{attach_child_rmaps, child_vma};
impl AddressSpace {
    /// Clone VMA tree into a new AS with the supplied PT root.
    /// Mapped pages are NOT copied; child entries demand-page on
    /// first access (KernelBytes copy, Anonymous zero-fill).
    /// For full POSIX fork incl. Anonymous-page copy see
    /// [`fork_copy_pages`].
    /// # C: O(N) over VMA count.
    pub fn fork(&self, new_root_pa: u64) -> KResult<Arc<Self>> {
        let src = self.vmas.read();
        let mut dst = VmaTree::new();
        for vma in src.iter() {
            dst.insert(child_vma(vma)).map_err(|_| Error::NoMem)?;
        }
        let accounting = super::super::accounting::VmAccounting::from_vmas(new_root_pa, &dst);
        let child = Arc::new_cyclic(|w| Self {
            vmas: super::super::rwsem::MmapRwsem::new(dst),
            pt_lock: Spinlock::new(()),
            root_pa: new_root_pa,
            brk:     core::sync::atomic::AtomicU64::new(self.brk()),
            brk_max: core::sync::atomic::AtomicU64::new(self.brk_max()),
            teardown: core::sync::atomic::AtomicU64::new(0),
            exe_path: Spinlock::new(self.exe_path.lock().clone()),
            mmap_base: core::sync::atomic::AtomicU64::new(self.mmap_base()),
            mmap_topdown: core::sync::atomic::AtomicBool::new(self.mmap_topdown()),
            oom_skip: core::sync::atomic::AtomicBool::new(false),
            vdso_rt_sigreturn: core::sync::atomic::AtomicU64::new(self.vdso_rt_sigreturn()),
            membarrier: super::super::membarrier::MembarrierState::forked_from(&self.membarrier),
            mdwe: super::super::mdwe::MdweState::inherited_from(&self.mdwe),
            self_weak: w.clone(),
            has_uffd: core::sync::atomic::AtomicBool::new(false), // set by dup_uffd_registrations for a fork-tracking monitor only
            mlock_future: core::sync::atomic::AtomicBool::new(false), // Linux does not inherit mlockall state across fork.
            mlock_onfault: core::sync::atomic::AtomicBool::new(false),
            // Fresh/forked AS: no CPU has loaded it yet (Linux clears
            // mm_cpumask on mm init; the activating CPU sets its bit).
            cpumask: core::sync::atomic::AtomicU64::new(0),
            mm_layout: super::super::mmfields::MmLayout::forked(&self.mm_layout),
            pkeys: super::super::pkeys::PkeyContext::forked(&self.pkeys),
            accounting,
        });
        super::super::accounting::register_page_table_owner(new_root_pa, &child.accounting);
        super::super::register_live_address_space(new_root_pa, Arc::downgrade(&child));
        attach_child_rmaps(&child);
        // Linux `dup_userfaultfd` + `dup_userfaultfd_complete`: a monitor that
        // tracks mappings gets a context for the child and is told about the
        // fork; one that does not gets nothing in the child. Runs with no VMA
        // lock held — the announcement blocks the forking thread.
        drop(src);
        super::super::uffd::dup_uffd_registrations(self, &child);
        Ok(child)
    }
}
