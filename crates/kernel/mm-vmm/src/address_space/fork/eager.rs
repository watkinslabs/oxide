// Eager-copy fork: every writable mapped page is copied into a fresh frame in
// the child. Retained for callers that have not moved to the copy-on-write path.

use alloc::sync::Arc;

use hal::{MmuOps, Pa, PageSize, Va, PAGE_SIZE_BYTES};
use sync::Spinlock;

use crate::tree::VmaTree;
use crate::vma::{VmaBacking, VmaProt};
use crate::{Error, KResult};

use super::super::AddressSpace;
use super::super::rss::{class_of, RssTally};
use super::shared::{attach_child_rmaps, child_vma};
impl AddressSpace {
    /// Eager-copy fork — pre-COW path retained for callers that
    /// haven't migrated. Prefer `fork_cow_pages` (Linux-equivalent
    /// COW). This path allocates fresh frames for every writable
    /// page in the parent.
    /// # SAFETY: same as `fork_cow_pages`.
    /// # C: O(N_vmas + P_writable_pages) eager-copy.
    pub fn fork_copy_pages<M: MmuOps, F: FnMut() -> Option<u64>>(
        &self,
        new_root_pa: u64,
        hhdm_offset: u64,
        mut alloc_frame: F,
    ) -> KResult<Arc<Self>> {
        let src = self.vmas.read();
        let mut dst = VmaTree::new();
        for vma in src.iter() {
            dst.insert(child_vma(vma)).map_err(|_| Error::NoMem)?;
        }
        let mut tally = RssTally::default();
        for vma in src.iter() {
            // Copy mapped pages for any writable VMA, regardless of
            // backing. KernelBytes-backed PT_LOAD-with-write segments
            // (BSS + .data) get their own per-task frame on first
            // fault, then accumulate runtime writes; if we don't copy
            // those frames at fork time, the child re-faults from the
            // original read-only Box and silently loses every
            // post-init write the parent made (e.g. svcd's units[]
            // table). Read-only KernelBytes segments (.text, .rodata)
            // can be skipped — both PTs map the same shared Box.
            let writable = vma.prot.contains(VmaProt::WRITE);
            let copy_backing = match vma.backing {
                VmaBacking::Anonymous       => true,
                VmaBacking::KernelBytes { .. } => writable,
                _                           => false,
            };
            if !copy_backing { continue; }
            let class = class_of(&vma.backing);
            let mut va = vma.start.as_u64();
            let end = vma.end.as_u64();
            while va < end {
                if let Some((src_pa, _)) = M::translate(Va(va)) {
                    let dst_pa = match alloc_frame() {
                        Some(p) => p,
                        None    => return Err(Error::NoMem),
                    };
                    // SAFETY: src_pa came from the active PT walk; HHDM mirror at hhdm + page-aligned src_pa is read-mapped; dst_pa is fresh PMM frame; non-overlapping copy.
                    unsafe {
                        let s = (hhdm_offset + (src_pa.0 & !(PAGE_SIZE_BYTES - 1))) as *const u8;
                        let d = (hhdm_offset + dst_pa) as *mut u8;
                        core::ptr::copy_nonoverlapping(s, d, PAGE_SIZE_BYTES as usize);
                    }
                    let pte_flags = vma.page_flags();
                    // SAFETY: new_root_pa carries kernel-half clone of master per P2-19; va page-aligned in user range; dst_pa fresh; flags carry USER per `11§5`.
                    unsafe {
                        M::map_at(new_root_pa, Va(va), Pa(dst_pa), pte_flags, PageSize::P4K);
                    }
                    tally.add(class);
                }
                va += PAGE_SIZE_BYTES;
            }
        }
        let accounting = super::super::accounting::VmAccounting::from_vmas(new_root_pa, &dst);
        accounting.seed_ptes(&tally);
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
