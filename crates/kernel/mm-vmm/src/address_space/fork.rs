use alloc::sync::Arc;

use hal::{MmuOps, Pa, PageSize, Va, PAGE_SIZE_BYTES};
use sync::{RwLock, Spinlock};

use crate::tree::VmaTree;
use crate::vma::{VmaBacking, VmaFlags, VmaProt};
use crate::{Error, KResult};

use super::AddressSpace;

/// Undo every swap leaf installed in an unpublished child root and return its
/// matching PMM slot reference.  The PTE is cleared before release so no page
/// table can reach a slot after its last reference disappears.
/// # C: O(number of cloned swap PTEs)
fn rollback_swap_fork<M: MmuOps, FS: FnMut(hal::pt_walker::SwapEntry)>(
    root_pa: u64, entries: &[(u64, hal::pt_walker::SwapEntry)], release: &mut FS,
) {
    for (va, entry) in entries.iter().rev() {
        // SAFETY: rollback owns the unpublished child root and each tuple was
        // recorded only after the corresponding exact PTE installation.
        let cleared = unsafe { M::clear_swap_at(root_pa, Va(*va), *entry) };
        if cleared { release(*entry); }
    }
}

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
            dst.insert(vma.clone()).map_err(|_| Error::NoMem)?;
        }
        let accounting = super::accounting::VmAccounting::from_vmas(new_root_pa, &dst);
        let child = Arc::new_cyclic(|w| Self {
            vmas: RwLock::new(dst),
            pt_lock: Spinlock::new(()),
            root_pa: new_root_pa,
            brk:     core::sync::atomic::AtomicU64::new(self.brk()),
            brk_max: core::sync::atomic::AtomicU64::new(self.brk_max()),
            teardown: core::sync::atomic::AtomicU64::new(0),
            exe_path: Spinlock::new(self.exe_path.lock().clone()),
            mmap_base: core::sync::atomic::AtomicU64::new(self.mmap_base()),
            vdso_rt_sigreturn: core::sync::atomic::AtomicU64::new(self.vdso_rt_sigreturn()),
            membarrier: super::membarrier::MembarrierState::forked_from(&self.membarrier),
            self_weak: w.clone(),
            has_uffd: core::sync::atomic::AtomicBool::new(false), // fork clears child uffd (no EVENT_FORK)
            mlock_future: core::sync::atomic::AtomicBool::new(false), // Linux does not inherit mlockall state across fork.
            mlock_onfault: core::sync::atomic::AtomicBool::new(false),
            // Fresh/forked AS: no CPU has loaded it yet (Linux clears
            // mm_cpumask on mm init; the activating CPU sets its bit).
            cpumask: core::sync::atomic::AtomicU64::new(0),
            mm_layout: super::mmfields::MmLayout::forked(&self.mm_layout),
            accounting,
        });
        super::accounting::register_page_table_owner(new_root_pa, &child.accounting);
        super::register_live_address_space(new_root_pa, Arc::downgrade(&child));
        Ok(child)
    }

    /// Full POSIX fork per docs/11§7: clone VMA tree + copy every
    /// mapped Anonymous page into fresh frames in `new_root_pa`.
    /// KernelBytes re-fault in child against the shared slice.
    /// `new_root_pa` must be a PT root with kernel-half cloned
    /// from master per `11§2` invariant 5.
    ///
    /// # SAFETY: source AS is the active CR3 / TTBR0 (so
    /// `M::translate` resolves source PTEs); single-CPU UP;
    /// preempt-off; caller is the `sys_fork` handler.
    /// # C: O(N_vmas + P_anon_pages)
    /// F157: COW fork (Linux equivalent). Replaces the eager-copy
    /// `fork_copy_pages` with refcount-based page sharing per
    /// `mm/memory.c` `copy_present_pte`:
    /// 1. Clone the VMA tree.
    /// 2. Walk parent's mapped pages: for each present leaf,
    ///    - bump struct-page refcount via `inc_ref`,
    ///    - install the SAME PA in the child PT,
    ///    - if the VMA is writable, clear the W bit on BOTH PTEs
    ///      (parent + child) and TLB-flush parent's VA so the next
    ///      write fault dispatches to `handle_page_fault` for COW
    ///      split.
    /// Read-only VMAs (.text / .rodata) keep their RO PTEs and
    /// share frames forever — same Linux behaviour for shared file
    /// pages.
    ///
    /// `new_root_pa` must be an already-allocated PT root with
    /// kernel-half cloned from master per `11§2` invariant 5.
    /// `inc_ref(pa)` bumps the struct-page refcount for shared frames.
    ///
    /// # SAFETY: source AS is the active CR3 / TTBR0; preempt-off;
    /// single-CPU UP; caller is `sys_fork` / `sys_clone` handler.
    /// # C: O(N_vmas + P_mapped_pages)
    pub fn fork_cow_pages<M: MmuOps, IR: FnMut(u64)>(
        &self,
        new_root_pa: u64,
        hhdm_offset: u64,
        inc_ref: IR,
    ) -> KResult<Arc<Self>> {
        self.fork_cow_pages_with_swap::<M, _, _, _, _>(
            new_root_pa, hhdm_offset, inc_ref,
            |_, _| Err(Error::NoMem),
            |_entry| {},
            |_entry| {},
        )
    }

    /// Full COW fork including non-present swap leaves.  `retain_swap` and
    /// `release_swap` are PMM's sole slot-reference owner: VMM copies only
    /// the PTE representation and never maintains a parallel swap count.
    ///
    /// # SAFETY: same active-parent and serialized-fork preconditions as
    /// [`Self::fork_cow_pages`].
    /// # C: O(N_vmas + P_present + P_swap)
    pub fn fork_cow_pages_with_swap<M, IR, RS, FS, WM>(
        &self, new_root_pa: u64, _hhdm_offset: u64, mut inc_ref: IR,
        mut retain_swap: RS, mut release_swap: FS, mut register_migration_wait: WM,
    ) -> KResult<Arc<Self>>
    where
        M: MmuOps,
        IR: FnMut(u64),
        RS: FnMut(u64, hal::pt_walker::SwapEntry) -> KResult<()>,
        FS: FnMut(hal::pt_walker::SwapEntry),
        WM: FnMut(hal::pt_walker::MigrationEntry),
    {
        // Linux dup_mmap holds mmap_lock WRITE for the whole copy: a peer
        // thread's fault (which takes the read lock) must not interleave
        // with the per-page translate/inc_ref/map_at/W-strip sequence, or
        // its COW copy in the window is torn down by the parent remap
        // (frame leak + retired stores reverted).
        let src = self.vmas.write();
        // A migration marker is transient state, not an inheritable PTE.
        // Register under the token lock and return before writing the child;
        // the syscall drops mmap_lock, sleeps, then retries this whole fork
        // against the committed resident/swap PTE.  This covers File/shmem
        // mappings as well as any future migration-capable backing.
        for vma in src.iter() {
            if vma.flags.contains(VmaFlags::DONTFORK) { continue; }
            let mut va = vma.start.as_u64();
            while va < vma.end.as_u64() {
                if let Some(marker) = M::migration_entry_at(self.root_pa, Va(va)) {
                    let _ = crate::migration_pending_then(marker, || register_migration_wait(marker));
                    return Err(Error::Again);
                }
                va += PAGE_SIZE_BYTES;
            }
        }
        let mut dst = VmaTree::new();
        for vma in src.iter() {
            // MADV_DONTFORK (Linux VM_DONTCOPY): the child does not
            // inherit this VMA at all.
            if vma.flags.contains(VmaFlags::DONTFORK) { continue; }
            dst.insert(vma.clone()).map_err(|_| Error::NoMem)?;
        }
        // A child PTE owns a separate reference to the canonical swap slot.
        // Copy these first: a recoverable table-allocation failure then rolls
        // back all slot references before any present-page refcount changes.
        let mut cloned_swaps = alloc::vec::Vec::<(u64, hal::pt_walker::SwapEntry)>::new();
        for vma in src.iter() {
            if vma.flags.contains(VmaFlags::DONTFORK)
                || (vma.flags.contains(VmaFlags::WIPEONFORK)
                    && matches!(vma.backing, VmaBacking::Anonymous))
                || !matches!(vma.backing, VmaBacking::Anonymous)
            { continue; }
            let mut va = vma.start.as_u64();
            while va < vma.end.as_u64() {
                let Some(entry) = M::swap_entry_at(self.root_pa, Va(va)) else {
                    va += PAGE_SIZE_BYTES;
                    continue;
                };
                if let Err(error) = retain_swap(va, entry) {
                    rollback_swap_fork::<M, FS>(new_root_pa, &cloned_swaps, &mut release_swap);
                    return Err(error);
                }
                // SAFETY: `new_root_pa` is an unpublished child root and the
                // fork holds the parent mmap write lock for this transaction.
                let installed = unsafe { M::map_swap_at(new_root_pa, Va(va), entry) };
                if installed.is_err() {
                    release_swap(entry);
                    rollback_swap_fork::<M, FS>(new_root_pa, &cloned_swaps, &mut release_swap);
                    return Err(Error::NoMem);
                }
                if cloned_swaps.try_reserve(1).is_err() {
                    // SAFETY: the just-installed unpublished child PTE is
                    // exact, so clearing it cannot disturb another mapping.
                    let _ = unsafe { M::clear_swap_at(new_root_pa, Va(va), entry) };
                    release_swap(entry);
                    rollback_swap_fork::<M, FS>(new_root_pa, &cloned_swaps, &mut release_swap);
                    return Err(Error::NoMem);
                }
                cloned_swaps.push((va, entry));
                va += PAGE_SIZE_BYTES;
            }
        }
        for vma in src.iter() {
            if vma.flags.contains(VmaFlags::DONTFORK) { continue; }
            // MADV_WIPEONFORK (Linux VM_WIPEONFORK): the child keeps the
            // VMA but NO pages — every touch refaults as fresh zeros
            // (systemd random-util's fork-detection contract).
            if vma.flags.contains(VmaFlags::WIPEONFORK)
                && matches!(vma.backing, VmaBacking::Anonymous) { continue; }
            let writable = vma.prot.contains(VmaProt::WRITE);
            // MAP_SHARED VMAs are NOT copy-on-write: parent and child keep
            // writing the SAME frame (Linux shmem / MAP_SHARED|MAP_ANON). The
            // child maps it writable and the parent stays writable — no W-strip,
            // no COW split. Critical now that tmpfs/memfd MAP_SHARED aliases real
            // frames: COW-splitting them on fork would silently fork the journal
            // page away from journald's shared view.
            // REVERTED fix #8: keeping VMAs writable-across-fork for the SHARED
            // flag caused WRITE-WHILE-SHARED corruption — a private page stayed
            // writable in both parent and child, so parallel-forked children
            // (systemd's generators) clobbered each other's memory (garbage
            // syscall args, futex wedge). PROOF: forcing COW for all VMAs made
            // the garbage corruption vanish (no PID1 crash either). Linux maps
            // EVERY fork-shared anon/private page READ-ONLY and copies on first
            // write; genuine MAP_SHARED needs a real shared backing object (the
            // tmpfs/memfd path, fix #7), NOT in-place writable COW frames.
            //
            // CORRECTED (refcount-safe, Linux mm/memory.c): the blanket
            // `shared=false` ALSO caught genuine inode-backed MAP_SHARED
            // (memfd/tmpfs File VMAs whose pages ARE the inode's shared
            // frames). Forcing those through COW W-stripped the shared frame
            // and copied it private on first write, so a forked peer silently
            // froze its shared view at fork time and never saw later writes
            // (lost-write / stale-read corruption — a random journald/systemd
            // shared-memfd page read garbage -> SIGSEGV). Linux DOES share
            // these across fork (one backing object, no anon_vma, no COW).
            // Restrict the share decision to File-backed SHARED VMAs: anon
            // (incl. MAP_SHARED|ANON, which we lack a shmem backing for) stays
            // on the COW path so the reverted anon write-while-shared bug stays
            // fixed; only true file backings keep their frame writable+shared.
            // Refcount is unaffected — `inc_ref` + `map_at` below run for both
            // branches; `shared` only gates the W-strip + parent RO-remap.
            let shared = vma.flags.contains(VmaFlags::SHARED)
                && matches!(vma.backing, VmaBacking::File { .. });
            // B18 fix: COW-share Anonymous + KernelBytes + File-backed
            // frames. File backings are required so child processes
            // inherit their parent's mmap'd shared-library mappings
            // (libpam.so, libc.so, …) — Linux mm/memory.c semantic.
            // Skipping File backings caused pam_unix's helper-fork
            // child to SIGSEGV the moment it called any libpam.so
            // function: child's PT had no entries for the libpam.so
            // VMA range. Read-only File pages (.text/.rodata) stay
            // shared forever; writable File pages (.data) get the
            // same RO-remap + COW-on-first-write treatment as anon.
            let share_pages = matches!(
                vma.backing,
                VmaBacking::Anonymous
                | VmaBacking::KernelBytes { .. }
                | VmaBacking::File { .. }
            );
            if !share_pages { continue; }
            let mut va = vma.start.as_u64();
            let end = vma.end.as_u64();
            while va < end {
                // SAFETY: M::translate reads the active PT for the parent.
                if let Some((src_pa, _)) = unsafe { Some(M::translate(Va(va))).flatten() } {
                    let pa = src_pa.0 & !(PAGE_SIZE_BYTES - 1);
                    // Bump per-page refcount: child + parent both ref it.
                    inc_ref(pa);
                    // Compute child PTE flags. If the VMA is writable,
                    // strip the W bit so first-write triggers
                    // copy-on-write split. Else use the VMA prot
                    // verbatim (RO/RX pages stay shared forever).
                    let child_prot = if writable && !shared {
                        let mut p = vma.prot;
                        p.remove(VmaProt::WRITE);
                        p
                    } else {
                        vma.prot
                    };
                    let child_flags = child_prot.to_page_flags();
                    // DIAG (debug-atexit): fork map_at into the child root at a
                    // lib-arena VA. ino=2 marks fork origin; root=child root.
                    #[cfg(feature = "debug-atexit")]
                    if (0x7ffff6000000..0x7ffff8000000).contains(&va) {
                        crate::tailwatch::log_install(b"fork", 2, 0, va, pa, new_root_pa);
                    }
                    // SAFETY: new_root_pa carries kernel-half clone; va aligned in user range; flags carry USER per `11§5`; pa is the parent's mapped frame whose refcount we just bumped.
                    unsafe {
                        M::map_at(new_root_pa, Va(va), Pa(pa), child_flags, PageSize::P4K);
                    }
                    // If parent's PTE was writable, remap RO so the
                    // next parent write also triggers COW split. The
                    // M::map writes through the active CR3 (parent's
                    // root). M::map's own implementation flushes the
                    // VA on x86; aarch64 may need an explicit flush.
                    if writable && !shared {
                        // SAFETY: parent's CR3 is active; same-PA remap
                        // with W bit cleared; pa is current mapping per
                        // translate above.
                        unsafe { M::map(Va(va), Pa(pa), child_flags, PageSize::P4K); }
                        // SAFETY: privileged TLB invalidation is legal at CPL=0/EL1.
                        unsafe { M::flush_va(Va(va)); }
                        // debug-cow: this frame is now RO-shared between
                        // parent + child. Snapshot its content; any later
                        // change before a COW copy = a peer wrote a RO-shared
                        // page (stale TLB / wrong frame). No-op when feature
                        // off. ANON → [COW-CORRUPT]; FILE-private (shared-lib
                        // .data/GOT/.bss W-stripped at fork) → [FILE-CORRUPT].
                        if matches!(vma.backing, VmaBacking::Anonymous) {
                            crate::debug_cow::record(pa, _hhdm_offset);
                        } else if matches!(vma.backing, VmaBacking::File { .. }) {
                            crate::debug_cow::record_file(pa, _hhdm_offset);
                        }
                    }
                }
                va += PAGE_SIZE_BYTES;
            }
        }
        // SMP TLB coherence (`20§5`): we just write-protected the parent's
        // own PTEs (the W-strip above) on THIS CPU only. Other CPUs running
        // a peer thread of the SAME mm still hold the old WRITABLE entries in
        // their TLB and would write straight into frames now COW-shared with
        // the child — write-while-shared corruption invisible to refcount.
        // x86 invlpg is local-only (no hardware broadcast like aarch64
        // tlbi-is), so broadcast a full remote flush. No-op on UP / aarch64 /
        // hosted. One full flush beats a per-page IPI across the whole AS.
        // Target only the CPUs that have THIS mm loaded (the parent's
        // cpumask) per Linux flush_tlb_others — not every online CPU.
        hal::tlb::shootdown_others_all(self.cpumask());
        let accounting = super::accounting::VmAccounting::from_vmas(new_root_pa, &dst);
        let child = Arc::new_cyclic(|w| Self {
            vmas: RwLock::new(dst),
            pt_lock: Spinlock::new(()),
            root_pa: new_root_pa,
            brk:     core::sync::atomic::AtomicU64::new(self.brk()),
            brk_max: core::sync::atomic::AtomicU64::new(self.brk_max()),
            teardown: core::sync::atomic::AtomicU64::new(0),
            exe_path: Spinlock::new(self.exe_path.lock().clone()),
            mmap_base: core::sync::atomic::AtomicU64::new(self.mmap_base()),
            vdso_rt_sigreturn: core::sync::atomic::AtomicU64::new(self.vdso_rt_sigreturn()),
            membarrier: super::membarrier::MembarrierState::forked_from(&self.membarrier),
            self_weak: w.clone(),
            has_uffd: core::sync::atomic::AtomicBool::new(false), // fork clears child uffd (no EVENT_FORK)
            mlock_future: core::sync::atomic::AtomicBool::new(false), // Linux does not inherit mlockall state across fork.
            mlock_onfault: core::sync::atomic::AtomicBool::new(false),
            // Fresh/forked AS: no CPU has loaded it yet (Linux clears
            // mm_cpumask on mm init; the activating CPU sets its bit).
            cpumask: core::sync::atomic::AtomicU64::new(0),
            mm_layout: super::mmfields::MmLayout::forked(&self.mm_layout),
            accounting,
        });
        // Linux `anon_vma_fork`: each anonymous VMA in the child
        // inherits the parent's `Arc<AnonVma>` (already cloned by
        // `Vma::clone` above) and adds an rmap chain edge for the
        // child's own (mm, vma_range). Without this, rmap_walk on a
        // shared frame would only enumerate the parent — child PTEs
        // would be invisible to migration / KSM / pageout.
        let child_weak = Arc::downgrade(&child);
        let child_tree = child.vmas.read();
        for cv in child_tree.iter() {
            if let Some(av) = cv.anon_vma.as_ref() {
                av.attach(child_weak.clone(), cv.start.as_u64(), cv.end.as_u64());
            }
            if let (Some(rmap), VmaBacking::File { off, .. }) = (cv.file_rmap.as_ref(), &cv.backing) {
                rmap.attach(child_weak.clone(), cv.start.as_u64(), cv.end.as_u64(), off / PAGE_SIZE_BYTES);
            }
        }
        drop(child_tree);
        Ok(child)
    }

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
            dst.insert(vma.clone()).map_err(|_| Error::NoMem)?;
        }
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
                    let pte_flags = vma.prot.to_page_flags();
                    // SAFETY: new_root_pa carries kernel-half clone of master per P2-19; va page-aligned in user range; dst_pa fresh; flags carry USER per `11§5`.
                    unsafe {
                        M::map_at(new_root_pa, Va(va), Pa(dst_pa), pte_flags, PageSize::P4K);
                    }
                }
                va += PAGE_SIZE_BYTES;
            }
        }
        let accounting = super::accounting::VmAccounting::from_vmas(new_root_pa, &dst);
        Ok(Arc::new_cyclic(|w| Self {
            vmas: RwLock::new(dst),
            pt_lock: Spinlock::new(()),
            root_pa: new_root_pa,
            brk:     core::sync::atomic::AtomicU64::new(self.brk()),
            brk_max: core::sync::atomic::AtomicU64::new(self.brk_max()),
            teardown: core::sync::atomic::AtomicU64::new(0),
            exe_path: Spinlock::new(self.exe_path.lock().clone()),
            mmap_base: core::sync::atomic::AtomicU64::new(self.mmap_base()),
            vdso_rt_sigreturn: core::sync::atomic::AtomicU64::new(self.vdso_rt_sigreturn()),
            membarrier: super::membarrier::MembarrierState::forked_from(&self.membarrier),
            self_weak: w.clone(),
            has_uffd: core::sync::atomic::AtomicBool::new(false), // fork clears child uffd (no EVENT_FORK)
            mlock_future: core::sync::atomic::AtomicBool::new(false), // Linux does not inherit mlockall state across fork.
            mlock_onfault: core::sync::atomic::AtomicBool::new(false),
            // Fresh/forked AS: no CPU has loaded it yet (Linux clears
            // mm_cpumask on mm init; the activating CPU sets its bit).
            cpumask: core::sync::atomic::AtomicU64::new(0),
            mm_layout: super::mmfields::MmLayout::forked(&self.mm_layout),
            accounting,
        }))
    }

}
