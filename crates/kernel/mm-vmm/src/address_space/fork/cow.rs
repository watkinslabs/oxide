// Copy-on-write fork: the child shares its parent's frames, both sides lose
// write permission where a split is due, and the non-present leaves — swap
// slots and markers, with the write-protect state riding on them — are
// inherited by value.

use alloc::sync::Arc;

use hal::{MmuOps, Pa, PageSize, Va, PAGE_SIZE_BYTES};
use sync::Spinlock;

use crate::tree::VmaTree;
use crate::vma::{VmaBacking, VmaFlags, VmaProt};
use crate::{Error, KResult};

use super::super::AddressSpace;
use super::super::rss::{class_of, RssTally};
use super::shared::{attach_child_rmaps, child_vma, needs_cow_wrprotect, rollback_swap_fork};
impl AddressSpace {
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
    /// `fork_copy_pages` with refcount-based page sharing, matching
    /// Linux's fork-time present-PTE copy:
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
            dst.insert(child_vma(vma)).map_err(|_| Error::NoMem)?;
        }
        // A child PTE owns a separate reference to the canonical swap slot.
        // Copy these first: a recoverable table-allocation failure then rolls
        // back all slot references before any present-page refcount changes.
        let mut cloned_swaps = alloc::vec::Vec::<(u64, hal::pt_walker::SwapEntry)>::new();
        // Linux `copy_page_range` charges the CHILD's `rss_stat` per copied
        // leaf. The child root is unpublished until this returns, so the
        // counts accumulate here and land in one `seed_ptes` below; without
        // them a forked process under-reports its residency for its whole
        // life, since nothing ever installs the leaves it already holds.
        let mut tally = RssTally::default();
        for vma in src.iter() {
            if vma.flags.contains(VmaFlags::DONTFORK)
                || (vma.flags.contains(VmaFlags::WIPEONFORK)
                    && matches!(vma.backing, VmaBacking::Anonymous))
                || !matches!(vma.backing, VmaBacking::Anonymous)
            { continue; }
            let keeps_wp = crate::uffd::child_keeps_wp(
                vma.flags & VmaFlags::UFFD_MASK,
                vma.uffd.as_ref().is_some_and(|c| c.wants_event(crate::uffd::UffdEventKind::Fork)));
            let mut va = vma.start.as_u64();
            while va < vma.end.as_u64() {
                let Some(entry) = M::swap_entry_at(self.root_pa, Va(va)) else {
                    va += PAGE_SIZE_BYTES;
                    continue;
                };
                // The barrier rides on the parent's swap leaf; the child's copy
                // gets one only if the child also inherits the monitor.
                let wp = keeps_wp && M::nonpresent_uffd_wp_at(self.root_pa, Va(va));
                if let Err(error) = retain_swap(va, entry) {
                    rollback_swap_fork::<M, FS>(new_root_pa, &cloned_swaps, &mut release_swap);
                    return Err(error);
                }
                // SAFETY: `new_root_pa` is an unpublished child root and the
                // fork holds the parent mmap write lock for this transaction.
                let installed = unsafe { M::map_swap_at(new_root_pa, Va(va), entry, wp) };
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
                tally.add_swap();
                va += PAGE_SIZE_BYTES;
            }
        }
        // A MARKER leaf is inherited as it stands. It names no page and no swap
        // slot, so there is nothing to retain and nothing to roll back — but
        // leaving it behind would hand the child a mapping whose contents were
        // declared unrecoverable as ordinary zeroes, or drop a write-protect
        // barrier the monitor still believes covers the child's range.
        for vma in src.iter() {
            if vma.flags.contains(VmaFlags::DONTFORK)
                || (vma.flags.contains(VmaFlags::WIPEONFORK)
                    && matches!(vma.backing, VmaBacking::Anonymous))
            { continue; }
            let mut va = vma.start.as_u64();
            while va < vma.end.as_u64() {
                if let Some(m) = M::pte_marker_at(self.root_pa, Va(va)) {
                    // SAFETY: `new_root_pa` is an unpublished child root and the fork holds the parent mmap write lock for this transaction; a marker leaf is non-present, so publishing it creates no mapping reference.
                    if unsafe { M::map_marker_at(new_root_pa, Va(va), m) }.is_err() {
                        rollback_swap_fork::<M, FS>(new_root_pa, &cloned_swaps, &mut release_swap);
                        return Err(Error::NoMem);
                    }
                }
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
            // CORRECTED (refcount-safe, matching Linux's fork-time page
            // sharing): the blanket
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
            // (libpam.so, libc.so, …) — matching Linux's fork page-sharing.
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
            let keeps_wp = crate::uffd::child_keeps_wp(
                vma.flags & VmaFlags::UFFD_MASK,
                vma.uffd.as_ref().is_some_and(|c| c.wants_event(crate::uffd::UffdEventKind::Fork)));
            // Granule this VMA's leaves use, read from the backing rather than
            // assumed: a hugetlbfs mapping has one block leaf per huge page,
            // and copying it as base pages would install 4 KiB leaves in the
            // child over memory the parent maps as one huge page.
            let huge_bytes = match &vma.backing {
                VmaBacking::File { backing, .. } => backing.huge_page_size(),
                _ => 0,
            };
            let (step, granule) = match hal::PageSize::from_bytes(huge_bytes) {
                Some(g) if huge_bytes != 0 => (huge_bytes, g),
                _                          => (PAGE_SIZE_BYTES, PageSize::P4K),
            };
            let mut va = vma.start.as_u64();
            let end = vma.end.as_u64();
            while va < end {
                // M::translate reads the active PT for the parent.
                if let Some((src_pa, src_flags)) = Some(M::translate(Va(va))).flatten() {
                    let pa = src_pa.0 & !(step - 1);
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
                    let mut child_flags = child_prot.to_page_flags().with_pkey(vma.pkey);
                    // The parent's page carries the monitor's barrier in its own
                    // permissions; rebuilding the child leaf from VMA protection
                    // alone would hand the child a writable copy of a page the
                    // monitor still believes it is watching.
                    if keeps_wp && src_flags.contains(hal::PageFlags::UFFD_WP) {
                        child_flags |= hal::PageFlags::UFFD_WP;
                    }
                    // DIAG (debug-atexit): fork map_at into the child root at a
                    // lib-arena VA. ino=2 marks fork origin; root=child root.
                    #[cfg(feature = "debug-atexit")]
                    if (0x7ffff6000000..0x7ffff8000000).contains(&va) {
                        crate::tailwatch::log_install(b"fork", 2, 0, va, pa, new_root_pa);
                    }
                    // SAFETY: new_root_pa carries kernel-half clone; va aligned in user range; flags carry USER per `11§5`; pa is the parent's mapped frame whose refcount we just bumped.
                    unsafe {
                        M::map_at(new_root_pa, Va(va), Pa(pa), child_flags, granule);
                    }
                    tally.add(class_of(&vma.backing));
                    // If parent's PTE was writable, remap RO so the
                    // next parent write also triggers COW split. The
                    // M::map writes through the active CR3 (parent's
                    // root). M::map's own implementation flushes the
                    // VA on x86; aarch64 may need an explicit flush.
                    if needs_cow_wrprotect(writable, shared,
                                           src_flags.contains(hal::PageFlags::WRITE)) {
                        // SAFETY: parent's CR3 is active; same-PA remap
                        // with W bit cleared; pa is current mapping per
                        // translate above.
                        unsafe { M::map(Va(va), Pa(pa), child_flags, granule); }
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
                va += step;
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
        // A child that never joins these directories is invisible to every
        // owner that routes by page-table root: its page-table frames are
        // never counted, `swapoff` never finds its swap leaves, and the
        // system-wide fold silently omits it. Since COW fork is how every
        // process after init comes into existence, omitting the registration
        // here meant those owners saw one address space, not all of them.
        super::super::accounting::register_page_table_owner(new_root_pa, &child.accounting);
        super::super::register_live_address_space(new_root_pa, Arc::downgrade(&child));
        // Linux `anon_vma_fork` plus the file `i_mmap` counterpart.
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
