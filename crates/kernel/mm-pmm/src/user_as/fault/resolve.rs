// Resolution of one classified user fault against a specific address space:
// the swap and migration leaves that must be settled before demand paging can
// treat the address as absent, the userfaultfd interception, and the call into
// the VMM fill.

use super::super::*;
use super::{PAGE_BYTES, PAGE_MASK};

/// Cgroup identity captured when an anonymous page is born. A kernel-thread
/// or pre-scheduler fault resolves to root through the cgroup hierarchy.
/// # C: O(log n)
fn current_memcg() -> u64 {
    let pid = sched::live::current()
        .map(|task| task.tgid.load(core::sync::atomic::Ordering::Acquire) as u64)
        .unwrap_or(0);
    cgroup::cgroup_of(pid)
}

/// Park a faulting task on a real migration marker and make it restart after
/// the pageout transaction publishes either the restored resident PTE or the
/// canonical swap PTE.  The registry registration occurs while its token lock
/// is held, but the page-table lock is dropped before scheduling.
fn handle_migration_fault(as_: &AddressSpace, uva: UserVirtAddr, hhdm: u64) -> bool {
    let va = uva.as_u64() & !PAGE_MASK;
    let marker = {
        let _pt = as_.lock_page_table();
        // SAFETY: the page-table lock is held for the whole walk and `as_` is
        // borrowed by the caller, so neither the root nor any intermediate
        // table can be freed under it; HHDM covers every table page read.
        #[cfg(target_arch = "x86_64")]
        let entry = unsafe {
            hal::pt_walker::migration_entry_4k_at_root::<hal_x86_64::vmm::PtWalkerX86>(
                as_.root_pa(), va, hhdm,
            )
        };
        // SAFETY: same held page-table lock and HHDM coverage as the x86_64
        // arm above; only the walker type differs.
        #[cfg(target_arch = "aarch64")]
        let entry = unsafe {
            hal::pt_walker::migration_entry_4k_at_root::<hal_aarch64::vmm::PtWalkerArm>(
                as_.root_pa(), va, hhdm,
            )
        };
        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        let entry = { let _ = (as_, va, hhdm); None };
        entry.filter(|entry| {
            vmm::migration_pending_then(*entry, || sched::live::migration_wait::park(entry.token()))
        })
    };
    if marker.is_none() { return false; }
    sched::live::migration_wait::schedule_after_park();
    true
}

// SIGSEGV delivery + fault-to-signal terminator implementations
// split into `signal.rs` per `08§7` file-length cap.

/// Run the demand-page resolver against a specific AS. F157: uses
/// the COW-aware variant — passes refcount + dec_ref callbacks so
/// Protection-write faults short-circuit to a same-PA W-flip when
/// we're the sole owner, and copy + dec_ref the shared frame
/// otherwise.
/// F158: NotPresent faults try MAP_GROWSDOWN stack auto-extension
/// before falling through to the normal demand-page path.
pub(in crate::user_as) fn do_handle(as_: &AddressSpace, uva: UserVirtAddr, fault: FaultKind, hhdm: u64,
                        user_mode: bool)
    -> Result<(), vmm::Error>
{
    // DIAG (debug-atexit): sentinel-frame re-verify on every fault entry —
    // names the window in which the watched tail page went zero ([TAILZAP]).
    #[cfg(feature = "debug-atexit")]
    vmm::tailwatch::check(sched::live::current().map(|c| c.tid).unwrap_or(0));
    // RANK-1 decisive test (graph analysis): a fault resolves against `as_`'s
    // VMA tree but installs into the ACTIVE root. If active CR3 != as_.root_pa
    // the install lands in the WRONG address space — the deterministic-target /
    // random-victim geometry. Log both roots + the faulting VA; do not panic
    // (boot continues so the corruption still reproduces for correlation).
    #[cfg(all(feature = "debug-atexit", target_arch = "x86_64"))]
    {
        let cr3 = hal_x86_64::read_cr3() & !PAGE_MASK;
        let mmroot = as_.root_pa() & !PAGE_MASK;
        if cr3 != mmroot {
            klog::write_raw(b"[CR3-DESYNC] va=");
            klog::write_hex_u64(uva.as_u64());
            klog::write_raw(b" cr3=");
            klog::write_hex_u64(cr3);
            klog::write_raw(b" mm-root=");
            klog::write_hex_u64(mmroot);
            klog::write_raw(b" tid=");
            klog::write_dec_u64(sched::live::current().map(|c| c.tid as u64).unwrap_or(0));
            klog::write_raw(b"\n");
        }
    }
    // debug-cow item 2: task-struct integrity. Validate the running task's
    // head fields on every fault entry (the cheapest place that already has
    // `current()`); a clobbered struct head (the sched task corruption
    // candidate) surfaces as [TASK-CORRUPT]. The task struct is sched-owned,
    // so we hand it the field's own address + fixed length rather than add
    // a magic field across the crate boundary. No-op off.
    // B1414: `name` is now an embedded `[u8; TASK_COMM_LEN]` behind a
    // Spinlock (mutable per-thread comm), not a `&'static str` fat pointer —
    // there is no separate ptr/len pair to canary-check for this field
    // anymore, so the old ptr==0/len>256 signal is structurally inert
    // (always non-null, always TASK_COMM_LEN); only the `tid`-range check
    // inside `check_task` still does anything for this call site.
    #[cfg(feature = "debug-cow")]
    if let Some(t) = sched::current() {
        let name_addr = core::ptr::addr_of!(t.name) as u64;
        vmm::debug_cow::check_task(t.tid, name_addr, sched::TASK_COMM_LEN as u64);
    }
    // F158: stack auto-grow. If the fault lands just below a
    // GROWSDOWN VMA's start (within Linux's 64 KiB guard distance),
    // extend the VMA to cover the faulting address. Subsequent
    // demand-page resolves it normally.
    if matches!(fault, FaultKind::NotPresent { .. }) {
        if as_.find_vma(uva).is_none() {
            let (max_size, max_grow) = stack_growth_caps(as_);
            as_.try_grow_stack(uva, max_size, max_grow);
        }
    }
    // A swap PTE is neither an absent mapping nor a userfaultfd-MISSING
    // page. Resolve it before either path can treat it as zero-fillable.
    // The install below compares the exact encoded entry while holding this
    // mm's PTE lock, so two simultaneous faults cannot overwrite each other.
    if let FaultKind::NotPresent { access } = fault {
        if handle_migration_fault(as_, uva, hhdm) { return Ok(()); }
        if handle_swap_fault(as_, uva, access, hhdm)? { return Ok(()); }
    }
    // userfaultfd interception. A fault the monitor owns never reaches the
    // resolve below: `uffd::*` enqueue a message, wake the monitor and BLOCK
    // this thread until an ioctl resolves the address, then ask for a retry.
    // A poisoned page is checked FIRST — its contents are gone, so no mode and
    // no backing may re-materialise it.
    //
    // `Intercept::Fail` is the unresolved arm (a kernel-mode fault against a
    // user-mode-only context, or a poisoned page under uaccess): report the
    // fault so the exception table turns the access into EFAULT rather than
    // parking the kernel in a monitor's queue.
    let mut install_uffd_wp = false;
    {
        use crate::user_as::uffd::Intercept;
        let decided = match fault {
            FaultKind::NotPresent { access } => {
                let page = uva.as_u64() & !(hal::PAGE_SIZE_BYTES - 1);
                uffd::poisoned(as_, page, user_mode, hhdm).or_else(|| {
                    uffd::not_present(as_, uva, matches!(access, FaultAccess::Write), user_mode, hhdm)
                })
            }
            FaultKind::Protection { access: FaultAccess::Write } =>
                uffd::write_protected(as_, uva, user_mode, hhdm),
            FaultKind::Protection { .. } => None,
        };
        match decided {
            Some(Intercept::Retry) => return Ok(()),
            Some(Intercept::Fail)  => return Err(vmm::Error::Fault),
            // The address carried the write-protect state with no page to hold
            // it. The resolve below materialises the page ALREADY protected, in
            // the one store that publishes it — never writable for a window a
            // peer thread's write could use.
            Some(Intercept::ResolveProtected) => install_uffd_wp = true,
            None => {}
        }
    }
    // debug-cow item 1: re-verify the RO-shared anon checksum at the COW
    // write-fault, BEFORE the handler copies/reuses the frame. Translate the
    // faulting VA to its current frame and hand it to the vmm side, which
    // logs [COW-CORRUPT] iff that frame's content changed while it was
    // supposed to be RO-shared (a peer wrote it via a stale writable TLB, or
    // the wrong frame was installed). Done here (not in vmm) so the log can
    // name the running task (pid==tid) + CPU. No-op when the feature is off.
    #[cfg(feature = "debug-cow")]
    if let FaultKind::Protection { access: FaultAccess::Write } = fault {
        use hal::MmuOps;
        let va_page = uva.as_u64() & !(hal::PAGE_SIZE_BYTES - 1);
        // Read-only translate of the active CR3/TTBR0 for the faulting VA
        // through the safe `MmuOps` trait method.
        #[cfg(target_arch = "x86_64")]
        let cur = hal_x86_64::mmu_ops::X86Mmu::translate(hal::Va(va_page));
        #[cfg(target_arch = "aarch64")]
        let cur = hal_aarch64::mmu_ops::ArmMmu::translate(hal::Va(va_page));
        if let Some((p, _)) = cur {
            let tid = sched::current().map(|t| t.tid).unwrap_or(0);
            let cpu = current_cpu_idx() as u32;
            vmm::debug_cow::check_write(p.0 & !PAGE_MASK, va_page, hhdm, tid, cpu);
        }
    }
    // SAFETY: live per-arch MmuOps state initialised by kernel_main; alloc closure wraps the global PMM; synchronous fault context owns this task's frame; `as_` is borrowed read-only at entry (the AS takes its own RwLock internally). `set_rmap` invokes Linux-shape `page_add_anon_rmap` against the kernel's PageMeta-backed AnonVma slot.
    unsafe {
        #[cfg(target_arch = "x86_64")]
        let admitted_memcg = core::cell::Cell::new(cgroup::NO_MEMCG);
        #[cfg(target_arch = "x86_64")]
        let r = as_.handle_page_fault_cow_rmap::<hal_x86_64::mmu_ops::X86Mmu, _, _, _, _, _, _, _, _>(
            uva, fault, hhdm, install_uffd_wp,
            || crate::setup::alloc_one_frame(),
            |pa| crate::setup::frame_refcount(pa),
            // SAFETY: dec_ref of a previously-mapped shared frame after COW split; rmap_aware_dec_and_maybe_free clears page->mapping before the frame returns to PMM.
            |pa| crate::setup::rmap_aware_dec_and_maybe_free(pa),
            // SAFETY: live AnonVma; pa is freshly-installed PTE frame.
            |pa, av, idx| {
                crate::setup::set_anon_rmap_for_pa(pa, av, idx);
                crate::setup::set_memcg_for_pa(pa, admitted_memcg.replace(cgroup::NO_MEMCG));
                kassert!(crate::setup::admit_anon_lru(pa).is_ok(), "anon lru admission invariant");
            },
            // inc_ref for KernelFrame (vvar) so AS-drop dec balances to kernel's reference
            // (unsafe context inherited from the enclosing block).
            |pa| { crate::setup::inc_ref(pa); },
            // F157-A3 wp_page_reuse predicate: anon && PageAnonExclusive && mapcount==1.
            |pa| crate::setup::can_reuse_anon_exclusive(pa),
            || {
                let memcg = current_memcg();
                if !cgroup::try_charge_memcg(memcg, PAGE_BYTES) { return Err(vmm::Error::NoMem); }
                admitted_memcg.set(memcg);
                Ok(())
            },
            || {
                let memcg = admitted_memcg.replace(cgroup::NO_MEMCG);
                if memcg != cgroup::NO_MEMCG {
                    cgroup::uncharge_memcg(memcg, PAGE_BYTES);
                }
            });
        #[cfg(target_arch = "aarch64")]
        let admitted_memcg = core::cell::Cell::new(cgroup::NO_MEMCG);
        #[cfg(target_arch = "aarch64")]
        let r = as_.handle_page_fault_cow_rmap::<hal_aarch64::mmu_ops::ArmMmu, _, _, _, _, _, _, _, _>(
            uva, fault, hhdm, install_uffd_wp,
            || crate::setup::alloc_one_frame(),
            |pa| crate::setup::frame_refcount(pa),
            // SAFETY: dec_ref + rmap clear; rmap_aware free path.
            |pa| crate::setup::rmap_aware_dec_and_maybe_free(pa),
            |pa, av, idx| {
                crate::setup::set_anon_rmap_for_pa(pa, av, idx);
                crate::setup::set_memcg_for_pa(pa, admitted_memcg.replace(cgroup::NO_MEMCG));
                kassert!(crate::setup::admit_anon_lru(pa).is_ok(), "anon lru admission invariant");
            },
            // inc_ref for KernelFrame (vvar); balances AS-drop dec (unsafe context
            // inherited from the enclosing block).
            |pa| { crate::setup::inc_ref(pa); },
            // F157-A3 wp_page_reuse predicate: anon && PageAnonExclusive && mapcount==1.
            |pa| crate::setup::can_reuse_anon_exclusive(pa),
            || {
                let memcg = current_memcg();
                if !cgroup::try_charge_memcg(memcg, PAGE_BYTES) { return Err(vmm::Error::NoMem); }
                admitted_memcg.set(memcg);
                Ok(())
            },
            || {
                let memcg = admitted_memcg.replace(cgroup::NO_MEMCG);
                if memcg != cgroup::NO_MEMCG {
                    cgroup::uncharge_memcg(memcg, PAGE_BYTES);
                }
            });
        // Shared file/shmem pages are owned by the backing inode's i_mmap
        // reverse-map tree.  Bind PageMeta only after the PTE commit succeeded;
        // a failed/stale fault must not leave a frame pointing at an unrelated
        // file owner.  The VMA supplies the canonical file-page index.
        if r.is_ok() {
            if let Some(vma) = as_.find_vma(uva) {
                if let (Some(rmap), VmaBacking::File { off, .. }) = (vma.file_rmap.as_ref(), &vma.backing) {
                    use hal::MmuOps;
                    let va_page = uva.as_u64() & !PAGE_MASK;
                    #[cfg(target_arch = "x86_64")]
                    let mapped = hal_x86_64::mmu_ops::X86Mmu::translate(hal::Va(va_page));
                    #[cfg(target_arch = "aarch64")]
                    let mapped = hal_aarch64::mmu_ops::ArmMmu::translate(hal::Va(va_page));
                    if let Some((pa, _)) = mapped {
                        let index = off.saturating_add(va_page - vma.start.as_u64()) / PAGE_BYTES;
                        // Successful shared-file PTE install retains this frame; PageMeta
                        // becomes the matching file-rmap owner (unsafe context inherited
                        // from the enclosing block).
                        crate::setup::set_file_rmap_for_pa(pa.0 & !PAGE_MASK, rmap, index as u32);
                    }
                }
            }
        }
        // A VM_LOCKED mapping must move an already-admitted resident page to
        // PMM's unevictable LRU only after the fault transaction has installed
        // its PTE and all backing/accounting ownership is valid. This also
        // covers MCL_ONFAULT without making VMM own PageMeta transitions.
        if r.is_ok() && as_.find_vma(uva).map(|v| v.flags.contains(VmaFlags::LOCKED)).unwrap_or(false) {
            use hal::MmuOps;
            let va_page = uva.as_u64() & !PAGE_MASK;
            // The successful fault installed this leaf in the active current
            // address space; this is a read-only translation.
            #[cfg(target_arch = "x86_64")]
            let mapped = hal_x86_64::mmu_ops::X86Mmu::translate(hal::Va(va_page));
            #[cfg(target_arch = "aarch64")]
            let mapped = hal_aarch64::mmu_ops::ArmMmu::translate(hal::Va(va_page));
            if let Some((pa, _)) = mapped {
                let _ = crate::setup::set_lru_unevictable(pa.0 & !PAGE_MASK, true);
            }
        }
        r
    }
}

/// Resolve one architecture-encoded swap PTE for the current address space.
/// Returns `Ok(false)` when the leaf is not a swap entry, allowing ordinary
/// demand paging to continue. A changed PTE after I/O is a benign stale fault:
/// the fresh frame is released and the instruction retries against its winner.
/// # C: O(page I/O + walk depth)
fn handle_swap_fault(
    as_: &AddressSpace, uva: UserVirtAddr, access: FaultAccess, hhdm: u64,
) -> Result<bool, vmm::Error> {
    let va_page = uva.as_u64() & !PAGE_MASK;
    // SAFETY: `as_` is live for this fault; HHDM covers its page tables.
    let entry = unsafe {
        #[cfg(target_arch = "x86_64")]
        { hal::pt_walker::swap_entry_4k_at_root::<hal_x86_64::vmm::PtWalkerX86>(as_.root_pa(), va_page, hhdm) }
        #[cfg(target_arch = "aarch64")]
        { hal::pt_walker::swap_entry_4k_at_root::<hal_aarch64::vmm::PtWalkerArm>(as_.root_pa(), va_page, hhdm) }
        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        { None }
    };
    let Some(entry) = entry else { return Ok(false); };
    crate::user_as::swap_in::restore_swap_entry(as_, uva, entry, Some(access), hhdm)
}
