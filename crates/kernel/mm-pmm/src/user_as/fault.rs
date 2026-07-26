use super::*;
const PAGE_MASK: u64 = hal::PAGE_SIZE_BYTES - 1;
const PAGE_BYTES: u64 = hal::PAGE_SIZE_BYTES;

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
        #[cfg(target_arch = "x86_64")]
        let entry = unsafe {
            hal::pt_walker::migration_entry_4k_at_root::<hal_x86_64::vmm::PtWalkerX86>(
                as_.root_pa(), va, hhdm,
            )
        };
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
#[cfg(feature = "debug-mount")]
use crate::user_as::debug::{STEP_ROOT, STEP_RIP, STEP_VA};

#[cfg(target_arch = "x86_64")]
pub fn user_fault_handler(vec: u64, err: u64, _rip: u64, cr2: u64) -> bool {
    if vec != 14 {
        // B44: non-#PF traps (#GP, #UD, #DE, #SS, #AC, ...). If they
        // came from user mode (CPL=3 in saved CS), the right answer
        // is to kill the task with SIGSEGV, not halt the kernel.
        // Without this, a single user-mode #GP (e.g. dhcpcd
        // dereferencing a non-canonical heap pointer) wedges every
        // CPU forever. Kernel-mode trips still fall through to the
        // halt-and-print path so we notice them.
        let frame_ptr = hal_x86_64::current_fault_frame();
        if !frame_ptr.is_null() {
            // SAFETY: live FaultFrame published by oxide_fault_print_rust on the kernel stack; we only read cs to check CPL.
            let cs = unsafe { (*frame_ptr).cs };
            if cs & 3 == 3 {
                deliver_sigsegv_x86(vec, err, _rip, cr2);
            }
        }
        return false;
    }
    let kind = match classify_x86_pf(err, cr2) {
        Some(k) => k,
        None    => return false,
    };
    // DIAG (debug-mount): the libc lock page is mapped RO (File arm) so its
    // first write traps here — log the writing instruction's RIP. RIP inside
    // glibc lll_lock = the lock pointer is right (a different bug); RIP inside
    // a str/mem* or a stray addr (cr2 != the lock word) = the corruptor.
    #[cfg(feature = "debug-mount")]
    if matches!(kind, FaultKind::Protection { access: FaultAccess::Write }) {
        if let Some(cur) = sched::live::current() {
            // SAFETY: single-mutator mm slot per 13§5; read-only VMA query.
            if let Some(mm) = unsafe { cur.mm_ref() } {
                if let Some(uva) = UserVirtAddr::new(cr2 & !PAGE_MASK) {
                    if let Some(v) = mm.find_vma(uva) {
                        if let VmaBacking::File { off, backing } = &v.backing {
                            let foff = off.wrapping_add((cr2 & !PAGE_MASK).wrapping_sub(v.start.as_u64()));
                            if foff == 0x1e7000 && backing.ino() == 0x6e54000000062076
                                && STEP_VA.load(Ordering::Acquire) == 0 {
                                // Single-step write-trap: make the page writable
                                // in place, arm RFLAGS.TF so a #DB fires right
                                // after THIS write instruction, and stash the
                                // target/RIP. The #DB hook (lock_step_hook) then
                                // reads the bytes just written — when they're an
                                // ASCII path ("/lib…") that RIP is the corruptor
                                // — re-protects the page RO, and clears TF.
                                let root = mm.root_pa();
                                unsafe { mprotect_pages(root, cr2 & !PAGE_MASK, PAGE_BYTES as usize, VmaProt::READ | VmaProt::WRITE); }
                                let f = hal_x86_64::current_fault_frame();
                                if !f.is_null() {
                                    // SAFETY: live FaultFrame on the kernel stack; set TF (bit 8).
                                    unsafe { (*f).rflags |= 0x100; }
                                    STEP_ROOT.store(root, Ordering::Release);
                                    STEP_RIP.store(_rip, Ordering::Release);
                                    STEP_VA.store(cr2, Ordering::Release);
                                    return true;
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    if handle(cr2, kind) {
        return true;
    }
    // debug-cow probe 2: the fault is now fatal (the demand-page resolver
    // refused it). Dump the failing VA + VMA + PTE/frame before SIGSEGV.
    #[cfg(feature = "debug-cow")]
    segv_dump(_rip, cr2, err);
    // Unhandled fault from user mode. F158: try Linux-style
    // catchable SIGSEGV — rewrite the live FaultFrame to call
    // the user-installed handler. If no handler is installed
    // (SIG_DFL), fall back to terminate via deliver_sigsegv.
    if err & 0x4 != 0 {
        if try_deliver_sigsegv_via_handler_x86(cr2) {
            return true;   // asm iretqs to user handler with rewritten frame
        }
        deliver_sigsegv_x86(vec, err, _rip, cr2);
    }
    false
}

/// # C: O(log N_vmas) + O(walk depth) on demand-page; O(1) reject
#[cfg(target_arch = "aarch64")]
pub fn user_fault_handler(esr: u64, far: u64, _elr: u64) -> bool {
    let kind = match classify_arm_abort(esr, far) {
        Some(k) => k,
        None    => return false,
    };
    if handle(far, kind) {
        return true;
    }
    #[cfg(feature = "debug-displaystack")]
    if let Some(cur) = sched::live::current() {
        // SAFETY: the synchronous EL0 fault runs against the current task;
        // this trace only snapshots the task-owned AddressSpace VMA tree.
        if let Some(mm) = unsafe { cur.mm_ref() } { dump_arm_vmas(mm); }
    }
    // Retained executable-stack fault provenance.  The same display-stack
    // feature that traces wait/futex calls records the exception class and
    // exact EL0/EL1 return PC when a child fails during desktop startup.
    // This is diagnostic-only and absent from production builds.
    #[cfg(feature = "debug-displaystack")]
    if let Some(cur) = sched::live::current() {
        klog::write_raw(b"[FAULT-ARM-CTX] tid=");
        klog::write_dec_u64(cur.tid as u64);
        klog::write_raw(b" vpid=");
        klog::write_dec_u64(cur.vtgid.load(Ordering::Acquire) as u64);
        klog::write_raw(b" esr=");
        klog::write_hex_u64(esr);
        klog::write_raw(b" ec=");
        klog::write_hex_u64((esr >> 26) & 0x3F);
        klog::write_raw(b" far=");
        klog::write_hex_u64(far);
        klog::write_raw(b" elr=");
        klog::write_hex_u64(_elr);
        klog::write_raw(b"\n");
    }
    // D339: distinguish a missing VMA from a page-table/fault-fill failure
    // for the ARM userspace translation fault that blocks target verification.
    #[cfg(feature = "debug-boot")]
    if let Some(cur) = sched::live::current() {
        // SAFETY: the current task's mm is read under the active-task
        // single-mutator invariant while handling its synchronous fault.
        if let Some(mm) = unsafe { cur.mm_ref() } {
            klog::write_raw(b"[FAULT-ARM-VMA] far=");
            klog::write_hex_u64(far);
            klog::write_raw(b" root=");
            klog::write_hex_u64(mm.root_pa());
            if let Some(v) = hal::UserVirtAddr::new(far).and_then(|va| mm.find_vma(va)) {
                klog::write_raw(b" hit start=");
                klog::write_hex_u64(v.start.as_u64());
                klog::write_raw(b" end=");
                klog::write_hex_u64(v.end.as_u64());
                klog::write_raw(b" prot=");
                klog::write_hex_u64(v.prot.bits() as u64);
                klog::write_raw(b" flags=");
                klog::write_hex_u64(v.flags.bits() as u64);
            } else {
                klog::write_raw(b" miss");
            }
            klog::write_raw(b"\n");
        }
    }
    // debug-cow probe 2: fatal fault — dump VA/VMA/PTE before SIGSEGV.
    // (ELR / FAR / ESR map to the rip / cr2 / err columns.)
    #[cfg(feature = "debug-cow")]
    segv_dump(_elr, far, esr);
    // Same SIGSEGV-on-user-fault contract as x86. ESR EC bits 26..31
    // distinguish lower-EL (user) from same-EL (kernel-mode user-buf
    // access): EC=0x20/0x24 are EL0 (user), EC=0x21/0x25 are EL1
    // same-EL (kernel-side). Only terminate the task on the EL0 case.
    let ec = (esr >> 26) & 0x3F;
    if matches!(ec, 0x20 | 0x24) {
        deliver_sigsegv_arm(esr, far, _elr);
    }
    false
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
pub(super) fn do_handle(as_: &AddressSpace, uva: UserVirtAddr, fault: FaultKind, hhdm: u64)
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
            as_.try_grow_stack(uva);
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
    // F1 userfaultfd MISSING: a NotPresent fault inside a MISSING-
    // registered range is handed to userspace (Linux `handle_userfault`)
    // — enqueue a PAGEFAULT message, wake the monitor, and BLOCK this
    // thread until UFFDIO_COPY/ZEROPAGE/WAKE resolves it. Only for a
    // genuinely-absent page: if the leaf is already present (a racer /
    // stale fault) fall through to the normal resolve. `uffd_for` clones
    // the ctx out + releases the vmas lock, so no lock is held across the
    // block below.
    if let FaultKind::NotPresent { access } = fault {
        if as_.maybe_uffd() {
            if let Some((ctx, true)) = as_.uffd_for(uva) {
                use hal::MmuOps;
                let va_page = uva.as_u64() & !(hal::PAGE_SIZE_BYTES - 1);
                #[cfg(target_arch = "x86_64")]
                let present = hal_x86_64::mmu_ops::X86Mmu::translate(hal::Va(va_page)).is_some();
                #[cfg(target_arch = "aarch64")]
                let present = hal_aarch64::mmu_ops::ArmMmu::translate(hal::Va(va_page)).is_some();
                if !present {
                    ctx.missing_fault(va_page, matches!(access, FaultAccess::Write));
                    return Ok(());
                }
            }
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
        // SAFETY: read-only translate of the active CR3/TTBR0 for the faulting VA.
        #[cfg(target_arch = "x86_64")]
        let cur = unsafe { hal_x86_64::mmu_ops::X86Mmu::translate(hal::Va(va_page)) };
        #[cfg(target_arch = "aarch64")]
        let cur = unsafe { hal_aarch64::mmu_ops::ArmMmu::translate(hal::Va(va_page)) };
        if let Some((p, _)) = cur {
            let tid = sched::current().map(|t| t.tid).unwrap_or(0);
            let cpu = current_cpu_idx() as u32;
            vmm::debug_cow::check_write(p.0 & !PAGE_MASK, va_page, hhdm, tid, cpu);
        }
    }
    // SAFETY: live per-arch MmuOps state initialised by kernel_main; alloc closure wraps the global PMM; fault context has IRQs masked; `as_` is borrowed read-only at entry (the AS takes its own RwLock internally). `set_rmap` invokes Linux-shape `page_add_anon_rmap` against the kernel's PageMeta-backed AnonVma slot.
    unsafe {
        #[cfg(target_arch = "x86_64")]
        let admitted_memcg = core::cell::Cell::new(cgroup::NO_MEMCG);
        #[cfg(target_arch = "x86_64")]
        let r = as_.handle_page_fault_cow_rmap::<hal_x86_64::mmu_ops::X86Mmu, _, _, _, _, _, _, _, _>(
            uva, fault, hhdm,
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
            // SAFETY: inc_ref for KernelFrame (vvar) so AS-drop dec balances to kernel's reference.
            |pa| unsafe { crate::setup::inc_ref(pa); },
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
            uva, fault, hhdm,
            || crate::setup::alloc_one_frame(),
            |pa| crate::setup::frame_refcount(pa),
            // SAFETY: dec_ref + rmap clear; rmap_aware free path.
            |pa| crate::setup::rmap_aware_dec_and_maybe_free(pa),
            |pa, av, idx| {
                crate::setup::set_anon_rmap_for_pa(pa, av, idx);
                crate::setup::set_memcg_for_pa(pa, admitted_memcg.replace(cgroup::NO_MEMCG));
                kassert!(crate::setup::admit_anon_lru(pa).is_ok(), "anon lru admission invariant");
            },
            // SAFETY: inc_ref for KernelFrame (vvar); balances AS-drop dec.
            |pa| unsafe { crate::setup::inc_ref(pa); },
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
                    let mapped = unsafe { hal_x86_64::mmu_ops::X86Mmu::translate(hal::Va(va_page)) };
                    #[cfg(target_arch = "aarch64")]
                    let mapped = unsafe { hal_aarch64::mmu_ops::ArmMmu::translate(hal::Va(va_page)) };
                    if let Some((pa, _)) = mapped {
                        let index = off.saturating_add(va_page - vma.start.as_u64()) / PAGE_BYTES;
                        // SAFETY: successful shared-file PTE install retains this
                        // frame; PageMeta becomes the matching file-rmap owner.
                        unsafe { crate::setup::set_file_rmap_for_pa(pa.0 & !PAGE_MASK, rmap, index as u32); }
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
            // SAFETY: the successful fault installed this leaf in the active
            // current address space; this is a read-only translation.
            #[cfg(target_arch = "x86_64")]
            let mapped = unsafe { hal_x86_64::mmu_ops::X86Mmu::translate(hal::Va(va_page)) };
            #[cfg(target_arch = "aarch64")]
            let mapped = unsafe { hal_aarch64::mmu_ops::ArmMmu::translate(hal::Va(va_page)) };
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

/// Dispatch the classified fault into the **current task's** AS.
/// Falls back to the global AS for boot-time faults that arrive
/// before any task is current (e.g. the demand-page smoke). Allocates
/// a PMM frame and installs the leaf via per-arch MmuOps; flushes
/// the faulting VA's TLB. Returns true to retry, false to halt.
fn handle(va_raw: u64, fault: FaultKind) -> bool {
    let hhdm = HHDM_OFFSET.load(Ordering::Acquire);
    let uva = match UserVirtAddr::new(va_raw) {
        Some(u) => u,
        None    => return false,
    };
    // DIAG (debug-atexit): the File fill installs lib-arena writable pages
    // READ-ONLY, so the FIRST write to a correctly-filled library page arrives
    // here as Protection{Write}. Capture the writing RIP (user ld.so text vs
    // kernel) + the pre-write bytes at the observed corruption offset (0x20).
    // A bulk `rep stosq` memset faults on its first store, so this names a
    // memset zeroer; the RIP range names user vs kernel.
    #[cfg(all(feature = "debug-atexit", target_arch = "x86_64"))]
    if matches!(fault, FaultKind::Protection { access: FaultAccess::Write })
        && (0x7ffff6000000..0x7ffff8000000).contains(&va_raw) {
        let fp = hal_x86_64::current_fault_frame();
        let rip = if fp.is_null() { 0 } else { unsafe { (*fp).rip } };
        // memset lives at ld.so bias 0x40000000 + [0x24970, 0x24a40). When the
        // zeroing store faults inside memset, dump its ARGS (rdi=dst, sil=val,
        // rdx=len) — the exact range ld.so clears. A val==0 memset whose
        // [dst,dst+len) spans file-data pages is the corruption: ld.so's BSS
        // clear range is wrong (kernel gave it a bad filesz/segment view).
        // Log the EXACT faulting offset (cr2 low 12 bits) + RIP for writes near
        // a .dynamic entry boundary (offset a multiple of 0x10, i.e. an
        // Elf64_Dyn slot). A zeroed slot at offset 0x20/0x40/... = DT_NULL early
        // terminator. memset RIPs additionally dump their dst/len.
        let off = va_raw & PAGE_MASK;
        let in_memset = (0x40024970..0x40024a40).contains(&rip);
        static WCOUNT: AtomicU64 = AtomicU64::new(0);
        if (off < 0x400) && WCOUNT.fetch_add(1, Ordering::Relaxed) < 300 {
            klog::write_raw(b"[W] va=");
            klog::write_hex_u64(va_raw);
            klog::write_raw(b" rip=");
            klog::write_hex_u64(rip);
            if in_memset {
                let gp = hal_x86_64::current_fault_gprs();
                if !gp.is_null() {
                    let g = unsafe { &*gp };
                    klog::write_raw(b" MEMSET dst=");
                    klog::write_hex_u64(g.rdi);
                    klog::write_raw(b" len=");
                    klog::write_hex_u64(g.rdx);
                }
            }
            klog::write_raw(b" tid=");
            klog::write_dec_u64(sched::live::current().map(|c| c.tid as u64).unwrap_or(0));
            klog::write_raw(b"\n");
        }
    }
    // Pick the AS the active CR3/TTBR0 actually targets: the
    // current task's mm if there is one (post-execve this is the
    // new AS, not the boot global). With `Task.mm` wrapped in
    // UnsafeCell we read via `mm_ref` under the single-mutator
    // invariant (preempt-off, single-CPU UP).
    // Resolve against the running task's mm only. There is no global address
    // space: every user fault belongs to the current task's AS. A user-VA
    // fault with no current user task (boot context before PID 1, or a kthread)
    // is a kernel bug, not something to paper over against a shared AS — return
    // unhandled so it surfaces. The boot PID-1 stack is mapped eagerly via
    // `prefault_stack` (setup_arg_pages), so no boot-context user fault occurs.
    let r = match sched::live::current() {
        // SAFETY: fault dispatcher with IRQs masked; cur is the running task on this CPU; no concurrent mm writer.
        Some(cur) => unsafe { cur.mm_ref() }.map(|mm| do_handle(mm, uva, fault, hhdm)),
        None => None,
    };
    #[cfg(all(feature = "debug-boot", target_arch = "x86_64"))]
    if !matches!(&r, Some(Ok(()))) {
        klog::write_raw(b"[FAULT-RESOLVE] va=");
        klog::write_hex_u64(va_raw);
        klog::write_raw(b" rip=");
        let frame = hal_x86_64::current_fault_frame();
        if frame.is_null() {
            klog::write_raw(b"none");
        } else {
            // SAFETY: the architecture publishes the live fault frame for
            // the duration of this synchronous fault dispatch.
            klog::write_hex_u64(unsafe { (*frame).rip });
        }
        match fault {
            FaultKind::NotPresent { access: _ } => klog::write_raw(b" kind=np"),
            FaultKind::Protection { access: _ } => klog::write_raw(b" kind=prot"),
        }
        let access = match fault {
            FaultKind::NotPresent { access } | FaultKind::Protection { access } => access,
        };
        match access {
            FaultAccess::Read => klog::write_raw(b" access=read"),
            FaultAccess::Write => klog::write_raw(b" access=write"),
            FaultAccess::Exec => klog::write_raw(b" access=exec"),
        }
        match &r {
            None => klog::write_raw(b" result=no-mm"),
            Some(Err(vmm::Error::NotImplemented)) => klog::write_raw(b" result=not-implemented"),
            Some(Err(vmm::Error::NoMem)) => klog::write_raw(b" result=no-mem"),
            Some(Err(vmm::Error::Inval)) => klog::write_raw(b" result=invalid"),
            Some(Err(vmm::Error::Fault)) => klog::write_raw(b" result=fault"),
            Some(Err(vmm::Error::Perm)) => klog::write_raw(b" result=permission"),
            Some(Err(vmm::Error::Again)) => klog::write_raw(b" result=again"),
            Some(Err(vmm::Error::Access)) => klog::write_raw(b" result=access"),
            Some(Err(vmm::Error::Io)) => klog::write_raw(b" result=io"),
            Some(Ok(())) => klog::write_raw(b" result=ok"),
        }
        klog::write_raw(b" cr3=");
        klog::write_hex_u64(hal_x86_64::read_cr3() & !PAGE_MASK);
        match sched::live::current().and_then(|cur| unsafe { cur.mm_ref() }) {
            Some(mm) => {
                klog::write_raw(b" mm=");
                klog::write_hex_u64(mm.root_pa());
                if let Some(vma) = mm.find_vma(uva) {
                    klog::write_raw(b" vma=");
                    klog::write_hex_u64(vma.start.as_u64());
                    klog::write_raw(b"-");
                    klog::write_hex_u64(vma.end.as_u64());
                    klog::write_raw(b" prot=");
                    klog::write_hex_u64(vma.prot.bits() as u64);
                } else { klog::write_raw(b" vma=none"); }
            }
            None => klog::write_raw(b" mm=none"),
        }
        klog::write_raw(b"\n");
    }
    match r {
        Some(Ok(())) => {
            // Flush the faulting VA so the retry sees the new PTE.
            // SAFETY: privileged TLB invalidation legal at CPL=0/EL1.
            #[cfg(target_arch = "x86_64")]
            unsafe { hal_x86_64::flush_local_va(va_raw); }
            // Prior no-op left a stale TLB entry on a remapped VA (heap
            // churn); the inner-shareable tlbi is also mandatory once APs
            // share the page tables. Use the existing ArmMmu::flush_va.
            #[cfg(target_arch = "aarch64")]
            // SAFETY: tlbi vae1is invalidates the just-mapped VA so the faulting instruction's retry walks the new PTE; privileged but legal at EL1.
            unsafe { <hal_aarch64::mmu_ops::ArmMmu as hal::MmuOps>::flush_va(hal::Va(va_raw)); }
            true
        }
        _ => false,
    }
}
