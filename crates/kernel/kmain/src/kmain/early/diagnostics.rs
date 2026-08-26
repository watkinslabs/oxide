#[allow(unused_imports)] use super::*;

#[cfg(target_os = "oxide-kernel")]
pub(super) fn kalloc_smoke() {
    debug_boot! {
        let mut tree = vmm::VmaTree::new();
        let start = hal::UserVirtAddr::new(0x1000).expect("test addr");
        let end   = hal::UserVirtAddr::new(0x2000).expect("test addr");
        let inserted = tree.insert(vmm::Vma::new(start, end, vmm::VmaProt::READ,
            vmm::VmaFlags::PRIVATE | vmm::VmaFlags::ANONYMOUS, vmm::VmaBacking::Anonymous)).is_ok();
        if inserted { klog::kinfo!("kalloc-smoke: VmaTree insert ok"); }
        else { klog::kerror!("kalloc-smoke: VmaTree insert failed"); }
    }
}
#[cfg(target_os = "oxide-kernel")]
pub(super) fn debug_sched_smokes() {
    debug_sched! {
        // SAFETY: every smoke here spawns kthreads and yields; they require an
        // initialised scheduler on the boot CPU, which `sched_init` established
        // above, and run before any user task exists.
        unsafe {
            kthread::smoke();
            kthread::smoke_yield();
            smoke::ksched::smoke_rr(4);
            #[cfg(target_arch = "x86_64")]
            smoke::preempt::smoke_preempt_x86(4, 1_000_000);
            #[cfg(target_arch = "aarch64")]
            smoke::preempt::smoke_preempt_arm(4, 50_000);
            #[cfg(target_arch = "x86_64")]
            smoke::canary::smoke_canary_x86(1_000_000);
            #[cfg(target_arch = "aarch64")]
            smoke::canary::smoke_canary_arm(50_000);
        }
    }
}

#[cfg(target_os = "oxide-kernel")]
pub(super) fn debug_pf_smoke() {
    // SAFETY: the fault-recovery smoke installs and removes its own fixup
    // handler on the boot CPU before any user address space exists.
    #[cfg(all(target_arch = "x86_64", feature = "debug-vmm"))]
    unsafe { smoke::pf_recover::run(); }
}

/// B1347: pack the running task's context for kalloc's diag-validate capture:
/// bits[63:40]=`preempt_count`(24), [39:20]=`last_syscall_nr`(20), [19:0]=`tid`(20);
/// `u64::MAX` when no task is current (very-early boot / idle loop). # C: O(1)
#[cfg(all(target_os = "oxide-kernel", any(feature = "debug-heappoison", feature = "debug-dealloc-diag")))]
pub(super) fn kalloc_current_ctx() -> u64 {
    match sched::current() {
        Some(t) => {
            let tid = (t.tid as u64) & 0xF_FFFF;
            let sc = ((t.last_syscall_nr.load(core::sync::atomic::Ordering::Relaxed) as u64) & 0xF_FFFF) << 20;
            let pc = ((sched::preempt::preempt_count() as u64) & 0xFF_FFFF) << 40;
            pc | sc | tid
        }
        None => u64::MAX,
    }
}

/// B1347: pack the hard-IRQ arrival counter + last vector `(IRQ_SEQ << 8) | vec`
/// from the arch IRQ dispatcher, for kalloc's corruption detector. # C: O(1)
#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel", any(feature = "debug-heappoison", feature = "debug-dealloc-diag")))]
pub(super) fn kalloc_irq_info() -> u64 {
    use core::sync::atomic::Ordering;
    (arch_irq::lapic::IRQ_SEQ.load(Ordering::Acquire) << 8)
        | (arch_irq::lapic::IRQ_LAST_VEC.load(Ordering::Acquire) & 0xff)
}

#[cfg(target_os = "oxide-kernel")]
pub(super) fn debug_boot_smokes() {
    debug_boot! {
        ::devfs::misc::smoke_test();
        procfs::smoke_test();
        fs::pipe::smoke_test();
        fs::tmpfs::smoke_test();
        devpts::smoke_test();
    }
    debug_boot! { klog::write_raw(b"[INFO]  syscall: ~200 slots wired (real impls + compat stubs)\n"); }
}


/// Fault-path stack naming: resolve `va` to its kstack slot and name it.
///
/// Lock-free by construction — atomics and arithmetic only — because it runs
/// from the fault printer, including the double-fault path.
/// # C: O(n_cpus)
#[cfg(target_arch = "x86_64")]
pub(super) fn stack_name_for_fault(va: u64, out: &mut hal_x86_64::StackReport) -> bool {
    match ::sched::kstack::describe_fault(va) {
        Some((kind, span)) => {
            let (site, count) = ::sched::kstack::stack_top_repeat(&span);
            *out = hal_x86_64::StackReport {
                name: kind.name(), guard_lo: span.guard_lo,
                stack_lo: span.stack_lo, stack_hi: span.stack_hi,
                repeat_site: site, repeat_count: count,
            };
            true
        }
        None => false,
    }
}
