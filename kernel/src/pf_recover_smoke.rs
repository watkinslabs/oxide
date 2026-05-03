// Page-fault recovery smoke (P1-86c). Validates the recoverable
// fault path landed in #162 end-to-end on real CR3 walks:
//
//   1. Pre-allocate a backing frame from PMM.
//   2. Install a fault handler that on `#PF` with `cr2 == FAULT_VA`
//      maps the backing frame R|W, flushes the VA's TLB, returns
//      `true` (retry).
//   3. Write to FAULT_VA (currently unmapped) → CPU #PFs → handler
//      maps + retries → write completes.
//   4. Read back, verify magic.
//   5. Unmap, restore prior handler, log success.
//
// Prior attempt (session 18 abandoned): handler entered twice then
// hung. Suspected root cause: missing TLB invalidation on the
// faulting VA, so the CPU retried with a stale negative entry and
// re-faulted. This re-attempt explicitly `invlpg`s the VA before
// returning true.

#![cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]

use core::sync::atomic::{AtomicU64, AtomicBool, Ordering};
use hal::{MmuOps, Pa, PageFlags, PageSize, Va};
use hal_x86_64::{flush_local_va, install_fault_handler, FaultHandler};

const FAULT_VA: u64 = 0xffff_fd00_0001_0000;
const MAGIC: u64 = 0xC0FFEE_DEADBEEF;

/// Backing frame for the demand-paged page; populated by `run` and
/// read by the fault handler. Single-CPU pre-init context.
static BACKING_PA: AtomicU64 = AtomicU64::new(0);

/// Tripwire: handler sets this on its first invocation. Asserted
/// after the smoke completes to confirm we actually took the fault
/// (rather than e.g. the page accidentally being already mapped).
static HANDLER_FIRED: AtomicBool = AtomicBool::new(false);

/// Recursion guard: if the handler is entered with the page already
/// present, something else is broken — return false to halt cleanly
/// rather than spin.
static HANDLED_ONCE: AtomicBool = AtomicBool::new(false);

fn pf_recover_handler(vec: u64, _err: u64, _rip: u64, cr2: u64) -> bool {
    if vec != 14 || cr2 != FAULT_VA {
        return false;
    }
    HANDLER_FIRED.store(true, Ordering::Release);
    if HANDLED_ONCE.swap(true, Ordering::AcqRel) {
        // Second entry for the same VA → mapping didn't take. Halt.
        debug_irq! { klog::kerror!("pf-recover: re-fault after map; halting"); }
        return false;
    }
    let pa = BACKING_PA.load(Ordering::Acquire);
    if pa == 0 {
        debug_irq! { klog::kerror!("pf-recover: backing pa unset"); }
        return false;
    }
    // SAFETY: FAULT_VA is the kernel-half scratch slot owned by this
    // smoke; pa is a freshly-allocated PMM frame; flags are R|W with
    // EXEC clear (NX set on x86 leaf). MmuOps state initialised by
    // kernel_main pre-init.
    unsafe {
        <hal_x86_64::mmu_ops::X86Mmu as MmuOps>::map(
            Va(FAULT_VA),
            Pa(pa),
            PageFlags::READ | PageFlags::WRITE,
            PageSize::P4K,
        );
    }
    // SAFETY: `invlpg` is a privileged invalidation, legal at CPL=0;
    // drops any stale (negative) TLB entry the original fault might
    // have populated. Without this the CPU retry can re-fault and
    // cause the handler to loop / wedge.
    unsafe { flush_local_va(FAULT_VA); }
    true  // retry the faulting write
}

/// Run the recoverable-fault smoke. Halts cleanly on any failure
/// path; logs `pf-recover: ok` on success.
/// # SAFETY: caller is the boot path; PMM + MmuOps initialised;
/// FAULT_VA currently unmapped; single-CPU; IRQs masked.
/// # C: O(1) modulo a single PT walk on the fault path.
/// # Ctx: pre-init, IRQ-off, single-CPU
pub unsafe fn run() {
    // Reset state in case this fn ever runs >1× per boot.
    HANDLER_FIRED.store(false, Ordering::Release);
    HANDLED_ONCE.store(false, Ordering::Release);

    let pa = match crate::pmm_setup::alloc_one_frame() {
        Some(p) => p,
        None => {
            debug_irq! { klog::kerror!("pf-recover: PMM alloc failed"); }
            return;
        }
    };
    BACKING_PA.store(pa, Ordering::Release);

    // SAFETY: handler fn is 'static; pre-init single-CPU swap.
    let prev: FaultHandler = unsafe { install_fault_handler(pf_recover_handler) };

    // Trigger: write magic through the unmapped VA. CPU #PFs, the
    // handler maps the frame + invlpg, retries — write completes.
    // SAFETY: FAULT_VA's mapping is created on-fault by the handler;
    // we own the VA exclusively for the duration of this smoke.
    unsafe { core::ptr::write_volatile(FAULT_VA as *mut u64, MAGIC); }

    // Verify the write landed.
    // SAFETY: FAULT_VA is now mapped R|W; same exclusive-owner contract.
    let read = unsafe { core::ptr::read_volatile(FAULT_VA as *const u64) };

    // Restore prior handler so subsequent smokes (P1-82 userspace)
    // see the default behaviour again.
    // SAFETY: pre-init single-CPU swap; `prev` was returned by the matching install_fault_handler call above so it satisfies the AtomicPtr-tagged FaultHandler invariant.
    let _ = unsafe { install_fault_handler(prev) };

    if !HANDLER_FIRED.load(Ordering::Acquire) {
        debug_irq! { klog::kerror!("pf-recover: handler never fired (page already mapped?)"); }
        // SAFETY: FAULT_VA owned by this smoke; clean up.
        unsafe { <hal_x86_64::mmu_ops::X86Mmu as MmuOps>::unmap(Va(FAULT_VA), PageSize::P4K); }
        return;
    }
    if read != MAGIC {
        debug_irq! {
            klog::write_raw(b"[FAULT] pf-recover: read mismatch want=");
            klog::write_hex_u64(MAGIC);
            klog::write_raw(b" got=");
            klog::write_hex_u64(read);
            klog::write_raw(b"\n");
        }
        // SAFETY: FAULT_VA owned by this smoke; clean up.
        unsafe { <hal_x86_64::mmu_ops::X86Mmu as MmuOps>::unmap(Va(FAULT_VA), PageSize::P4K); }
        return;
    }

    // SAFETY: FAULT_VA owned by this smoke; clean up before exit.
    unsafe { <hal_x86_64::mmu_ops::X86Mmu as MmuOps>::unmap(Va(FAULT_VA), PageSize::P4K); }
    // SAFETY: invalidate the now-stale TLB entry post-unmap.
    unsafe { flush_local_va(FAULT_VA); }

    debug_irq! {
        klog::write_raw(b"[INFO]  pf-recover: ok pa=");
        klog::write_hex_u64(pa);
        klog::write_raw(b" magic=");
        klog::write_hex_u64(MAGIC);
        klog::write_raw(b"\n");
    }
}
