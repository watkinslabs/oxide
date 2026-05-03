// First userspace `iretq` smoke per `20§3` step 12 / Phase 1→2 boundary.
//
// Drops to CPL=3 by building a synthetic IRET frame and executing
// `iretq`. User code is a single `int3` (0xCC) — the CPU vectors back
// into the kernel via IDT[3] (#BP), proving:
//   - kernel-owned GDT user CS/SS descriptors are walkable (P1-93),
//   - TSS.RSP0 is the kernel-side stack on CPL3→CPL0 (P1-94),
//   - U/S=1 propagated through every interior PT entry (P1-95),
//   - the fault dispatcher receives the #BP from CPL=3 with the
//     CPU-pushed iretq frame intact.
//
// Layout:
//   USER_CODE_VA  0x0040_0000   1 page R|W|X|U  → first byte = 0xCC
//   USER_STACK_VA 0x0050_0000   1 page R|W|U
//   IRQ_STACK     PMM frame      → TSS.RSP0 = top
//
// On success the installed fault handler logs
//   `[INFO] userspace-eret-smoke: ok ring3 #BP rip=…`
// then halts. The pre-existing `boot: kernel ready, halting` is no
// longer reached on x86 builds with this smoke wired; the success
// log replaces it as the boot-completion signal.

#![cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]

use hal::{MmuOps, Pa, PageFlags, PageSize, Va};
use hal_x86_64::{install_fault_handler, set_rsp0, USER_CS, USER_DS};

const USER_CODE_VA:  u64 = 0x0040_0000;
const USER_STACK_VA: u64 = 0x0050_0000;
const USER_STACK_TOP: u64 = USER_STACK_VA + 0x1000;
const KSTACK_SIZE: u64 = 0x1000;

/// User-mode #BP detector. Logs success only if the fault came from
/// `USER_CODE_VA` (= our int3); otherwise stays silent and returns
/// false so the default halt path runs (some other unrelated fault).
fn user_bp_handler(vec: u64, _err: u64, rip: u64, _cr2: u64) -> bool {
    // Intel SDM Vol. 3 §6.7: #BP from `int3` (0xCC) is a trap, so
    // CPU pushes RIP = next instruction (= USER_CODE_VA + 1).
    if vec == 3 && rip == USER_CODE_VA + 1 {
        debug_irq! {
            klog::write_raw(b"[INFO]  userspace-eret-smoke: ok ring3 #BP rip=");
            klog::write_hex_u64(rip);
            klog::write_raw(b"\n");
        }
        // Fall through to halt; #BP from user is a one-shot smoke
        // landmark, not a recoverable event.
    }
    false
}

/// Map a single 4 KiB user page at `va` with the given flags.
/// # SAFETY: caller asserts `va` is unmapped on entry; PMM + MmuOps
/// state initialised; single-CPU pre-init.
unsafe fn map_user_page<M: MmuOps>(va: u64, flags: PageFlags) -> Option<u64> {
    let pa = crate::pmm_setup::alloc_one_frame()?;
    // SAFETY: per fn contract; flags carry USER for the leaf U bit.
    unsafe { M::map(Va(va), Pa(pa), flags, PageSize::P4K); }
    Some(pa)
}

/// Run the smoke against `M = X86Mmu`. `hhdm_offset` is the kernel's
/// HHDM base — used to derive a kernel VA for the IRQ landing stack.
/// # SAFETY: caller is the boot path; PMM + MmuOps + GDT + TSS + IDT
/// initialised; single-CPU; IRQs masked. Diverges (halts) on success
/// or first failure.
/// # C: O(1) modulo PT walks
/// # Ctx: pre-init, IRQ-off, single-CPU
pub unsafe fn run<M: MmuOps>(hhdm_offset: u64) -> ! {
    // Map user code page R|W|X|U (W is for our 0xCC write; W^X is
    // accepted only because this is a one-shot smoke).
    // SAFETY: USER_CODE_VA is unmapped on entry to the smoke; PMM + MmuOps state initialised by kernel_main pre-init; single-CPU.
    let code_pa = match unsafe {
        map_user_page::<M>(
            USER_CODE_VA,
            PageFlags::READ | PageFlags::WRITE | PageFlags::EXEC | PageFlags::USER,
        )
    } {
        Some(pa) => pa,
        None => {
            debug_irq! { klog::kerror!("userspace-eret-smoke: code-page alloc failed"); }
            halt_forever();
        }
    };
    // Map user stack page R|W|U.
    // SAFETY: USER_STACK_VA is unmapped on entry; PMM + MmuOps state initialised by kernel_main pre-init; single-CPU.
    let _stack_pa = match unsafe {
        map_user_page::<M>(
            USER_STACK_VA,
            PageFlags::READ | PageFlags::WRITE | PageFlags::USER,
        )
    } {
        Some(pa) => pa,
        None => {
            debug_irq! { klog::kerror!("userspace-eret-smoke: stack-page alloc failed"); }
            halt_forever();
        }
    };
    let _ = code_pa;

    // Write the user blob: 0xCC = int3. Subsequent retries land on
    // 0x00 (NOP-ish) — we never expect a retry since the handler
    // halts.
    // SAFETY: USER_CODE_VA mapped W|U|EXEC, sole owner this CPU.
    unsafe { core::ptr::write_volatile(USER_CODE_VA as *mut u8, 0xCCu8); }

    // Per-CPU IRQ landing stack. CPU writes to TSS.RSP0 on CPL3→CPL0
    // entry; the fault stub then runs on this stack.
    let kstack_pa = match crate::pmm_setup::alloc_one_frame() {
        Some(p) => p,
        None => {
            debug_irq! { klog::kerror!("userspace-eret-smoke: kstack alloc failed"); }
            halt_forever();
        }
    };
    // Use the HHDM kernel-side mapping (already established by Limine
    // and propagated via PMM/MmuOps init) so we have a kernel VA for
    // the IRQ stack.
    let kstack_top = hhdm_offset + kstack_pa + KSTACK_SIZE;
    // SAFETY: TSS in kernel BSS; we serialise pre-init; rsp0 points
    // at the top of a freshly-allocated, HHDM-mapped 4 KiB frame.
    unsafe { set_rsp0(kstack_top); }

    // Install the #BP handler. Default returns false (halt); ours
    // logs on user-#BP then also returns false (halt).
    // SAFETY: handler fn is 'static; pre-init single-CPU swap.
    let _prev = unsafe { install_fault_handler(user_bp_handler) };

    debug_irq! {
        klog::write_raw(b"[INFO]  userspace-eret-smoke: about to iretq cs=");
        klog::write_hex_u64(USER_CS as u64);
        klog::write_raw(b" rip=");
        klog::write_hex_u64(USER_CODE_VA);
        klog::write_raw(b" ss=");
        klog::write_hex_u64(USER_DS as u64);
        klog::write_raw(b" rsp=");
        klog::write_hex_u64(USER_STACK_TOP);
        klog::write_raw(b"\n");
    }

    // Build the iretq frame. CPU pops in order: RIP, CS, RFLAGS, RSP, SS.
    // RFLAGS = 0x002 (IF=0, reserved bit 1) — keep IRQs masked while
    // in user; the smoke fires int3 immediately so timer can't race.
    // SAFETY: synthetic CPL3-bound iretq frame; values built from
    // kernel-validated constants and freshly-mapped user-VA pages.
    unsafe {
        core::arch::asm!(
            "push {ss}",
            "push {rsp_u}",
            "push {rfl}",
            "push {cs}",
            "push {rip_u}",
            "iretq",
            ss    = in(reg) USER_DS as u64,
            rsp_u = in(reg) USER_STACK_TOP,
            rfl   = in(reg) 0x002u64,
            cs    = in(reg) USER_CS as u64,
            rip_u = in(reg) USER_CODE_VA,
            options(noreturn),
        );
    }
}

fn halt_forever() -> ! {
    loop {
        // SAFETY: hlt at CPL=0 parks until next IRQ; with IRQs masked
        // and no NMI source on the QEMU smoke, this is the terminal
        // state.
        unsafe { core::arch::asm!("hlt", options(nomem, nostack, preserves_flags)); }
    }
}
