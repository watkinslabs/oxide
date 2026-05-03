// First aarch64 userspace `eret` smoke. Mirror of the x86_64 P1-82
// smoke; unblocked now that `PtWalker::read_pt_base(va)` plumbs
// user-half VAs into TTBR0_EL1 (P2-08).
//
// Drops to EL0 via `eret`, executes a single `brk #0`, traps back
// to EL1 via the synchronous-from-lower-EL vector (VBAR_EL1+0x400)
// where the fault dispatcher classifies ESR.EC=0x3C and a custom
// handler logs success.
//
// Real syscall (SVC) path lands separately — this PR validates the
// transition + return mechanics + walker fix on a known-good
// foundation.

#![cfg(all(target_os = "oxide-kernel", target_arch = "aarch64"))]

use hal::{MmuOps, Pa, PageFlags, PageSize, Va};
use hal_aarch64::install_fault_handler;

const USER_CODE_VA:   u64 = 0x0000_0000_0040_0000;
const USER_STACK_VA:  u64 = 0x0000_0000_0050_0000;
const USER_STACK_TOP: u64 = USER_STACK_VA + 0x1000;

// `brk #0` little-endian: 0xD4200000 → 00 00 20 D4.
const USER_BLOB: [u8; 4] = [0x00, 0x00, 0x20, 0xD4];

/// ESR.EC = 0b111100 (0x3C) = "BRK instruction execution in AArch64".
const EC_BRK_AARCH64: u64 = 0x3C;

fn user_brk_handler(esr: u64, _far: u64, elr: u64) -> bool {
    let ec = (esr >> 26) & 0x3F;
    if ec == EC_BRK_AARCH64 && elr == USER_CODE_VA {
        debug_irq! {
            klog::write_raw(b"[INFO]  userspace-eret-smoke-arm: ok EL0 BRK elr=");
            klog::write_hex_u64(elr);
            klog::write_raw(b" esr=");
            klog::write_hex_u64(esr);
            klog::write_raw(b"\n");
        }
    }
    false
}

unsafe fn map_user_page<M: MmuOps>(va: u64, flags: PageFlags) -> Option<u64> {
    let pa = crate::pmm_setup::alloc_one_frame()?;
    // SAFETY: caller asserts va unmapped on entry; pa fresh PMM frame.
    unsafe { M::map(Va(va), Pa(pa), flags, PageSize::P4K); }
    Some(pa)
}

fn halt_forever() -> ! {
    loop {
        // SAFETY: `wfi` parks the core; with DAIF.I masked this is the
        // terminal state for the smoke.
        unsafe { core::arch::asm!("wfi", options(nomem, nostack, preserves_flags)); }
    }
}

/// Run the smoke. Diverges (halts) on success or failure.
/// # SAFETY: caller is the boot path; PMM + MmuOps initialised;
/// USER_CODE_VA / USER_STACK_VA unmapped on entry; single-CPU; IRQs
/// masked at EL1.
/// # C: O(1) modulo PT walks.
/// # Ctx: pre-init, IRQ-off, single-CPU
pub unsafe fn run<M: MmuOps>() -> ! {
    // SAFETY: USER_CODE_VA unmapped on entry; PMM + MmuOps state initialised by kernel_main pre-init; bit-55 selector in P2-08 routes the walker into TTBR0_EL1 for these low VAs.
    let _code_pa = match unsafe {
        map_user_page::<M>(
            USER_CODE_VA,
            PageFlags::READ | PageFlags::WRITE | PageFlags::EXEC | PageFlags::USER,
        )
    } {
        Some(pa) => pa,
        None => {
            debug_irq! { klog::kerror!("userspace-eret-smoke-arm: code-page alloc failed"); }
            halt_forever();
        }
    };
    // SAFETY: USER_STACK_VA unmapped on entry; PMM + MmuOps state initialised by kernel_main pre-init.
    let _stack_pa = match unsafe {
        map_user_page::<M>(
            USER_STACK_VA,
            PageFlags::READ | PageFlags::WRITE | PageFlags::USER,
        )
    } {
        Some(pa) => pa,
        None => {
            debug_irq! { klog::kerror!("userspace-eret-smoke-arm: stack-page alloc failed"); }
            halt_forever();
        }
    };

    // Write `brk #0` at USER_CODE_VA.
    // SAFETY: USER_CODE_VA mapped W|U|EXEC; sole owner this CPU.
    unsafe {
        for (i, b) in USER_BLOB.iter().enumerate() {
            core::ptr::write_volatile((USER_CODE_VA + i as u64) as *mut u8, *b);
        }
    }

    // SAFETY: handler fn is 'static; pre-init single-CPU swap.
    let _prev = unsafe { install_fault_handler(user_brk_handler) };

    debug_irq! {
        klog::write_raw(b"[INFO]  userspace-eret-smoke-arm: about to eret elr=");
        klog::write_hex_u64(USER_CODE_VA);
        klog::write_raw(b" sp_el0=");
        klog::write_hex_u64(USER_STACK_TOP);
        klog::write_raw(b"\n");
    }

    // SPSR_EL1 = 0x3C0 → M=EL0t (0b0000), DAIF all masked. User
    // runs IRQs-off through to BRK so the timer can't race.
    //
    // SAFETY: privileged system-reg writes at EL1; values are
    // kernel-validated constants pointing at freshly-mapped EL0
    // pages. `eret` uses ELR_EL1/SPSR_EL1 to transition.
    unsafe {
        core::arch::asm!(
            "msr sp_el0,   {sp_u}",
            "msr elr_el1,  {elr_u}",
            "msr spsr_el1, {spsr}",
            "eret",
            sp_u  = in(reg) USER_STACK_TOP,
            elr_u = in(reg) USER_CODE_VA,
            spsr  = in(reg) 0x3C0u64,
            options(noreturn),
        );
    }
}
