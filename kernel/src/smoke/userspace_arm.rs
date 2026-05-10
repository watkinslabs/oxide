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

// User blob: `mov w8, #39 (sys_getpid); svc #0; brk #0`.
// Issues a syscall, gets the retval (1) in x0 via the SVC handler's
// eret epilogue, then traps via `brk #0` so the smoke handler logs
// the round-trip landmark. All instructions little-endian.
//
//   0x52800508  movz w8, #0x0028        ; nr = 39 (sys_getpid)
//   0xD4000001  svc #0
//   0xD4200000  brk #0
//
// Encoding of `movz w8, #imm16`: 0x52800000 | (imm16 << 5) | rd
//   imm16 = 39 = 0x27, rd = 8 → 0x52800000 | (0x27 << 5) | 8
//                            = 0x52800000 | 0x4E0 | 0x08
//                            = 0x528004E8.
const USER_BLOB: [u8; 12] = [
    0xE8, 0x04, 0x80, 0x52,   // movz w8, #39  (LE)
    0x01, 0x00, 0x00, 0xD4,   // svc  #0
    0x00, 0x00, 0x20, 0xD4,   // brk  #0
];

const USER_RIP_POST_SVC: u64 = USER_CODE_VA + 8;  // brk lives here

/// ESR.EC = 0b111100 (0x3C) = "BRK instruction execution in AArch64".
const EC_BRK_AARCH64: u64 = 0x3C;

fn user_brk_handler(esr: u64, far: u64, elr: u64) -> bool {
    // Delegate demand-paging first per `11§5`. user_as routes any
    // EL0 abort whose FAR is in a registered VMA through the AS
    // page-fault path; if it resolves the fault we retry. Only
    // unhandled aborts fall through to the smoke landmark.
    if pmm::user_as::user_fault_handler(esr, far, elr) {
        return true;
    }
    let ec = (esr >> 26) & 0x3F;
    // After SVC + sysret-equivalent eret, user lands at the BRK
    // instruction at USER_CODE_VA+8 — that's the round-trip success
    // landmark. The original USER_CODE_VA path stays for older blob
    // shapes; either is success.
    if ec == EC_BRK_AARCH64 && (elr == USER_RIP_POST_SVC || elr == USER_CODE_VA) {
        debug_irq! {
            klog::write_raw(b"[INFO]  userspace-sysret-smoke-arm: ok EL0 BRK elr=");
            klog::write_hex_u64(elr);
            klog::write_raw(b" esr=");
            klog::write_hex_u64(esr);
            klog::write_raw(b"\n");
        }
    }
    false
}

unsafe fn map_user_page<M: MmuOps>(va: u64, flags: PageFlags) -> Option<u64> {
    let pa = pmm::setup::alloc_one_frame()?;
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

    // SAFETY: GDT-equivalent (TTBR0/TTBR1, VBAR_EL1) all set; user code+stack mapped USER+EXEC/USER+WRITE; single-CPU; DAIF.I masked. Diverges.
    unsafe { drop_to_el0(USER_CODE_VA, USER_STACK_TOP, user_brk_handler); }
}

/// Install `fault_handler` and `eret` into EL0 at `(elr, sp)`.
/// Diverges. Mirrors x86_64's `crate::smoke::userspace::drop_to_ring3` —
/// the ELF smoke (P2-16c) reuses this primitive.
///
/// SPSR_EL1 = 0x3C0 → M=EL0t (0b0000), DAIF all masked. User runs
/// IRQs-off through to its first SVC; timer can't race.
///
/// # SAFETY: caller has fully initialised TTBR0/TTBR1, VBAR_EL1,
/// SCTLR_EL1; user code at `elr` is mapped USER+EXEC; user stack
/// at `sp` is mapped USER+WRITE (or will demand-page from a
/// registered VMA); EL1; DAIF.I masked.
/// # C: O(1)
/// # Ctx: pre-init, IRQ-off, single-CPU; diverges
pub unsafe fn drop_to_el0(elr: u64, sp: u64, fault_handler: hal_aarch64::FaultHandler) -> ! {
    // SAFETY: handler fn is 'static; pre-init single-CPU swap.
    let _prev = unsafe { install_fault_handler(fault_handler) };

    debug_irq! {
        klog::write_raw(b"[INFO]  drop-to-el0: elr=");
        klog::write_hex_u64(elr);
        klog::write_raw(b" sp_el0=");
        klog::write_hex_u64(sp);
        klog::write_raw(b"\n");
    }

    // SAFETY: privileged system-reg writes at EL1; values are
    // kernel-validated constants pointing at freshly-mapped EL0
    // pages. `eret` uses ELR_EL1/SPSR_EL1 to transition.
    unsafe {
        core::arch::asm!(
            "msr sp_el0,   {sp_u}",
            "msr elr_el1,  {elr_u}",
            "msr spsr_el1, {spsr}",
            "eret",
            sp_u  = in(reg) sp,
            elr_u = in(reg) elr,
            spsr  = in(reg) 0x3C0u64,
            options(noreturn),
        );
    }
}
