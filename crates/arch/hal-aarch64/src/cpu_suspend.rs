// EL1 processor-state save, the physical resume entry, and the
// `SYSTEM_SUSPEND` call that hands the machine to firmware (`32a§9`).
//
// `SYSTEM_SUSPEND` never returns on success: the core comes back out of reset
// at the physical entry point handed to firmware, with the MMU and caches off,
// nothing in a register except the context identifier, and every EL1 system
// register at its reset value. So the caller saves and the entry restores.
//
// Audited against `54§1`: this is not an exception stub. Both stubs are AAPCS64
// leaf routines, so x0-x18 are the caller's to clobber; the callee-saved set
// x19-x28, fp, lr and sp is exactly what is stored and reloaded. `TPIDR_EL1` is
// read and written as the per-CPU base only, never used as scratch (`54§1.3`) —
// the scratch registers here are x1-x4 and x9.
//
// Layout, offsets, field set and restore order live in `cpu_suspend_ctx.rs`,
// which is ungated and whose tests read THIS file's text to hold the two
// together.

#![cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]

use crate::cpu_suspend_ctx::{SuspendCtx, OXIDE_SUSPEND_CTX_MAGIC};
use crate::psci_probe::{preflight, suspend_call_result, SuspendRefusal, SuspendSupport};
use crate::psci_uapi::{PsciStatus, PSCI_SYSTEM_SUSPEND_64};

/// Cache-line stride used to push the saved context out to the point of
/// coherency. The resume entry runs with `SCTLR_EL1.C` clear and reads the
/// block from memory, so a dirty line left in the cache is a block firmware
/// never sees.
const DCACHE_LINE_BYTES: u64 = 64;

// ---------------------------------------------------------------------------
// Save side. Returns 1 down the suspend path, 0 when the resume entry has put
// the context back and returned into the caller as if this call had returned.
// ---------------------------------------------------------------------------

core::arch::global_asm!(
    ".global oxide_arm_cpu_suspend_enter",
    ".section .text,\"ax\",@progbits",
    ".balign 4",
    "oxide_arm_cpu_suspend_enter:",
    // x0 = &mut SuspendCtx (kernel VA, MMU on).
    "  str x19, [x0, #0xa8]",
    "  str x20, [x0, #0xb0]",
    "  str x21, [x0, #0xb8]",
    "  str x22, [x0, #0xc0]",
    "  str x23, [x0, #0xc8]",
    "  str x24, [x0, #0xd0]",
    "  str x25, [x0, #0xd8]",
    "  str x26, [x0, #0xe0]",
    "  str x27, [x0, #0xe8]",
    "  str x28, [x0, #0xf0]",
    "  str x29, [x0, #0xa0]",
    "  str x30, [x0, #0x98]",
    "  str x18, [x0, #0x88]",
    "  mov x1, sp",
    "  str x1, [x0, #0x90]",
    "  mrs x1, mair_el1",
    "  str x1, [x0, #0x20]",
    "  mrs x1, tcr_el1",
    "  str x1, [x0, #0x28]",
    "  mrs x1, ttbr1_el1",
    "  str x1, [x0, #0x30]",
    "  mrs x1, sctlr_el1",
    "  str x1, [x0, #0x38]",
    "  mrs x1, ttbr0_el1",
    "  str x1, [x0, #0x40]",
    "  mrs x1, vbar_el1",
    "  str x1, [x0, #0x48]",
    "  mrs x1, tpidr_el1",
    "  str x1, [x0, #0x50]",
    "  mrs x1, mdscr_el1",
    "  str x1, [x0, #0x58]",
    "  mrs x1, cpacr_el1",
    "  str x1, [x0, #0x60]",
    "  mrs x1, contextidr_el1",
    "  str x1, [x0, #0x68]",
    "  mrs x1, tpidr_el0",
    "  str x1, [x0, #0x70]",
    "  mrs x1, tpidrro_el0",
    "  str x1, [x0, #0x78]",
    "  mrs x1, sp_el0",
    "  str x1, [x0, #0x80]",
    "  dsb sy",
    "  mov x0, #1",
    "  ret",
    // save-block end
);

// ---------------------------------------------------------------------------
// Resume entry. Firmware enters here at a PHYSICAL address with the MMU off,
// caches off, DAIF masked, and x0 = the context identifier we handed to
// `SYSTEM_SUSPEND` (the physical address of the saved block).
// ---------------------------------------------------------------------------

core::arch::global_asm!(
    ".global oxide_arm_resume_entry",
    ".section .text.resume_entry,\"ax\",@progbits",
    ".balign 4",
    "oxide_arm_resume_entry:",
    // Magic first. A firmware that resumed somewhere unexpected, or with a
    // stale context identifier, stops here instead of loading garbage into
    // TTBR/SCTLR with the MMU off.
    "  ldr x1, [x0, #0x00]",
    "  movz x2, #0x4443",
    "  movk x2, #0x504d, lsl #16",
    "  movk x2, #0x5553, lsl #32",
    "  movk x2, #0x5352, lsl #48",
    "  cmp x1, x2",
    "  b.ne oxide_arm_resume_bad_magic",
    // Describe the translation tables BEFORE switching them on. TTBR0 takes the
    // identity table, not the saved kernel one: between `SCTLR_EL1.M` and the
    // branch to the kernel half the PC is still a physical address and must
    // stay mapped.
    "  ldr x3, [x0, #0x20]",
    "  msr mair_el1, x3",
    "  ldr x3, [x0, #0x28]",
    "  msr tcr_el1, x3",
    "  ldr x3, [x0, #0x18]",
    "  msr ttbr0_el1, x3",
    "  ldr x3, [x0, #0x30]",
    "  msr ttbr1_el1, x3",
    "  dsb sy",
    "  tlbi vmalle1",
    "  dsb sy",
    "  isb",
    // MMU + caches on.
    "  ldr x3, [x0, #0x38]",
    "  msr sctlr_el1, x3",
    "  isb",
    // Branch to the kernel half by absolute linked VA.
    "  movz x9, #:abs_g0_nc:oxide_arm_resume_high",
    "  movk x9, #:abs_g1_nc:oxide_arm_resume_high",
    "  movk x9, #:abs_g2_nc:oxide_arm_resume_high",
    "  movk x9, #:abs_g3:oxide_arm_resume_high",
    "  br x9",
    "oxide_arm_resume_high:",
    // Still on the identity TTBR0, so the physical block pointer in x0 is
    // readable. Pick up its kernel VA before handing TTBR0 back.
    "  ldr x4, [x0, #0x10]",
    "  ldr x3, [x0, #0x40]",
    "  msr ttbr0_el1, x3",
    "  dsb sy",
    "  tlbi vmalle1",
    "  dsb sy",
    "  isb",
    "  mov x0, x4",
    // The rest of the EL1 state, reachable now only by VA.
    "  ldr x3, [x0, #0x48]",
    "  msr vbar_el1, x3",
    "  ldr x3, [x0, #0x50]",
    "  msr tpidr_el1, x3",
    "  ldr x3, [x0, #0x58]",
    "  msr mdscr_el1, x3",
    "  ldr x3, [x0, #0x60]",
    "  msr cpacr_el1, x3",
    "  ldr x3, [x0, #0x68]",
    "  msr contextidr_el1, x3",
    "  ldr x3, [x0, #0x70]",
    "  msr tpidr_el0, x3",
    "  ldr x3, [x0, #0x78]",
    "  msr tpidrro_el0, x3",
    "  ldr x3, [x0, #0x80]",
    "  msr sp_el0, x3",
    "  isb",
    // Callee-saved set, stack, and the link register that makes this look like
    // a return from the save call.
    "  ldr x18, [x0, #0x88]",
    "  ldr x3, [x0, #0x90]",
    "  mov sp, x3",
    "  ldr x30, [x0, #0x98]",
    "  ldr x29, [x0, #0xa0]",
    "  ldr x19, [x0, #0xa8]",
    "  ldr x20, [x0, #0xb0]",
    "  ldr x21, [x0, #0xb8]",
    "  ldr x22, [x0, #0xc0]",
    "  ldr x23, [x0, #0xc8]",
    "  ldr x24, [x0, #0xd0]",
    "  ldr x25, [x0, #0xd8]",
    "  ldr x26, [x0, #0xe0]",
    "  ldr x27, [x0, #0xe8]",
    "  ldr x28, [x0, #0xf0]",
    "  mov x0, #0",
    "  ret",
    // Unexpected resume. No console is reachable with the MMU off and every
    // system register at its reset value, so the core parks at a named symbol
    // rather than executing whatever the block happens to contain.
    "oxide_arm_resume_bad_magic:",
    "  wfi",
    "  b oxide_arm_resume_bad_magic",
    // resume-entry end
);

extern "C" {
    /// Save the callee-saved and EL1 system-register state into `ctx`.
    /// Returns 1 on the suspend path, 0 when reached via the resume entry.
    fn oxide_arm_cpu_suspend_enter(ctx: *mut SuspendCtx) -> u64;
    /// Physical resume entry point handed to firmware.
    fn oxide_arm_resume_entry();
}

/// Why a `SYSTEM_SUSPEND` attempt did not put the machine to sleep.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum SuspendError {
    /// Rejected before firmware was asked.
    Refused(SuspendRefusal),
    /// Firmware returned instead of suspending.
    Firmware(PsciStatus),
}

/// Translate a kernel VA to its physical address through the MMU. Returns 0 on
/// a translation fault, which the preflight turns into a refusal.
/// # SAFETY: `va` is a mapped kernel VA; `at s1e1r` performs a stage-1 EL1 read
/// translation into `PAR_EL1` and touches no memory.
/// # C: O(1)
unsafe fn va_to_pa(va: u64) -> u64 {
    let par: u64;
    // SAFETY: AT S1E1R translates `va` into PAR_EL1 without accessing memory; the isb orders the AT ahead of the PAR_EL1 read on this PE.
    unsafe {
        core::arch::asm!(
            "at s1e1r, {v}",
            "isb",
            "mrs {p}, par_el1",
            v = in(reg) va, p = out(reg) par,
            options(nostack, preserves_flags),
        );
    }
    if par & 1 != 0 { return 0; }
    (par & 0x000F_FFFF_FFFF_F000) | (va & 0xFFF)
}

/// Push `len` bytes at `va` out to the point of coherency.
/// # SAFETY: `va..va+len` is a live mapped kernel allocation; `dc cvac` cleans
/// by VA and has no effect beyond cache state.
/// # C: O(len / line)
unsafe fn clean_to_poc(va: u64, len: usize) {
    let mut p = va & !(DCACHE_LINE_BYTES - 1);
    let end = va + len as u64;
    while p < end {
        // SAFETY: `dc cvac` cleans the line holding VA p to the point of coherency; p lies inside the caller's live mapping and no memory is read or written.
        unsafe { core::arch::asm!("dc cvac, {x}", x = in(reg) p, options(nostack, preserves_flags)); }
        p += DCACHE_LINE_BYTES;
    }
    // SAFETY: `dsb sy` drains the cache maintenance above before the firmware call that follows.
    unsafe { core::arch::asm!("dsb sy", options(nostack, preserves_flags)); }
}

/// Virtual address of the resume entry symbol.
///
/// Routed through a pointer rather than casting the function item straight to
/// an integer: the direct cast is denied repo-wide, and it is denied because a
/// function item's cast target is inferred, so a narrower integer type silently
/// truncates the address.
/// # C: O(1)
fn resume_entry_va() -> u64 { oxide_arm_resume_entry as *const () as u64 }

/// Enter the platform's deep sleep state.
///
/// Saves EL1 state, hands firmware the physical resume entry and the physical
/// address of the saved block as the context identifier, and returns `Ok` once
/// the resume entry has restored everything. An `Err` means the machine never
/// slept.
///
/// # SAFETY: caller is the suspend sequence at `32a§5` step 15 — interrupts
/// disabled, one CPU online, devices already suspended. The saved block lives
/// on the caller's stack and must not be reused until this returns.
/// # C: O(sleep) — returns on wakeup.
/// # Ctx: IRQ-off, single-CPU
pub unsafe fn system_suspend(support: SuspendSupport) -> Result<(), SuspendError> {
    let mut ctx = SuspendCtx::new();
    ctx.ttbr0_identity_pa = crate::smp::identity_ttbr0_pa();
    let ctx_va = &raw mut ctx as u64;
    ctx.self_va = ctx_va;
    // SAFETY: `ctx` is a live stack allocation in the kernel mapping, and the resume-entry symbol is linked into the kernel image; both are mapped VAs for AT S1E1R.
    let (ctx_pa, entry_pa) = unsafe {
        (va_to_pa(ctx_va), va_to_pa(resume_entry_va()))
    };
    ctx.self_pa = ctx_pa;
    if let Err(r) = preflight(support, entry_pa, ctx.ttbr0_identity_pa, ctx_pa) {
        return Err(SuspendError::Refused(r));
    }
    debug_assert_eq!(ctx.magic, OXIDE_SUSPEND_CTX_MAGIC);
    // SAFETY: the stub writes only through the `ctx` pointer it is handed and preserves every callee-saved register; a 0 return is the resume entry having already restored this frame.
    let saved = unsafe { oxide_arm_cpu_suspend_enter(&raw mut ctx) };
    if saved == 0 { return Ok(()); }
    // SAFETY: `ctx` is live and fully written by the stub above; the resume entry reads it with caches off, so the block must reach memory first.
    unsafe { clean_to_poc(ctx_va, core::mem::size_of::<SuspendCtx>()); }
    // SAFETY: PSCI conduit is the platform's (HVC on QEMU virt); `entry_pa` is the resume entry's physical address and `ctx_pa` the cleaned block's. Returns only on failure.
    let raw = unsafe { crate::psci::conduit_call(PSCI_SYSTEM_SUSPEND_64, entry_pa, ctx_pa, 0) };
    Err(SuspendError::Firmware(suspend_call_result(raw).unwrap_err()))
}
