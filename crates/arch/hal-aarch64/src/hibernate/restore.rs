// Safe executable restore loop and saved-context handoff (`32b§11`).

#![cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]

use core::convert::Infallible;

use super::plan::{ArchHeader, CurrentHeader, PlanError, RestorePlan,
                  ARCH_HEADER_VERSION, PAGE_BYTES};

const ARG_MAGIC: u64 = 0x4849_4241_5247_5331;
#[repr(C)]
#[derive(Copy, Clone)]
struct RestoreArgs {
    magic: u64,
    temporary_ttbr1_pa: u64,
    image_ttbr1_pa: u64,
    zero_page_pa: u64,
    collision_head_va: u64,
    linear_offset: u64,
    context_pa: u64,
    continuation_va: u64,
    mair_el1: u64,
    tcr_el1: u64,
    sctlr_el1: u64,
}

core::arch::global_asm!(
    ".section .hibernate.restore,\"ax\",@progbits",
    ".balign 4",
    ".global oxide_arm_hibernate_restore_start",
    ".global oxide_arm_hibernate_restore_end",
    "oxide_arm_hibernate_restore_start:",
    // x0 = safe RestoreArgs VA. Load every nonlocal value before copied
    // destinations can replace the fresh kernel.
    "  ldr x9, [x0, #0x00]",
    "  movz x10, #0x5331",
    "  movk x10, #0x5247, lsl #16",
    "  movk x10, #0x4241, lsl #32",
    "  movk x10, #0x4849, lsl #48",
    "  cmp x9, x10",
    "  b.ne 9f",
    "  ldr x19, [x0, #0x08]",
    "  ldr x20, [x0, #0x10]",
    "  ldr x21, [x0, #0x18]",
    "  ldr x22, [x0, #0x20]",
    "  ldr x24, [x0, #0x28]",
    "  ldr x25, [x0, #0x30]",
    "  ldr x26, [x0, #0x38]",
    "  ldr x28, [x0, #0x40]",
    "  ldr x17, [x0, #0x48]",
    "  ldr x16, [x0, #0x50]",
    // The cold path enters the shared high continuation directly, so it must
    // perform the translation/control restore normally owned by the firmware
    // resume entry. Admission proved these values compatible with the fresh
    // kernel before any destination was claimed.
    "  msr mair_el1, x28",
    "  msr tcr_el1, x17",
    "  isb",
    // Break-before-make: an all-zero table removes old TTBR1 walks before the
    // safe linear-map copy becomes visible.
    "  msr ttbr1_el1, x21",
    "  isb",
    "  tlbi vmalle1",
    "  dsb nsh",
    "  msr ttbr1_el1, x19",
    "  isb",
    "  cbz x22, 5f",
    // Collision entries contain physical addresses. The temporary linear map
    // reaches both ends at the same offset while the original image is copied.
    "1:",
    "  ldr x23, [x22, #8]",
    "  add x27, x22, #16",
    "6:",
    "  cbz x23, 4f",
    "  ldp x0, x1, [x27], #16",
    "  add x0, x0, x24",
    "  add x1, x1, x24",
    "  mov x11, x1",
    "  mov x12, #4096",
    "2:",
    "  ldp x2, x3, [x0], #16",
    "  ldp x4, x5, [x0], #16",
    "  ldp x6, x7, [x0], #16",
    "  ldp x8, x9, [x0], #16",
    "  stp x2, x3, [x1], #16",
    "  stp x4, x5, [x1], #16",
    "  stp x6, x7, [x1], #16",
    "  stp x8, x9, [x1], #16",
    "  subs x12, x12, #64",
    "  b.ne 2b",
    // Clean every copied destination to PoU before any restored instruction
    // can be fetched. CTR_EL0.DminLine is log2(words per D-cache line).
    "  mrs x12, ctr_el0",
    "  ubfx x12, x12, #16, #4",
    "  mov x13, #4",
    "  lsl x12, x13, x12",
    "  mov x13, x11",
    "  add x14, x11, #4096",
    "3:",
    "  dc cvau, x13",
    "  add x13, x13, x12",
    "  cmp x13, x14",
    "  b.lo 3b",
    "  subs x23, x23, #1",
    "  b.ne 6b",
    "4:",
    "  ldr x22, [x22]",
    "  cbz x22, 5f",
    // CollisionPage::next_pa is a physical locator. Re-enter the temporary
    // linear map before dereferencing the next node.
    "  add x22, x22, x24",
    "  b 1b",
    "5:",
    "  dsb ish",
    // The second BBM installs the restored kernel's TTBR1. Execution remains
    // on the TTBR0 identity mapping until the shared continuation takes over.
    "  msr ttbr1_el1, x21",
    "  isb",
    "  tlbi vmalle1",
    "  dsb nsh",
    "  msr ttbr1_el1, x20",
    "  isb",
    "  msr sctlr_el1, x16",
    "  isb",
    "  ic ialluis",
    "  dsb ish",
    "  isb",
    "  mov x0, x25",
    "  br x26",
    "9:",
    "  wfi",
    "  b 9b",
    "oxide_arm_hibernate_restore_end:",
    ".previous",
);

extern "C" {
    fn oxide_arm_cpu_suspend_enter(ctx: *mut crate::cpu_suspend_ctx::SuspendCtx) -> u64;
    fn oxide_arm_hibernate_restore_start();
    fn oxide_arm_hibernate_restore_end();
}

fn current_el() -> u64 {
    let value: u64;
    // SAFETY: CurrentEL is a read-only architectural status register at EL1.
    unsafe { core::arch::asm!("mrs {v}, CurrentEL", v = out(reg) value, options(nomem, nostack, preserves_flags)); }
    value >> 2
}

/// Whether the current CPU can expose the complete hibernation adapter.
/// Refuse before hook installation when MTE tags cannot be persisted.
/// # C: O(1)
pub fn restore_path_available() -> bool {
    super::plan::restore_path_available_for(
        crate::cpuid::supports_mte(crate::cpuid::id_aa64pfr1_el1()))
}

fn mapped_va(pa: u64, offset: u64) -> Result<u64, PlanError> { pa.checked_add(offset).ok_or(PlanError::Range) }

unsafe fn clean_range(va: u64, len: usize, executable: bool) {
    let ctr: u64;
    // SAFETY: CTR_EL0 is a read-only cache-geometry register at EL1.
    unsafe { core::arch::asm!("mrs {v}, ctr_el0", v = out(reg) ctr, options(nomem, nostack, preserves_flags)); }
    let dline = 4u64 << ((ctr >> 16) & 0xf);
    let mut p = va & !(dline - 1);
    let end = va + len as u64;
    while p < end {
        // SAFETY: caller supplied a live safe linear-map allocation spanning this complete range.
        unsafe { core::arch::asm!("dc cvau, {p}", p = in(reg) p, options(nostack, preserves_flags)); }
        p += dline;
    }
    // SAFETY: the D-cache clean must finish before any corresponding I-cache invalidation begins.
    unsafe { core::arch::asm!("dsb ish", options(nostack, preserves_flags)); }
    if executable {
        let iline = 4u64 << (ctr & 0xf);
        p = va & !(iline - 1);
        while p < end {
            // SAFETY: invalidates only the instruction-cache line corresponding to the safe executable allocation.
            unsafe { core::arch::asm!("ic ivau, {p}", p = in(reg) p, options(nostack, preserves_flags)); }
            p += iline;
        }
    }
    // SAFETY: orders publication of safe data and executable bytes before terminal entry.
    unsafe { core::arch::asm!("dsb ish", "isb", options(nostack, preserves_flags)); }
}

/// Capture the resumable CPU context, then invoke the image callback.
///
/// A cold restore reaches the shared continuation and makes this return zero;
/// an ordinary save-side callback return is forwarded unchanged.
///
/// # Safety
/// Interrupts are disabled, one CPU runs, live FP/SIMD ownership is
/// flushed, `state` has the supplied stable physical address, and the callback
/// does not move or release it while serializing the snapshot.
/// # C: O(image callback)
/// # Ctx: IRQ-off, single CPU
pub unsafe fn capture_image_continuation(
    state: &mut crate::cpu_suspend_ctx::SuspendCtx, state_pa: u64,
    identity_ttbr0_pa: u64, image: extern "C" fn() -> u64,
) -> Result<u64, PlanError> {
    if state_pa == 0 || !state_pa.is_multiple_of(PAGE_BYTES) || identity_ttbr0_pa == 0
        || !identity_ttbr0_pa.is_multiple_of(PAGE_BYTES) { return Err(PlanError::Alignment); }
    *state = crate::cpu_suspend_ctx::SuspendCtx::new();
    state.por_el0 = crate::read_por();
    state.self_pa = state_pa;
    state.self_va = state as *mut crate::cpu_suspend_ctx::SuspendCtx as u64;
    state.ttbr0_identity_pa = identity_ttbr0_pa;
    // SAFETY: fn contract supplies the stable privileged context; the shared
    // leaf routine preserves the complete callee-saved set and returns zero
    // only after its sole resume continuation restored this exact block.
    let saved = unsafe { oxide_arm_cpu_suspend_enter(state) };
    if saved == 0 {
        // A reset loses optional per-CPU extension enables that are not safe
        // to touch from the feature-agnostic assembly continuation. Reapply
        // them only after the restored image and its capability latch are live.
        // SAFETY: one boot CPU, IRQs masked, before ordinary kernel work resumes.
        unsafe { crate::cpu_suspend::restore_cpu_extensions_after_reset(state.por_el0); }
        return Ok(0);
    }
    Ok(image())
}

/// Create the persistent architecture header from the captured state. # C: O(1)
pub fn header_from_captured_state(
    state: &crate::cpu_suspend_ctx::SuspendCtx, kernel_load_pa: u64,
) -> Result<ArchHeader, PlanError> {
    if crate::cpuid::supports_mte(crate::cpuid::id_aa64pfr1_el1()) {
        return Err(PlanError::MteUnsupported);
    }
    if !state.magic_ok() || state.self_pa == 0 || state.self_va == 0
        || state.ttbr0_identity_pa == 0 { return Err(PlanError::Header); }
    let h = ArchHeader {
        version: ARCH_HEADER_VERSION,
        continuation_va: crate::cpu_suspend::hibernate_continuation_va(),
        context_pa: state.self_pa,
        image_ttbr1_pa: state.ttbr1_el1 & crate::PTE_PHYS_MASK,
        kernel_load_pa,
        boot_mpidr: crate::mpidr_el1(),
        exception_level: current_el(),
        mte_tag_pages: 0,
        cpu_signature: crate::midr_el1(),
        mair_el1: state.mair_el1,
        tcr_el1: state.tcr_el1,
        sctlr_el1: state.sctlr_el1,
    };
    super::plan::validate_header(&h)?;
    Ok(h)
}

/// Snapshot current boot-CPU facts for pure pre-load admission. # C: O(1)
pub fn current_header() -> CurrentHeader {
    let mair_el1: u64;
    let tcr_el1: u64;
    let sctlr_el1: u64;
    // SAFETY: these are read-only snapshots of the current EL1 translation
    // regime, used solely for pre-destination compatibility admission.
    unsafe {
        core::arch::asm!("mrs {v}, mair_el1", v = out(reg) mair_el1,
            options(nomem, nostack, preserves_flags));
        core::arch::asm!("mrs {v}, tcr_el1", v = out(reg) tcr_el1,
            options(nomem, nostack, preserves_flags));
        core::arch::asm!("mrs {v}, sctlr_el1", v = out(reg) sctlr_el1,
            options(nomem, nostack, preserves_flags));
    }
    CurrentHeader { continuation_va: crate::cpu_suspend::hibernate_continuation_va(),
        boot_mpidr: crate::mpidr_affinity(), exception_level: current_el(),
        cpu_signature: crate::midr_el1(),
        mair_el1, tcr_el1, sctlr_el1,
        mte_supported: crate::cpuid::supports_mte(crate::cpuid::id_aa64pfr1_el1()) }
}

/// Copy safe operands, install the identity TTBR0, and never return on success.
///
/// # Safety
/// Caller holds the sole hibernation transition; every `safe_pages`
/// frame and both complete table hierarchies remain exclusively claimed; the
/// described mappings are live and writable; DAIF is masked and one CPU runs.
/// # C: O(collision pages)
/// # Ctx: IRQ/FIQ-off, single CPU, terminal
pub unsafe fn restore(h: &ArchHeader, p: &RestorePlan<'_>) -> Result<Infallible, PlanError> {
    super::plan::validate_restore_plan(h, p)?;
    super::plan::validate_current_header(h, current_header())?;
    let start = oxide_arm_hibernate_restore_start as *const () as usize;
    let end = oxide_arm_hibernate_restore_end as *const () as usize;
    let code_len = end.checked_sub(start).ok_or(PlanError::Range)?;
    if code_len > PAGE_BYTES as usize { return Err(PlanError::Capacity); }
    let trampoline_va = mapped_va(p.trampoline_pa, p.linear_map.va_offset)?;
    let args_va = mapped_va(p.arguments_pa, p.linear_map.va_offset)?;
    // SAFETY: caller contract pins the complete list and validation bounds every node.
    unsafe { super::plan::validate_collision_chain(p)?; }
    let collision_head_va = if p.collision_head_pa == 0 { 0 }
        else { mapped_va(p.collision_head_pa, p.linear_map.va_offset)? };
    let args = RestoreArgs {
        magic: ARG_MAGIC, temporary_ttbr1_pa: p.temporary_ttbr1_pa,
        image_ttbr1_pa: h.image_ttbr1_pa, zero_page_pa: p.zero_page_pa,
        collision_head_va,
        linear_offset: p.linear_map.va_offset, context_pa: h.context_pa,
        continuation_va: h.continuation_va,
        mair_el1: h.mair_el1, tcr_el1: h.tcr_el1, sctlr_el1: h.sctlr_el1,
    };
    // SAFETY: validation proves all three destinations are disjoint safe pages mapped by the live and temporary linear maps; source lengths fit their reserved ranges.
    unsafe {
        core::ptr::copy_nonoverlapping(start as *const u8, trampoline_va as *mut u8, code_len);
        core::ptr::write(args_va as *mut RestoreArgs, args);
        clean_range(trampoline_va, code_len, true);
        clean_range(args_va, core::mem::size_of::<RestoreArgs>(), false);
        for pa in p.safe_pages { clean_range(mapped_va(*pa, p.linear_map.va_offset)?, PAGE_BYTES as usize, false); }
    }
    // SAFETY: all fallible work is complete; the copied code is identity mapped and the arguments remain mapped across the temporary TTBR1 switch.
    unsafe {
        core::arch::asm!(
            "msr daifset, #0xf",
            "msr ttbr0_el1, {ttbr0}",
            "dsb sy",
            "tlbi vmalle1",
            "dsb sy",
            "isb",
            "mov x0, {args}",
            "br {entry}",
            ttbr0 = in(reg) p.temporary_ttbr0_pa,
            args = in(reg) args_va,
            entry = in(reg) p.trampoline_pa,
            options(noreturn),
        );
    }
}
