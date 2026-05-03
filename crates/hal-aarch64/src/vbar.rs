// aarch64 EL1 vector table install per `22§5`.
//
// VMSAv8 mandates a 16-entry table at `VBAR_EL1`; each entry is
// 0x80 bytes. Layout per ARM ARM D1.10 Tab. D1-7:
//   0x000 Sync           current EL with SP_EL0
//   0x080 IRQ            current EL with SP_EL0
//   0x100 FIQ            current EL with SP_EL0
//   0x180 SError         current EL with SP_EL0
//   0x200 Sync           current EL with SP_ELx
//   0x280 IRQ            current EL with SP_ELx
//   0x300 FIQ            current EL with SP_ELx
//   0x380 SError         current EL with SP_ELx
//   0x400 Sync           lower EL using AArch64
//   0x480 IRQ            lower EL using AArch64
//   0x500 FIQ            lower EL using AArch64
//   0x580 SError         lower EL using AArch64
//   0x600 Sync           lower EL using AArch32
//   0x680 IRQ            lower EL using AArch32
//   0x700 FIQ            lower EL using AArch32
//   0x780 SError         lower EL using AArch32
//
// v1 lands the data path: a single default-vector handler that
// masks DAIF and `wfi`-loops, plus an `install_default` that writes
// `VBAR_EL1`. Per-cause dispatch (`ESR.EC` decode → SVC syscall /
// IABT/DABT page fault / etc.) rides alongside the GICv3 bring-up.

/// Vector table is exactly 16 × 0x80 = 0x800 bytes per ARM ARM.
pub const VECTOR_TABLE_SIZE: usize = 0x800;

/// Per-entry stride.
pub const VECTOR_ENTRY_BYTES: usize = 0x80;

#[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
core::arch::global_asm!(
    ".section .text",
    ".balign 0x800",
    ".globl oxide_vector_table",
    ".type  oxide_vector_table, %function",
    "oxide_vector_table:",
    // 16 entries; each pads to 0x80 bytes via `.balign` after the
    // `b` insn so the next slot lands on the right offset.
    "    b oxide_default_vector_handler",
    "    .balign 0x80",
    "    b oxide_default_vector_handler",
    "    .balign 0x80",
    "    b oxide_default_vector_handler",
    "    .balign 0x80",
    "    b oxide_default_vector_handler",
    "    .balign 0x80",
    "    b oxide_default_vector_handler",
    "    .balign 0x80",
    "    b oxide_default_vector_handler",
    "    .balign 0x80",
    "    b oxide_default_vector_handler",
    "    .balign 0x80",
    "    b oxide_default_vector_handler",
    "    .balign 0x80",
    "    b oxide_default_vector_handler",
    "    .balign 0x80",
    "    b oxide_default_vector_handler",
    "    .balign 0x80",
    "    b oxide_default_vector_handler",
    "    .balign 0x80",
    "    b oxide_default_vector_handler",
    "    .balign 0x80",
    "    b oxide_default_vector_handler",
    "    .balign 0x80",
    "    b oxide_default_vector_handler",
    "    .balign 0x80",
    "    b oxide_default_vector_handler",
    "    .balign 0x80",
    "    b oxide_default_vector_handler",
    "    .balign 0x80",
    ".size oxide_vector_table, . - oxide_vector_table",

    ".balign 4",
    ".globl oxide_default_vector_handler",
    ".type  oxide_default_vector_handler, %function",
    "oxide_default_vector_handler:",
    "    msr daifset, #0xf",   // mask D, A, I, F
    // Reserve a 16-aligned scratch area on the stack for the printer
    // call frame. Prepare ELR_EL1, ESR_EL1, FAR_EL1 in arg regs and
    // tail-call into the Rust printer; halt on return.
    "    sub  sp, sp, #16",
    "    mrs  x0, esr_el1",
    "    mrs  x1, far_el1",
    "    mrs  x2, elr_el1",
    "    bl   oxide_fault_print_rust",
    "1:  wfi",
    "    b 1b",
    ".size oxide_default_vector_handler, . - oxide_default_vector_handler",
);

#[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
extern "C" {
    static oxide_vector_table: u8;
}

/// Address of the vector table, or 0 on host where the asm symbol
/// doesn't exist.
fn vector_table_addr() -> u64 {
    #[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
    {
        // SAFETY: taking the address of a `&'static` extern symbol;
        // no read of the bytes themselves at this site.
        unsafe { &oxide_vector_table as *const u8 as u64 }
    }
    #[cfg(not(all(target_arch = "aarch64", target_os = "oxide-kernel")))]
    { 0 }
}

/// Install the default vector table by writing `VBAR_EL1`. Single-
/// shot at boot.
///
/// # SAFETY: caller is the boot path; runs single-CPU with IRQs
/// masked. The table is stored in `.text` and is read-only from
/// kernel code; the CPU dereferences entries asynchronously on every
/// exception.
/// # C: O(1)
/// # Ctx: pre-init, IRQ-off, single-CPU
pub unsafe fn install_default() {
    let base = vector_table_addr();
    #[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
    {
        // SAFETY: `msr vbar_el1` is privileged at EL1; sets the
        // vector base. ARM ARM D13.2.111. `isb` ensures subsequent
        // exceptions vector to the new table.
        unsafe {
            core::arch::asm!(
                "msr vbar_el1, {b}",
                "isb",
                b = in(reg) base,
                options(nomem, nostack, preserves_flags),
            );
        }
    }
    let _ = base;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vector_table_size_matches_arm_arm() {
        // ARM ARM D1.10: 16 entries × 0x80 bytes = 0x800.
        assert_eq!(VECTOR_TABLE_SIZE, 0x800);
        assert_eq!(VECTOR_ENTRY_BYTES, 0x80);
        assert_eq!(VECTOR_ENTRY_BYTES * 16, VECTOR_TABLE_SIZE);
    }

    #[test]
    fn install_default_compiles_on_host() {
        // SAFETY: hosted test; the asm path is cfg'd out, so install
        // exercises only the no-op fallback branch.
        unsafe { install_default() };
    }
}
