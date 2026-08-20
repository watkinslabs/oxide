// Host unit tests for the syscall entry/exit contract: the MSR bits the
// entry depends on, the frame the stub pushes, and the ring-3 selector pair
// its synthesized IRETQ image must agree with.

use super::*;

#[test]
fn sfmask_includes_if_df_ac() {
    assert!(SFMASK_BITS & (1 << 9)  != 0, "IF cleared on entry");
    assert!(SFMASK_BITS & (1 << 10) != 0, "DF cleared on entry");
    assert!(SFMASK_BITS & (1 << 18) != 0, "AC cleared on entry");
}

#[test]
fn efer_sce_bit_position() {
    assert_eq!(EFER_SCE, 1);
}

#[test]
fn resume_rebuilds_the_syscall_msrs_from_kernel_owned_values() {
    let image = syscall_msr_image(0xffff_ffff_8100_1000, 0xffff_ffff_8100_2000, false);
    assert_eq!(image.star,
        ((crate::idt::KERNEL_CS as u64) << 32) | ((crate::gdt::USER_CS32 as u64) << 48));
    assert_eq!(image.lstar, 0xffff_ffff_8100_1000);
    assert_eq!(image.cstar, Some(0xffff_ffff_8100_2000));
    assert_eq!(image.sfmask, SFMASK_BITS);

    // Linux avoids CSTAR writes on Intel, where the MSR is ignored and can
    // fault under TDX, while still rebuilding every syscall MSR that applies.
    assert_eq!(syscall_msr_image(1, 2, true).cstar, None);
}

#[test]
fn syscall_kstack_size_is_4k() {
    assert_eq!(core::mem::size_of::<SyscallKStack>(), 4096);
}

#[test]
fn current_task_slot_has_the_native_module_offset() {
    assert_eq!(LINUX_CURRENT_TASK_OFFSET, 32);
    // SAFETY: host build does not emit the GS-relative instruction.
    unsafe { set_linux_current_task(core::ptr::null()); }
}

#[test]
fn the_entry_stub_pushes_exactly_one_pt_regs() {
    // 22 `push`es in `oxide_syscall_entry`; the frame it leaves is what
    // `current_pt_regs()` re-derives from the kstack top.
    assert_eq!(PT_REGS_BYTES, 22 * 8);
    // ...and that count keeps rsp 16-aligned at the `call`, which is why
    // the stub needs no alignment pad before `oxide_syscall_dispatch`.
    assert_eq!(PT_REGS_BYTES % 16, 0, "entry pushes must not skew the SysV alignment");
}

#[test]
fn the_syscall_vector_sentinel_survives_the_asm_immediate() {
    // `push -1` is what the assembler accepts; `from_syscall()` tests
    // against the u64 spelling.
    assert_eq!(PT_REGS_VECTOR_SYSCALL_IMM as u64, PT_REGS_VECTOR_SYSCALL);
    assert_eq!(PT_REGS_VECTOR_SYSCALL, u64::MAX);
}

#[test]
fn the_synthesized_selectors_are_the_ring3_gdt_pair() {
    // The IRETQ image `syscall` does not push is synthesized from these;
    // they must be the very selectors `sysretq` reloads (gdt.rs STAR
    // arithmetic), or the first IRQ from ring 3 pushes a mismatched SS.
    assert_eq!(USER_CS_SELECTOR, crate::gdt::USER_CS as u64);
    assert_eq!(USER_SS_SELECTOR, crate::gdt::USER_DS as u64);
    assert_eq!(USER_CS_SELECTOR & 3, 3);
    assert_eq!(USER_SS_SELECTOR & 3, 3);
}
