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
fn syscall_kstack_size_is_4k() {
    assert_eq!(core::mem::size_of::<SyscallKStack>(), 4096);
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
