// The register and floating-point blocks a thread's notes carry.
//
// Every assertion here is a byte offset a debugger decodes at: a register
// landing one slot over is invisible to a compiler and to a boot, and shows up
// only as a backtrace that makes no sense.

use crate::coredump::gregset::*;

fn word(b: &[u8], i: usize) -> u64 {
    u64::from_le_bytes(b[i * 8..i * 8 + 8].try_into().expect("eight bytes"))
}

/// Each field's own index, so a transposition cannot hide behind a
/// symmetrical mistake.
fn x86_marked() -> X86Frame {
    X86Frame {
        r15: 0x15, r14: 0x14, r13: 0x13, r12: 0x12, rbp: 0xb9, rbx: 0xbb,
        r11: 0x11, r10: 0x10, r9: 0x09, r8: 0x08,
        rdi: 0xd1, rsi: 0x51, rdx: 0xd2, rcx: 0xc1,
        rax: 0xaa, orig_rax: 0x3b,
        rip: 0x4011_22, cs: 0x33, rflags: 0x202, rsp: 0x7fff_0000, ss: 0x2b,
    }
}

#[test]
fn the_x86_block_is_twenty_seven_registers_in_the_documented_order() {
    let seg = X86SegBases { fs_base: 0xfbfb, gs_base: 0x9b9b };
    let b = x86_64_block(&x86_marked(), &seg);
    assert_eq!(b.len(), X86_NGREG * 8);
    let f = x86_marked();
    assert_eq!(word(&b, X86_U_R15), f.r15);
    assert_eq!(word(&b, X86_U_R14), f.r14);
    assert_eq!(word(&b, X86_U_R13), f.r13);
    assert_eq!(word(&b, X86_U_R12), f.r12);
    assert_eq!(word(&b, X86_U_RBP), f.rbp);
    assert_eq!(word(&b, X86_U_RBX), f.rbx);
    assert_eq!(word(&b, X86_U_R11), f.r11);
    assert_eq!(word(&b, X86_U_R10), f.r10);
    assert_eq!(word(&b, X86_U_R9),  f.r9);
    assert_eq!(word(&b, X86_U_R8),  f.r8);
    assert_eq!(word(&b, X86_U_RAX), f.rax);
    assert_eq!(word(&b, X86_U_RCX), f.rcx);
    assert_eq!(word(&b, X86_U_RDX), f.rdx);
    assert_eq!(word(&b, X86_U_RSI), f.rsi);
    assert_eq!(word(&b, X86_U_RDI), f.rdi);
    assert_eq!(word(&b, X86_U_ORIG_RAX), f.orig_rax);
    assert_eq!(word(&b, X86_U_RIP),    f.rip);
    assert_eq!(word(&b, X86_U_CS),     f.cs);
    assert_eq!(word(&b, X86_U_EFLAGS), f.rflags);
    assert_eq!(word(&b, X86_U_RSP),    f.rsp);
    assert_eq!(word(&b, X86_U_SS),     f.ss);
    assert_eq!(word(&b, X86_U_FS_BASE), seg.fs_base);
    assert_eq!(word(&b, X86_U_GS_BASE), seg.gs_base);
    // No entry on this port saves the four data selectors.
    for i in [X86_U_DS, X86_U_ES, X86_U_FS, X86_U_GS] { assert_eq!(word(&b, i), 0); }
}

/// `rax` and `orig_rax` are DIFFERENT registers: the first is the value the
/// crash left there, the second the syscall number an entry parked. A block
/// that reports one for the other tells gdb a fault was an interrupted call.
#[test]
fn the_x86_return_register_and_the_syscall_number_are_separate_slots() {
    let b = x86_64_block(&x86_marked(), &X86SegBases::default());
    assert_ne!(word(&b, X86_U_RAX), word(&b, X86_U_ORIG_RAX));
    assert_eq!(word(&b, X86_U_RAX), 0xaa);
    assert_eq!(word(&b, X86_U_ORIG_RAX), 0x3b);
}

/// A trap frame keeps the entry word independently from its architectural RAX.
#[test]
fn a_trap_frame_reports_its_independent_entry_word() {
    let f = X86Frame { orig_rax: 0xdecafbad, ..x86_marked() };
    let b = x86_64_block(&f, &X86SegBases::default());
    assert_eq!(word(&b, X86_U_ORIG_RAX), 0xdecafbad);
    assert_eq!(word(&b, X86_U_RAX), 0xaa);
}

/// The live-frame reader picks that rule from the entry tag rather than from
/// a guess about the register's value, preserving the trap's entry word.
#[cfg(target_arch = "x86_64")]
#[test]
fn the_live_frame_reader_takes_the_syscall_number_only_from_a_syscall_entry() {
    /// A page-fault vector: any entry tag that is not the syscall sentinel.
    const VECTOR_PAGE_FAULT: u64 = 14;
    let mut r = hal_x86_64::PtRegs {
        rax: 0x27, error: 0x7172, rip: 0x401000, ..Default::default()
    };
    r.vector = VECTOR_PAGE_FAULT;
    // SAFETY: `r` is a local frame value owned by this test for the call's duration.
    let trap = unsafe { current_block(&r as *const _, &X86SegBases::default()) };
    assert_eq!(word(&trap, X86_U_ORIG_RAX), 0x7172);
    assert_eq!(word(&trap, X86_U_RAX), 0x27);

    r.vector = hal_x86_64::PT_REGS_VECTOR_SYSCALL;
    // SAFETY: same local frame, still exclusively owned here.
    let call = unsafe { current_block(&r as *const _, &X86SegBases::default()) };
    assert_eq!(word(&call, X86_U_ORIG_RAX), 0x27);
}

#[test]
fn the_arm_block_is_thirty_one_general_registers_then_sp_pc_and_pstate() {
    let mut gpr = [0u64; ARM_NGPR];
    for (i, g) in gpr.iter_mut().enumerate() { *g = 0x1000 + i as u64 }
    let b = aarch64_block(&gpr, 0x7ff0, 0x4008_00, 0x6000_0000);
    assert_eq!(b.len(), ARM_NGREG * 8);
    for i in 0..ARM_NGPR { assert_eq!(word(&b, i), 0x1000 + i as u64) }
    assert_eq!(word(&b, ARM_U_SP), 0x7ff0);
    assert_eq!(word(&b, ARM_U_PC), 0x4008_00);
    assert_eq!(word(&b, ARM_U_PSTATE), 0x6000_0000);
}

/// The kernel's own save area stores the control word first and the status
/// word second; the note's order is the other way round. Copying the area
/// verbatim would swap them, which is exactly the mistake this pins.
#[test]
fn the_arm_float_block_reports_the_status_word_before_the_control_word() {
    let mut v = [[0u8; ARM_VREG_BYTES]; ARM_NVREG];
    for (i, q) in v.iter_mut().enumerate() { q[0] = i as u8 }
    let b = aarch64_fpregs_block(&v, 0x5555_5555, 0xAAAA_AAAA);
    assert_eq!(b.len(), ARM_FPREG_BYTES);
    for i in 0..ARM_NVREG { assert_eq!(b[i * ARM_VREG_BYTES], i as u8) }
    let base = ARM_NVREG * ARM_VREG_BYTES;
    assert_eq!(u32::from_le_bytes(b[base..base + 4].try_into().expect("four bytes")), 0x5555_5555);
    assert_eq!(u32::from_le_bytes(b[base + 4..base + 8].try_into().expect("four bytes")), 0xAAAA_AAAA);
    assert!(b[base + 8..].iter().all(|&x| x == 0), "descriptor tail is padding");
}

/// Both blocks are exactly what the note layout reserves for them, or the
/// register file lands on top of `pr_fpvalid`.
#[test]
fn each_block_is_the_length_its_note_reserves() {
    use crate::coredump::elf::CoreArch;
    assert_eq!(x86_64_block(&X86Frame::default(), &X86SegBases::default()).len(),
        CoreArch::X86_64.gregset_bytes());
    assert_eq!(aarch64_block(&[0; ARM_NGPR], 0, 0, 0).len(), CoreArch::Aarch64.gregset_bytes());
    assert_eq!(ARM_FPREG_BYTES, CoreArch::Aarch64.fpregset_bytes());
}
