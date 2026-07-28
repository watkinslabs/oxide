// The ONE x86_64 user-register frame. Every kernel entry — syscall,
// CPU exception, IRQ — saves user state in this exact shape, so the
// signal-frame builder, the fault printer, the IRQ dispatcher and the
// fork scaffold all read one struct instead of three ad-hoc layouts.
// aarch64's `SvcFrame` is the mirror of this on the other arch.
//
// Modeled on Linux `struct pt_regs`
// (`/home/nd/oxide/linux-master/arch/x86/include/asm/ptrace.h`, the
// `#else /* __i386__ */` arm): callee-saved r15..rbx first, then the
// callee-clobbered set, then the entry tag, then the IRETQ image
// (ip/cs/flags/sp/ss). Field ORDER is identical to Linux's.
//
// oxide deviation, deliberate: Linux overloads ONE slot (`orig_ax`) as
// syscall-nr / CPU error-code / IRQ vector, and recovers "did we come
// from a syscall" from `orig_ax != -1` — which forces the trap paths to
// write a fake syscall nr and the syscall path to keep the nr somewhere
// else once the return value lands in `ax`. We split it in two:
//
//   `vector` — synthetic entry tag: the CPU/IRQ vector on a trap,
//              `PT_REGS_VECTOR_SYSCALL` on a `syscall` entry.
//   `error`  — CPU-pushed error code (synthesized 0 where the CPU
//              pushes none, and 0 on a syscall entry).
//
// and keep `rax` holding the SYSCALL NUMBER for the whole dispatch (the
// syscall epilogue never writes the dispatcher's return value back into
// the frame — it leaves it live in the rax register for `sysretq`), so
// `rax` plays Linux's `orig_ax` role for restart while `vector` answers
// `from_syscall()`. See `syscall.rs` `oxide_syscall_entry`.
//
// Layout is asm-coupled: `fault/stubs.rs`, `irq.rs` and `syscall.rs`
// all push exactly these 22 quadwords, and `context.rs` hand-builds the
// same image for a first-run task. Const asserts + tests pin every
// offset; reordering a field breaks the boundary loudly.

use syscall::SyscallArgs;

/// `vector` value stamped by `oxide_syscall_entry`, i.e. "this frame is a
/// `syscall` entry, not a trap". Linux answers the same question with
/// `syscall_get_nr(current, regs) != -1` (`arch/x86/kernel/signal.c`
/// `arch_do_signal_or_restart`); oxide uses a dedicated slot instead of
/// overloading `orig_ax`, so the sentinel means the OPPOSITE of Linux's
/// `-1` — see the module header.
pub const PT_REGS_VECTOR_SYSCALL: u64 = u64::MAX;

/// Saved user state at any kernel entry. Field order == Linux
/// `struct pt_regs` (x86_64) with `orig_ax` split into `vector`/`error`.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct PtRegs {
    // Callee-saved by the C ABI. Linux only saves these on entries that
    // need a complete pt_regs; oxide saves them on EVERY entry so one
    // shape serves all three paths (a signal delivered on IRQ return
    // otherwise writes garbage rbx/rbp/r12-r15 into the ucontext).
    pub r15: u64, // 0x00
    pub r14: u64, // 0x08
    pub r13: u64, // 0x10
    pub r12: u64, // 0x18
    pub rbp: u64, // 0x20
    pub rbx: u64, // 0x28
    // Callee-clobbered. Always saved on kernel entry.
    pub r11: u64, // 0x30
    pub r10: u64, // 0x38
    pub r9:  u64, // 0x40
    pub r8:  u64, // 0x48
    pub rdi: u64, // 0x50
    pub rsi: u64, // 0x58
    pub rdx: u64, // 0x60
    pub rcx: u64, // 0x68
    pub rax: u64, // 0x70 — syscall nr on a syscall entry (Linux `orig_ax`)
    // Entry tag (oxide's split of Linux's single `orig_ax` slot).
    pub vector: u64, // 0x78
    pub error:  u64, // 0x80
    // The IRETQ return frame starts here — CPU-pushed on a trap/IRQ,
    // synthesized by the syscall stub (`syscall` pushes nothing).
    pub rip:    u64, // 0x88
    pub cs:     u64, // 0x90
    pub rflags: u64, // 0x98
    pub rsp:    u64, // 0xa0
    pub ss:     u64, // 0xa8
}

/// Byte size of the saved frame every entry stub pushes.
pub const PT_REGS_BYTES: usize = core::mem::size_of::<PtRegs>();

const _: () = {
    assert!(core::mem::offset_of!(PtRegs, r15)    == 0x00);
    assert!(core::mem::offset_of!(PtRegs, r14)    == 0x08);
    assert!(core::mem::offset_of!(PtRegs, r13)    == 0x10);
    assert!(core::mem::offset_of!(PtRegs, r12)    == 0x18);
    assert!(core::mem::offset_of!(PtRegs, rbp)    == 0x20);
    assert!(core::mem::offset_of!(PtRegs, rbx)    == 0x28);
    assert!(core::mem::offset_of!(PtRegs, r11)    == 0x30);
    assert!(core::mem::offset_of!(PtRegs, r10)    == 0x38);
    assert!(core::mem::offset_of!(PtRegs, r9)     == 0x40);
    assert!(core::mem::offset_of!(PtRegs, r8)     == 0x48);
    assert!(core::mem::offset_of!(PtRegs, rdi)    == 0x50);
    assert!(core::mem::offset_of!(PtRegs, rsi)    == 0x58);
    assert!(core::mem::offset_of!(PtRegs, rdx)    == 0x60);
    assert!(core::mem::offset_of!(PtRegs, rcx)    == 0x68);
    assert!(core::mem::offset_of!(PtRegs, rax)    == 0x70);
    assert!(core::mem::offset_of!(PtRegs, vector) == 0x78);
    assert!(core::mem::offset_of!(PtRegs, error)  == 0x80);
    assert!(core::mem::offset_of!(PtRegs, rip)    == 0x88);
    assert!(core::mem::offset_of!(PtRegs, cs)     == 0x90);
    assert!(core::mem::offset_of!(PtRegs, rflags) == 0x98);
    assert!(core::mem::offset_of!(PtRegs, rsp)    == 0xa0);
    assert!(core::mem::offset_of!(PtRegs, ss)     == 0xa8);
    assert!(PT_REGS_BYTES == 0xb0);
};

impl PtRegs {
    /// Did this frame enter the kernel through the `syscall` instruction?
    /// Linux's equivalent test is `syscall_get_nr(current, regs) != -1`
    /// (`arch/x86/kernel/signal.c` `arch_do_signal_or_restart`), which
    /// gates syscall restart and the `-ERESTART*` rewrite; a trap frame
    /// must never be restarted as if it were a syscall.
    /// # C: O(1)
    pub fn from_syscall(&self) -> bool { self.vector == PT_REGS_VECTOR_SYSCALL }

    /// Did the entry come from ring 3? Linux `user_mode(regs)`.
    /// # C: O(1)
    pub fn from_user(&self) -> bool { (self.cs & 3) == 3 }

    /// Syscall number the user asked for (Linux `syscall_get_nr` reading
    /// `orig_ax`). Meaningful only when `from_syscall()`; the syscall
    /// epilogue deliberately leaves the dispatcher's return value in the
    /// live `rax` register instead of writing it back here, so this stays
    /// valid for the whole dispatch including the restart path.
    /// # C: O(1)
    pub fn syscall_nr(&self) -> u64 { self.rax }

    /// Extract the 6 syscall arg registers per `15§1.1`.
    /// # C: O(1)
    pub fn to_syscall_args(&self) -> SyscallArgs {
        SyscallArgs {
            a0: self.rdi,
            a1: self.rsi,
            a2: self.rdx,
            a3: self.r10, // NOT rcx — the `syscall` insn clobbers rcx with the user RIP
            a4: self.r8,
            a5: self.r9,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layout_offsets_pin_the_asm_boundary() {
        // Every entry stub pushes exactly this image; `context.rs` writes
        // it by hand for a first-run task. Any reorder breaks all four.
        assert_eq!(core::mem::offset_of!(PtRegs, r15),    0x00);
        assert_eq!(core::mem::offset_of!(PtRegs, r14),    0x08);
        assert_eq!(core::mem::offset_of!(PtRegs, r13),    0x10);
        assert_eq!(core::mem::offset_of!(PtRegs, r12),    0x18);
        assert_eq!(core::mem::offset_of!(PtRegs, rbp),    0x20);
        assert_eq!(core::mem::offset_of!(PtRegs, rbx),    0x28);
        assert_eq!(core::mem::offset_of!(PtRegs, r11),    0x30);
        assert_eq!(core::mem::offset_of!(PtRegs, r10),    0x38);
        assert_eq!(core::mem::offset_of!(PtRegs, r9),     0x40);
        assert_eq!(core::mem::offset_of!(PtRegs, r8),     0x48);
        assert_eq!(core::mem::offset_of!(PtRegs, rdi),    0x50);
        assert_eq!(core::mem::offset_of!(PtRegs, rsi),    0x58);
        assert_eq!(core::mem::offset_of!(PtRegs, rdx),    0x60);
        assert_eq!(core::mem::offset_of!(PtRegs, rcx),    0x68);
        assert_eq!(core::mem::offset_of!(PtRegs, rax),    0x70);
        assert_eq!(core::mem::offset_of!(PtRegs, vector), 0x78);
        assert_eq!(core::mem::offset_of!(PtRegs, error),  0x80);
        assert_eq!(core::mem::offset_of!(PtRegs, rip),    0x88);
        assert_eq!(core::mem::offset_of!(PtRegs, cs),     0x90);
        assert_eq!(core::mem::offset_of!(PtRegs, rflags), 0x98);
        assert_eq!(core::mem::offset_of!(PtRegs, rsp),    0xa0);
        assert_eq!(core::mem::offset_of!(PtRegs, ss),     0xa8);
        assert_eq!(core::mem::size_of::<PtRegs>(),        0xb0);
        assert_eq!(PT_REGS_BYTES, 0xb0);
    }

    #[test]
    fn the_gpr_block_is_followed_immediately_by_the_iretq_image() {
        // The fault stubs push 15 GPRs on top of the CPU-pushed IRETQ
        // frame + the stub's own (vector, error) pair. That adjacency IS
        // the layout contract: `[GPRs][vector][error][iretq image]`.
        assert_eq!(core::mem::offset_of!(PtRegs, vector),
                   core::mem::offset_of!(PtRegs, rax) + 8, "vector must follow rax");
        assert_eq!(core::mem::offset_of!(PtRegs, rip),
                   core::mem::offset_of!(PtRegs, error) + 8, "iretq image must follow error");
        assert_eq!(core::mem::size_of::<PtRegs>(),
                   core::mem::offset_of!(PtRegs, ss) + 8, "no tail padding");
    }

    #[test]
    fn from_syscall_only_for_the_syscall_sentinel() {
        let mut r = PtRegs { vector: PT_REGS_VECTOR_SYSCALL, ..Default::default() };
        assert!(r.from_syscall());
        // Every real CPU vector (and the pooled 0xff stub tag) is a trap.
        for v in [0u64, 1, 3, 6, 13, 14, 0x40, 0x57, 0xff] {
            r.vector = v;
            assert!(!r.from_syscall(), "vector {v:#x} misread as a syscall entry");
        }
    }

    #[test]
    fn from_user_reads_the_cs_rpl() {
        let mut r = PtRegs::default();
        r.cs = 0x28;        // kernel CS, RPL 0
        assert!(!r.from_user());
        r.cs = 0x48 | 3;    // USER_CS
        assert!(r.from_user());
    }

    #[test]
    fn args_extracted_per_sysv_amd64_convention() {
        // `15§1.1`: nr=rax; args=rdi,rsi,rdx,r10,r8,r9. Note r10 not rcx.
        let regs = PtRegs {
            rax: 9, // sys_mmap
            rdi: 0x1000, rsi: 0x4000, rdx: 0x7,
            r10: 0x32, r8: 0x0, r9: 0x0,
            rcx: 0xdead_beef, // user RIP the `syscall` insn parked here
            vector: PT_REGS_VECTOR_SYSCALL,
            ..Default::default()
        };
        assert_eq!(regs.syscall_nr(), 9);
        let args = regs.to_syscall_args();
        assert_eq!(args.a0, 0x1000);
        assert_eq!(args.a1, 0x4000);
        assert_eq!(args.a2, 0x7);
        assert_eq!(args.a3, 0x32, "a3 must come from r10, not rcx");
        assert_eq!(args.a4, 0x0);
        assert_eq!(args.a5, 0x0);
    }
}
