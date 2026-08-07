// User-register sanitation: the exact bit rules Linux applies to a
// USER-SUPPLIED EFLAGS / PSTATE before it reaches the hardware on a
// CPL3 / EL0 return. Two consumers, ONE owner, so they cannot drift:
//
//   * `rt_sigreturn`  — `hal-x86_64/src/signal.rs::restore_signal_frame`,
//                       `hal-aarch64/src/signal.rs::restore_signal_frame`
//   * `ptrace(2)`     — `syscalls/src/101_ptrace/regs.rs`
//
// Same rule for the ABI register STRUCT a debugger decodes (`user_regs`,
// `user_pt_regs` below): the live ptrace path and the core-dump `NT_PRSTATUS`
// path both index with these, so they cannot tell different stories about the
// same registers. Neither owns the KERNEL frame layout — that is the struct
// the entry asm pushes (`PtRegs` / `SvcFrame`), and every consumer reads it
// through named fields rather than a restated offset table.
//
// Both take a word straight out of memory an unprivileged process writes.
// Without the rules below a forged `pstate.M[3:0] = 0b0101` returns the
// process's own code at EL1, and a forged `eflags.IOPL = 3` hands it the
// x86 I/O port space; SYSRET copies R11 bits 12-13 (IOPL) and 9 (IF)
// verbatim per Intel SDM `RFLAGS := (R11 & 3C7FD7H) | 2`.
//
// Pure decision logic, NO target gate — every rule is host-unit-tested
// against the hostile inputs in `uregs/tests.rs`.
//
// Module manifest:
//   `x86_64`  — EFLAGS bit names, `FIX_EFLAGS`, ptrace `FLAG_MASK`, merges.
//   `aarch64` — SPSR_EL1 bit names, RES0 mask, `valid_native_regs` port.

/// x86_64 EFLAGS. Bit names from `arch/x86/include/uapi/asm/processor-flags.h`.
pub mod x86_64 {
    /// `struct user_regs_struct` (x86_64) — quadword index of each field, in
    /// the order a debugger decodes `PTRACE_GETREGS` / `NT_PRSTATUS`. This is
    /// the ABI order, which is NOT the order the kernel's entry frame stores
    /// registers in; mapping between the two is the consumer's job.
    pub mod user_regs {
        pub const R15: usize = 0;
        pub const R14: usize = 1;
        pub const R13: usize = 2;
        pub const R12: usize = 3;
        pub const RBP: usize = 4;
        pub const RBX: usize = 5;
        pub const R11: usize = 6;
        pub const R10: usize = 7;
        pub const R9:  usize = 8;
        pub const R8:  usize = 9;
        pub const RAX: usize = 10;
        pub const RCX: usize = 11;
        pub const RDX: usize = 12;
        pub const RSI: usize = 13;
        pub const RDI: usize = 14;
        pub const ORIG_RAX: usize = 15;
        pub const RIP:      usize = 16;
        pub const CS:       usize = 17;
        pub const EFLAGS:   usize = 18;
        pub const RSP:      usize = 19;
        pub const SS:       usize = 20;
        pub const FS_BASE:  usize = 21;
        pub const GS_BASE:  usize = 22;
        pub const DS:       usize = 23;
        pub const ES:       usize = 24;
        pub const FS:       usize = 25;
        pub const GS:       usize = 26;

        /// Quadwords in the struct.
        pub const N: usize = 27;
    }

    pub const X86_EFLAGS_CF:   u64 = 1 << 0;
    /// Bit 1 reads as 1 architecturally; SYSRET ORs it back in unconditionally.
    pub const X86_EFLAGS_FIXED: u64 = 1 << 1;
    pub const X86_EFLAGS_PF:   u64 = 1 << 2;
    pub const X86_EFLAGS_AF:   u64 = 1 << 4;
    pub const X86_EFLAGS_ZF:   u64 = 1 << 6;
    pub const X86_EFLAGS_SF:   u64 = 1 << 7;
    pub const X86_EFLAGS_TF:   u64 = 1 << 8;
    pub const X86_EFLAGS_IF:   u64 = 1 << 9;
    pub const X86_EFLAGS_DF:   u64 = 1 << 10;
    pub const X86_EFLAGS_OF:   u64 = 1 << 11;
    /// I/O privilege level, bits 13:12. CPL3 with IOPL=3 may run `IN`/`OUT`
    /// and `CLI`/`STI` — the escalation a missing mask hands out.
    pub const X86_EFLAGS_IOPL: u64 = 3 << 12;
    pub const X86_EFLAGS_NT:   u64 = 1 << 14;
    pub const X86_EFLAGS_RF:   u64 = 1 << 16;
    pub const X86_EFLAGS_VM:   u64 = 1 << 17;
    pub const X86_EFLAGS_AC:   u64 = 1 << 18;
    pub const X86_EFLAGS_VIF:  u64 = 1 << 19;
    pub const X86_EFLAGS_VIP:  u64 = 1 << 20;
    pub const X86_EFLAGS_ID:   u64 = 1 << 21;

    /// Segment-selector RPL field (`SEGMENT_RPL_MASK`,
    /// `arch/x86/include/asm/segment.h`).
    pub const X86_CS_RPL_MASK: u64 = 3;
    /// `USER_RPL` — the RPL a CPL3 selector carries. Linux `user_mode(regs)` is
    /// `!!(regs->cs & 3)` on x86_64 (`arch/x86/include/asm/ptrace.h`), so the
    /// saved CS's RPL is the whole test for "this entry came from user mode" —
    /// the gate on whether a return runs `exit_to_user_mode_loop`.
    pub const X86_CS_RPL_USER: u64 = 3;

    /// Linux `user_mode(regs)`, x86_64 arm. # C: O(1)
    pub const fn user_mode(cs: u64) -> bool { (cs & X86_CS_RPL_MASK) == X86_CS_RPL_USER }

    /// The saved register state a syscall return needs before `SYSRETQ` may be
    /// used instead of `IRETQ` — a direct port of the tail of
    /// `do_syscall_64()` (`arch/x86/entry/syscall_64.c`), which returns this
    /// same bool for its asm caller to branch on.
    ///
    /// `SYSRETQ` FORCES `RIP := RCX` and `RFLAGS := R11`; it cannot restore an
    /// independent RCX/R11. That is invisible for an ordinary syscall (the
    /// `SYSCALL` instruction already clobbered both, so the ABI lets userspace
    /// assume nothing about them) and fatal the moment the frame carries a
    /// real interrupted context: `rt_sigreturn`, `ptrace(POKEUSER)` and
    /// `execve` all install register sets where `rcx != rip`.
    ///
    /// B1471 hit exactly that. Once signals could be delivered mid-computation
    /// (not only at a syscall boundary), a handler's `rt_sigreturn` resumed the
    /// interrupted code with `rcx` overwritten by the resume address — a
    /// `movdqu %xmm4,(%rcx)` in the interrupted loop then stored into its own
    /// text and took SIGSEGV. Before B1471 this could not be observed, because
    /// the x86 syscall frame conflated `rcx`/`rip` in one slot and there was
    /// never a distinct `rcx` to lose.
    ///
    /// `user_va_end` is the caller's `hal::USER_VA_END` (Linux `TASK_SIZE_MAX`):
    /// `SYSRET` with a non-canonical RCX `#GP`s **in kernel space** with the
    /// user's RSP loaded, which hands the process the kernel — hence Linux's
    /// comment calling it "essentially lets the user take over the kernel".
    /// # C: O(1)
    #[allow(clippy::too_many_arguments)]
    pub const fn sysret_ok(rcx: u64, rip: u64, r11: u64, rflags: u64,
                           cs: u64, ss: u64,
                           user_cs: u64, user_ss: u64, user_va_end: u64) -> bool {
        // "SYSRET requires RCX == RIP and R11 == EFLAGS"
        if rcx != rip || r11 != rflags { return false; }
        // "CS and SS must match the values set in MSR_STAR"
        if cs != user_cs || ss != user_ss { return false; }
        // Non-canonical RIP: `SYSRET` #GPs at CPL0 with the user stack live.
        if rip >= user_va_end { return false; }
        // "SYSRET cannot restore RF. It can restore TF, but unlike IRET,
        //  restoring TF results in a trap from userspace immediately after
        //  SYSRET." — which is why PTRACE_SINGLESTEP must take the IRET path.
        if (rflags & (X86_EFLAGS_RF | X86_EFLAGS_TF)) != 0 { return false; }
        true
    }

    /// Linux `FIX_EFLAGS` (`arch/x86/include/asm/sighandling.h`) — the ONLY
    /// EFLAGS bits `rt_sigreturn` takes from the user's `sigcontext.flags`.
    /// Everything outside it keeps the kernel's saved value, so IF, IOPL, NT,
    /// VM, VIF, VIP and ID cannot be forged through a signal frame.
    pub const FIX_EFLAGS: u64 =
        X86_EFLAGS_AC | X86_EFLAGS_OF | X86_EFLAGS_DF | X86_EFLAGS_TF |
        X86_EFLAGS_SF | X86_EFLAGS_ZF | X86_EFLAGS_AF | X86_EFLAGS_PF |
        X86_EFLAGS_CF | X86_EFLAGS_RF;

    /// Linux x86_64 ptrace `FLAG_MASK` = `FLAG_MASK_32 | X86_EFLAGS_NT`
    /// (`arch/x86/kernel/ptrace.c`, `#else /* CONFIG_X86_64 */` arm). Same set
    /// as `FIX_EFLAGS` plus NT — a tracer may set NT, a signal frame may not.
    pub const PTRACE_FLAG_MASK: u64 = FIX_EFLAGS | X86_EFLAGS_NT;

    /// Linux's `regs->flags = (regs->flags & ~MASK) | (user & MASK)` splice.
    /// # C: O(1)
    pub const fn merge_eflags(cur: u64, user: u64, mask: u64) -> u64 {
        (cur & !mask) | (user & mask)
    }

    /// `restore_sigcontext` (`arch/x86/kernel/signal_64.c`):
    /// `regs->flags = (regs->flags & ~FIX_EFLAGS) | (sc.flags & FIX_EFLAGS)`.
    /// `cur` is the interrupted task's saved RFLAGS (the r11 slot the SYSCALL
    /// instruction filled), `user` the word read out of the user sigcontext.
    /// # C: O(1)
    pub const fn sigreturn_eflags(cur: u64, user: u64) -> u64 {
        merge_eflags(cur, user, FIX_EFLAGS)
    }

    /// `putreg`/`genregs_set` (`arch/x86/kernel/ptrace.c`) EFLAGS arm.
    /// # C: O(1)
    pub const fn ptrace_eflags(cur: u64, user: u64) -> u64 {
        merge_eflags(cur, user, PTRACE_FLAG_MASK)
    }

    /// `handle_signal` (`arch/x86/kernel/signal.c`), post-`setup_rt_frame`:
    /// `regs->flags &= ~(X86_EFLAGS_DF | X86_EFLAGS_RF | X86_EFLAGS_TF)`.
    /// DF because the SysV ABI requires it clear at function entry — a handler
    /// entered with DF set runs every `rep movs` backwards. TF so a SIGTRAP
    /// handler does not immediately re-trap. The value saved into the frame's
    /// `sigcontext.eflags` is the PRE-clear one, so `rt_sigreturn` puts DF/TF
    /// back exactly as the interrupted code had them.
    pub const SIGNAL_ENTRY_CLEAR: u64 = X86_EFLAGS_DF | X86_EFLAGS_RF | X86_EFLAGS_TF;

    /// EFLAGS a signal handler is ENTERED with. See `SIGNAL_ENTRY_CLEAR`.
    /// # C: O(1)
    pub const fn handler_entry_eflags(cur: u64) -> u64 { cur & !SIGNAL_ENTRY_CLEAR }
}

/// aarch64 SPSR_EL1. Bit names from `arch/arm64/include/uapi/asm/ptrace.h`
/// (plus IL from `arch/arm64/include/asm/ptrace.h` and SS = `DBG_SPSR_SS`
/// from `arch/arm64/include/asm/debug-monitors.h`).
pub mod aarch64 {
    /// `struct user_pt_regs` (arm64) — `regs[31]`, then the three named
    /// words. Same ownership rule as the x86_64 sibling.
    pub mod user_pt_regs {
        /// General registers the struct leads with: `x0`..`x30`.
        pub const NGPR: usize = 31;
        pub const SP:     usize = 31;
        pub const PC:     usize = 32;
        pub const PSTATE: usize = 33;

        /// Quadwords in the struct.
        pub const N: usize = 34;
    }

    /// `M[3:0]` — the exception level + stack-pointer selector.
    pub const PSR_MODE_MASK:  u64 = 0x0000_000f;
    /// EL0 with SP_EL0: the ONLY mode a user context may carry.
    pub const PSR_MODE_EL0T:  u64 = 0x0000_0000;
    /// `M[4]` — AArch32 execution state.
    pub const PSR_MODE32_BIT: u64 = 1 << 4;
    pub const PSR_F_BIT:      u64 = 1 << 6;
    pub const PSR_I_BIT:      u64 = 1 << 7;
    pub const PSR_A_BIT:      u64 = 1 << 8;
    pub const PSR_D_BIT:      u64 = 1 << 9;
    pub const PSR_BTYPE_MASK: u64 = 0b11 << 10;
    /// `PSR_BTYPE_C` — the BTYPE an indirect `BLR` sets; Linux stamps it on a
    /// signal handler's entry PSTATE when the CPU implements FEAT_BTI.
    pub const PSR_BTYPE_C:    u64 = 0b10 << 10;
    pub const PSR_SSBS_BIT:   u64 = 1 << 12;
    /// Illegal-execution-state bit — kernel-reserved, RES0 to userspace.
    pub const PSR_IL_BIT:     u64 = 1 << 20;
    /// Software-step (`DBG_SPSR_SS`). Not RES0: driven by the ptrace
    /// single-step state, never taken from the user word.
    pub const PSR_SS_BIT:     u64 = 1 << 21;
    pub const PSR_PAN_BIT:    u64 = 1 << 22;
    pub const PSR_UAO_BIT:    u64 = 1 << 23;
    pub const PSR_DIT_BIT:    u64 = 1 << 24;
    pub const PSR_TCO_BIT:    u64 = 1 << 25;
    pub const PSR_V_BIT:      u64 = 1 << 28;
    pub const PSR_C_BIT:      u64 = 1 << 29;
    pub const PSR_Z_BIT:      u64 = 1 << 30;
    pub const PSR_N_BIT:      u64 = 1 << 31;
    /// Condition flags — all that survives a rejected PSTATE.
    pub const PSR_NZCV: u64 = PSR_N_BIT | PSR_Z_BIT | PSR_C_BIT | PSR_V_BIT;

    /// Linux `SPSR_EL1_AARCH64_RES0_BITS` (`arch/arm64/kernel/ptrace.c`):
    /// `GENMASK_ULL(63,32) | GENMASK_ULL(27,26) | GENMASK_ULL(23,22) |
    ///  GENMASK_ULL(20,13) | GENMASK_ULL(5,5)`. Architecturally RES0, plus
    /// PAN/UAO (meaningless at EL0) and IL (kernel-reserved). SSBS (bit 12),
    /// DIT (24) and TCO (25) are deliberately OUTSIDE the mask — Linux lets
    /// userspace set those.
    pub const SPSR_EL1_AARCH64_RES0_BITS: u64 =
        genmask(63, 32) | genmask(27, 26) | genmask(23, 22) |
        genmask(20, 13) | genmask(5, 5);

    /// Linux `GENMASK_ULL(hi, lo)`, inclusive both ends.
    /// # C: O(1)
    const fn genmask(hi: u32, lo: u32) -> u64 {
        (u64::MAX << lo) & (u64::MAX >> (63 - hi))
    }

    /// Port of `valid_user_regs` → `user_regs_reset_single_step` +
    /// `valid_native_regs` (`arch/arm64/kernel/ptrace.c`), whose comment names
    /// signal-handler security as the reason it exists.
    ///
    /// Returns `(pstate, accepted)`. `accepted == false` means the caller must
    /// treat the whole register set as bad — Linux's `restore_sigframe` folds
    /// the `!valid_user_regs()` result into `err` and `rt_sigreturn` then
    /// `goto badframe` → `force_sig(SIGSEGV)`; `gpr_set` returns `-EINVAL`.
    /// The returned word is still sanitized (collapsed to NZCV, i.e. EL0t with
    /// DAIF clear) so a caller that installs it anyway cannot escalate.
    ///
    /// `single_step` is the task's ptrace single-step state, NOT anything read
    /// from user memory: Linux sets SS when `TIF_SINGLESTEP`, clears it
    /// otherwise, so a process can never software-step itself by forging the
    /// bit in a signal frame.
    /// # C: O(1)
    pub const fn sanitize_native_pstate(user: u64, single_step: bool) -> (u64, bool) {
        // `user_regs_reset_single_step()`
        let mut p = if single_step { user | PSR_SS_BIT } else { user & !PSR_SS_BIT };
        // `valid_native_regs()`
        p &= !SPSR_EL1_AARCH64_RES0_BITS;
        let accepted = (p & PSR_MODE_MASK) == PSR_MODE_EL0T
            && (p & PSR_MODE32_BIT) == 0
            && (p & PSR_D_BIT) == 0
            && (p & PSR_A_BIT) == 0
            && (p & PSR_I_BIT) == 0
            && (p & PSR_F_BIT) == 0;
        if accepted { (p, true) } else { (p & PSR_NZCV, false) }
    }

    /// Linux `user_mode(regs)`, arm64 arm: `(regs->pstate & PSR_MODE_MASK) ==
    /// PSR_MODE_EL0t` (`arch/arm64/include/asm/ptrace.h`). The gate on whether
    /// a return runs `exit_to_user_mode_loop`.
    /// # C: O(1)
    pub const fn user_mode(pstate: u64) -> bool {
        (pstate & PSR_MODE_MASK) == PSR_MODE_EL0T
    }

    /// `setup_return` (`arch/arm64/kernel/signal.c`): the PSTATE a handler is
    /// ENTERED with. TCO is always cleared for a signal handler; BTYPE is set
    /// to `PSR_BTYPE_C` only where FEAT_BTI is implemented, since PSTATE.BTYPE
    /// is RES0 without it.
    /// # C: O(1)
    pub const fn handler_entry_pstate(cur: u64, bti: bool) -> u64 {
        let p = cur & !PSR_TCO_BIT;
        if bti { (p & !PSR_BTYPE_MASK) | PSR_BTYPE_C } else { p }
    }
}

#[cfg(test)]
#[path = "uregs/tests.rs"] mod tests;
