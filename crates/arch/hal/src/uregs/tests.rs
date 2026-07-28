// Hostile-input tests for the EFLAGS / PSTATE sanitizers. These are the
// privilege boundary: a bit that leaks through here is an unprivileged
// process choosing its own hardware state on the next CPL3 / EL0 return.

use super::*;

mod x86 {
    use super::x86_64::*;

    /// The interrupted context the kernel merges INTO — IF set (user always
    /// runs with interrupts on), IOPL 0, nothing else.
    const KERNEL_SAVED: u64 = X86_EFLAGS_IF | X86_EFLAGS_FIXED;

    #[test]
    fn fix_eflags_is_linux_0x50dd5() {
        // arch/x86/include/asm/sighandling.h: AC|OF|DF|TF|SF|ZF|AF|PF|CF|RF.
        assert_eq!(FIX_EFLAGS, 0x0005_0DD5);
        assert_eq!(PTRACE_FLAG_MASK, 0x0005_4DD5);
    }

    #[test]
    fn sigreturn_cannot_raise_iopl() {
        let forged = sigreturn_eflags(KERNEL_SAVED, X86_EFLAGS_IOPL);
        assert_eq!(forged & X86_EFLAGS_IOPL, 0, "IOPL leaked into RFLAGS");
    }

    #[test]
    fn sigreturn_cannot_clear_the_interrupt_flag() {
        // SYSRET copies R11 bit 9 verbatim; a cleared IF would return to
        // userspace with interrupts off and wedge the CPU.
        let out = sigreturn_eflags(KERNEL_SAVED, 0);
        assert_eq!(out & X86_EFLAGS_IF, X86_EFLAGS_IF);
    }

    #[test]
    fn sigreturn_cannot_set_the_interrupt_flag_when_the_kernel_had_it_clear() {
        let out = sigreturn_eflags(X86_EFLAGS_FIXED, u64::MAX);
        assert_eq!(out & X86_EFLAGS_IF, 0);
    }

    #[test]
    fn sigreturn_blocks_every_privileged_and_reserved_bit() {
        let out = sigreturn_eflags(KERNEL_SAVED, u64::MAX);
        for (name, bit) in [
            ("IOPL", X86_EFLAGS_IOPL), ("NT", X86_EFLAGS_NT), ("VM", X86_EFLAGS_VM),
            ("VIF", X86_EFLAGS_VIF),   ("VIP", X86_EFLAGS_VIP), ("ID", X86_EFLAGS_ID),
        ] {
            assert_eq!(out & bit, 0, "{name} leaked through FIX_EFLAGS");
        }
        // Reserved bits 3, 5, 15 and everything above 21 stay the kernel's.
        assert_eq!(out & !(FIX_EFLAGS | KERNEL_SAVED), 0);
        assert_eq!(out >> 22, 0);
    }

    #[test]
    fn sigreturn_passes_the_arithmetic_direction_and_trap_bits_through() {
        let want = X86_EFLAGS_CF | X86_EFLAGS_PF | X86_EFLAGS_AF | X86_EFLAGS_ZF |
                   X86_EFLAGS_SF | X86_EFLAGS_TF | X86_EFLAGS_DF | X86_EFLAGS_OF |
                   X86_EFLAGS_RF | X86_EFLAGS_AC;
        let out = sigreturn_eflags(KERNEL_SAVED, want);
        assert_eq!(out & want, want, "a legitimate user-settable bit was dropped");
        assert_eq!(out, want | KERNEL_SAVED);
    }

    #[test]
    fn sigreturn_clears_a_user_settable_bit_the_user_dropped() {
        // The splice must be a replace, not an OR: DF left set across a
        // sigreturn that cleared it would silently reverse `rep movsb`.
        let out = sigreturn_eflags(KERNEL_SAVED | X86_EFLAGS_DF, 0);
        assert_eq!(out & X86_EFLAGS_DF, 0);
    }

    #[test]
    fn handler_entry_clears_df_rf_and_tf_only() {
        let cur = KERNEL_SAVED | X86_EFLAGS_DF | X86_EFLAGS_RF | X86_EFLAGS_TF |
                  X86_EFLAGS_ZF | X86_EFLAGS_CF;
        let out = handler_entry_eflags(cur);
        assert_eq!(out & X86_EFLAGS_DF, 0, "SysV requires DF clear at fn entry");
        assert_eq!(out & X86_EFLAGS_RF, 0);
        assert_eq!(out & X86_EFLAGS_TF, 0, "SIGTRAP handler would re-trap");
        assert_eq!(out, KERNEL_SAVED | X86_EFLAGS_ZF | X86_EFLAGS_CF);
    }

    #[test]
    fn ptrace_allows_nt_but_sigreturn_does_not() {
        assert_eq!(ptrace_eflags(KERNEL_SAVED, X86_EFLAGS_NT) & X86_EFLAGS_NT, X86_EFLAGS_NT);
        assert_eq!(sigreturn_eflags(KERNEL_SAVED, X86_EFLAGS_NT) & X86_EFLAGS_NT, 0);
        assert_eq!(ptrace_eflags(KERNEL_SAVED, u64::MAX) & X86_EFLAGS_IOPL, 0);
    }
}

mod arm {
    use super::aarch64::*;

    /// SPSR_EL1 for a normal EL0 AArch64 thread with NZCV set.
    const USER_PSTATE: u64 = PSR_NZCV;

    #[test]
    fn res0_mask_is_linux_genmask_union() {
        assert_eq!(SPSR_EL1_AARCH64_RES0_BITS, 0xFFFF_FFFF_0CDF_E020);
        // Bits Linux deliberately leaves user-settable.
        for (name, bit) in [("SSBS", PSR_SSBS_BIT), ("DIT", PSR_DIT_BIT),
                            ("TCO", PSR_TCO_BIT), ("BTYPE", PSR_BTYPE_MASK)] {
            assert_eq!(SPSR_EL1_AARCH64_RES0_BITS & bit, 0, "{name} must not be RES0");
        }
        // Bits Linux reserves.
        for (name, bit) in [("IL", PSR_IL_BIT), ("PAN", PSR_PAN_BIT), ("UAO", PSR_UAO_BIT)] {
            assert_eq!(SPSR_EL1_AARCH64_RES0_BITS & bit, bit, "{name} must be RES0");
        }
    }

    #[test]
    fn rt_sigreturn_cannot_promote_to_el1() {
        // M[3:0] = 0b0101 = EL1h — the forged sigcontext.pstate that turns
        // rt_sigreturn into arbitrary EL1 execution.
        for mode in [0x4u64, 0x5, 0x8, 0x9, 0xc, 0xd] {
            let (p, ok) = sanitize_native_pstate(USER_PSTATE | mode, false);
            assert!(!ok, "mode {mode:#x} accepted");
            assert_eq!(p & PSR_MODE_MASK, PSR_MODE_EL0T, "mode {mode:#x} survived");
            assert_eq!(p, PSR_NZCV);
        }
    }

    #[test]
    fn rt_sigreturn_cannot_mask_daif() {
        for (name, bit) in [("D", PSR_D_BIT), ("A", PSR_A_BIT),
                            ("I", PSR_I_BIT), ("F", PSR_F_BIT)] {
            let (p, ok) = sanitize_native_pstate(USER_PSTATE | bit, false);
            assert!(!ok, "{name} accepted");
            assert_eq!(p & bit, 0, "{name} survived");
        }
    }

    #[test]
    fn rt_sigreturn_cannot_enter_aarch32() {
        let (p, ok) = sanitize_native_pstate(USER_PSTATE | PSR_MODE32_BIT, false);
        assert!(!ok);
        assert_eq!(p & PSR_MODE32_BIT, 0);
    }

    #[test]
    fn rt_sigreturn_cannot_set_il_pan_uao_or_any_res0_bit() {
        let (p, ok) = sanitize_native_pstate(USER_PSTATE | PSR_IL_BIT, false);
        assert!(ok, "IL is masked, not a rejection — the rest of the word is legal");
        assert_eq!(p & PSR_IL_BIT, 0, "IL would make the next eret illegal-state");
        let (p, ok) = sanitize_native_pstate(u64::MAX, false);
        assert!(!ok, "all-ones carries EL3h + DAIF");
        assert_eq!(p, PSR_NZCV);
        // Every RES0 bit is gone even on the accepted path.
        let (p, ok) = sanitize_native_pstate(USER_PSTATE | SPSR_EL1_AARCH64_RES0_BITS
                                             & !PSR_MODE_MASK & !PSR_MODE32_BIT, false);
        assert!(ok);
        assert_eq!(p & SPSR_EL1_AARCH64_RES0_BITS, 0);
    }

    #[test]
    fn rt_sigreturn_cannot_arm_software_step() {
        let (p, ok) = sanitize_native_pstate(USER_PSTATE | PSR_SS_BIT, false);
        assert!(ok);
        assert_eq!(p & PSR_SS_BIT, 0, "a process software-stepped itself");
        // A traced task keeps SS regardless of what the user word said.
        let (p, ok) = sanitize_native_pstate(USER_PSTATE, true);
        assert!(ok);
        assert_eq!(p & PSR_SS_BIT, PSR_SS_BIT);
    }

    #[test]
    fn rt_sigreturn_passes_the_legitimate_bits_through() {
        let want = PSR_NZCV | PSR_SSBS_BIT | PSR_DIT_BIT | PSR_TCO_BIT | PSR_BTYPE_MASK;
        let (p, ok) = sanitize_native_pstate(want, false);
        assert!(ok, "a legal EL0t PSTATE was rejected");
        assert_eq!(p, want);
    }

    #[test]
    fn handler_entry_clears_tco_and_stamps_btype_only_with_bti() {
        let cur = PSR_NZCV | PSR_TCO_BIT | PSR_BTYPE_MASK;
        assert_eq!(handler_entry_pstate(cur, false), PSR_NZCV | PSR_BTYPE_MASK);
        assert_eq!(handler_entry_pstate(cur, true), PSR_NZCV | PSR_BTYPE_C);
    }
}

// `user_mode(regs)` — the gate that decides whether a return runs the
// return-to-user work loop. A wrong answer here either delivers a signal into
// a kernel frame or leaves a spinning task unkillable (B1471).
mod user_mode {
    use crate::uregs::{aarch64 as a64, x86_64 as x86};

    #[test]
    fn x86_kernel_cs_is_not_user_mode() {
        // Linux `!!(regs->cs & 3)`. Kernel CS has RPL 0.
        assert!(!x86::user_mode(0x08));
        assert!(!x86::user_mode(0x10));
    }

    #[test]
    fn x86_user_cs_is_user_mode() {
        // The 64-bit user code selector this kernel loads via STAR.
        assert!(x86::user_mode(0x33));
        assert!(x86::user_mode(0x2b));
    }

    #[test]
    fn arm_el0t_is_user_mode_and_every_el1_mode_is_not() {
        assert!(a64::user_mode(a64::PSR_MODE_EL0T));
        // Condition flags and DAIF bits outside M[3:0] must not change it.
        assert!(a64::user_mode(a64::PSR_MODE_EL0T | a64::PSR_NZCV | a64::PSR_SSBS_BIT));
        // EL1t (0b0100) and EL1h (0b0101) — the modes a forged frame would use.
        assert!(!a64::user_mode(0b0100));
        assert!(!a64::user_mode(0b0101));
        assert!(!a64::user_mode(0b1001));
    }
}

// `sysret_ok` — whether a syscall return may use SYSRETQ. Port of the tail of
// Linux `do_syscall_64()`; every `false` arm is a real corruption or fault.
mod sysret {
    use crate::uregs::x86_64::{self as x86, X86_EFLAGS_RF, X86_EFLAGS_TF};

    /// This kernel's ring-3 selectors and user-VA bound.
    const UCS: u64 = 0x4b;
    const USS: u64 = 0x43;
    const VA_END: u64 = 0x0000_8000_0000_0000;
    const RIP: u64 = 0x0000_0000_0040_6adf;
    const FLAGS: u64 = 0x202;

    fn ok(rcx: u64, rip: u64, r11: u64, rflags: u64, cs: u64, ss: u64) -> bool {
        x86::sysret_ok(rcx, rip, r11, rflags, cs, ss, UCS, USS, VA_END)
    }

    #[test]
    fn a_clean_syscall_return_uses_sysret() {
        // SYSCALL left rcx = rip and r11 = rflags, nothing rewrote the frame.
        assert!(ok(RIP, RIP, FLAGS, FLAGS, UCS, USS));
    }

    #[test]
    fn an_independent_rcx_forces_iret() {
        // THE B1471 case: `rt_sigreturn` restores the interrupted context's
        // own rcx. SYSRETQ would overwrite it with the resume RIP — which is
        // how a spin loop's `movdqu %xmm4,(%rcx)` came to store into its own
        // text and take SIGSEGV.
        assert!(!ok(0xdead_beef, RIP, FLAGS, FLAGS, UCS, USS));
    }

    #[test]
    fn an_independent_r11_forces_iret() {
        // Same shape for RFLAGS: SYSRETQ takes them from r11.
        assert!(!ok(RIP, RIP, 0xdead_beef, FLAGS, UCS, USS));
    }

    #[test]
    fn a_rewritten_selector_forces_iret() {
        // SYSRETQ hardcodes the selectors from MSR_STAR; a frame carrying
        // anything else must go through IRETQ or userspace silently gets the
        // wrong CS/SS.
        assert!(!ok(RIP, RIP, FLAGS, FLAGS, 0x33, USS));
        assert!(!ok(RIP, RIP, FLAGS, FLAGS, UCS, 0x2b));
    }

    #[test]
    fn a_non_canonical_rip_forces_iret() {
        // The security-critical arm: SYSRET with non-canonical RCX #GPs at
        // CPL0 with the user's RSP live. Linux: "essentially lets the user
        // take over the kernel".
        let bad = VA_END;                    // first non-user address
        assert!(!ok(bad, bad, FLAGS, FLAGS, UCS, USS));
        assert!(!ok(u64::MAX, u64::MAX, FLAGS, FLAGS, UCS, USS));
        // The last user-space byte is still fine.
        assert!(ok(VA_END - 1, VA_END - 1, FLAGS, FLAGS, UCS, USS));
    }

    #[test]
    fn trap_and_resume_flags_force_iret() {
        // SYSRET cannot restore RF at all, and restoring TF traps immediately
        // after the SYSRET rather than after the first user instruction — so
        // PTRACE_SINGLESTEP must take the IRET path.
        let tf = FLAGS | X86_EFLAGS_TF;
        assert!(!ok(RIP, RIP, tf, tf, UCS, USS));
        let rf = FLAGS | X86_EFLAGS_RF;
        assert!(!ok(RIP, RIP, rf, rf, UCS, USS));
    }
}
