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
