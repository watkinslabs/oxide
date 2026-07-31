// Hosted proof of the trap -> (signal, si_code) tables. Encodes the mapping
// verified against the reference kernel's x86 trap entries and arm64
// `fault_info[]` table; these tests are the durable provenance.

use super::*;

const SIGILL_: u8 = 4;
const SIGTRAP_: u8 = 5;
const SIGBUS_: u8 = 7;
const SIGFPE_: u8 = 8;
const SIGSEGV_: u8 = 11;

mod x86 {
    use super::*;
    use super::super::x86_64::*;

    #[test]
    fn an_absent_mapping_is_maperr_and_a_protection_violation_is_accerr() {
        // A JIT's guard page and a COW-probe both key on this distinction.
        assert_eq!(page_fault(PF_USER), FaultSignal { signo: SIGSEGV_, code: code::SEGV_MAPERR });
        assert_eq!(page_fault(PF_USER | PF_PROT),
                   FaultSignal { signo: SIGSEGV_, code: code::SEGV_ACCERR });
    }

    #[test]
    fn an_invalid_opcode_is_sigill_illopn_not_sigsegv() {
        assert_eq!(trap(TRAP_UD), FaultSignal { signo: SIGILL_, code: code::ILL_ILLOPN });
    }

    #[test]
    fn a_divide_error_is_sigfpe_intdiv() {
        assert_eq!(trap(TRAP_DE), FaultSignal { signo: SIGFPE_, code: code::FPE_INTDIV });
    }

    #[test]
    fn an_alignment_check_is_sigbus_adraln() {
        assert_eq!(trap(TRAP_AC), FaultSignal { signo: SIGBUS_, code: code::BUS_ADRALN });
    }

    #[test]
    fn a_breakpoint_is_sigtrap_brkpt_and_a_debug_trap_is_sigtrap_trace() {
        assert_eq!(trap(TRAP_BP), FaultSignal { signo: SIGTRAP_, code: code::TRAP_BRKPT });
        assert_eq!(trap(TRAP_DB), FaultSignal { signo: SIGTRAP_, code: code::TRAP_TRACE });
    }

    #[test]
    fn a_general_protection_fault_is_sigsegv_with_no_si_code_classification() {
        // Linux reports #GP through `force_sig(SIGSEGV)`, which carries no
        // `_sigfault` classification — not SEGV_MAPERR.
        assert_eq!(trap(TRAP_GP), FaultSignal { signo: SIGSEGV_, code: SI_KERNEL });
        assert_eq!(trap_addr(TRAP_GP, 0x401000), 0, "a #GP names no address");
    }

    #[test]
    fn the_segment_traps_split_between_sigsegv_and_sigbus() {
        assert_eq!(trap(TRAP_TS).signo, SIGSEGV_);
        assert_eq!(trap(TRAP_NP).signo, SIGBUS_);
        assert_eq!(trap(TRAP_SS).signo, SIGBUS_);
    }

    #[test]
    fn a_bounds_trap_is_sigsegv_bnderr_and_a_control_protection_fault_is_cperr() {
        assert_eq!(trap(TRAP_BR), FaultSignal { signo: SIGSEGV_, code: code::SEGV_BNDERR });
        assert_eq!(trap(TRAP_CP), FaultSignal { signo: SIGSEGV_, code: code::SEGV_CPERR });
    }

    #[test]
    fn the_instruction_naming_traps_report_the_faulting_pc_as_si_addr() {
        for v in [TRAP_DE, TRAP_UD, TRAP_MF, TRAP_XF, TRAP_BP] {
            assert_eq!(trap_addr(v, 0x401000), 0x401000, "vec {v}");
        }
    }

    #[test]
    fn an_unmodelled_vector_still_produces_a_fatal_signal_never_nothing() {
        // A trap we do not name must not fall through silently; that is how a
        // user-mode exception wedges a CPU.
        assert_eq!(trap(0x1f), FaultSignal { signo: SIGSEGV_, code: SI_KERNEL });
    }
}

mod arm {
    use super::*;
    use super::super::aarch64::*;

    /// Build an ESR_EL1 with the given exception class and fault status code.
    fn esr(ec_val: u64, dfsc_val: u64) -> u64 { (ec_val << 26) | dfsc_val }

    #[test]
    fn a_translation_fault_is_maperr_at_every_level() {
        for level in 0..4u64 {
            let e = esr(EC_DABT_LOW, 0x04 + level);
            assert_eq!(sync(e), FaultSignal { signo: SIGSEGV_, code: code::SEGV_MAPERR },
                       "level {level}");
        }
        // The level -1 translation fault is encoded far away at 0b101011.
        assert_eq!(sync(esr(EC_DABT_LOW, 0x2b)).code, code::SEGV_MAPERR);
    }

    #[test]
    fn a_permission_or_access_flag_fault_is_accerr() {
        for dfsc_val in 0x08..=0x0fu64 {
            assert_eq!(sync(esr(EC_DABT_LOW, dfsc_val)),
                       FaultSignal { signo: SIGSEGV_, code: code::SEGV_ACCERR }, "dfsc {dfsc_val:#x}");
        }
    }

    #[test]
    fn an_address_size_fault_is_maperr() {
        for dfsc_val in 0x00..=0x03u64 {
            assert_eq!(sync(esr(EC_IABT_LOW, dfsc_val)).code, code::SEGV_MAPERR);
        }
    }

    #[test]
    fn an_external_abort_is_sigbus_objerr() {
        assert_eq!(sync(esr(EC_DABT_LOW, 0x10)),
                   FaultSignal { signo: SIGBUS_, code: code::BUS_OBJERR });
        assert_eq!(sync(esr(EC_DABT_LOW, 0x18)).code, code::BUS_OBJERR);
    }

    #[test]
    fn an_alignment_fault_is_sigbus_adraln() {
        assert_eq!(sync(esr(EC_DABT_LOW, 0x21)),
                   FaultSignal { signo: SIGBUS_, code: code::BUS_ADRALN });
        // PC and SP alignment faults have their own exception classes.
        assert_eq!(sync(esr(EC_PC_ALIGN, 0)), FaultSignal { signo: SIGBUS_, code: code::BUS_ADRALN });
        assert_eq!(sync(esr(EC_SP_ALIGN, 0)), FaultSignal { signo: SIGBUS_, code: code::BUS_ADRALN });
    }

    #[test]
    fn an_unknown_or_illegal_execution_state_is_sigill() {
        assert_eq!(sync(esr(EC_UNKNOWN, 0)), FaultSignal { signo: SIGILL_, code: code::ILL_ILLOPC });
        assert_eq!(sync(esr(EC_ILLEGAL_STATE, 0)).signo, SIGILL_);
    }

    #[test]
    fn brk_and_the_debug_exceptions_are_sigtrap_with_distinct_codes() {
        assert_eq!(sync(esr(EC_BRK, 0)), FaultSignal { signo: SIGTRAP_, code: code::TRAP_BRKPT });
        assert_eq!(sync(esr(EC_SOFTSTEP_LOW, 0)).code, code::TRAP_TRACE);
        assert_eq!(sync(esr(EC_WATCHPT_LOW, 0)).code, code::TRAP_HWBKPT);
    }

    #[test]
    fn a_floating_point_exception_is_sigfpe() {
        assert_eq!(sync(esr(EC_FP_EXC, 0)), FaultSignal { signo: SIGFPE_, code: code::FPE_FLTUNK });
    }

    #[test]
    fn only_the_lower_el_abort_classes_report_as_user_aborts() {
        assert!(from_el0(esr(EC_DABT_LOW, 0x04)));
        assert!(from_el0(esr(EC_IABT_LOW, 0x04)));
        // 0x21 / 0x25 are the SAME-EL (kernel uaccess) abort classes.
        assert!(!from_el0(esr(0x25, 0x04)));
        assert!(!from_el0(esr(0x21, 0x04)));
    }

    #[test]
    fn ec_and_dfsc_decode_the_documented_bit_positions() {
        assert_eq!(ec(esr(EC_DABT_LOW, 0x3f)), EC_DABT_LOW);
        assert_eq!(dfsc(esr(EC_DABT_LOW, 0x3f)), 0x3f);
    }
}
