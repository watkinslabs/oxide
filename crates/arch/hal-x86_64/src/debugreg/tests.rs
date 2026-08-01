// Hosted coverage of the pure DR7 validation ladder and DR6 classifier.
// These encode the verified x86 debug-register ABI so later work can re-check
// the contract without leaving the repository.

use hal::siginfo::code;

use super::dr6::*;
use super::dr7::*;
use super::state::DebugRegs;

/// End of the user half — mirrors the kernel's own limit.
const UEND: u64 = hal::USER_VA_END;
/// A canonical kernel address: above `UEND`.
const KADDR: u64 = 0xFFFF_FFFF_8000_0000;

/// Build a DR7 arming slot 0 locally with the given rw/len encodings.
fn dr7_slot0(rw: u64, len: u64) -> u64 {
    DR7_RESERVED_ONE | local_enable(0) | (rw << rw_shift(0)) | (len << len_shift(0))
}

/// Build a DR7 arming `slot` locally with the given rw/len encodings.
fn dr7_slot(slot: usize, rw: u64, len: u64) -> u64 {
    DR7_RESERVED_ONE | local_enable(slot) | (rw << rw_shift(slot)) | (len << len_shift(slot))
}

fn addrs(a0: u64) -> [u64; HBP_NUM] { [a0, 0, 0, 0] }

#[test]
fn default_is_reset_value_and_unarmed() {
    let d = DebugRegs::default();
    assert_eq!(d.dr7, 0x400, "DR7 reset value: reserved bit 10 set, nothing else");
    assert_eq!(d.dr7 & DR7_RESERVED_ONE, DR7_RESERVED_ONE);
    assert_eq!(d.addr, [0; HBP_NUM]);
    assert_eq!(d.dr6, 0);
    assert!(!d.is_armed());
    assert_eq!(DebugRegs::empty(), d);
}

#[test]
fn enable_bit_makes_state_armed() {
    let mut d = DebugRegs::default();
    assert!(!d.is_armed());
    d.set_dr7_limit(dr7_slot0(DR7_RW_WRITE, DR7_LEN_1), UEND).unwrap();
    assert!(d.is_armed());
    d.disarm();
    assert!(!d.is_armed());
}

#[test]
fn global_enable_alone_arms_slot() {
    let dr7 = DR7_RESERVED_ONE | global_enable(2) | (DR7_RW_WRITE << rw_shift(2));
    assert!(slot_enabled(dr7, 2));
    let mut d = DebugRegs::default();
    d.set_dr7_limit(dr7, UEND).unwrap();
    assert!(d.is_armed());
}

#[test]
fn slot_field_shifts_match_hardware_layout() {
    assert_eq!((rw_shift(0), len_shift(0)), (16, 18));
    assert_eq!((rw_shift(1), len_shift(1)), (20, 22));
    assert_eq!((rw_shift(2), len_shift(2)), (24, 26));
    assert_eq!((rw_shift(3), len_shift(3)), (28, 30));
    assert_eq!(local_enable(0), 1 << 0);
    assert_eq!(global_enable(0), 1 << 1);
    assert_eq!(local_enable(3), 1 << 6);
    assert_eq!(global_enable(3), 1 << 7);
    assert_eq!(DR7_ENABLE_MASK, 0xFF);
}

#[test]
fn len_encodings_decode_to_byte_spans() {
    assert_eq!(len_bytes(DR7_LEN_1), 1);
    assert_eq!(len_bytes(DR7_LEN_2), 2);
    assert_eq!(len_bytes(DR7_LEN_4), 4);
    assert_eq!(len_bytes(DR7_LEN_8), 8);
}

#[test]
fn every_rw_len_pair_with_aligned_addr_is_accepted() {
    for &rw in &[DR7_RW_WRITE, DR7_RW_READWRITE] {
        for &len in &[DR7_LEN_1, DR7_LEN_2, DR7_LEN_4, DR7_LEN_8] {
            let dr7 = dr7_slot0(rw, len);
            // 0x1000 is aligned for every span 1..8.
            let got = validate_dr7(dr7, &addrs(0x1000), UEND);
            assert_eq!(got, Ok(dr7 | DR7_RESERVED_ONE), "rw={rw} len={len}");
        }
    }
    // Execute breakpoints are always 1 byte and need no alignment.
    let dr7 = dr7_slot0(DR7_RW_EXECUTE, DR7_LEN_1);
    assert_eq!(validate_dr7(dr7, &addrs(0x1003), UEND), Ok(dr7 | DR7_RESERVED_ONE));
}

#[test]
fn execute_breakpoint_with_nonzero_len_is_rejected() {
    for &len in &[DR7_LEN_2, DR7_LEN_4, DR7_LEN_8] {
        let dr7 = dr7_slot0(DR7_RW_EXECUTE, len);
        assert_eq!(validate_dr7(dr7, &addrs(0x1000), UEND),
                   Err(Dr7Error::ExecuteLen { slot: 0 }), "len={len}");
    }
}

#[test]
fn io_breakpoint_is_rejected_on_every_slot() {
    for slot in 0..HBP_NUM {
        let dr7 = dr7_slot(slot, DR7_RW_IO, DR7_LEN_1);
        assert_eq!(validate_dr7(dr7, &[0x1000; HBP_NUM], UEND),
                   Err(Dr7Error::IoBreakpoint { slot }));
    }
}

#[test]
fn misaligned_watchpoint_address_is_rejected() {
    // 4-byte watch needs 4-byte alignment.
    let dr7_4 = dr7_slot0(DR7_RW_WRITE, DR7_LEN_4);
    for bad in [0x1001u64, 0x1002, 0x1003] {
        assert_eq!(validate_dr7(dr7_4, &addrs(bad), UEND),
                   Err(Dr7Error::Misaligned { slot: 0 }), "addr={bad:#x}");
    }
    assert!(validate_dr7(dr7_4, &addrs(0x1004), UEND).is_ok());
    // 8-byte watch needs 8-byte alignment.
    let dr7_8 = dr7_slot0(DR7_RW_READWRITE, DR7_LEN_8);
    assert_eq!(validate_dr7(dr7_8, &addrs(0x1004), UEND),
               Err(Dr7Error::Misaligned { slot: 0 }));
    assert!(validate_dr7(dr7_8, &addrs(0x1008), UEND).is_ok());
    // 2-byte watch needs 2-byte alignment.
    let dr7_2 = dr7_slot0(DR7_RW_WRITE, DR7_LEN_2);
    assert_eq!(validate_dr7(dr7_2, &addrs(0x1001), UEND),
               Err(Dr7Error::Misaligned { slot: 0 }));
    assert!(validate_dr7(dr7_2, &addrs(0x1002), UEND).is_ok());
    // 1-byte watch accepts any address.
    let dr7_1 = dr7_slot0(DR7_RW_WRITE, DR7_LEN_1);
    assert!(validate_dr7(dr7_1, &addrs(0x1001), UEND).is_ok());
}

#[test]
fn general_detect_bit_is_rejected() {
    let dr7 = dr7_slot0(DR7_RW_WRITE, DR7_LEN_1) | DR7_GD;
    assert_eq!(validate_dr7(dr7, &addrs(0x1000), UEND), Err(Dr7Error::GeneralDetect));
    // GD alone, with no slot armed, is still refused.
    assert_eq!(validate_dr7(DR7_RESERVED_ONE | DR7_GD, &addrs(0), UEND),
               Err(Dr7Error::GeneralDetect));
}

#[test]
fn reserved_zero_bits_are_rejected() {
    for bit in [11u32, 12, 14, 15, 32, 63] {
        let dr7 = DR7_RESERVED_ONE | (1u64 << bit);
        assert_eq!(validate_dr7(dr7, &addrs(0), UEND), Err(Dr7Error::Reserved),
                   "bit={bit}");
    }
    // LE/GE (bits 8/9) are software-settable, not reserved.
    assert!(validate_dr7(DR7_RESERVED_ONE | DR7_LE | DR7_GE, &addrs(0), UEND).is_ok());
}

#[test]
fn kernel_breakpoint_address_is_rejected() {
    let dr7 = dr7_slot0(DR7_RW_WRITE, DR7_LEN_8);
    assert_eq!(validate_dr7(dr7, &addrs(KADDR), UEND),
               Err(Dr7Error::KernelAddress { slot: 0 }));
    // The last user byte is fine; a span that runs past the limit is not.
    assert!(validate_dr7(dr7, &addrs(UEND - 8), UEND).is_ok());
    assert_eq!(validate_dr7(dr7, &addrs(UEND), UEND),
               Err(Dr7Error::KernelAddress { slot: 0 }));
    // Address-register write is guarded independently of DR7.
    assert_eq!(validate_addr(1, KADDR, UEND), Err(Dr7Error::KernelAddress { slot: 1 }));
    assert_eq!(validate_addr(1, UEND - 1, UEND), Ok(()));
    assert_eq!(validate_addr(1, u64::MAX, UEND), Err(Dr7Error::KernelAddress { slot: 1 }));
}

#[test]
fn disabled_slot_is_not_validated() {
    // Slot 1 carries an I/O rw, an execute-with-len pair, a misaligned kernel
    // address — all garbage, none of it enabled, so DR7 installs cleanly.
    let dr7 = dr7_slot0(DR7_RW_WRITE, DR7_LEN_1)
        | (DR7_RW_IO << rw_shift(1)) | (DR7_LEN_8 << len_shift(1))
        | (DR7_RW_EXECUTE << rw_shift(2)) | (DR7_LEN_4 << len_shift(2));
    let a = [0x1000u64, KADDR | 3, KADDR | 1, 0];
    assert_eq!(validate_dr7(dr7, &a, UEND), Ok(dr7 | DR7_RESERVED_ONE));
    // Enabling that slot flips it to an error.
    assert_eq!(validate_dr7(dr7 | local_enable(1), &a, UEND),
               Err(Dr7Error::IoBreakpoint { slot: 1 }));
}

#[test]
fn failed_dr7_write_leaves_state_untouched() {
    let mut d = DebugRegs::default();
    d.set_addr_limit(0, 0x2000, UEND).unwrap();
    let before = d;
    assert_eq!(d.set_dr7_limit(dr7_slot0(DR7_RW_IO, DR7_LEN_1), UEND),
               Err(Dr7Error::IoBreakpoint { slot: 0 }));
    assert_eq!(d, before);
    assert_eq!(d.set_addr_limit(0, KADDR, UEND), Err(Dr7Error::KernelAddress { slot: 0 }));
    assert_eq!(d, before);
    assert_eq!(d.set_addr_limit(HBP_NUM, 0, UEND),
               Err(Dr7Error::KernelAddress { slot: HBP_NUM }));
}

#[test]
fn debugreg_index_map_matches_u_debugreg() {
    let mut d = DebugRegs::default();
    for slot in 0..HBP_NUM { d.set_addr_limit(slot, 0x1000 + slot as u64 * 8, UEND).unwrap(); }
    d.record_dr6(DR6_B2);
    for slot in 0..HBP_NUM { assert_eq!(d.get(slot), Some(0x1000 + slot as u64 * 8)); }
    assert_eq!(d.get(4), Some(d.dr6));
    assert_eq!(d.get(6), Some(d.dr6));
    assert_eq!(d.get(5), Some(d.dr7));
    assert_eq!(d.get(7), Some(d.dr7));
    assert_eq!(d.get(8), None);
}

#[test]
fn dr6_classifier_names_each_slot() {
    for slot in 0..HBP_NUM {
        let s = Dr6Status::decode(normalize(DR6_RESERVED_ONES | (1u64 << slot)));
        assert_eq!(s.first_slot(), Some(slot));
        assert!(s.hit(slot));
        assert!(!s.single_step);
        assert!(!s.is_empty());
        assert_eq!(s.si_code(), code::TRAP_HWBKPT, "slot={slot}");
    }
    assert_eq!(DR6_TRAP_BITS, 0xF);
}

#[test]
fn dr6_classifier_reports_multiple_hits() {
    let s = Dr6Status::decode(DR6_B1 | DR6_B3);
    assert_eq!(s.hits, 0b1010);
    assert_eq!(s.first_slot(), Some(1));
    assert!(s.hit(1) && s.hit(3) && !s.hit(0) && !s.hit(2));
    assert_eq!(s.si_code(), code::TRAP_HWBKPT);
}

#[test]
fn dr6_single_step_reports_trap_trace() {
    let s = Dr6Status::decode(DR6_BS);
    assert!(s.single_step);
    assert_eq!(s.hits, 0);
    assert_eq!(s.si_code(), code::TRAP_TRACE);
    // Single-step outranks a concurrent breakpoint match.
    assert_eq!(Dr6Status::decode(DR6_BS | DR6_B0).si_code(), code::TRAP_TRACE);
    assert_eq!(si_code_for(DR6_BS), code::TRAP_TRACE);
}

#[test]
fn dr6_without_cause_bits_reports_breakpoint_trap() {
    // An untriggered hardware DR6 normalises to zero — no cause, so a #DB that
    // reached the handler is an `int3`-class breakpoint trap.
    assert_eq!(normalize(DR6_RESERVED_ONES), 0);
    let s = Dr6Status::decode(normalize(DR6_RESERVED_ONES));
    assert!(s.is_empty());
    assert_eq!(s.first_slot(), None);
    assert_eq!(s.si_code(), code::TRAP_BRKPT);
    assert_eq!(Dr6Status::default(), s);
    assert_eq!(si_code_for_raw(DR6_RESERVED_ONES), code::TRAP_BRKPT);
    // Bus-lock is active-LOW: hardware reports it by CLEARING bit 11.
    assert!(Dr6Status::decode(normalize(DR6_RESERVED_ONES & !DR6_BUS_LOCK)).bus_lock);
    assert!(!Dr6Status::decode(normalize(DR6_RESERVED_ONES)).bus_lock);
    assert_eq!(si_code_for_raw(DR6_RESERVED_ONES | DR6_BS), code::TRAP_TRACE);
    assert_eq!(si_code_for_raw(DR6_RESERVED_ONES | DR6_B3), code::TRAP_HWBKPT);
}

#[test]
fn dr6_side_causes_decode() {
    assert!(Dr6Status::decode(DR6_BT).task_switch);
    assert!(Dr6Status::decode(DR6_BD).general_detect);
    assert!(Dr6Status::decode(DR6_BUS_LOCK).bus_lock);
    assert_eq!((DR6_BD, DR6_BS, DR6_BT, DR6_BUS_LOCK), (0x2000, 0x4000, 0x8000, 0x800));
    assert_eq!(DR6_RESERVED_ONES, 0xFFFF_0FF0);
}

#[test]
fn recorded_dr6_accumulates_only_cause_bits() {
    let mut d = DebugRegs::default();
    d.record_dr6_raw(DR6_RESERVED_ONES | DR6_B0);
    assert_eq!(d.dr6, DR6_B0, "reserved-one bits are not stored");
    d.record_dr6(DR6_BS);
    assert_eq!(d.status().hits, 0b1);
    assert!(d.status().single_step);
    d.clear_dr6();
    assert!(d.status().is_empty());
}
