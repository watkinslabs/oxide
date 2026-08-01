// DBGBCR/DBGWCR field positions and the full slot validation ladder.

use super::common::{uctrl, UEND};
use crate::hw_breakpoint::ctrl::*;

#[test]
fn ctrl_round_trips_the_abi_visible_fields() {
    let c = Ctrl { enabled: true, privilege: PRIV_EL0, kind: TYPE_LOAD_STORE, bas: BAS_LEN_8 };
    assert_eq!(decode(encode(c)), c);
}

#[test]
fn ctrl_fields_sit_at_the_architectural_positions() {
    let raw = encode(Ctrl { enabled: true, privilege: PRIV_EL0, kind: TYPE_STORE, bas: BAS_LEN_4 });
    assert_eq!(raw & CTRL_E, CTRL_E);
    assert_eq!((raw >> CTRL_PRIV_SHIFT) & CTRL_PRIV_MASK, PRIV_EL0 as u32);
    assert_eq!((raw >> CTRL_TYPE_SHIFT) & CTRL_TYPE_MASK, TYPE_STORE as u32);
    assert_eq!((raw >> CTRL_BAS_SHIFT) & CTRL_BAS_MASK, BAS_LEN_4 as u32);
}

#[test]
fn ctrl_decode_ignores_the_kernel_owned_fields() {
    // HMC, SSC, LBN, WT and the watchpoint address MASK are kernel-owned: a
    // task-supplied word carrying them decodes exactly as if it had not.
    let base = encode(Ctrl { enabled: true, privilege: PRIV_EL0, kind: TYPE_LOAD, bas: BAS_LEN_2 });
    let noisy = base | CTRL_HMC | (CTRL_SSC_MASK << CTRL_SSC_SHIFT)
        | (CTRL_LBN_MASK << CTRL_LBN_SHIFT) | CTRL_WT | (CTRL_MASK_MASK << CTRL_MASK_SHIFT);
    assert_eq!(decode(noisy), decode(base));
    assert_eq!(noisy & CTRL_USER_MASK, base);
}

// ---------------------------------------------------------------------------
// BAS length encodings
// ---------------------------------------------------------------------------

#[test]
fn bas_encodes_every_legal_length() {
    let table = [(BAS_LEN_1, 1u8), (BAS_LEN_2, 2), (BAS_LEN_3, 3), (BAS_LEN_4, 4),
                 (BAS_LEN_5, 5), (BAS_LEN_6, 6), (BAS_LEN_7, 7), (BAS_LEN_8, 8)];
    for (bas, len) in table {
        assert_eq!(bas_len_bytes(bas), Some(len), "bas {bas:#x}");
        assert_eq!(bas_for_len(len), Some(bas), "len {len}");
        assert_eq!(bas_fields(bas), Ok((len, 0)));
    }
}

#[test]
fn bas_zero_selects_no_byte() {
    assert_eq!(bas_fields(0), Err(HwBpError::ZeroLen));
}

#[test]
fn bas_rejects_non_contiguous_patterns() {
    // Gaps in the run name no length, whatever the population count.
    for bas in [0b0000_0101u8, 0b1000_0001, 0b0101_0101, 0b1001_1110] {
        assert_eq!(bas_fields(bas), Err(HwBpError::Len), "bas {bas:#010b}");
    }
}

#[test]
fn bas_reports_the_shift_of_a_high_run() {
    // A run starting four bytes in watches four bytes at offset four.
    assert_eq!(bas_fields(0xf0), Ok((4, 4)));
    assert_eq!(bas_fields(0x80), Ok((1, 7)));
    assert_eq!(bas_fields(0x0c), Ok((2, 2)));
}

// ---------------------------------------------------------------------------
// Validation ladder — types
// ---------------------------------------------------------------------------

#[test]
fn breakpoint_accepts_only_the_execute_type() {
    assert!(parse(RegFile::Break, uctrl(TYPE_EXECUTE, BAS_LEN_4), 0x1000, UEND).is_ok());
    for kind in [TYPE_LOAD, TYPE_STORE, TYPE_LOAD_STORE] {
        assert_eq!(parse(RegFile::Break, uctrl(kind, BAS_LEN_4), 0x1000, UEND),
                   Err(HwBpError::Type), "kind {kind}");
    }
}

#[test]
fn watchpoint_rejects_the_execute_type() {
    assert_eq!(parse(RegFile::Watch, uctrl(TYPE_EXECUTE, BAS_LEN_4), 0x1000, UEND),
               Err(HwBpError::Type));
    for kind in [TYPE_LOAD, TYPE_STORE, TYPE_LOAD_STORE] {
        assert!(parse(RegFile::Watch, uctrl(kind, BAS_LEN_4), 0x1000, UEND).is_ok(),
                "kind {kind}");
    }
}

// ---------------------------------------------------------------------------
// Validation ladder — lengths, offsets, alignment
// ---------------------------------------------------------------------------

#[test]
fn watchpoint_accepts_every_length_at_an_aligned_address() {
    for len in 1u8..=8 {
        let bas = bas_for_len(len).unwrap();
        let v = parse(RegFile::Watch, uctrl(TYPE_LOAD_STORE, bas), 0x2000, UEND).unwrap();
        assert_eq!(v.addr, 0x2000);
        assert_eq!(v.ctrl.bas, bas, "len {len}");
        assert_eq!(v.ctrl.privilege, PRIV_EL0);
        assert!(v.ctrl.enabled);
    }
}

#[test]
fn watchpoint_rounds_the_address_down_and_shifts_bas_up() {
    // One byte at 0x2003 becomes the doubleword at 0x2000 with byte 3 selected.
    let v = parse(RegFile::Watch, uctrl(TYPE_STORE, BAS_LEN_1), 0x2003, UEND).unwrap();
    assert_eq!(v.addr, 0x2000);
    assert_eq!(v.ctrl.bas, BAS_LEN_1 << 3);
}

#[test]
fn watchpoint_bas_offset_advances_the_address_before_alignment() {
    // A BAS already shifted by two names the two bytes starting two into the
    // span, so the request resolves to the same slot as an unshifted request
    // against an address two higher.
    let shifted = parse(RegFile::Watch, uctrl(TYPE_LOAD, BAS_LEN_2 << 2), 0x2000, UEND).unwrap();
    let plain = parse(RegFile::Watch, uctrl(TYPE_LOAD, BAS_LEN_2), 0x2002, UEND).unwrap();
    assert_eq!(shifted, plain);
    assert_eq!(shifted.ctrl.bas, BAS_LEN_2 << 2);
}

#[test]
fn watchpoint_refuses_a_span_that_would_overflow_the_bas_field() {
    // Eight bytes at a misaligned address would need nine byte-selects.
    assert_eq!(parse(RegFile::Watch, uctrl(TYPE_LOAD, BAS_LEN_8), 0x2001, UEND),
               Err(HwBpError::LenOverflow));
    // Four bytes five into the doubleword likewise runs off the end.
    assert_eq!(parse(RegFile::Watch, uctrl(TYPE_LOAD, BAS_LEN_4), 0x2005, UEND),
               Err(HwBpError::LenOverflow));
    // Four bytes four into the doubleword exactly fills it.
    assert!(parse(RegFile::Watch, uctrl(TYPE_LOAD, BAS_LEN_4), 0x2004, UEND).is_ok());
}

#[test]
fn breakpoint_is_resolved_to_one_a64_instruction_whatever_length_is_asked() {
    for len in 1u8..=8 {
        let bas = bas_for_len(len).unwrap();
        let v = parse(RegFile::Break, uctrl(TYPE_EXECUTE, bas), 0x4000, UEND).unwrap();
        assert_eq!(v.addr, 0x4000, "len {len}");
        assert_eq!(v.ctrl.bas, BAS_LEN_4, "len {len}");
    }
}

#[test]
fn breakpoint_aligns_to_the_instruction_not_the_doubleword() {
    // 0x4009 rounds to 0x4008 (instruction granule), not 0x4008-aligned by 8.
    let v = parse(RegFile::Break, uctrl(TYPE_EXECUTE, BAS_LEN_4), 0x4009, UEND).unwrap();
    assert_eq!(v.addr, 0x4008);
    assert_eq!(v.ctrl.bas, BAS_LEN_4 << 1);
}

// ---------------------------------------------------------------------------
// Validation ladder — privilege and address range
// ---------------------------------------------------------------------------

#[test]
fn slot_privilege_is_always_el0_and_never_taken_from_the_caller() {
    // A caller asking for EL1 privilege gets EL0: the field is derived from
    // the address, never honoured from the request.
    let raw = encode(Ctrl { enabled: true, privilege: PRIV_EL1, kind: TYPE_EXECUTE, bas: BAS_LEN_4 });
    let v = parse(RegFile::Break, raw, 0x1000, UEND).unwrap();
    assert_eq!(v.ctrl.privilege, PRIV_EL0);
}

#[test]
fn kernel_address_is_refused_for_a_per_task_slot() {
    for file in [RegFile::Break, RegFile::Watch] {
        let kind = if file == RegFile::Break { TYPE_EXECUTE } else { TYPE_LOAD };
        assert_eq!(parse(file, uctrl(kind, BAS_LEN_4), UEND, UEND),
                   Err(HwBpError::KernelAddress), "{file:?}");
        assert_eq!(parse(file, uctrl(kind, BAS_LEN_4), u64::MAX & !0x7, UEND),
                   Err(HwBpError::KernelAddress), "{file:?}");
    }
}

#[test]
fn span_starting_inside_the_user_range_stays_el0() {
    // The last user doubleword resolves even though the watched bytes reach
    // the boundary: privilege follows the first watched byte.
    let v = parse(RegFile::Watch, uctrl(TYPE_LOAD, BAS_LEN_8), UEND - 8, UEND).unwrap();
    assert_eq!(v.ctrl.privilege, PRIV_EL0);
    assert_eq!(v.addr, UEND - 8);
}

#[test]
fn length_overflow_is_reported_before_the_address_range() {
    // Ordering matters: a debugger fixing the length must not first be told
    // the address is wrong.
    assert_eq!(parse(RegFile::Watch, uctrl(TYPE_LOAD, BAS_LEN_8), u64::MAX - 6, UEND),
               Err(HwBpError::LenOverflow));
}

#[test]
fn address_arithmetic_overflow_is_its_own_error() {
    assert_eq!(parse(RegFile::Watch, uctrl(TYPE_LOAD, BAS_LEN_1 << 7), u64::MAX, UEND),
               Err(HwBpError::Address));
}

#[test]
fn a_disabled_slot_is_stored_without_validation() {
    // A debugger legitimately writes an address before the control word that
    // gives it a length; a disabled slot must not be refused for it.
    let raw = encode(Ctrl { enabled: false, privilege: 0, kind: TYPE_EXECUTE, bas: 0 });
    let v = parse(RegFile::Break, raw, 0xdead_beef, UEND).unwrap();
    assert!(!v.ctrl.enabled);
    assert_eq!(v.addr, 0xdead_beef);
}

