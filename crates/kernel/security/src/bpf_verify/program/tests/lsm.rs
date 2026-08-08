//! LSM hook admission contract.
//!
//! The hook, not the program type, fixes what a program may address and
//! what it may exit with. Every accepted shape below is paired with the
//! nearest shape that must be refused, so a verifier that admitted
//! everything would fail this file rather than pass it.

use super::*;

use crate::bpf_lsm::{Hook, SLOT_BYTES};

const LDX_W: u8 = 0x61;
const LDX_DW: u8 = 0x79;
const STX_DW: u8 = 0x7b;
const MOV_IMM: u8 = 0xb7;
const MOV_REG: u8 = 0xbf;
const EXIT: u8 = 0x95;

/// Largest magnitude an int-returning hook admits as a refusal.
const MAX_ERRNO: i32 = 4095;
/// Context slot holding the hook's first argument.
const ARG0: i16 = 0;
/// Context slot holding the pending return value, for a one-argument hook.
const RETVAL: i16 = SLOT_BYTES as i16;
/// First offset past the addressable context of a one-argument hook.
const PAST_END: i16 = 2 * SLOT_BYTES as i16;

fn verify_lsm(insns: &[u8]) -> Result<(), VerifyError> {
    verify_lsm_program(Hook::FileOpen, insns, &[])
}

/// `r0 = value; exit`
fn exits_with(value: i32) -> alloc::vec::Vec<u8> {
    cat(&[raw(MOV_IMM, 0, 0, 0, value), raw(EXIT, 0, 0, 0, 0)])
}

/// `r2 = *(size *)(r1 + off); r0 = 0; exit`
fn reads_context(opcode: u8, off: i16) -> alloc::vec::Vec<u8> {
    cat(&[
        raw(opcode, 2, 1, off, 0),
        raw(MOV_IMM, 0, 0, 0, 0),
        raw(EXIT, 0, 0, 0, 0),
    ])
}

// ------------------------------------------------------------- return range

#[test] fn allowing_is_admitted() {
    assert_eq!(verify_lsm(&exits_with(0)), Ok(()));
}

#[test] fn every_negative_errno_is_admitted() {
    for value in [-1, -13, -MAX_ERRNO] {
        assert_eq!(verify_lsm(&exits_with(value)), Ok(()), "exit {value}");
    }
}

#[test] fn a_positive_exit_value_is_refused() {
    // Reject control for the accept cases above: an int-returning hook has
    // no positive answer, so a program that could return one is refused at
    // load rather than producing a nonsense verdict at the hook.
    for value in [1, 2, MAX_ERRNO] {
        assert!(verify_lsm(&exits_with(value)).is_err(), "exit {value} was admitted");
    }
}

#[test] fn an_exit_value_below_the_errno_floor_is_refused() {
    assert!(verify_lsm(&exits_with(-(MAX_ERRNO + 1))).is_err());
}

#[test] fn an_unbounded_exit_value_is_refused() {
    // The argument slot's value is unknown to the verifier, so exiting
    // with it cannot be proved inside the hook's range.
    let p = cat(&[raw(LDX_DW, 0, 1, ARG0, 0), raw(EXIT, 0, 0, 0, 0)]);
    assert!(verify_lsm(&p).is_err());
}

#[test] fn exiting_without_setting_the_answer_is_refused() {
    assert_eq!(verify_lsm(&cat(&[raw(EXIT, 0, 0, 0, 0)])),
        Err(VerifyError::UninitializedReg));
}

#[test] fn exiting_with_a_pointer_is_refused() {
    let p = cat(&[raw(MOV_REG, 0, 10, 0, 0), raw(EXIT, 0, 0, 0, 0)]);
    assert!(verify_lsm(&p).is_err());
}

// ----------------------------------------------------------- context access

#[test] fn each_declared_slot_is_readable_whole() {
    for off in [ARG0, RETVAL] {
        assert_eq!(verify_lsm(&reads_context(LDX_DW, off)), Ok(()), "offset {off}");
    }
}

#[test] fn a_slot_past_the_last_one_is_refused() {
    // Reject control for the accept case above: a one-argument hook
    // publishes exactly the argument and the pending return value.
    for off in [PAST_END, PAST_END + SLOT_BYTES as i16] {
        assert_eq!(verify_lsm(&reads_context(LDX_DW, off)),
            Err(VerifyError::UnsafeContextAccess), "offset {off}");
    }
}

#[test] fn an_offset_that_is_not_a_whole_slot_is_refused() {
    for off in [1, 4, 7, 9] {
        assert_eq!(verify_lsm(&reads_context(LDX_DW, off)),
            Err(VerifyError::UnsafeContextAccess), "offset {off}");
    }
}

#[test] fn a_narrow_read_of_a_slot_is_refused() {
    assert_eq!(verify_lsm(&reads_context(LDX_W, ARG0)),
        Err(VerifyError::UnsafeContextAccess));
}

#[test] fn writing_the_context_is_refused() {
    let p = cat(&[
        raw(MOV_IMM, 2, 0, 0, 0),
        raw(STX_DW, 1, 2, ARG0, 0),
        raw(MOV_IMM, 0, 0, 0, 0),
        raw(EXIT, 0, 0, 0, 0),
    ]);
    assert_eq!(verify_lsm(&p), Err(VerifyError::UnsafeContextAccess));
    let p = cat(&[
        raw(MOV_IMM, 2, 0, 0, 0),
        raw(STX_DW, 1, 2, RETVAL, 0),
        raw(MOV_IMM, 0, 0, 0, 0),
        raw(EXIT, 0, 0, 0, 0),
    ]);
    assert_eq!(verify_lsm(&p), Err(VerifyError::UnsafeContextAccess));
}

#[test] fn following_the_argument_pointer_is_refused() {
    // The argument slot holds a typed kernel pointer this verifier proves
    // no field access through, so the loaded value is not a pointer and a
    // load through it has no admitted shape.
    let p = cat(&[
        raw(LDX_DW, 2, 1, ARG0, 0),
        raw(LDX_DW, 3, 2, 0, 0),
        raw(MOV_IMM, 0, 0, 0, 0),
        raw(EXIT, 0, 0, 0, 0),
    ]);
    assert!(verify_lsm(&p).is_err());
}

#[test] fn context_addressing_stops_at_the_published_size() {
    // Pointer arithmetic onto the context cannot reach past what the hook
    // publishes, regardless of the field rules.
    const ADD_IMM: u8 = 0x07;
    let p = cat(&[
        raw(ADD_IMM, 1, 0, 0, PAST_END as i32),
        raw(LDX_DW, 2, 1, 0, 0),
        raw(MOV_IMM, 0, 0, 0, 0),
        raw(EXIT, 0, 0, 0, 0),
    ]);
    assert_eq!(verify_lsm(&p), Err(VerifyError::UnsafeContextAccess));
}
