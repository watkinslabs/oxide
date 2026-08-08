//! Iterator program admission contract.
//!
//! An iterator program addresses two context slots — the iteration meta
//! record and the object of the current step — and answers one of two
//! things per step. Every accepted shape below is paired with the nearest
//! shape that must be refused, so a verifier that admitted everything
//! would fail this file rather than pass it.

use super::*;

use crate::bpf::{ITER_SLOT_BYTES, iter_context_bytes};

const LDX_W: u8 = 0x61;
const LDX_DW: u8 = 0x79;
const STX_DW: u8 = 0x7b;
const MOV_IMM: u8 = 0xb7;
const EXIT: u8 = 0x95;

/// Context slot holding the iteration meta record.
const META: i16 = 0;
/// Context slot holding the object of the current step.
const OBJECT: i16 = ITER_SLOT_BYTES as i16;
/// First offset past the addressable context.
const PAST_END: i16 = 2 * ITER_SLOT_BYTES as i16;

fn verify_iter(insns: &[u8]) -> Result<bool, VerifyError> {
    verify_program(
        crate::bpf::uapi::prog_type::TRACING,
        crate::bpf::uapi::attach_type::TRACE_ITER,
        insns,
        &[],
    )
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

// -------------------------------------------------------------- return range

#[test] fn showing_the_object_and_asking_for_a_repeat_are_both_admitted() {
    assert_eq!(verify_iter(&exits_with(0)), Ok(false));
    assert_eq!(verify_iter(&exits_with(1)), Ok(false));
}

#[test] fn any_other_answer_is_refused() {
    // Reject control for the two accepted answers: a step has exactly two
    // outcomes, so a program that could exit with a third is refused at
    // load rather than producing an unclassifiable step at run time.
    for value in [-1, 2, 4095, i32::MIN] {
        assert!(verify_iter(&exits_with(value)).is_err(), "exit {value} was admitted");
    }
}

#[test] fn an_unbounded_exit_value_is_refused() {
    // The object slot's value is unknown to the verifier, so exiting with
    // it cannot be proved inside the step's two-valued range.
    let p = cat(&[raw(LDX_DW, 0, 1, OBJECT, 0), raw(EXIT, 0, 0, 0, 0)]);
    assert!(verify_iter(&p).is_err());
}

#[test] fn exiting_without_setting_the_answer_is_refused() {
    assert_eq!(verify_iter(&cat(&[raw(EXIT, 0, 0, 0, 0)])),
        Err(VerifyError::UninitializedReg));
}

// ------------------------------------------------------------ context access

#[test] fn both_slots_are_readable_whole() {
    for off in [META, OBJECT] {
        assert_eq!(verify_iter(&reads_context(LDX_DW, off)), Ok(false), "slot {off}");
    }
}

#[test] fn a_partial_slot_read_is_refused() {
    // Reject control for the reads above: a slot holds one register-wide
    // value, so a word-wide read of half of it is not a field access this
    // context admits.
    for off in [META, OBJECT] {
        assert_eq!(verify_iter(&reads_context(LDX_W, off)),
            Err(VerifyError::UnsafeContextAccess), "slot {off}");
    }
}

#[test] fn an_unaligned_slot_read_is_refused() {
    assert_eq!(verify_iter(&reads_context(LDX_DW, 4)),
        Err(VerifyError::UnsafeContextAccess));
}

#[test] fn reading_past_the_last_slot_is_refused() {
    for off in [PAST_END, PAST_END + 8, 1024] {
        assert_eq!(verify_iter(&reads_context(LDX_DW, off)),
            Err(VerifyError::UnsafeContextAccess), "offset {off}");
    }
}

#[test] fn the_context_is_read_only() {
    let p = cat(&[
        raw(MOV_IMM, 2, 0, 0, 0),
        raw(STX_DW, 1, 2, OBJECT, 0),
        raw(MOV_IMM, 0, 0, 0, 0),
        raw(EXIT, 0, 0, 0, 0),
    ]);
    assert_eq!(verify_iter(&p), Err(VerifyError::UnsafeContextAccess));
}

#[test] fn the_addressable_context_is_exactly_the_two_slots() {
    assert_eq!(iter_context_bytes(), 2 * ITER_SLOT_BYTES);
    assert_eq!(PAST_END as usize, iter_context_bytes());
}

/// Following a slot's value is refused: the slot holds a typed kernel
/// pointer this verifier proves no field access through, so a program may
/// observe it and may never dereference it.
#[test] fn following_the_object_pointer_is_refused() {
    let p = cat(&[
        raw(LDX_DW, 2, 1, OBJECT, 0),
        raw(LDX_DW, 3, 2, 0, 0),
        raw(MOV_IMM, 0, 0, 0, 0),
        raw(EXIT, 0, 0, 0, 0),
    ]);
    assert!(verify_iter(&p).is_err());
}
