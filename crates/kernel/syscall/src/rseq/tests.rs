// Hosted coverage for the rseq(2) decision ladders (`syscall::rseq`).
// These run under a plain `cargo test`; the kernel-side caller
// (`sched::rseq`) is target-gated and cannot host its own tests.

use super::*;

fn reg(ptr: u64, len: u32, sig: u32) -> Registration { Registration { ptr, len, sig } }

const AREA: u64 = 0x7fff_0000;
const SIG:  u32 = 0x5309_1234;

#[test]
fn fresh_registration_accepts_legacy_size_and_alignment() {
    assert_eq!(decide(None, AREA, ORIG_RSEQ_SIZE, 0, SIG), Ok(RseqAction::Register));
}

#[test]
fn fresh_registration_rejects_null_area() {
    assert_eq!(decide(None, 0, ORIG_RSEQ_SIZE, 0, SIG), Err(Errno::Einval));
}

#[test]
fn fresh_registration_rejects_short_length() {
    assert_eq!(decide(None, AREA, ORIG_RSEQ_SIZE - 1, 0, SIG), Err(Errno::Einval));
    assert_eq!(decide(None, AREA, 0, 0, SIG), Err(Errno::Einval));
}

#[test]
fn legacy_length_requires_32_byte_alignment() {
    assert!(length_valid(AREA, ORIG_RSEQ_SIZE));
    assert!(!length_valid(AREA + 8, ORIG_RSEQ_SIZE));
    assert!(!length_valid(AREA + 16, ORIG_RSEQ_SIZE));
}

#[test]
fn extended_length_requires_alloc_align_and_end_offset() {
    // 64-byte aligned + covers offsetof(struct rseq, end).
    assert!(length_valid(AREA, RSEQ_END_OFFSET));
    assert!(length_valid(AREA, 64));
    // A non-legacy length below `offsetof(struct rseq, end)` is impossible:
    // 33 is the first size above ORIG_RSEQ_SIZE, so the gate that bites is
    // alignment. 32-aligned but not 64-aligned is fine ONLY for the legacy size.
    assert!(!length_valid(AREA + 32, RSEQ_END_OFFSET));
    assert!(length_valid(AREA + 32, ORIG_RSEQ_SIZE));
}

#[test]
fn register_rejects_unknown_flags_but_accepts_slice_ext_default_on() {
    assert_eq!(decide(None, AREA, ORIG_RSEQ_SIZE, RSEQ_FLAG_SLICE_EXT_DEFAULT_ON, SIG),
               Ok(RseqAction::Register));
    assert_eq!(decide(None, AREA, ORIG_RSEQ_SIZE, 1 << 2, SIG), Err(Errno::Einval));
    assert_eq!(decide(None, AREA, ORIG_RSEQ_SIZE, u32::MAX & !RSEQ_FLAG_UNREGISTER, SIG),
               Err(Errno::Einval));
}

#[test]
fn identical_reregistration_is_ebusy() {
    let live = Some(reg(AREA, ORIG_RSEQ_SIZE, SIG));
    assert_eq!(decide(live, AREA, ORIG_RSEQ_SIZE, 0, SIG), Err(Errno::Ebusy));
}

#[test]
fn reregistration_with_a_different_area_is_einval() {
    let live = Some(reg(AREA, ORIG_RSEQ_SIZE, SIG));
    assert_eq!(decide(live, AREA + 64, ORIG_RSEQ_SIZE, 0, SIG), Err(Errno::Einval));
    assert_eq!(decide(live, AREA, ORIG_RSEQ_SIZE + 32, 0, SIG), Err(Errno::Einval));
}

#[test]
fn reregistration_with_a_different_signature_is_eperm() {
    let live = Some(reg(AREA, ORIG_RSEQ_SIZE, SIG));
    assert_eq!(decide(live, AREA, ORIG_RSEQ_SIZE, 0, SIG ^ 1), Err(Errno::Eperm));
}

#[test]
fn unregister_requires_a_live_matching_registration() {
    let f = RSEQ_FLAG_UNREGISTER;
    assert_eq!(decide(None, AREA, ORIG_RSEQ_SIZE, f, SIG), Err(Errno::Einval));
    let live = Some(reg(AREA, ORIG_RSEQ_SIZE, SIG));
    assert_eq!(decide(live, AREA, ORIG_RSEQ_SIZE, f, SIG), Ok(RseqAction::Unregister));
    assert_eq!(decide(live, AREA + 64, ORIG_RSEQ_SIZE, f, SIG), Err(Errno::Einval));
    assert_eq!(decide(live, AREA, ORIG_RSEQ_SIZE * 2, f, SIG), Err(Errno::Einval));
    assert_eq!(decide(live, AREA, ORIG_RSEQ_SIZE, f, SIG ^ 1), Err(Errno::Eperm));
}

#[test]
fn unregister_rejects_extra_flag_bits() {
    let live = Some(reg(AREA, ORIG_RSEQ_SIZE, SIG));
    let f = RSEQ_FLAG_UNREGISTER | RSEQ_FLAG_SLICE_EXT_DEFAULT_ON;
    assert_eq!(decide(live, AREA, ORIG_RSEQ_SIZE, f, SIG), Err(Errno::Einval));
}

const TASK_SIZE: u64 = 0x0000_8000_0000_0000;

#[test]
fn ip_inside_the_critical_section_restarts_at_abort_ip() {
    let start = 0x400_000u64;
    let abort = 0x401_000u64;
    assert_eq!(cs_outcome(start,      start, 0x40, abort, TASK_SIZE, SIG, SIG), CsOutcome::Fixup(abort));
    assert_eq!(cs_outcome(start + 0x3f, start, 0x40, abort, TASK_SIZE, SIG, SIG), CsOutcome::Fixup(abort));
}

#[test]
fn ip_at_or_past_post_commit_only_clears() {
    let start = 0x400_000u64;
    let abort = 0x401_000u64;
    assert_eq!(cs_outcome(start + 0x40, start, 0x40, abort, TASK_SIZE, SIG, SIG), CsOutcome::Clear);
    // Below start_ip: Linux relies on the unsigned wrap landing outside.
    assert_eq!(cs_outcome(start - 1, start, 0x40, abort, TASK_SIZE, SIG, SIG), CsOutcome::Clear);
    // Zero-length section can never contain the IP.
    assert_eq!(cs_outcome(start, start, 0, abort, TASK_SIZE, SIG, SIG), CsOutcome::Clear);
}

#[test]
fn abort_ip_outside_user_space_is_fatal() {
    let start = 0x400_000u64;
    assert_eq!(cs_outcome(start, start, 0x40, TASK_SIZE, TASK_SIZE, SIG, SIG), CsOutcome::Fatal);
    assert_eq!(cs_outcome(start, start, 0x40, u64::MAX, TASK_SIZE, SIG, SIG), CsOutcome::Fatal);
    // Must leave room for the signature word below abort_ip.
    assert_eq!(cs_outcome(start, start, 0x40, 2, TASK_SIZE, SIG, SIG), CsOutcome::Fatal);
}

#[test]
fn signature_mismatch_is_fatal_not_a_silent_jump() {
    let start = 0x400_000u64;
    let abort = 0x401_000u64;
    assert_eq!(cs_outcome(start, start, 0x40, abort, TASK_SIZE, SIG, SIG ^ 1), CsOutcome::Fatal);
    assert_eq!(cs_outcome(start, start, 0x40, abort, TASK_SIZE, SIG, 0), CsOutcome::Fatal);
}

#[test]
fn signature_is_not_consulted_when_the_ip_is_outside() {
    let start = 0x400_000u64;
    let abort = 0x401_000u64;
    assert_eq!(cs_outcome(start + 0x100, start, 0x40, abort, TASK_SIZE, SIG, 0), CsOutcome::Clear);
}

#[test]
fn cs_addr_must_hold_a_whole_descriptor_inside_user_space() {
    assert!(cs_addr_usable(0x400_000, TASK_SIZE));
    assert!(!cs_addr_usable(0, TASK_SIZE));
    assert!(!cs_addr_usable(TASK_SIZE, TASK_SIZE));
    assert!(!cs_addr_usable(TASK_SIZE - RSEQ_CS_SIZE + 1, TASK_SIZE));
    assert!(cs_addr_usable(TASK_SIZE - RSEQ_CS_SIZE, TASK_SIZE));
    assert!(!cs_addr_usable(u64::MAX, TASK_SIZE));
}

#[test]
fn struct_offsets_match_the_uapi_layout() {
    assert_eq!(RSEQ_OFF_CPU_ID_START, 0);
    assert_eq!(RSEQ_OFF_CPU_ID, 4);
    assert_eq!(RSEQ_OFF_RSEQ_CS, 8);
    assert_eq!(RSEQ_OFF_FLAGS, 16);
    assert_eq!(RSEQ_OFF_NODE_ID, 20);
    assert_eq!(RSEQ_OFF_MM_CID, 24);
    assert_eq!(RSEQ_CS_SIZE, 32);
    assert_eq!(RSEQ_CPU_ID_UNINITIALIZED, u32::MAX);
    assert_eq!(RSEQ_CPU_ID_REGISTRATION_FAILED, u32::MAX - 1);
}
