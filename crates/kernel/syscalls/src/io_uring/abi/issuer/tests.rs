use super::*;

const A: u32 = 11;
const B: u32 = 22;

#[test]
fn a_single_issuer_ring_is_claimed_by_its_creator_at_setup() {
    assert!(claims_at_setup(IORING_SETUP_SINGLE_ISSUER));
    // Not at setup for a disabled ring: the creator is not the submitter.
    assert!(!claims_at_setup(IORING_SETUP_SINGLE_ISSUER | IORING_SETUP_R_DISABLED));
    // And never for a ring that did not ask for the guarantee.
    assert!(!claims_at_setup(0));
    assert!(!claims_at_setup(IORING_SETUP_R_DISABLED));
}

#[test]
fn a_disabled_single_issuer_ring_is_claimed_by_whoever_enables_it() {
    assert!(claims_at_enable(IORING_SETUP_SINGLE_ISSUER | IORING_SETUP_R_DISABLED));
    assert!(claims_at_enable(IORING_SETUP_SINGLE_ISSUER));
    assert!(!claims_at_enable(IORING_SETUP_R_DISABLED));
    assert!(!claims_at_enable(0));
}

/// The defect this module exists to fix: a ring created by A and first entered
/// by B used to be admitted, because the claim happened at the first enter.
/// With the claim at setup, B is EEXIST — which is the whole content of the
/// flag.
#[test]
fn a_second_task_entering_a_claimed_ring_is_eexist() {
    let f = IORING_SETUP_SINGLE_ISSUER;
    assert_eq!(admit_submit(f, A, A), Ok(()));
    assert_eq!(admit_submit(f, A, B), Err(Errno::Eexist));
}

#[test]
fn a_ring_without_the_flag_admits_every_task() {
    assert_eq!(admit_submit(0, A, B), Ok(()));
    assert_eq!(admit_submit(IORING_SETUP_R_DISABLED, UNCLAIMED, B), Ok(()));
}

/// An `R_DISABLED` single-issuer ring has no submitter until it is enabled, so
/// nobody may submit to it — including the task that created it.
#[test]
fn an_unclaimed_single_issuer_ring_admits_nobody() {
    let f = IORING_SETUP_SINGLE_ISSUER | IORING_SETUP_R_DISABLED;
    assert_eq!(admit_submit(f, UNCLAIMED, A), Err(Errno::Eexist));
    assert_eq!(admit_submit(f, UNCLAIMED, B), Err(Errno::Eexist));
}

/// Registration keys off the recorded submitter, not off the flag: that is
/// what lets a task register buffers and restrictions on a disabled ring it is
/// about to hand over.
#[test]
fn registration_is_open_until_a_submitter_is_recorded() {
    assert_eq!(admit_register(UNCLAIMED, A), Ok(()));
    assert_eq!(admit_register(UNCLAIMED, B), Ok(()));
    assert_eq!(admit_register(A, A), Ok(()));
    assert_eq!(admit_register(A, B), Err(Errno::Eexist));
}
