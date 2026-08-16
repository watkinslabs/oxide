// `32a§2` invariant 7 as a table: a state that loses CPU context is admitted
// only when BOTH a resume vector and a saved processor state exist. Admitting
// `mem` without a resume vector turns a suspend into a power-off, so every
// missing-fact combination is enumerated here rather than sampled.

use super::*;

fn all() -> PlatformFacts {
    PlatformFacts { s1_action: true, s3_action: true, resume_vector: true, state_save: true }
}

#[test]
fn standby_needs_only_an_s1_action() {
    let mut f = all();
    f.resume_vector = false;
    f.s3_action = false;
    assert!(admits(f, SuspendState::Standby), "S1 retains CPU context and needs no resume vector");
    f.s1_action = false;
    assert!(!admits(f, SuspendState::Standby));
}

#[test]
fn mem_needs_the_action_the_vector_and_the_save() {
    assert!(admits(all(), SuspendState::Mem));
    for drop in 0..3 {
        let mut f = all();
        match drop { 0 => f.s3_action = false, 1 => f.resume_vector = false, _ => f.state_save = false }
        assert!(!admits(f, SuspendState::Mem), "mem admitted with fact {drop} missing");
    }
}

#[test]
fn mem_is_never_admitted_on_a_machine_with_no_resume_vector() {
    // The single most expensive way to get this wrong: `_S3` exists, the
    // registers resolve, and the stub could not be placed. Entering then
    // powers the machine off with everything unsaved.
    let f = PlatformFacts { s1_action: true, s3_action: true, resume_vector: false, state_save: true };
    assert!(!admits(f, SuspendState::Mem));
    assert!(admits(f, SuspendState::Standby));
}

#[test]
fn nothing_is_admitted_on_a_machine_that_published_no_sx() {
    let f = PlatformFacts::default();
    for state in [SuspendState::On, SuspendState::ToIdle, SuspendState::Standby, SuspendState::Mem] {
        assert!(!admits(f, state), "{state:?} admitted with no firmware support");
    }
}

#[test]
fn suspend_to_idle_is_never_answered_by_the_platform_table() {
    // `freeze` needs no platform support and routes to the s2idle table;
    // answering it here would advertise a path this file does not implement.
    assert!(!admits(all(), SuspendState::ToIdle));
    assert!(!admits(all(), SuspendState::On));
}
