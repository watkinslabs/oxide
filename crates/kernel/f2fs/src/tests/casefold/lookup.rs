// Which passes a lookup makes. A directory that outlived an encoding change
// holds entries hashed under the old rules, so a hash-directed miss is not
// always an absence — but rescanning costs the whole directory, so who decides
// is a mount choice the volume can only veto in one direction.

use crate::casefold::{
    fallback_to_linear, plan, plan_for, LookupMode, Pass, Plan, DEFAULT_LOOKUP_MODE,
};

use super::fixture::{lenient, no_fallback};

#[test]
fn the_mount_option_parses_to_the_three_modes_and_back() {
    assert_eq!(LookupMode::parse(b"perf"), Some(LookupMode::Perf));
    assert_eq!(LookupMode::parse(b"compat"), Some(LookupMode::Compat));
    assert_eq!(LookupMode::parse(b"auto"), Some(LookupMode::Auto));
    assert_eq!(LookupMode::parse(b"PERF"), None);
    assert_eq!(LookupMode::parse(b"linear"), None);
    assert_eq!(LookupMode::parse(b""), None);
    assert_eq!(LookupMode::Perf.name(), "perf");
    assert_eq!(LookupMode::Compat.name(), "compat");
    assert_eq!(LookupMode::Auto.name(), "auto");
}

#[test]
fn a_mount_that_asks_for_nothing_trusts_the_hash() {
    assert_eq!(DEFAULT_LOOKUP_MODE, LookupMode::Perf);
    assert!(!fallback_to_linear(DEFAULT_LOOKUP_MODE, false));
    assert!(!fallback_to_linear(DEFAULT_LOOKUP_MODE, true));
}

#[test]
fn each_mode_decides_the_rescan() {
    // Trust the hash, whatever the volume says.
    assert!(!fallback_to_linear(LookupMode::Perf, false));
    assert!(!fallback_to_linear(LookupMode::Perf, true));
    // Always rescan — the volume's assertion cannot switch this off.
    assert!(fallback_to_linear(LookupMode::Compat, false));
    assert!(fallback_to_linear(LookupMode::Compat, true));
    // Rescan unless the volume asserts no entry predates the encoding.
    assert!(fallback_to_linear(LookupMode::Auto, false));
    assert!(!fallback_to_linear(LookupMode::Auto, true));
}

#[test]
fn a_case_folding_directory_gets_the_second_pass_when_the_mode_says_so() {
    assert_eq!(plan(true, LookupMode::Perf, false), Plan::HashOnly);
    assert_eq!(plan(true, LookupMode::Compat, false), Plan::HashThenLinear);
    assert_eq!(plan(true, LookupMode::Compat, true), Plan::HashThenLinear);
    assert_eq!(plan(true, LookupMode::Auto, false), Plan::HashThenLinear);
    assert_eq!(plan(true, LookupMode::Auto, true), Plan::HashOnly);
}

#[test]
fn a_directory_that_does_not_fold_never_rescans() {
    // Its names have one hash each and no history to be wrong about, so the
    // second pass could only cost the whole directory to find nothing.
    for mode in [LookupMode::Perf, LookupMode::Compat, LookupMode::Auto] {
        assert_eq!(plan(false, mode, false), Plan::HashOnly);
        assert_eq!(plan(false, mode, true), Plan::HashOnly);
    }
}

#[test]
fn the_plan_reads_the_volumes_assertion_off_its_encoding() {
    assert_eq!(plan_for(true, LookupMode::Auto, &lenient()), Plan::HashThenLinear);
    assert_eq!(plan_for(true, LookupMode::Auto, &no_fallback()), Plan::HashOnly);
    assert_eq!(plan_for(true, LookupMode::Compat, &no_fallback()), Plan::HashThenLinear);
    assert_eq!(plan_for(true, LookupMode::Perf, &lenient()), Plan::HashOnly);
    assert_eq!(plan_for(false, LookupMode::Compat, &lenient()), Plan::HashOnly);
}

#[test]
fn the_hash_pass_always_runs_first_and_the_linear_pass_only_after_it() {
    // There is no linear-only lookup: for every entry written under the
    // current encoding the hash is correct and reads two blocks per level.
    assert_eq!(Plan::HashOnly.passes(), &[Pass::Hash]);
    assert_eq!(Plan::HashThenLinear.passes(), &[Pass::Hash, Pass::Linear]);
    assert_eq!(Plan::HashOnly.passes().len(), 1);
    assert_eq!(Plan::HashThenLinear.passes().len(), 2);
    assert_eq!(Plan::HashThenLinear.passes()[0], Pass::Hash);
}
