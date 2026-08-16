// Admission-ladder and return-decode tests. Hosted; the parent module carries
// no target gate.

use super::*;
use crate::psci_uapi::{psci_version, PsciStatus};

#[test]
fn version_gate_rejects_pre_1_0_firmware() {
    assert!(!version_has_features(psci_version(0, 1)));
    assert!(!version_has_features(psci_version(0, 2)));
    assert!(version_has_features(psci_version(1, 0)));
    assert!(version_has_features(psci_version(1, 1)));
    assert!(version_has_features(psci_version(2, 0)));
}

#[test]
fn a_pre_1_0_platform_is_never_admitted_however_the_query_answers() {
    // Even a "supported" looking word is meaningless from firmware that does
    // not implement the query.
    assert_eq!(classify_support(psci_version(0, 2), 0), SuspendSupport::TooOld);
    assert!(!classify_support(psci_version(0, 2), 0).admits_mem());
}

#[test]
fn not_supported_is_the_only_absent_answer() {
    assert!(!feature_present(-1));
    assert!(feature_present(0));
    assert!(feature_present(1));
    // A firmware answering some other error still counts as implementing the
    // function; the interface reserves NOT_SUPPORTED for absence.
    assert!(feature_present(-2));
}

#[test]
fn classify_admits_only_when_version_and_feature_both_pass() {
    assert_eq!(classify_support(psci_version(1, 1), -1), SuspendSupport::Unsupported);
    assert!(!classify_support(psci_version(1, 1), -1).admits_mem());
    assert_eq!(classify_support(psci_version(1, 1), 0), SuspendSupport::Supported(0));
    assert!(classify_support(psci_version(1, 1), 0).admits_mem());
    assert_eq!(classify_support(psci_version(1, 0), 5), SuspendSupport::Supported(5));
}

#[test]
fn an_unprobed_platform_admits_nothing() {
    assert!(!SuspendSupport::Unprobed.admits_mem());
    assert!(!SuspendSupport::TooOld.admits_mem());
    assert!(!SuspendSupport::Unsupported.admits_mem());
}

#[test]
fn every_return_from_the_suspend_call_is_a_failure_including_success() {
    // The call returning at all means the machine never slept.
    assert_eq!(suspend_call_result(0),  Err(PsciStatus::Success));
    assert_eq!(suspend_call_result(-1), Err(PsciStatus::NotSupported));
    assert_eq!(suspend_call_result(-2), Err(PsciStatus::InvalidParameters));
    assert_eq!(suspend_call_result(-3), Err(PsciStatus::Denied));
    assert_eq!(suspend_call_result(-9), Err(PsciStatus::InvalidAddress));
}

#[test]
fn a_not_supported_return_is_never_decoded_as_success() {
    assert_ne!(suspend_call_result(-1), Err(PsciStatus::Success));
    assert!(suspend_call_result(-1).is_err());
}

#[test]
fn support_round_trips_through_the_cache_word() {
    for s in [SuspendSupport::Unprobed, SuspendSupport::TooOld,
              SuspendSupport::Unsupported, SuspendSupport::Supported(0),
              SuspendSupport::Supported(0xDEAD_BEEF)] {
        assert_eq!(decode_support(encode_support(s)), s);
    }
}

#[test]
fn a_zeroed_cache_word_is_unprobed_not_supported() {
    assert_eq!(decode_support(0), SuspendSupport::Unprobed);
    assert!(!decode_support(0).admits_mem());
    // An unrecognised tag must fail closed too.
    assert!(!decode_support(0x00FF_0000_0000_0000).admits_mem());
}

#[test]
fn preflight_reports_the_first_missing_piece() {
    let ok = SuspendSupport::Supported(0);
    assert_eq!(preflight(SuspendSupport::Unsupported, 1, 1, 1), Err(SuspendRefusal::Unsupported));
    assert_eq!(preflight(ok, 0, 1, 1), Err(SuspendRefusal::NoResumeEntry));
    assert_eq!(preflight(ok, 1, 0, 1), Err(SuspendRefusal::NoIdentityTable));
    assert_eq!(preflight(ok, 1, 1, 0), Err(SuspendRefusal::NoContextAddress));
    assert_eq!(preflight(ok, 0x4008_0000, 0x4010_0000, 0x4020_0000), Ok(()));
}
