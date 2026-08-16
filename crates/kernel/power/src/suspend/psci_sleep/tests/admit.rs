// State-admission and error-mapping tests. Hosted: `admit.rs` carries no
// target gate, so these compile and run on an x86 `cargo test`.

use super::*;

const SUPPORTED: SuspendSupport = SuspendSupport::Supported(0);

#[test]
fn mem_is_admitted_only_when_the_feature_probe_says_so() {
    assert!(valid(SUPPORTED, SuspendState::Mem));
    assert!(!valid(SuspendSupport::Unsupported, SuspendState::Mem));
    assert!(!valid(SuspendSupport::TooOld, SuspendState::Mem));
    assert!(!valid(SuspendSupport::Unprobed, SuspendState::Mem));
}

#[test]
fn standby_is_never_admitted_even_on_a_supporting_platform() {
    // PSCI has no shallow system state; `32a§9`.
    assert!(!valid(SUPPORTED, SuspendState::Standby));
    assert!(!valid(SuspendSupport::Unsupported, SuspendState::Standby));
}

#[test]
fn the_deep_table_claims_neither_freeze_nor_the_awake_state() {
    assert!(!valid(SUPPORTED, SuspendState::ToIdle));
    assert!(!valid(SUPPORTED, SuspendState::On));
}

#[test]
fn firmware_refusals_keep_their_distinctions() {
    assert_eq!(firmware_error(PsciStatus::NotSupported),      Error::Opnotsupp);
    assert_eq!(firmware_error(PsciStatus::InvalidParameters), Error::Inval);
    assert_eq!(firmware_error(PsciStatus::InvalidAddress),    Error::Inval);
    assert_eq!(firmware_error(PsciStatus::Denied),            Error::Perm);
    assert_eq!(firmware_error(PsciStatus::InternalFailure),   Error::Io);
    assert_eq!(firmware_error(PsciStatus::Other),             Error::Io);
}

#[test]
fn a_success_word_coming_back_out_of_the_call_is_a_failure() {
    // The call only returns when the machine did not sleep.
    assert_eq!(firmware_error(PsciStatus::Success), Error::Io);
}

#[test]
fn only_the_unsupported_refusal_reports_no_such_facility() {
    assert_eq!(refusal_error(SuspendRefusal::Unsupported),      Error::Opnotsupp);
    assert_eq!(refusal_error(SuspendRefusal::NoResumeEntry),    Error::Io);
    assert_eq!(refusal_error(SuspendRefusal::NoIdentityTable),  Error::Io);
    assert_eq!(refusal_error(SuspendRefusal::NoContextAddress), Error::Io);
}
