// Response-code decode. The failure mode these guard against is a non-zero
// code read as success, either directly or by decoding the wrong format and
// finding no match.

use crate::rc::{Fmt1Subject, Rc};
use crate::uapi::{
    RESMGR_TPM_RC_LAYER, TPM2_RC_COMMAND_CODE, TPM2_RC_FAILURE, TPM2_RC_FMT1, TPM2_RC_HANDLE,
    TPM2_RC_HASH, TPM2_RC_INITIALIZE, TPM2_RC_INTEGRITY, TPM2_RC_RETRY, TPM2_RC_SESSION_MEMORY,
    TPM2_RC_SUCCESS, TPM2_RC_TESTING, TPM2_RC_VER1, TPM2_RC_WARN,
};

#[test]
fn only_zero_is_success() {
    assert!(Rc::new(TPM2_RC_SUCCESS).is_success());
    for raw in [1u32, TPM2_RC_HASH, TPM2_RC_HANDLE, TPM2_RC_INITIALIZE, TPM2_RC_FAILURE,
                TPM2_RC_TESTING, TPM2_RC_RETRY, TPM2_RC_COMMAND_CODE, 0x18B, 0x2CB, 0x98B] {
        assert!(!Rc::new(raw).is_success(), "0x{raw:X} must not read as success");
    }
}

#[test]
fn format_selector_picks_the_layout() {
    assert!(Rc::new(TPM2_RC_HASH).is_fmt1());
    assert!(Rc::new(TPM2_RC_HANDLE).is_fmt1());
    assert!(Rc::new(TPM2_RC_INTEGRITY).is_fmt1());
    assert!(!Rc::new(TPM2_RC_INITIALIZE).is_fmt1());
    assert!(!Rc::new(TPM2_RC_TESTING).is_fmt1());
}

#[test]
fn warnings_are_not_errors_and_not_successes() {
    for raw in [TPM2_RC_TESTING, TPM2_RC_RETRY, TPM2_RC_SESSION_MEMORY] {
        let rc = Rc::new(raw);
        assert!(rc.is_warning(), "0x{raw:X} is a warning");
        assert!(!rc.is_error());
        assert!(!rc.is_success());
        assert_eq!(rc.base(), Some(TPM2_RC_WARN));
    }
    for raw in [TPM2_RC_INITIALIZE, TPM2_RC_FAILURE, TPM2_RC_COMMAND_CODE] {
        let rc = Rc::new(raw);
        assert!(!rc.is_warning(), "0x{raw:X} is an error, not a warning");
        assert!(rc.is_error());
        assert_eq!(rc.base(), Some(TPM2_RC_VER1));
    }
}

#[test]
fn format_one_value_masks_off_the_subject_number() {
    // The same error against handle 1, parameter 2 and session 1 all decode
    // to the same named code.
    let handle1 = Rc::new(TPM2_RC_HANDLE | (1 << 8));
    let param2 = Rc::new(TPM2_RC_HANDLE | 0x40 | (2 << 8));
    let session1 = Rc::new(TPM2_RC_HANDLE | (0x9 << 8));
    for rc in [handle1, param2, session1] {
        assert_eq!(rc.value(), TPM2_RC_HANDLE, "0x{:X} must reduce to the named code", rc.raw());
        assert!(rc.is_error());
        assert_eq!(rc.base(), Some(TPM2_RC_FMT1));
    }
    assert_eq!(handle1.subject(), Fmt1Subject::Handle(1));
    assert_eq!(param2.subject(), Fmt1Subject::Parameter(2));
    assert_eq!(session1.subject(), Fmt1Subject::Session(1));
    assert_eq!(Rc::new(TPM2_RC_HASH).subject(), Fmt1Subject::None);
    assert_eq!(Rc::new(TPM2_RC_TESTING).subject(), Fmt1Subject::None);
}

#[test]
fn format_zero_codes_keep_their_whole_number() {
    assert_eq!(Rc::new(TPM2_RC_TESTING).value(), TPM2_RC_TESTING);
    assert_eq!(Rc::new(TPM2_RC_INITIALIZE).value(), TPM2_RC_INITIALIZE);
    assert_eq!(Rc::new(TPM2_RC_TESTING).error_number(), 0x0A);
    assert_eq!(Rc::new(TPM2_RC_RETRY).error_number(), 0x22);
    assert_eq!(Rc::new(TPM2_RC_HASH).error_number(), 0x03);
    assert_eq!(Rc::new(TPM2_RC_INTEGRITY).error_number(), 0x1F);
}

#[test]
fn a_software_layer_does_not_hide_the_code() {
    let rc = Rc::new(TPM2_RC_COMMAND_CODE | RESMGR_TPM_RC_LAYER);
    assert_eq!(rc.layer(), 11);
    assert_eq!(rc.code(), TPM2_RC_COMMAND_CODE);
    assert!(!rc.is_success());
    assert!(rc.is_error());
    assert_eq!(Rc::new(TPM2_RC_COMMAND_CODE).layer(), 0);
}
