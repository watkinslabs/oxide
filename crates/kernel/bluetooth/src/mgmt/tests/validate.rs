//! Command admission. The ordering assertions are the point: each one pairs a
//! request that fails two checks and pins which of the two answers.

use super::*;
use crate::uapi::mgmt::op::*;

fn req(opcode: u16, index: u16, param_len: usize, trusted: bool,
       controller: Option<ControllerState>) -> Request {
    Request { opcode, index, param_len, trusted, controller }
}

/// A trusted request naming no controller, for the stack-wide reads.
fn stackwide(opcode: u16, param_len: usize) -> Request {
    req(opcode, MGMT_INDEX_NONE, param_len, true, None)
}

/// A trusted request against a ready controller at index zero.
fn ready(opcode: u16, param_len: usize) -> Request {
    req(opcode, 0, param_len, true, Some(ControllerState::Ready))
}

fn status_of(v: Verdict) -> Option<u8> {
    match v { Verdict::Status(s) => Some(s), Verdict::Dispatch(_) => None }
}

#[test]
fn short_buffer_is_dropped_not_answered() {
    for n in 0..MGMT_HDR_SIZE {
        let buf = alloc::vec![0u8; n];
        assert_eq!(check_frame(&buf), Err(FrameError::Short), "len {n}");
    }
}

#[test]
fn declared_length_must_match_payload() {
    // Header says one byte follows; none does.
    let buf = [0x01, 0x00, 0xff, 0xff, 0x01, 0x00];
    assert_eq!(check_frame(&buf), Err(FrameError::LengthMismatch));
    // Header says none follows; one does.
    let buf = [0x01, 0x00, 0xff, 0xff, 0x00, 0x00, 0xaa];
    assert_eq!(check_frame(&buf), Err(FrameError::LengthMismatch));
    // Agreement.
    let buf = [0x05, 0x00, 0x00, 0x00, 0x01, 0x00, 0xaa];
    let (hdr, body) = check_frame(&buf).expect("well formed");
    assert_eq!(hdr.opcode, MGMT_OP_SET_POWERED);
    assert_eq!(hdr.index, 0);
    assert_eq!(body, &[0xaa]);
}

#[test]
fn opcode_zero_and_past_the_table_are_unknown() {
    for op in [0u16, MGMT_OP_MAX + 1, 0x1000, u16::MAX] {
        let v = validate(&stackwide(op, 0));
        assert_eq!(status_of(v), Some(MGMT_STATUS_UNKNOWN_COMMAND), "opcode {op:#x}");
    }
}

#[test]
fn untrusted_socket_is_refused_a_privileged_command() {
    let r = req(MGMT_OP_SET_POWERED, 0, 1, false, Some(ControllerState::Ready));
    assert_eq!(status_of(validate(&r)), Some(MGMT_STATUS_PERMISSION_DENIED));
}

#[test]
fn untrusted_socket_may_issue_the_reads() {
    let r = req(MGMT_OP_READ_INFO, 0, 0, false, Some(ControllerState::Ready));
    assert!(matches!(validate(&r), Verdict::Dispatch(_)));
    let r = req(MGMT_OP_READ_INDEX_LIST, MGMT_INDEX_NONE, 0, false, None);
    assert!(matches!(validate(&r), Verdict::Dispatch(_)));
}

/// An unknown opcode outranks the permission check: an untrusted socket sending
/// garbage learns the opcode is unknown, not that it lacks permission.
#[test]
fn unknown_opcode_outranks_permission() {
    let r = req(0xFFFF, 0, 0, false, Some(ControllerState::Ready));
    assert_eq!(status_of(validate(&r)), Some(MGMT_STATUS_UNKNOWN_COMMAND));
}

/// Permission outranks the index checks: an untrusted socket naming a
/// nonexistent controller is told permission denied, not invalid index.
#[test]
fn permission_outranks_index() {
    let r = req(MGMT_OP_SET_POWERED, 7, 1, false, None);
    assert_eq!(status_of(validate(&r)), Some(MGMT_STATUS_PERMISSION_DENIED));
    let r = req(MGMT_OP_SET_POWERED, 7, 1, false, Some(ControllerState::Setup));
    assert_eq!(status_of(validate(&r)), Some(MGMT_STATUS_PERMISSION_DENIED));
}

/// And the same request from a trusted socket does reach the index check, which
/// is what makes the assertion above about ordering rather than about the
/// permission check swallowing everything.
#[test]
fn trusted_socket_reaches_the_index_check() {
    let r = req(MGMT_OP_SET_POWERED, 7, 1, true, None);
    assert_eq!(status_of(validate(&r)), Some(MGMT_STATUS_INVALID_INDEX));
}

#[test]
fn index_naming_nothing_is_invalid() {
    assert_eq!(status_of(validate(&req(MGMT_OP_SET_POWERED, 3, 1, true, None))),
               Some(MGMT_STATUS_INVALID_INDEX));
}

#[test]
fn controller_mid_bringup_is_invalid() {
    for st in [ControllerState::Setup, ControllerState::Config, ControllerState::UserChannel] {
        let r = req(MGMT_OP_SET_POWERED, 0, 1, true, Some(st));
        assert_eq!(status_of(validate(&r)), Some(MGMT_STATUS_INVALID_INDEX), "{st:?}");
    }
}

#[test]
fn unconfigured_controller_admits_only_the_configuration_commands() {
    let unconf = Some(ControllerState::Unconfigured);
    // Refused: an ordinary command.
    let r = req(MGMT_OP_SET_POWERED, 0, 1, true, unconf);
    assert_eq!(status_of(validate(&r)), Some(MGMT_STATUS_INVALID_INDEX));
    // Admitted: the three that carry the unconfigured flag.
    for (op, len) in [
        (MGMT_OP_READ_CONFIG_INFO, MGMT_READ_CONFIG_INFO_SIZE),
        (MGMT_OP_SET_EXTERNAL_CONFIG, MGMT_SET_EXTERNAL_CONFIG_SIZE),
        (MGMT_OP_SET_PUBLIC_ADDRESS, MGMT_SET_PUBLIC_ADDRESS_SIZE),
    ] {
        let r = req(op, 0, len, true, unconf);
        assert!(matches!(validate(&r), Verdict::Dispatch(_)), "opcode {op:#x}");
    }
}

#[test]
fn a_stackwide_command_must_not_name_a_controller() {
    let r = ready(MGMT_OP_READ_INDEX_LIST, 0);
    assert_eq!(status_of(validate(&r)), Some(MGMT_STATUS_INVALID_INDEX));
}

#[test]
fn a_controller_command_must_name_one() {
    let r = stackwide(MGMT_OP_SET_POWERED, 1);
    assert_eq!(status_of(validate(&r)), Some(MGMT_STATUS_INVALID_INDEX));
}

#[test]
fn a_controller_optional_command_accepts_either() {
    let with = ready(MGMT_OP_READ_EXP_FEATURES_INFO, 0);
    assert!(matches!(validate(&with), Verdict::Dispatch(_)));
    let without = stackwide(MGMT_OP_READ_EXP_FEATURES_INFO, 0);
    assert!(matches!(validate(&without), Verdict::Dispatch(_)));
}

/// The index checks outrank the length check: a command with both a bad index
/// and a bad length is answered for the index.
#[test]
fn index_outranks_length() {
    let r = req(MGMT_OP_SET_POWERED, 9, 99, true, None);
    assert_eq!(status_of(validate(&r)), Some(MGMT_STATUS_INVALID_INDEX));
}

#[test]
fn a_fixed_length_command_demands_exactly_its_width() {
    for len in [0usize, 2, 3, 100] {
        let r = ready(MGMT_OP_SET_POWERED, len);
        assert_eq!(status_of(validate(&r)), Some(MGMT_STATUS_INVALID_PARAMS), "len {len}");
    }
    assert!(matches!(validate(&ready(MGMT_OP_SET_POWERED, 1)), Verdict::Dispatch(_)));
}

/// The width that matters is the one in the table, not a shared constant: a
/// three-byte command rejects the one-byte mode payload and vice versa.
#[test]
fn each_command_carries_its_own_width() {
    assert_eq!(status_of(validate(&ready(MGMT_OP_SET_DISCOVERABLE, 1))),
               Some(MGMT_STATUS_INVALID_PARAMS));
    assert!(matches!(validate(&ready(MGMT_OP_SET_DISCOVERABLE, 3)), Verdict::Dispatch(_)));
    assert!(matches!(validate(&ready(MGMT_OP_SET_LOCAL_NAME, 260)), Verdict::Dispatch(_)));
    assert_eq!(status_of(validate(&ready(MGMT_OP_SET_LOCAL_NAME, 259))),
               Some(MGMT_STATUS_INVALID_PARAMS));
}

#[test]
fn a_variable_length_command_demands_at_least_its_width() {
    // Minimum for LOAD_LINK_KEYS is three bytes; less is refused, more is fine.
    for len in [0usize, 1, 2] {
        let r = ready(MGMT_OP_LOAD_LINK_KEYS, len);
        assert_eq!(status_of(validate(&r)), Some(MGMT_STATUS_INVALID_PARAMS), "len {len}");
    }
    for len in [3usize, 28, 1000] {
        assert!(matches!(validate(&ready(MGMT_OP_LOAD_LINK_KEYS, len)), Verdict::Dispatch(_)),
                "len {len}");
    }
}

/// A zero-parameter command is still exact: it refuses a payload.
#[test]
fn a_zero_length_command_refuses_a_payload() {
    assert!(matches!(validate(&ready(MGMT_OP_READ_INFO, 0)), Verdict::Dispatch(_)));
    assert_eq!(status_of(validate(&ready(MGMT_OP_READ_INFO, 1))),
               Some(MGMT_STATUS_INVALID_PARAMS));
}

/// A zero-minimum variable-length command accepts anything, including nothing.
#[test]
fn a_zero_minimum_variable_command_accepts_anything() {
    for len in [0usize, 1, 500] {
        assert!(matches!(validate(&ready(MGMT_OP_SET_DEF_SYSTEM_CONFIG, len)),
                         Verdict::Dispatch(_)), "len {len}");
    }
}

#[test]
fn dispatch_returns_the_contract_it_was_admitted_against() {
    match validate(&ready(MGMT_OP_LOAD_IRKS, 2)) {
        Verdict::Dispatch(spec) => {
            assert!(spec.var_len());
            assert_eq!(spec.data_len as usize, MGMT_LOAD_IRKS_SIZE);
            assert!(!spec.untrusted());
        }
        Verdict::Status(s) => panic!("refused with {s:#x}"),
    }
}
