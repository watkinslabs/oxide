//! The two status tables, entry by entry. A wrong entry mislabels a failure to
//! userspace and nothing else would notice, so every one is written out here
//! independently of the table it checks.

use super::*;

/// Every controller status the table covers, spelled out. Order is the index.
const EXPECTED: [u8; 64] = [
    MGMT_STATUS_SUCCESS,
    MGMT_STATUS_UNKNOWN_COMMAND,
    MGMT_STATUS_NOT_CONNECTED,
    MGMT_STATUS_FAILED,
    MGMT_STATUS_CONNECT_FAILED,
    MGMT_STATUS_AUTH_FAILED,
    MGMT_STATUS_AUTH_FAILED,
    MGMT_STATUS_NO_RESOURCES,
    MGMT_STATUS_TIMEOUT,
    MGMT_STATUS_NO_RESOURCES,
    MGMT_STATUS_NO_RESOURCES,
    MGMT_STATUS_ALREADY_CONNECTED,
    MGMT_STATUS_BUSY,
    MGMT_STATUS_NO_RESOURCES,
    MGMT_STATUS_REJECTED,
    MGMT_STATUS_REJECTED,
    MGMT_STATUS_TIMEOUT,
    MGMT_STATUS_NOT_SUPPORTED,
    MGMT_STATUS_INVALID_PARAMS,
    MGMT_STATUS_DISCONNECTED,
    MGMT_STATUS_NO_RESOURCES,
    MGMT_STATUS_DISCONNECTED,
    MGMT_STATUS_DISCONNECTED,
    MGMT_STATUS_BUSY,
    MGMT_STATUS_REJECTED,
    MGMT_STATUS_FAILED,
    MGMT_STATUS_NOT_SUPPORTED,
    MGMT_STATUS_REJECTED,
    MGMT_STATUS_REJECTED,
    MGMT_STATUS_REJECTED,
    MGMT_STATUS_INVALID_PARAMS,
    MGMT_STATUS_FAILED,
    MGMT_STATUS_NOT_SUPPORTED,
    MGMT_STATUS_FAILED,
    MGMT_STATUS_TIMEOUT,
    MGMT_STATUS_FAILED,
    MGMT_STATUS_FAILED,
    MGMT_STATUS_REJECTED,
    MGMT_STATUS_FAILED,
    MGMT_STATUS_NOT_SUPPORTED,
    MGMT_STATUS_TIMEOUT,
    MGMT_STATUS_NOT_SUPPORTED,
    MGMT_STATUS_FAILED,
    MGMT_STATUS_FAILED,
    MGMT_STATUS_INVALID_PARAMS,
    MGMT_STATUS_REJECTED,
    MGMT_STATUS_NOT_SUPPORTED,
    MGMT_STATUS_REJECTED,
    MGMT_STATUS_INVALID_PARAMS,
    MGMT_STATUS_FAILED,
    MGMT_STATUS_BUSY,
    MGMT_STATUS_FAILED,
    MGMT_STATUS_FAILED,
    MGMT_STATUS_FAILED,
    MGMT_STATUS_INVALID_PARAMS,
    MGMT_STATUS_NOT_SUPPORTED,
    MGMT_STATUS_BUSY,
    MGMT_STATUS_REJECTED,
    MGMT_STATUS_BUSY,
    MGMT_STATUS_INVALID_PARAMS,
    MGMT_STATUS_TIMEOUT,
    MGMT_STATUS_AUTH_FAILED,
    MGMT_STATUS_CONNECT_FAILED,
    MGMT_STATUS_CONNECT_FAILED,
];

#[test]
fn every_controller_status_maps_as_specified() {
    for (i, want) in EXPECTED.iter().enumerate() {
        assert_eq!(from_hci(i as u8), *want, "controller status {i:#04x}");
    }
}

#[test]
fn the_table_covers_exactly_the_defined_range() {
    assert_eq!(HCI_STATUS_TABLE.len(), 64);
    // One past the end is a failure this host has no name for.
    assert_eq!(from_hci(64), MGMT_STATUS_FAILED);
    assert_eq!(from_hci(0xff), MGMT_STATUS_FAILED);
}

#[test]
fn success_is_the_only_zero() {
    assert_eq!(from_hci(0), MGMT_STATUS_SUCCESS);
    for i in 1..64u8 {
        assert_ne!(from_hci(i), MGMT_STATUS_SUCCESS, "controller status {i:#04x}");
    }
}

#[test]
fn the_errno_map_is_by_errno_not_by_number() {
    assert_eq!(from_errno(Errno::Eperm), MGMT_STATUS_REJECTED);
    assert_eq!(from_errno(Errno::Einval), MGMT_STATUS_INVALID_PARAMS);
    assert_eq!(from_errno(Errno::Eopnotsupp), MGMT_STATUS_NOT_SUPPORTED);
    assert_eq!(from_errno(Errno::Ebusy), MGMT_STATUS_BUSY);
    assert_eq!(from_errno(Errno::Etimedout), MGMT_STATUS_AUTH_FAILED);
    assert_eq!(from_errno(Errno::Enomem), MGMT_STATUS_NO_RESOURCES);
    assert_eq!(from_errno(Errno::Eisconn), MGMT_STATUS_ALREADY_CONNECTED);
    assert_eq!(from_errno(Errno::Enotconn), MGMT_STATUS_DISCONNECTED);
}

/// A timeout inside the host is an authentication failure, not a timeout: the
/// only thing that times out here is a pairing the peer never answered.
#[test]
fn an_internal_timeout_is_reported_as_an_auth_failure() {
    assert_eq!(from_errno(Errno::Etimedout), MGMT_STATUS_AUTH_FAILED);
    assert_ne!(from_errno(Errno::Etimedout), MGMT_STATUS_TIMEOUT);
}

#[test]
fn an_unmapped_errno_is_a_plain_failure() {
    for e in [Errno::Eio, Errno::Enoent, Errno::Eacces, Errno::Enodev] {
        assert_eq!(from_errno(e), MGMT_STATUS_FAILED, "{e:?}");
    }
}

#[test]
fn a_result_takes_the_table_its_source_belongs_to() {
    // The byte 0x05 is an authentication failure as a controller status.
    assert_eq!(from_result(Ok(5)), MGMT_STATUS_AUTH_FAILED);
    // The same number as an errno is something else entirely.
    assert_eq!(from_result(Err(Errno::Eio)), MGMT_STATUS_FAILED);
    assert_eq!(from_result(Ok(0)), MGMT_STATUS_SUCCESS);
}
