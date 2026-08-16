//! Status mapping. Two sources of failure reach userspace through one byte: a
//! controller status returned by the hardware, and an errno raised inside the
//! host. Each has its own table, and a wrong entry mislabels a failure without
//! anything going red, so both are pinned by test.

use syscall::errno::Errno;

use crate::uapi::mgmt::status::*;

/// Controller status byte to management status, indexed by the status itself.
/// The index is the controller's own error code; the comment names it.
pub const HCI_STATUS_TABLE: [u8; 64] = [
    MGMT_STATUS_SUCCESS,           // Success
    MGMT_STATUS_UNKNOWN_COMMAND,   // Unknown Command
    MGMT_STATUS_NOT_CONNECTED,     // No Connection
    MGMT_STATUS_FAILED,            // Hardware Failure
    MGMT_STATUS_CONNECT_FAILED,    // Page Timeout
    MGMT_STATUS_AUTH_FAILED,       // Authentication Failed
    MGMT_STATUS_AUTH_FAILED,       // PIN or Key Missing
    MGMT_STATUS_NO_RESOURCES,      // Memory Full
    MGMT_STATUS_TIMEOUT,           // Connection Timeout
    MGMT_STATUS_NO_RESOURCES,      // Max Number of Connections
    MGMT_STATUS_NO_RESOURCES,      // Max Number of SCO Connections
    MGMT_STATUS_ALREADY_CONNECTED, // ACL Connection Exists
    MGMT_STATUS_BUSY,              // Command Disallowed
    MGMT_STATUS_NO_RESOURCES,      // Rejected Limited Resources
    MGMT_STATUS_REJECTED,          // Rejected Security
    MGMT_STATUS_REJECTED,          // Rejected Personal
    MGMT_STATUS_TIMEOUT,           // Host Timeout
    MGMT_STATUS_NOT_SUPPORTED,     // Unsupported Feature
    MGMT_STATUS_INVALID_PARAMS,    // Invalid Parameters
    MGMT_STATUS_DISCONNECTED,      // OE User Ended Connection
    MGMT_STATUS_NO_RESOURCES,      // OE Low Resources
    MGMT_STATUS_DISCONNECTED,      // OE Power Off
    MGMT_STATUS_DISCONNECTED,      // Connection Terminated
    MGMT_STATUS_BUSY,              // Repeated Attempts
    MGMT_STATUS_REJECTED,          // Pairing Not Allowed
    MGMT_STATUS_FAILED,            // Unknown LMP PDU
    MGMT_STATUS_NOT_SUPPORTED,     // Unsupported Remote Feature
    MGMT_STATUS_REJECTED,          // SCO Offset Rejected
    MGMT_STATUS_REJECTED,          // SCO Interval Rejected
    MGMT_STATUS_REJECTED,          // Air Mode Rejected
    MGMT_STATUS_INVALID_PARAMS,    // Invalid LMP Parameters
    MGMT_STATUS_FAILED,            // Unspecified Error
    MGMT_STATUS_NOT_SUPPORTED,     // Unsupported LMP Parameter Value
    MGMT_STATUS_FAILED,            // Role Change Not Allowed
    MGMT_STATUS_TIMEOUT,           // LMP Response Timeout
    MGMT_STATUS_FAILED,            // LMP Error Transaction Collision
    MGMT_STATUS_FAILED,            // LMP PDU Not Allowed
    MGMT_STATUS_REJECTED,          // Encryption Mode Not Accepted
    MGMT_STATUS_FAILED,            // Unit Link Key Used
    MGMT_STATUS_NOT_SUPPORTED,     // QoS Not Supported
    MGMT_STATUS_TIMEOUT,           // Instant Passed
    MGMT_STATUS_NOT_SUPPORTED,     // Pairing Not Supported
    MGMT_STATUS_FAILED,            // Transaction Collision
    MGMT_STATUS_FAILED,            // Reserved for future use
    MGMT_STATUS_INVALID_PARAMS,    // Unacceptable Parameter
    MGMT_STATUS_REJECTED,          // QoS Rejected
    MGMT_STATUS_NOT_SUPPORTED,     // Classification Not Supported
    MGMT_STATUS_REJECTED,          // Insufficient Security
    MGMT_STATUS_INVALID_PARAMS,    // Parameter Out Of Range
    MGMT_STATUS_FAILED,            // Reserved for future use
    MGMT_STATUS_BUSY,              // Role Switch Pending
    MGMT_STATUS_FAILED,            // Reserved for future use
    MGMT_STATUS_FAILED,            // Slot Violation
    MGMT_STATUS_FAILED,            // Role Switch Failed
    MGMT_STATUS_INVALID_PARAMS,    // EIR Too Large
    MGMT_STATUS_NOT_SUPPORTED,     // Simple Pairing Not Supported
    MGMT_STATUS_BUSY,              // Host Busy Pairing
    MGMT_STATUS_REJECTED,          // Rejected, No Suitable Channel
    MGMT_STATUS_BUSY,              // Controller Busy
    MGMT_STATUS_INVALID_PARAMS,    // Unsuitable Connection Interval
    MGMT_STATUS_TIMEOUT,           // Directed Advertising Timeout
    MGMT_STATUS_AUTH_FAILED,       // Terminated Due to MIC Failure
    MGMT_STATUS_CONNECT_FAILED,    // Connection Establishment Failed
    MGMT_STATUS_CONNECT_FAILED,    // MAC Connection Failed
];

/// Map a controller status byte. A code past the table is a controller error
/// this host has no name for, which is a plain failure rather than a guess. # C: O(1)
pub fn from_hci(status: u8) -> u8 {
    let i = status as usize;
    if i < HCI_STATUS_TABLE.len() { HCI_STATUS_TABLE[i] } else { MGMT_STATUS_FAILED }
}

/// Map an internally raised errno. Only the errnos the interface actually
/// produces have a distinct status; everything else is a plain failure. # C: O(1)
pub fn from_errno(err: Errno) -> u8 {
    match err {
        Errno::Eperm => MGMT_STATUS_REJECTED,
        Errno::Einval => MGMT_STATUS_INVALID_PARAMS,
        Errno::Eopnotsupp => MGMT_STATUS_NOT_SUPPORTED,
        Errno::Ebusy => MGMT_STATUS_BUSY,
        Errno::Etimedout => MGMT_STATUS_AUTH_FAILED,
        Errno::Enomem => MGMT_STATUS_NO_RESOURCES,
        Errno::Eisconn => MGMT_STATUS_ALREADY_CONNECTED,
        Errno::Enotconn => MGMT_STATUS_DISCONNECTED,
        _ => MGMT_STATUS_FAILED,
    }
}

/// Map whichever of the two happened. Success is success; an errno takes the
/// errno table and a controller status takes the controller table. # C: O(1)
pub fn from_result(r: Result<u8, Errno>) -> u8 {
    match r {
        Ok(hci) => from_hci(hci),
        Err(e) => from_errno(e),
    }
}

#[cfg(test)]
#[path = "tests/status.rs"]
mod tests;
