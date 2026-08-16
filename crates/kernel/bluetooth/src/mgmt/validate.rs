//! Command admission. The ORDER of these checks is the contract: a request
//! that fails two of them must be answered for the earlier one, because that is
//! what a client uses to tell "you may not" from "there is no such thing".
//!
//! Worth stating because it reads backwards: an unknown opcode outranks the
//! permission check, so an untrusted socket sending garbage learns the opcode
//! is unknown rather than that it is untrusted. The permission check in turn
//! outranks every check that needs a controller.

use super::hdr::MgmtHdr;
use super::table::{self, HandlerSpec};
use crate::uapi::mgmt::limits::{MGMT_HDR_SIZE, MGMT_INDEX_NONE};
use crate::uapi::mgmt::status::{
    MGMT_STATUS_INVALID_INDEX, MGMT_STATUS_INVALID_PARAMS, MGMT_STATUS_PERMISSION_DENIED,
    MGMT_STATUS_UNKNOWN_COMMAND,
};

/// What a controller at the requested index is doing. A controller mid-bringup,
/// mid-configuration, or claimed by a user-channel owner is not addressable
/// through this interface at all, and is reported as if the index named nothing.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ControllerState {
    Setup,
    Config,
    UserChannel,
    /// Present, but lacking the identity it needs before it can be used. Only
    /// the configuration commands may address it.
    Unconfigured,
    Ready,
}

impl ControllerState {
    /// Whether the controller is unreachable through this interface. # C: O(1)
    pub fn is_unavailable(self) -> bool {
        matches!(self, ControllerState::Setup | ControllerState::Config | ControllerState::UserChannel)
    }
}

/// Everything admission depends on. `controller` is the state at `index`, or
/// `None` when the index names nothing; it is ignored when the index is the
/// no-controller sentinel.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Request {
    pub opcode: u16,
    pub index: u16,
    pub param_len: usize,
    pub trusted: bool,
    pub controller: Option<ControllerState>,
}

/// The admission answer.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Verdict {
    /// Run the handler. Carries the contract it was admitted against.
    Dispatch(HandlerSpec),
    /// Answer with a command status carrying this byte.
    Status(u8),
}

/// A frame that cannot be attributed to a command. Neither shape draws a reply:
/// with no trustworthy opcode there is nothing to answer for.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum FrameError {
    /// Fewer bytes than a header.
    Short,
    /// The header's length field disagrees with the bytes that follow.
    LengthMismatch,
}

/// Steps one and two: is this a frame at all? # C: O(1)
pub fn check_frame(buf: &[u8]) -> Result<(MgmtHdr, &[u8]), FrameError> {
    if buf.len() < MGMT_HDR_SIZE { return Err(FrameError::Short); }
    let hdr = match MgmtHdr::decode(buf) {
        Some(h) => h,
        None => return Err(FrameError::Short),
    };
    let body = &buf[MGMT_HDR_SIZE..];
    if body.len() != hdr.len as usize { return Err(FrameError::LengthMismatch); }
    Ok((hdr, body))
}

/// Steps three through seven, in order. # C: O(1)
pub fn validate(req: &Request) -> Verdict {
    // 3. An opcode with no handler — including one past the table.
    let spec = match table::lookup(req.opcode) {
        Some(s) => s,
        None => return Verdict::Status(MGMT_STATUS_UNKNOWN_COMMAND),
    };

    // 4. Permission, before anything that consults a controller.
    if !req.trusted && !spec.untrusted() {
        return Verdict::Status(MGMT_STATUS_PERMISSION_DENIED);
    }

    // 5. The named controller must exist and be addressable.
    let addressed = req.index != MGMT_INDEX_NONE;
    if addressed {
        let state = match req.controller {
            Some(s) => s,
            None => return Verdict::Status(MGMT_STATUS_INVALID_INDEX),
        };
        if state.is_unavailable() { return Verdict::Status(MGMT_STATUS_INVALID_INDEX); }
        if state == ControllerState::Unconfigured && !spec.unconfigured() {
            return Verdict::Status(MGMT_STATUS_INVALID_INDEX);
        }
    }

    // 6. A command that wants no controller must not be given one, and one that
    //    wants a controller must not arrive without. Skipped where the handler
    //    works either way.
    if !spec.hdev_optional() && spec.no_hdev() == addressed {
        return Verdict::Status(MGMT_STATUS_INVALID_INDEX);
    }

    // 7. Parameter width: exact unless the handler declares itself variable.
    let want = spec.data_len as usize;
    let bad = if spec.var_len() { req.param_len < want } else { req.param_len != want };
    if bad { return Verdict::Status(MGMT_STATUS_INVALID_PARAMS); }

    Verdict::Dispatch(spec)
}

#[cfg(test)]
#[path = "tests/validate.rs"]
mod tests;
