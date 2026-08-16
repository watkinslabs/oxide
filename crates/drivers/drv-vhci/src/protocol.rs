//! The character device's write protocol, as pure decisions.
//!
//! A process writes whole H:4 frames prefixed by their packet type. Four of the
//! types are traffic the controller is reporting to the host; the vendor type
//! is the out-of-band channel through which the process asks for a controller
//! to be created in the first place. Everything here is a total function of the
//! bytes written, so the whole protocol is checkable without a device.

extern crate alloc;
use alloc::vec::Vec;

use bluetooth::uapi::hci::{
    HCI_ACLDATA_PKT, HCI_EVENT_PKT, HCI_ISODATA_PKT, HCI_MAX_FRAME_SIZE,
    HCI_SCODATA_PKT, HCI_VENDOR_PKT,
};
use syscall::errno::Errno;

/// Smallest write the protocol accepts: a packet type and at least one byte
/// after it. A write of one byte names a type and carries nothing, which is
/// neither a frame nor a creation request.
pub const MIN_WRITE_LEN: usize = 2;

/// Reserved bits of the creation opcode. A process setting one is asking for a
/// property that does not exist, which is refused rather than ignored — a
/// silently ignored bit is a request the caller believes was honoured.
pub const CREATE_RESERVED_MASK: u8 = 0x3c;
/// The controller is configured out of band, so it comes up unconfigured.
pub const CREATE_EXTERNAL_CONFIG: u8 = 0x40;
/// The controller is presented raw: the host runs no setup sequence on it.
pub const CREATE_RAW_DEVICE: u8 = 0x80;

/// First byte of the creation acknowledgement, which marks the vendor frame as
/// this driver's own rather than a controller's.
pub const CREATE_ACK_MARK: u8 = 0xff;

/// What a write asks for.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WriteAction {
    /// Traffic from the controller toward the host, with its prefix intact.
    Frame(Vec<u8>),
    /// A request to create a controller with these properties.
    Create(CreateFlags),
}

/// Properties a creation request asks for.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct CreateFlags {
    pub external_config: bool,
    pub raw_device: bool,
    /// The opcode as written, kept so the acknowledgement echoes it back
    /// unchanged.
    pub opcode: u8,
}

/// Validate a creation opcode. # C: O(1)
pub fn parse_create_opcode(opcode: u8) -> Result<CreateFlags, Errno> {
    if opcode & CREATE_RESERVED_MASK != 0 { return Err(Errno::Einval); }
    Ok(CreateFlags {
        external_config: opcode & CREATE_EXTERNAL_CONFIG != 0,
        raw_device: opcode & CREATE_RAW_DEVICE != 0,
        opcode,
    })
}

/// Decide what one write asks for.
///
/// `have_device` is whether a controller already exists on this description: a
/// frame arriving before one has been created has nowhere to go, and a second
/// creation request would leave the first controller unreachable through a
/// description that now names another. # C: O(len)
pub fn parse_write(bytes: &[u8], have_device: bool) -> Result<WriteAction, Errno> {
    if bytes.len() < MIN_WRITE_LEN || bytes.len() > HCI_MAX_FRAME_SIZE {
        return Err(Errno::Einval);
    }
    let (&pkt_type, rest) = bytes.split_first().ok_or(Errno::Einval)?;
    match pkt_type {
        HCI_EVENT_PKT | HCI_ACLDATA_PKT | HCI_SCODATA_PKT | HCI_ISODATA_PKT => {
            if !have_device { return Err(Errno::Enodev); }
            Ok(WriteAction::Frame(bytes.to_vec()))
        }
        HCI_VENDOR_PKT => {
            // The creation request is exactly one opcode byte. Trailing bytes
            // mean the writer meant something else, so it is refused rather
            // than read as a bare opcode with rubbish after it.
            if rest.len() != 1 { return Err(Errno::Einval); }
            if have_device { return Err(Errno::Ebadf); }
            Ok(WriteAction::Create(parse_create_opcode(rest[0])?))
        }
        _ => Err(Errno::Einval),
    }
}

/// The frame handed back when a controller has been created: a vendor packet
/// carrying the mark, the opcode as requested, and the index the controller was
/// registered under, so the process learns which controller it now owns.
/// # C: O(1)
pub fn creation_ack(flags: CreateFlags, index: u16) -> Vec<u8> {
    let mut out = Vec::with_capacity(5);
    out.push(HCI_VENDOR_PKT);
    out.push(CREATE_ACK_MARK);
    out.push(flags.opcode);
    out.extend_from_slice(&index.to_le_bytes());
    out
}

#[cfg(test)]
#[path = "tests/protocol.rs"]
mod tests;
