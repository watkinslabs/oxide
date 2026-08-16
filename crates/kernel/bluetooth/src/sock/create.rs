//! `socket(AF_BLUETOOTH, type, protocol)` admission.
//!
//! Two screens, in this order and no other: the protocol selector is
//! range-checked first, then the protocol's own create operation screens the
//! socket type. The order is the contract — a request naming both an
//! out-of-range protocol and a wrong type reports the protocol, because the
//! family cannot dispatch to a protocol that does not exist in order to ask it
//! about the type.

use syscall::errno::Errno;

use crate::uapi::bt::{
    BTPROTO_AVDTP, BTPROTO_BNEP, BTPROTO_CMTP, BTPROTO_HCI, BTPROTO_HIDP, BTPROTO_ISO,
    BTPROTO_L2CAP, BTPROTO_LAST, BTPROTO_RFCOMM, BTPROTO_SCO,
};

/// Socket types, mirroring the family-independent values the socket layer uses.
pub const SOCK_STREAM:    u32 = 1;
pub const SOCK_DGRAM:     u32 = 2;
pub const SOCK_RAW:       u32 = 3;
pub const SOCK_SEQPACKET: u32 = 5;

/// The first protocol selector the family rejects outright.
pub const BT_MAX_PROTO: u32 = BTPROTO_LAST + 1;

/// What a successful admission decided the socket is.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum BtSocket {
    /// Raw controller access; the channel is chosen at bind, not here.
    Hci,
    L2cap { typ: u32 },
    Sco,
    Rfcomm { typ: u32 },
}

/// Whether a protocol selector names a protocol this family serves.
///
/// The three that are in range but unserved are refused with the
/// protocol-unsupported errno, NOT the out-of-range one: they are real
/// protocols this host does not carry, and reporting them as out of range
/// would tell a caller they can never exist. # C: O(1)
pub fn protocol_served(protocol: u32) -> bool {
    matches!(protocol, BTPROTO_HCI | BTPROTO_L2CAP | BTPROTO_SCO | BTPROTO_RFCOMM)
}

/// Whether a protocol selector is in range but not served here. # C: O(1)
pub fn protocol_unserved(protocol: u32) -> bool {
    matches!(protocol, BTPROTO_BNEP | BTPROTO_CMTP | BTPROTO_HIDP | BTPROTO_AVDTP | BTPROTO_ISO)
}

/// Decide one creation request.
///
/// `has_net_raw` is the caller's raw-network capability, passed in as a plain
/// boolean: this function looks up no task and reads no credential, which is
/// what keeps it checkable without a kernel. # C: O(1)
pub fn plan_create(protocol: u32, typ: u32, has_net_raw: bool) -> Result<BtSocket, Errno> {
    if protocol >= BT_MAX_PROTO { return Err(Errno::Einval); }
    if !protocol_served(protocol) { return Err(Errno::Eprotonosupport); }
    match protocol {
        BTPROTO_HCI => {
            if typ != SOCK_RAW { return Err(Errno::Esocktnosupport); }
            Ok(BtSocket::Hci)
        }
        BTPROTO_L2CAP => {
            if !matches!(typ, SOCK_SEQPACKET | SOCK_STREAM | SOCK_DGRAM | SOCK_RAW) {
                return Err(Errno::Esocktnosupport);
            }
            // The raw type reaches the signalling channel itself, so it is a
            // privileged socket — the type screen runs FIRST, so an unprivileged
            // caller naming a nonexistent type still learns the type is wrong.
            if typ == SOCK_RAW && !has_net_raw { return Err(Errno::Eperm); }
            Ok(BtSocket::L2cap { typ })
        }
        BTPROTO_SCO => {
            if typ != SOCK_SEQPACKET { return Err(Errno::Esocktnosupport); }
            Ok(BtSocket::Sco)
        }
        BTPROTO_RFCOMM => {
            if !matches!(typ, SOCK_STREAM | SOCK_RAW) { return Err(Errno::Esocktnosupport); }
            Ok(BtSocket::Rfcomm { typ })
        }
        _ => Err(Errno::Eprotonosupport),
    }
}

#[cfg(test)]
#[path = "tests/create.rs"]
mod tests;
