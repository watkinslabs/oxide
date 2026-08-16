// The controlled port.
//
// Before a link's key exchange has finished, the ONLY thing that may leave
// the interface is the exchange itself. Everything else — the first DHCP
// request, a stray retransmission from a socket that was open across a
// roam — must be refused, because it would go out in the clear on a network
// the user believes is protected.
//
// The decision is a pure function of three facts, so it can be checked
// without a radio and cannot drift with the rest of the transmit path.

use crate::uapi::{ETH_P_PAE, ETH_P_PREAUTH, ETH_P_TDLS};

/// Why a frame was refused.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PortVerdict {
    /// The frame may go out.
    Allow,
    /// The port is not authorized and this is not a frame that authorizes it.
    Blocked,
}

/// EtherTypes that may cross an unauthorized port. The port-access protocol
/// is what opens the port; preauthentication runs the same exchange with a
/// network the station has not joined yet; the direct-link setup protocol
/// negotiates its own keys and cannot wait for this port. Nothing else
/// qualifies, and widening this list is how a network leaks plaintext.
/// # C: O(1)
pub fn crosses_unauthorized_port(ethertype: u16) -> bool {
    matches!(ethertype, ETH_P_PAE | ETH_P_PREAUTH | ETH_P_TDLS)
}

/// Whether a frame may be transmitted.
///
/// `controlled` says the interface runs a controlled port at all — an open
/// network does not, and on one every frame is allowed. `authorized` says the
/// port is open. `ethertype` is the frame's protocol. # C: O(1)
pub fn verdict(controlled: bool, authorized: bool, ethertype: u16) -> PortVerdict {
    if !controlled || authorized { return PortVerdict::Allow; }
    if crosses_unauthorized_port(ethertype) { return PortVerdict::Allow; }
    PortVerdict::Blocked
}

/// Whether a frame is allowed. # C: O(1)
pub fn allowed(controlled: bool, authorized: bool, ethertype: u16) -> bool {
    verdict(controlled, authorized, ethertype) == PortVerdict::Allow
}
