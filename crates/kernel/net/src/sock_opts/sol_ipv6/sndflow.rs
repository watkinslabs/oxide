// `IPV6_FLOWINFO_SEND` — the one gate on the `sin6_flowinfo` word a caller
// puts in a `sockaddr_in6`.
//
// The word is inert until this option is set: a `connect(2)` destination, a
// `sendto(2)` destination and the name `getpeername(2)` reports all read or
// write it only for a socket that asked for it. That is what makes it safe
// for a caller to leave the field uninitialised, which most do.
//
// A connect settles the socket's flow information from its destination and
// every later packet carries it; a per-message destination replaces it for
// that message alone. Both keep only the low 28 bits — the traffic class and
// the flow label — because the top four are the IP version nibble the header
// builder owns.
//
// No target gate: the decision must run under hosted `cargo test`.

use crate::cmsg::IPV6_FLOWINFO_MASK;

/// The flow information a destination `sockaddr_in6` contributes, or `None`
/// when the socket never asked to send one. # C: O(1)
pub fn supplied(sndflow: bool, sin6_flowinfo: u32) -> Option<u32> {
    if !sndflow { return None; }
    Some(sin6_flowinfo & IPV6_FLOWINFO_MASK)
}

/// The `sin6_flowinfo` a peer name reports: the socket's settled flow
/// information for a socket that sends one, and zero for every other — a
/// socket that never opted in must not learn the value through its own name.
/// # C: O(1)
pub fn reported(sndflow: bool, settled: u32) -> u32 { if sndflow { settled } else { 0 } }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_word_is_inert_until_the_socket_asks_to_send_one() {
        assert_eq!(supplied(false, 0x0abc_def0), None);
        assert_eq!(reported(false, 0x0abc_def0), 0);
    }

    #[test]
    fn only_the_traffic_class_and_flow_label_survive() {
        // The top nibble is the version field, never a caller's to set.
        assert_eq!(supplied(true, 0xf123_4567), Some(0x0123_4567));
        assert_eq!(supplied(true, 0x0000_0000), Some(0));
        // What a connect settled is what the peer name reports, verbatim.
        assert_eq!(reported(true, 0x0123_4567), 0x0123_4567);
    }
}
