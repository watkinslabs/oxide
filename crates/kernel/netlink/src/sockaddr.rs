// `sockaddr_nl` destination decoding — the single owner every AF_NETLINK send
// path and the connected-destination snapshot share. Ungated so the whole
// contract is covered by hosted tests.

use crate::wire::{AF_NETLINK, SOCKADDR_NL_GROUPS_OFFSET, SOCKADDR_NL_PORT_ID_OFFSET,
    SOCKADDR_NL_SIZE};

/// One AF_NETLINK send destination: a unicast port ID plus the single
/// multicast group a send may reach, held as that group's bit.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct NlDest {
    pub port_id: u32,
    pub group: u32,
}

impl NlDest {
    /// The destination of a socket that has never connected. # C: O(1)
    pub const UNCONNECTED: Self = Self {
        port_id: crate::NETLINK_UNCONNECTED_PORT_ID,
        group: crate::NETLINK_UNCONNECTED_GROUPS,
    };
}

/// Retain only the least-significant requested multicast group.
///
/// A `sockaddr_nl` carries a group BITMASK, but a send reaches exactly one
/// group — the lowest one the sender asked for. Everything downstream matches
/// subscriptions against a bit, so the group is kept in that form.
/// # C: O(1)
pub fn first_group(groups: u32) -> u32 { groups & groups.wrapping_neg() }

/// Decode one `msg_name` as an AF_NETLINK destination.
///
/// A name shorter than a `sockaddr_nl` and a name whose family is not
/// AF_NETLINK are both EINVAL — the family mismatch is a malformed address for
/// this socket, not an unsupported address family.
/// # C: O(1)
pub fn parse_dest(name: &[u8]) -> Result<NlDest, vfs::VfsError> {
    if name.len() < SOCKADDR_NL_SIZE { return Err(vfs::VfsError::Einval); }
    let family = u16::from_ne_bytes([name[0], name[1]]);
    if family != AF_NETLINK { return Err(vfs::VfsError::Einval); }
    let word = |off: usize| u32::from_ne_bytes(
        [name[off], name[off + 1], name[off + 2], name[off + 3]]);
    Ok(NlDest {
        port_id: word(SOCKADDR_NL_PORT_ID_OFFSET),
        group: first_group(word(SOCKADDR_NL_GROUPS_OFFSET)),
    })
}

/// Whether this protocol declares its sends unprivileged. Exactly one does;
/// for every other one a caller-supplied destination is capability-gated.
/// # C: O(1)
pub fn nonroot_send(protocol: u16) -> bool { protocol == crate::wire::proto::NETLINK_USERSOCK }

/// Admit one CALLER-SUPPLIED destination.
///
/// Naming a port or a multicast group is privileged: without the
/// network-administration capability in the socket's own namespace it is EPERM,
/// unless the protocol declares its sends unprivileged. A destination that
/// names neither is not gated, and neither is the destination-less send — that
/// pair was admitted when the socket connected.
/// # C: O(1)
pub fn admit_dest(dest: NlDest, protocol: u16, net_admin: bool)
    -> Result<NlDest, vfs::VfsError>
{
    if (dest.port_id != 0 || dest.group != 0) && !nonroot_send(protocol) && !net_admin {
        return Err(vfs::VfsError::Eperm);
    }
    Ok(dest)
}

/// Decode and admit one caller-supplied `msg_name`. The malformed-address
/// answer outranks the permission one, which is the order the reference asks
/// them in. # C: O(1)
pub fn parse_supplied_dest(name: &[u8], protocol: u16, net_admin: bool)
    -> Result<NlDest, vfs::VfsError>
{
    admit_dest(parse_dest(name)?, protocol, net_admin)
}

/// Encode a destination back into `sockaddr_nl` wire bytes. # C: O(1)
pub fn encode_dest(dest: NlDest) -> [u8; SOCKADDR_NL_SIZE] {
    let mut out = [0u8; SOCKADDR_NL_SIZE];
    out[0..2].copy_from_slice(&AF_NETLINK.to_ne_bytes());
    out[SOCKADDR_NL_PORT_ID_OFFSET..SOCKADDR_NL_PORT_ID_OFFSET + 4]
        .copy_from_slice(&dest.port_id.to_ne_bytes());
    out[SOCKADDR_NL_GROUPS_OFFSET..SOCKADDR_NL_GROUPS_OFFSET + 4]
        .copy_from_slice(&dest.group.to_ne_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::{admit_dest, encode_dest, first_group, nonroot_send, parse_dest,
        parse_supplied_dest, NlDest};
    use crate::wire::proto::{NETLINK_AUDIT, NETLINK_ROUTE, NETLINK_USERSOCK};
    use crate::wire::{AF_NETLINK, SOCKADDR_NL_SIZE};

    fn name(family: u16, port_id: u32, groups: u32) -> [u8; SOCKADDR_NL_SIZE] {
        let mut out = [0u8; SOCKADDR_NL_SIZE];
        out[0..2].copy_from_slice(&family.to_ne_bytes());
        out[4..8].copy_from_slice(&port_id.to_ne_bytes());
        out[8..12].copy_from_slice(&groups.to_ne_bytes());
        out
    }

    #[test]
    fn a_name_shorter_than_sockaddr_nl_is_einval() {
        let full = name(AF_NETLINK, 42, 1);
        for len in 0..SOCKADDR_NL_SIZE {
            assert_eq!(parse_dest(&full[..len]), Err(vfs::VfsError::Einval), "len {len}");
        }
        assert!(parse_dest(&full).is_ok());
    }

    #[test]
    fn a_non_netlink_family_is_einval_not_eafnosupport() {
        const AF_INET: u16 = 2;
        const AF_UNSPEC: u16 = 0;
        for family in [AF_UNSPEC, AF_INET, AF_NETLINK + 1] {
            assert_eq!(parse_dest(&name(family, 42, 1)), Err(vfs::VfsError::Einval));
        }
    }

    #[test]
    fn trailing_bytes_past_sockaddr_nl_are_ignored() {
        let mut long = alloc::vec::Vec::from(name(AF_NETLINK, 7, 1));
        long.extend_from_slice(&[0xff; 20]);
        assert_eq!(parse_dest(&long), Ok(NlDest { port_id: 7, group: 1 }));
    }

    /// A sockaddr_nl group mask names several groups; a send reaches only the
    /// lowest one.
    #[test]
    fn only_the_least_significant_requested_group_is_kept() {
        assert_eq!(first_group(0), 0);
        assert_eq!(first_group(0b1100), 0b0100);
        assert_eq!(first_group(0b1011), 0b0001);
        assert_eq!(first_group(1 << 31), 1 << 31);
        assert_eq!(first_group(u32::MAX), 1);
        assert_eq!(parse_dest(&name(AF_NETLINK, 9, 0b1100)).unwrap().group, 0b0100);
    }

    #[test]
    fn port_and_group_are_read_from_their_own_offsets() {
        assert_eq!(parse_dest(&name(AF_NETLINK, 0xdead_beef, 1 << 4)),
            Ok(NlDest { port_id: 0xdead_beef, group: 1 << 4 }));
    }

    /// Naming a port or a group is privileged on every protocol but the one
    /// that declares its sends unprivileged.
    #[test]
    fn a_named_destination_needs_the_network_capability() {
        let port = NlDest { port_id: 42, group: 0 };
        let group = NlDest { port_id: 0, group: 1 << 3 };
        for dest in [port, group, NlDest { port_id: 42, group: 1 }] {
            for protocol in [NETLINK_ROUTE, NETLINK_AUDIT] {
                assert_eq!(admit_dest(dest, protocol, false), Err(vfs::VfsError::Eperm));
                assert_eq!(admit_dest(dest, protocol, true), Ok(dest));
            }
            assert_eq!(admit_dest(dest, NETLINK_USERSOCK, false), Ok(dest));
        }
    }

    /// The kernel itself is port 0 with no group: an unprivileged sender may
    /// always name it, which is the destination every request uses.
    #[test]
    fn the_unnamed_destination_is_not_gated_on_any_protocol() {
        let kernel = NlDest { port_id: 0, group: 0 };
        for protocol in [NETLINK_ROUTE, NETLINK_AUDIT, NETLINK_USERSOCK] {
            assert_eq!(admit_dest(kernel, protocol, false), Ok(kernel));
        }
    }

    #[test]
    fn exactly_one_protocol_declares_its_sends_unprivileged() {
        assert!(nonroot_send(NETLINK_USERSOCK));
        for protocol in 0..32u16 {
            assert_eq!(nonroot_send(protocol), protocol == NETLINK_USERSOCK);
        }
    }

    /// A malformed address is answered before the permission question: the
    /// caller learns its address is wrong whether or not it is privileged.
    #[test]
    fn a_malformed_name_outranks_the_permission_answer() {
        const AF_INET: u16 = 2;
        let foreign = name(AF_INET, 42, 1);
        assert_eq!(parse_supplied_dest(&foreign, NETLINK_ROUTE, false),
            Err(vfs::VfsError::Einval));
        let short = name(AF_NETLINK, 42, 1);
        assert_eq!(parse_supplied_dest(&short[..4], NETLINK_ROUTE, false),
            Err(vfs::VfsError::Einval));
        assert_eq!(parse_supplied_dest(&short, NETLINK_ROUTE, false), Err(vfs::VfsError::Eperm));
        assert_eq!(parse_supplied_dest(&short, NETLINK_ROUTE, true),
            Ok(NlDest { port_id: 42, group: 1 }));
    }

    #[test]
    fn encode_round_trips_through_parse() {
        let dest = NlDest { port_id: 1234, group: 1 << 2 };
        assert_eq!(parse_dest(&encode_dest(dest)), Ok(dest));
        assert_eq!(parse_dest(&encode_dest(NlDest::UNCONNECTED)), Ok(NlDest::UNCONNECTED));
    }
}
