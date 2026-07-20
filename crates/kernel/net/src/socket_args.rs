use syscall::errno::Errno;

pub const AF_UNSPEC:  u32 = 0;
pub const AF_UNIX:    u32 = 1;
pub const AF_INET:    u32 = 2;
pub const AF_INET6:   u32 = 10;
pub const AF_INET_WIRE:  u8 = AF_INET as u8;
pub const AF_INET6_WIRE: u8 = AF_INET6 as u8;
pub const AF_NETLINK: u32 = 16;
/// `sockaddr`/netlink wire-width form of the canonical family ID.
pub const AF_NETLINK_WIRE: u16 = AF_NETLINK as u16;
pub const AF_PACKET:  u32 = 17;
pub const AF_VSOCK:   u32 = 40;
pub const AF_UNIX_SOCK_WIRE:   u16 = AF_UNIX as u16;
pub const AF_INET_SOCK_WIRE:   u16 = AF_INET as u16;
pub const AF_INET6_SOCK_WIRE:  u16 = AF_INET6 as u16;
pub const AF_PACKET_SOCK_WIRE: u16 = AF_PACKET as u16;
pub const AF_INET_RULE:   u8 = AF_INET as u8;
pub const AF_INET6_RULE:  u8 = AF_INET6 as u8;
pub const AF_INET_NETLINK_WIRE:  u8 = AF_INET as u8;
pub const AF_INET6_NETLINK_WIRE: u8 = AF_INET6 as u8;

pub const SOCK_STREAM:    u32 = 1;
pub const SOCK_DGRAM:     u32 = 2;
pub const SOCK_RAW:       u32 = 3;
pub const SOCK_RDM:       u32 = 4;
pub const SOCK_SEQPACKET: u32 = 5;
pub const SOCK_PACKET:    u32 = 10;

pub const SOCK_TYPE_MASK: u32 = 0xf;
pub const SOCK_MAX:       u32 = SOCK_PACKET + 1;
pub const SOCK_CLOEXEC:   u32 = 0o2_000_000;
pub const SOCK_NONBLOCK:  u32 = 0o0_004_000;
const IPPROTO_MAX:        u32 = 256;
const IPPROTO_IP:         u32 = 0;
const IPPROTO_TCP:        u32 = 6;
const IPPROTO_UDP:        u32 = 17;
pub const IPPROTO_RAW:    u32 = 255;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct SocketArgs {
    pub family:   u32,
    pub typ:      u32,
    pub protocol: u32,
    pub cloexec:  bool,
    pub nonblock: bool,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct AcceptFlags {
    pub cloexec:  bool,
    pub nonblock: bool,
}

/// Linux `__sys_socket_create` + supported-family create gates. # C: O(1)
pub fn parse_socket_args(family: u32, raw_type: u32, protocol: u32, has_net_raw: bool) -> Result<SocketArgs, Errno> {
    let flags = raw_type & !SOCK_TYPE_MASK;
    if flags & !(SOCK_CLOEXEC | SOCK_NONBLOCK) != 0 { return Err(Errno::Einval); }
    let typ = raw_type & SOCK_TYPE_MASK;
    if typ >= SOCK_MAX { return Err(Errno::Einval); }
    let mut family = family;
    let typ = if family == AF_INET && typ == SOCK_PACKET {
        family = AF_PACKET;
        SOCK_PACKET
    } else {
        typ
    };
    match family {
        AF_INET | AF_INET6 => validate_inet(typ, protocol, has_net_raw)?,
        AF_UNIX           => validate_unix(typ, protocol)?,
        AF_NETLINK        => validate_netlink(typ, protocol)?,
        AF_PACKET         => validate_packet(typ, has_net_raw)?,
        AF_VSOCK          => validate_vsock(typ, protocol)?,
        _                 => return Err(Errno::Eafnosupport),
    }
    Ok(SocketArgs {
        family,
        typ,
        protocol,
        cloexec:  flags & SOCK_CLOEXEC != 0,
        nonblock: flags & SOCK_NONBLOCK != 0,
    })
}

/// Linux `__sys_accept4_file` flag gate. # C: O(1)
pub fn parse_accept_flags(flags: u64) -> Result<AcceptFlags, Errno> {
    let flags = u32::try_from(flags).map_err(|_| Errno::Einval)?;
    if flags & !(SOCK_CLOEXEC | SOCK_NONBLOCK) != 0 { return Err(Errno::Einval); }
    Ok(AcceptFlags {
        cloexec:  flags & SOCK_CLOEXEC != 0,
        nonblock: flags & SOCK_NONBLOCK != 0,
    })
}

fn validate_inet(typ: u32, protocol: u32, has_net_raw: bool) -> Result<(), Errno> {
    if protocol >= IPPROTO_MAX { return Err(Errno::Einval); }
    match typ {
        SOCK_STREAM => {
            if protocol == IPPROTO_IP || protocol == IPPROTO_TCP { Ok(()) } else { Err(Errno::Eprotonosupport) }
        }
        SOCK_DGRAM => {
            if protocol == IPPROTO_IP || protocol == IPPROTO_UDP { Ok(()) } else { Err(Errno::Eprotonosupport) }
        }
        SOCK_RAW => {
            if !has_net_raw { return Err(Errno::Eperm); }
            if protocol == IPPROTO_IP { Err(Errno::Eprotonosupport) } else { Ok(()) }
        }
        _ => Err(Errno::Esocktnosupport),
    }
}

fn validate_unix(typ: u32, protocol: u32) -> Result<(), Errno> {
    if protocol != 0 { return Err(Errno::Eprotonosupport); }
    match typ {
        SOCK_STREAM | SOCK_DGRAM | SOCK_SEQPACKET | SOCK_RAW => Ok(()),
        _ => Err(Errno::Esocktnosupport),
    }
}

fn validate_netlink(typ: u32, protocol: u32) -> Result<(), Errno> {
    if typ != SOCK_RAW && typ != SOCK_DGRAM { return Err(Errno::Esocktnosupport); }
    if protocol > u16::MAX as u32 { return Err(Errno::Eprotonosupport); }
    Ok(())
}

fn validate_packet(typ: u32, has_net_raw: bool) -> Result<(), Errno> {
    if !has_net_raw { return Err(Errno::Eperm); }
    match typ {
        SOCK_DGRAM | SOCK_RAW | SOCK_PACKET => Ok(()),
        _ => Err(Errno::Esocktnosupport),
    }
}

fn validate_vsock(typ: u32, protocol: u32) -> Result<(), Errno> {
    if protocol != 0 && protocol != AF_VSOCK { return Err(Errno::Eprotonosupport); }
    match typ {
        SOCK_DGRAM | SOCK_STREAM | SOCK_SEQPACKET => Ok(()),
        _ => Err(Errno::Esocktnosupport),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_unknown_socket_flag_bits_before_type_lookup() {
        assert_eq!(parse_socket_args(AF_INET, SOCK_STREAM | 0x100, 0, true), Err(Errno::Einval));
    }

    #[test]
    fn masks_type_with_linux_low_nibble_and_preserves_valid_flags() {
        let a = parse_socket_args(AF_INET, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0, true).unwrap();
        assert_eq!(a.typ, SOCK_STREAM);
        assert!(a.cloexec);
        assert!(a.nonblock);
    }

    #[test]
    fn accept4_flags_accept_only_cloexec_and_nonblock() {
        assert_eq!(parse_accept_flags(0).unwrap(), AcceptFlags { cloexec: false, nonblock: false });
        assert_eq!(
            parse_accept_flags((SOCK_CLOEXEC | SOCK_NONBLOCK) as u64).unwrap(),
            AcceptFlags { cloexec: true, nonblock: true },
        );
        assert_eq!(parse_accept_flags(0x100).unwrap_err(), Errno::Einval);
        assert_eq!(parse_accept_flags(u64::MAX).unwrap_err(), Errno::Einval);
    }

    #[test]
    fn rejects_out_of_range_type_as_einval() {
        assert_eq!(parse_socket_args(AF_INET, SOCK_MAX, 0, true), Err(Errno::Einval));
    }

    #[test]
    fn maps_obsolete_inet_sock_packet_to_packet_family() {
        let a = parse_socket_args(AF_INET, SOCK_PACKET, 0, true).unwrap();
        assert_eq!(a.family, AF_PACKET);
        assert_eq!(a.typ, SOCK_PACKET);
        assert_eq!(parse_socket_args(AF_INET, SOCK_PACKET, 0, false), Err(Errno::Eperm));
    }

    #[test]
    fn validates_inet_protocol_matrix() {
        assert_eq!(parse_socket_args(AF_INET, SOCK_STREAM, IPPROTO_UDP, true), Err(Errno::Eprotonosupport));
        assert_eq!(parse_socket_args(AF_INET, SOCK_DGRAM, IPPROTO_TCP, true), Err(Errno::Eprotonosupport));
        assert_eq!(parse_socket_args(AF_INET, SOCK_STREAM, IPPROTO_MAX, true), Err(Errno::Einval));
    }

    #[test]
    fn gates_raw_sockets_on_net_raw_capability() {
        assert_eq!(parse_socket_args(AF_INET, SOCK_RAW, IPPROTO_RAW, false), Err(Errno::Eperm));
        assert_eq!(parse_socket_args(AF_INET, SOCK_RAW, IPPROTO_IP, true), Err(Errno::Eprotonosupport));
        assert_eq!(parse_socket_args(AF_INET6, SOCK_RAW, IPPROTO_IP, true), Err(Errno::Eprotonosupport));
        assert_eq!(parse_socket_args(AF_PACKET, SOCK_RAW, 0, false), Err(Errno::Eperm));
    }

    #[test]
    fn validates_unix_netlink_packet_and_vsock_protocols() {
        assert_eq!(parse_socket_args(AF_UNIX, SOCK_STREAM, 1, true), Err(Errno::Eprotonosupport));
        assert!(parse_socket_args(AF_UNIX, SOCK_STREAM, 0, true).is_ok());
        assert_eq!(parse_socket_args(AF_NETLINK, SOCK_STREAM, 0, true), Err(Errno::Esocktnosupport));
        assert_eq!(parse_socket_args(AF_PACKET, SOCK_SEQPACKET, 0, true), Err(Errno::Esocktnosupport));
        assert_eq!(parse_socket_args(AF_VSOCK, SOCK_DGRAM, 0, true), Ok(SocketArgs {
            family: AF_VSOCK, typ: SOCK_DGRAM, protocol: 0, cloexec: false, nonblock: false,
        }));
        assert!(parse_socket_args(AF_VSOCK, SOCK_SEQPACKET, 0, true).is_ok());
        assert_eq!(parse_socket_args(AF_VSOCK, SOCK_STREAM, 1, true), Err(Errno::Eprotonosupport));
    }
}
