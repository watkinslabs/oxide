//! Winsock endpoint and error contract over the native socket owner.
//!
//! Socket state, protocol implementation, DNS, and asynchronous readiness
//! remain owned by the kernel networking stack. This crate fixes the Windows
//! ABI conversion and error vocabulary used by `ws2_32`.

extern crate alloc;

mod dns;
mod select;
mod readiness;
mod ipv6_options;

pub use dns::{addrinfo_error, resolve_addrinfo, NativeAddrInfo, NativeAddress, NativeResolver,
    NativeResolverError, ResolveError, ResolvedAddrInfo, MAX_ADDRINFO_RESULTS,
    MAX_CANONICAL_NAME};
pub use ipv6_options::{Ipv6OnlyOptions, Ipv6OnlyOptionError, IPV6_V6ONLY};
pub use select::{project_select, SelectProjection, SocketReadiness};
pub use select::{READY_ACCEPT, READY_CONNECT_ERROR, READY_ERROR, READY_HUP, READY_OOB,
    READY_READ, READY_RESET, READY_WRITE};
pub use readiness::{AsyncPollFd, AsyncPollRequest, AsyncPollResult, AsyncPollResultFd,
    NativeClose, NativeReadiness, MAX_ASYNC_POLL_FDS, NATIVE_POLLERR, NATIVE_POLLHUP,
    NATIVE_POLLIN, NATIVE_POLLNVAL, NATIVE_POLLPRI, NATIVE_POLLOUT, WSA_POLLERR,
    WSA_POLLHUP, WSA_POLLNVAL, WSA_POLLRDBAND, WSA_POLLRDNORM, WSA_POLLWRBAND,
    WSA_POLLWRNORM};

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SockAddrIn { pub family: u16, pub port_be: u16, pub addr_be: u32, pub zero: [u8; 8] }

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SockAddrIn6 { pub family: u16, pub port_be: u16, pub flow_info: u32, pub addr: [u8; 16], pub scope_id: u32 }

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SocketKind { Stream, Datagram }

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WsaError {
    Interrupted, BadFileDescriptor, PermissionDenied, Fault, InvalidArgument,
    TooManyOpenFiles, WouldBlock, InProgress, Already, NotSocket, DestinationRequired,
    MessageTooLong, WrongProtocol, ProtocolOption, ProtocolNotSupported,
    SocketTypeNotSupported, OperationNotSupported, ProtocolFamilyNotSupported,
    AddressFamilyNotSupported, AddressInUse, AddressNotAvailable, NetworkDown,
    NetworkUnreachable, NetworkReset, ConnectionAborted, ConnectionReset, NoBufferSpace,
    Connected, NotConnected, Shutdown, TooManyReferences, TimedOut, ConnectionRefused,
    Loop, NameTooLong, HostDown, HostUnreachable, NotEmpty, Unknown(i32),
}

/// Windows socket address-family values used by the wire ABI.
pub const AF_UNSPEC: u16 = 0;
pub const AF_INET: u16 = 2;
pub const AF_INET6: u16 = 23;
pub const AI_PASSIVE: u32 = 0x0001;
pub const AI_CANONNAME: u32 = 0x0002;
pub const AI_NUMERICHOST: u32 = 0x0004;
pub const AI_V4MAPPED: u32 = 0x0008;
pub const AI_ALL: u32 = 0x0100;
pub const AI_ADDRCONFIG: u32 = 0x0400;
pub const SOCK_RAW: u32 = 3;
pub const IPPROTO_IPV6: u32 = 41;

/// Canonical hint tuple passed to the native resolver after applying the
/// Windows compatibility rules. # C: O(1)
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NormalizedAddrInfoHints {
    pub family: u16,
    pub socket_type: u32,
    pub protocol: u32,
    pub flags: u32,
}

/// The Winsock error number returned by `WSAGetLastError`.
/// # C: O(1)
pub const fn wsa_code(error: WsaError) -> i32 {
    match error {
        WsaError::Interrupted => 10004, WsaError::BadFileDescriptor => 10009,
        WsaError::PermissionDenied => 10013, WsaError::Fault => 10014,
        WsaError::InvalidArgument => 10022, WsaError::TooManyOpenFiles => 10024,
        WsaError::WouldBlock => 10035, WsaError::InProgress => 10036,
        WsaError::Already => 10037, WsaError::NotSocket => 10038,
        WsaError::DestinationRequired => 10039, WsaError::MessageTooLong => 10040,
        WsaError::WrongProtocol => 10041, WsaError::ProtocolOption => 10042,
        WsaError::ProtocolNotSupported => 10043, WsaError::SocketTypeNotSupported => 10044,
        WsaError::OperationNotSupported => 10045, WsaError::ProtocolFamilyNotSupported => 10046,
        WsaError::AddressFamilyNotSupported => 10047, WsaError::AddressInUse => 10048,
        WsaError::AddressNotAvailable => 10049, WsaError::NetworkDown => 10050,
        WsaError::NetworkUnreachable => 10051, WsaError::NetworkReset => 10052,
        WsaError::ConnectionAborted => 10053, WsaError::ConnectionReset => 10054,
        WsaError::NoBufferSpace => 10055, WsaError::Connected => 10056,
        WsaError::NotConnected => 10057, WsaError::Shutdown => 10058,
        WsaError::TooManyReferences => 10059, WsaError::TimedOut => 10060,
        WsaError::ConnectionRefused => 10061, WsaError::Loop => 10062,
        WsaError::NameTooLong => 10063, WsaError::HostDown => 10064,
        WsaError::HostUnreachable => 10065, WsaError::NotEmpty => 10066,
        WsaError::Unknown(_) => 10014,
    }
}

/// Translate the native errno values that cross the Windows socket boundary.
/// # C: O(1)
pub const fn wsa_error(errno: i32) -> WsaError {
    match errno {
        1 => WsaError::PermissionDenied,
        11 => WsaError::WouldBlock,
        32 => WsaError::ConnectionReset,
        4 => WsaError::Interrupted,
        9 => WsaError::BadFileDescriptor,
        13 => WsaError::PermissionDenied,
        14 => WsaError::Fault,
        24 => WsaError::TooManyOpenFiles,
        36 => WsaError::InProgress,
        114 => WsaError::Already,
        89 => WsaError::DestinationRequired,
        90 => WsaError::MessageTooLong,
        91 => WsaError::WrongProtocol,
        92 => WsaError::ProtocolOption,
        93 => WsaError::ProtocolNotSupported,
        94 => WsaError::SocketTypeNotSupported,
        95 => WsaError::OperationNotSupported,
        97 => WsaError::AddressFamilyNotSupported,
        110 => WsaError::TimedOut,
        111 => WsaError::ConnectionRefused,
        98 => WsaError::AddressInUse,
        99 => WsaError::AddressNotAvailable,
        101 => WsaError::NetworkUnreachable,
        100 => WsaError::NetworkDown,
        102 => WsaError::NetworkReset,
        103 => WsaError::ConnectionAborted,
        104 => WsaError::ConnectionReset,
        105 => WsaError::NoBufferSpace,
        106 => WsaError::Connected,
        107 => WsaError::NotConnected,
        108 => WsaError::Shutdown,
        109 => WsaError::TooManyReferences,
        40 => WsaError::Loop,
        63 => WsaError::NameTooLong,
        112 => WsaError::HostDown,
        113 => WsaError::HostUnreachable,
        39 => WsaError::NotEmpty,
        22 => WsaError::InvalidArgument,
        88 => WsaError::NotSocket,
        other => WsaError::Unknown(other),
    }
}

/// Validate the address shape before the native socket owner sees it.
/// # C: O(1)
pub const fn validate_sockaddr(family: u16, length: usize) -> Result<(), WsaError> {
    match family {
        AF_INET if length >= core::mem::size_of::<SockAddrIn>() => Ok(()),
        AF_INET6 if length >= core::mem::size_of::<SockAddrIn6>() => Ok(()),
        AF_UNSPEC if length >= 2 => Ok(()),
        AF_INET | AF_INET6 | AF_UNSPEC => Err(WsaError::InvalidArgument),
        _ => Err(WsaError::AddressFamilyNotSupported),
    }
}

/// Validate the portable `getaddrinfo` hint subset used by normal applications.
/// DNS resolution itself remains owned by the native networking service.
/// # C: O(1)
pub const fn validate_addrinfo_hints(family: u16, socket_type: u32, protocol: u32,
    flags: u32) -> Result<(), WsaError> {
    if family != AF_UNSPEC && family != AF_INET && family != AF_INET6 {
        return Err(WsaError::AddressFamilyNotSupported);
    }
    if flags & !(AI_PASSIVE | AI_CANONNAME | AI_NUMERICHOST | AI_V4MAPPED | AI_ALL | AI_ADDRCONFIG) != 0 {
        return Err(WsaError::InvalidArgument);
    }
    if socket_type != 0 && socket_type != 1 && socket_type != 2 && socket_type != SOCK_RAW {
        return Err(WsaError::SocketTypeNotSupported);
    }
    if protocol != 0 && protocol != 6 && protocol != 17 && protocol != IPPROTO_IPV6 {
        return Err(WsaError::ProtocolNotSupported);
    }
    if flags & AI_ALL != 0 && flags & AI_V4MAPPED == 0 {
        return Err(WsaError::InvalidArgument);
    }
    Ok(())
}

/// Apply Wine-compatible hint normalization before invoking the native
/// resolver. Contradictory TCP/UDP type hints are ignored, while the IPv6
/// protocol selector is metadata rather than a resolver protocol. # C: O(1)
pub const fn normalize_addrinfo_hints(family: u16, socket_type: u32, protocol: u32,
    flags: u32) -> Result<NormalizedAddrInfoHints, WsaError> {
    match validate_addrinfo_hints(family, socket_type, protocol, flags) {
        Ok(()) => {}
        Err(error) => return Err(error),
    }
    let mut normalized_type = socket_type;
    let mut normalized_protocol = protocol;
    if normalized_protocol == IPPROTO_IPV6 { normalized_protocol = 0; }
    if normalized_protocol == 6 && normalized_type != 0 && normalized_type != 1 {
        normalized_type = 0;
    }
    if normalized_protocol == 17 && normalized_type != 0 && normalized_type != 2 {
        normalized_type = 0;
    }
    Ok(NormalizedAddrInfoHints { family, socket_type: normalized_type,
        protocol: normalized_protocol, flags })
}

/// Construct a zero-initialized IPv4 endpoint with network-order port/address.
/// # C: O(1)
pub const fn ipv4(port_be: u16, addr_be: u32) -> SockAddrIn {
    SockAddrIn { family: 2, port_be, addr_be, zero: [0; 8] }
}

/// Construct an IPv6 endpoint with network-order port.
/// # C: O(1)
pub const fn ipv6(port_be: u16, addr: [u8; 16], scope_id: u32) -> SockAddrIn6 {
    SockAddrIn6 { family: 23, port_be, flow_info: 0, addr, scope_id }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn socket_address_layouts_match_windows() {
        assert_eq!(core::mem::size_of::<SockAddrIn>(), 16);
        assert_eq!(core::mem::size_of::<SockAddrIn6>(), 28);
        assert_eq!(ipv4(0x3412, 0x0100007f).family, 2);
        assert_eq!(ipv6(0x3412, [0; 16], 4).family, 23);
    }

    #[test]
    fn native_errors_have_stable_winsock_meanings() {
        assert_eq!(wsa_error(11), WsaError::WouldBlock);
        assert_eq!(wsa_error(111), WsaError::ConnectionRefused);
        assert_eq!(wsa_error(101), WsaError::NetworkUnreachable);
        assert_eq!(wsa_error(777), WsaError::Unknown(777));
        assert_eq!(wsa_code(wsa_error(111)), 10061);
        assert_eq!(wsa_code(wsa_error(9)), 10009);
    }

    #[test]
    fn sockaddr_validation_matches_winsock_shape_requirements() {
        assert!(validate_sockaddr(AF_INET, 16).is_ok());
        assert_eq!(validate_sockaddr(AF_INET, 15), Err(WsaError::InvalidArgument));
        assert!(validate_sockaddr(AF_INET6, 28).is_ok());
        assert_eq!(validate_sockaddr(AF_INET6, 27), Err(WsaError::InvalidArgument));
        assert_eq!(validate_sockaddr(999, 28), Err(WsaError::AddressFamilyNotSupported));
    }

    #[test]
    fn addrinfo_hints_reject_unsupported_combinations() {
        assert!(validate_addrinfo_hints(AF_UNSPEC, 1, 6, AI_NUMERICHOST).is_ok());
        assert_eq!(validate_addrinfo_hints(999, 0, 0, 0), Err(WsaError::AddressFamilyNotSupported));
        assert_eq!(validate_addrinfo_hints(AF_INET6, 0, 0, AI_ALL), Err(WsaError::InvalidArgument));
        assert_eq!(validate_addrinfo_hints(AF_INET, 99, 0, 0), Err(WsaError::SocketTypeNotSupported));
    }

    #[test]
    fn ipv6_protocol_is_resolver_metadata_and_contradictory_types_are_ignored() {
        let hints = normalize_addrinfo_hints(AF_INET6, 2, IPPROTO_IPV6, 0).unwrap();
        assert_eq!(hints.protocol, 0);
        assert_eq!(hints.socket_type, 2);
        let tcp = normalize_addrinfo_hints(AF_UNSPEC, 2, 6, 0).unwrap();
        assert_eq!(tcp.socket_type, 0);
        let udp = normalize_addrinfo_hints(AF_UNSPEC, 1, 17, 0).unwrap();
        assert_eq!(udp.socket_type, 0);
    }

    #[test]
    fn raw_socket_hint_is_admitted_for_native_resolution() {
        assert!(validate_addrinfo_hints(AF_INET6, SOCK_RAW, 0, AI_NUMERICHOST).is_ok());
    }
}
