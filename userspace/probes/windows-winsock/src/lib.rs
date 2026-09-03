//! Winsock endpoint and error contract over the native socket owner.
//!
//! Socket state, protocol implementation, DNS, and asynchronous readiness
//! remain owned by the kernel networking stack. This crate fixes the Windows
//! ABI conversion and error vocabulary used by `ws2_32`.

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SockAddrIn { pub family: u16, pub port_be: u16, pub addr_be: u32, pub zero: [u8; 8] }

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SockAddrIn6 { pub family: u16, pub port_be: u16, pub flow_info: u32, pub addr: [u8; 16], pub scope_id: u32 }

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SocketKind { Stream, Datagram }

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WsaError { WouldBlock, Interrupted, TimedOut, ConnectionRefused, AddressInUse, AddressNotAvailable, NetworkUnreachable, InvalidArgument, NotSocket, Unknown(i32) }

/// Translate the native errno values that cross the Windows socket boundary.
/// # C: O(1)
pub const fn wsa_error(errno: i32) -> WsaError {
    match errno {
        11 | 35 => WsaError::WouldBlock,
        4 => WsaError::Interrupted,
        110 => WsaError::TimedOut,
        111 => WsaError::ConnectionRefused,
        98 => WsaError::AddressInUse,
        99 => WsaError::AddressNotAvailable,
        101 => WsaError::NetworkUnreachable,
        22 => WsaError::InvalidArgument,
        88 => WsaError::NotSocket,
        other => WsaError::Unknown(other),
    }
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
    }
}
