// Socket-address admission for port rules.
//
// The right asked for depends on the transport and the direction; which port it
// is asked about depends on the address family. Getting the family handling
// wrong would report a permission error where the network stack owes an
// argument error, so the family checks come first and are answered exactly.

use syscall::errno::Errno;

use crate::uapi::*;

/// Address families this check understands.
pub const AF_UNSPEC: u16 = 0;
pub const AF_INET:   u16 = 2;
pub const AF_INET6:  u16 = 10;

/// Minimum `addrlen` for each address shape.
pub const SOCKADDR_FAMILY_LEN: usize = 2;
pub const SOCKADDR_IN_LEN:     usize = 16;
pub const SOCKADDR_IN6_LEN:    usize = 24;

/// Transport of the socket the operation is on.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Proto { Tcp, Udp, Other }

/// Right a bind asks for; `None` means the transport carries no port rules.
/// # C: O(1)
pub fn bind_request(p: Proto) -> Option<AccessMask> {
    match p { Proto::Tcp => Some(ACCESS_NET_BIND_TCP), _ => None }
}

/// Right a connect asks for.
/// # C: O(1)
pub fn connect_request(p: Proto) -> Option<AccessMask> {
    match p { Proto::Tcp => Some(ACCESS_NET_CONNECT_TCP), _ => None }
}

/// What to do with an address once its family is understood.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Verdict {
    /// No port rule applies; let the operation through.
    Allow,
    /// Consult the port rules for this port.
    CheckPort(u16),
    /// Answer the caller with this error instead.
    Fail(Errno),
}

/// The address a socket operation names, already parsed by the caller.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Addr {
    pub sa_family: u16,
    pub addrlen:   usize,
    /// Port in host order, meaningful for the internet families.
    pub port:      u16,
    /// Whether an IPv4 address is the wildcard.
    pub v4_wildcard: bool,
}

impl Addr {
    /// Read an address off the wire. Both internet families put the family in
    /// the first two bytes in host order and the port in the next two in
    /// network order; the IPv4 address follows, and is the wildcard when zero.
    /// A buffer too short for a field reads it as zero, which the length checks
    /// in `classify` then reject.
    /// # C: O(1)
    pub fn parse(bytes: &[u8]) -> Self {
        let u16_le = |i: usize| -> u16 {
            if bytes.len() < i + 2 { 0 } else { u16::from_le_bytes([bytes[i], bytes[i + 1]]) }
        };
        let u16_be = |i: usize| -> u16 {
            if bytes.len() < i + 2 { 0 } else { u16::from_be_bytes([bytes[i], bytes[i + 1]]) }
        };
        Self {
            sa_family: u16_le(0),
            addrlen: bytes.len(),
            port: u16_be(2),
            v4_wildcard: bytes.len() >= 8 && bytes[4..8].iter().all(|b| *b == 0),
        }
    }
}

/// Decide an address. `sock_family` is the socket's own family; `connecting`
/// distinguishes establishing a peer from naming a local address.
///
/// An unspecified family means "drop the association" on connect, which is
/// always allowed — refusing it would make dropping a privilege harder than
/// keeping it. On bind it is accepted only where the network stack itself would
/// accept it, so a caller gets the argument error it is owed rather than a
/// permission error.
/// # C: O(1)
pub fn classify(access: AccessMask, connecting: bool, a: Addr, sock_family: u16) -> Verdict {
    if a.addrlen < SOCKADDR_FAMILY_LEN { return Verdict::Fail(Errno::Einval); }

    let family = if a.sa_family == AF_UNSPEC {
        if connecting && access == ACCESS_NET_CONNECT_TCP { return Verdict::Allow; }
        if access == ACCESS_NET_BIND_TCP {
            if sock_family == AF_INET {
                if a.addrlen < SOCKADDR_IN_LEN { return Verdict::Fail(Errno::Einval); }
                if !a.v4_wildcard { return Verdict::Fail(Errno::Eafnosupport); }
            } else {
                if a.addrlen < SOCKADDR_IN6_LEN { return Verdict::Fail(Errno::Einval); }
                return Verdict::Fail(Errno::Eafnosupport);
            }
        }
        // An unspecified family only stands in for IPv4, and only for a
        // wildcard bind.
        AF_INET
    } else {
        a.sa_family
    };

    match family {
        AF_INET  => if a.addrlen < SOCKADDR_IN_LEN  { return Verdict::Fail(Errno::Einval); },
        AF_INET6 => if a.addrlen < SOCKADDR_IN6_LEN { return Verdict::Fail(Errno::Einval); },
        _ => return Verdict::Allow,
    }

    // A family that disagrees with the socket's own is an argument error, not a
    // denial; only dropping to the unspecified family is a legitimate change.
    if a.sa_family != sock_family && a.sa_family != AF_UNSPEC {
        return Verdict::Fail(Errno::Einval);
    }
    Verdict::CheckPort(a.port)
}

#[cfg(test)]
#[path = "tests/netcheck.rs"]
mod tests;
