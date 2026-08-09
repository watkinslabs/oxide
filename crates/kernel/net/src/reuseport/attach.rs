// Which programs `SO_ATTACH_REUSEPORT_EBPF` accepts, and what each flavour
// becomes once attached.
//
// Two program types may steer a reuseport group, and the reference tries them
// in order: a socket filter first, then a reuseport selection program. Only
// the second one carries a socket-shape restriction — it exists to choose
// between INET stream or datagram sockets, so anything else is refused before
// the group ever sees it.
//
// Ungated on purpose: this is the decision, and a target-gated module would
// compile its tests away in silence (`docs/53§4`).

use syscall::errno::Errno;

use crate::bpf_filter::FilterKind;

/// A loaded program's type, as the attach path classifies it.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ProgFlavour {
    /// `BPF_PROG_TYPE_SOCKET_FILTER`: answers with the member index.
    SocketFilter,
    /// `BPF_PROG_TYPE_SK_REUSEPORT`: answers with an action, reading
    /// `sk_reuseport_md`.
    SkReuseport,
    /// Any other program type: not a reuseport program at all.
    Other,
}

/// The attaching socket, in the three terms the restriction is written in.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct SockShape {
    /// `SOCK_STREAM` or `SOCK_DGRAM`.
    pub stream_or_dgram: bool,
    /// `IPPROTO_TCP` or `IPPROTO_UDP`.
    pub tcp_or_udp: bool,
    /// `AF_INET` or `AF_INET6`.
    pub inet: bool,
}

impl SockShape {
    /// Read the shape off the socket personality the option tables share.
    /// # C: O(1)
    pub fn of(sock: &crate::sock_opts::sol_socket::OptSock) -> Self {
        Self {
            stream_or_dgram: sock.stream || sock.udp,
            tcp_or_udp: sock.tcp || sock.udp,
            inet: sock.inet(),
        }
    }

    /// Whether a selection program may steer this socket's group. # C: O(1)
    pub const fn selectable(self) -> bool {
        self.stream_or_dgram && self.tcp_or_udp && self.inet
    }
}

/// What an `SO_ATTACH_REUSEPORT_EBPF` program becomes, or why it is refused.
///
/// A program of neither type is `EINVAL`, which is what looking the fd up as
/// each type in turn produces. A selection program on a socket it cannot
/// steer is `ENOTSUPP` — distinct from `EOPNOTSUPP`, and the value the
/// reference returns here. # C: O(1)
pub fn admit_reuseport_prog(flavour: ProgFlavour, shape: SockShape)
    -> Result<FilterKind, Errno>
{
    match flavour {
        ProgFlavour::SocketFilter => Ok(FilterKind::Ebpf),
        ProgFlavour::SkReuseport if shape.selectable() => Ok(FilterKind::SkReuseport),
        ProgFlavour::SkReuseport => Err(Errno::Enotsupp),
        ProgFlavour::Other => Err(Errno::Einval),
    }
}

#[cfg(test)]
#[path = "attach_tests.rs"]
mod tests;
