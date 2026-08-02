// The bits of `net.ipv4.tcp_fastopen`. One int carries both halves of the
// feature: the client half decides whether this host may put data in a SYN it
// sends, the server half whether it may accept data in a SYN it receives. They
// are independent, and the compiled default enables only the client.

/// This host may open actively with data in the SYN. `TCP_FASTOPEN_CONNECT`
/// is refused with `EOPNOTSUPP` while it is clear.
pub const TFO_CLIENT_ENABLE: i32 = 1;

/// This host may accept data in a SYN it receives.
pub const TFO_SERVER_ENABLE: i32 = 2;

/// A listening socket gets a fast-open queue from `listen` alone, sized to the
/// backlog, without the server ever writing `TCP_FASTOPEN`. Set alongside the
/// server bit, it is how a host enables passive fast open for programs that
/// know nothing about the option.
pub const TFO_SERVER_WO_SOCKOPT1: i32 = 0x400;

/// Compiled default of the sysctl: the client half only. A host therefore
/// accepts `TCP_FASTOPEN_CONNECT` out of the box and fast-opens nothing it
/// listens for until an administrator says so.
pub const TFO_DEFAULT: i32 = TFO_CLIENT_ENABLE;

/// Whether an active open may carry data in its SYN. # C: O(1)
pub fn client_enabled(bits: i32) -> bool { bits & TFO_CLIENT_ENABLE != 0 }

/// Whether `listen` alone must give this socket a fast-open queue. A socket
/// that already has a bound keeps it: the value it was given by hand, or the
/// one a previous `listen` on the same socket installed, outranks the
/// automatic sizing. # C: O(1)
pub fn listen_enables_queue(bits: i32, max_qlen: i32) -> bool {
    bits & TFO_SERVER_WO_SOCKOPT1 != 0 && bits & TFO_SERVER_ENABLE != 0 && max_qlen == 0
}

#[cfg(test)]
#[path = "flags_tests.rs"]
mod tests;
