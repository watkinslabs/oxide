// TCP connection (TCB) per RFC 9293 §3.3.1.
//
// Module manifest:
// - types.rs      : TcpConn/Endpoint types, core state, errno enum, owned constants.
// - lifecycle.rs  : lifecycle + control-plane helpers (constructors, close, keepalive,
//                   congestion-window helpers, rcv-window autotune).
// - timers.rs     : RTO/RTT timer math and scheduling.
// - io.rs         : send/recv, segment input/output, state transitions.
// - sack.rs       : SACK block helpers and ACK-with-SACK encoding.
// - segment.rs    : wire-segment builders (ACK/data/SYN variants).
// - timing.rs     : monotonic clocks used by TS/keepalive.
// - delivery.rs   : transmit snapshots and ACK-derived delivery-rate samples.
// - chrono.rs     : send-state duration accounting for TCP_INFO.
// - route_policy.rs: selected IPv4 route metrics applied to a new TCB.
// - active_fastopen.rs: the client half of fast open — a SYN carrying data,
//                   and what its answer teaches.
// - reqsk.rs      : the half-open request sock (SYN-RECV minisock) a listener holds,
//                   its SYN-ACK timer accounting and the TCP_DEFER_ACCEPT rules.
// - tests.rs      : unit tests split out from in-module block.

extern crate alloc;

pub mod types;
pub mod lifecycle;
pub mod timers;
pub mod io;
pub mod sack;
pub mod segment;
pub mod syn_opts;
pub mod fastopen;
pub mod active_fastopen;
pub mod timing;
pub mod delivery;
pub mod chrono;
pub mod route_policy;
pub mod reqsk;

pub use types::passive_rcv_header;
pub use types::{
    Endpoint, OutOfOrderSegment, RecvBuf, TcpChrono, TcpCongestionControl, TcpConn, TcpConnError, UnackedSegment, OWN_MSS_DEFAULT,
    OWN_WSCALE, DATA_RETRIES_DEFAULT, DELACK_ATO_MIN_NS, DELACK_MAX_DEFAULT_NS, LINGER2_DEFAULT_NS,
    RTO_MAX_DEFAULT_NS, SYN_RETRIES_DEFAULT,
};
#[cfg(test)]
pub use types::RecvByte;
pub use timing::{ka_now_ns, tcp_now_ms};

#[cfg(test)]
mod tests;
