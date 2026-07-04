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
// - tests.rs      : unit tests split out from in-module block.

extern crate alloc;

pub mod types;
pub mod lifecycle;
pub mod timers;
pub mod io;
pub mod sack;
pub mod segment;
pub mod timing;

pub use types::{Endpoint, TcpConn, TcpConnError, UnackedSegment, OWN_MSS_DEFAULT, OWN_WSCALE};
pub use timing::{ka_now_ns, tcp_now_ms};

#[cfg(test)]
mod tests;
