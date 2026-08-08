/// `IPPROTO_UDP` option state and validation — the ungated owner of every decision
/// the slot-54/55 shims make at this level (option numbers, operand widths,
/// value windows, capability ladders, errno ordering). The shims parse,
/// validate through this module, call one work function, and encode.
///
/// Module manifest:
/// - `uapi`: option numbers, encapsulation types, and the segmentation limits.
/// - `state`: `UdpOpts`, the per-socket cells every level-17 option reads.
/// - `table`: the set/get decision tables (validation + errno ordering).
/// - `encap`: the `UDP_ENCAP` receive-side verdict the stack's UDP arms call.
/// - `cork`: `UDP_CORK` accumulation, destination pinning, and the push decision.
/// - `segment`: the `UDP_SEGMENT` transmit plan and its rejection ladder.
/// - `emit`: the transmit half — the only part that needs a live send path.
/// - `tests`: the verified ABI contract for all of the above.

pub mod uapi;
pub mod state;
pub mod table;
pub mod encap;
pub mod cork;
pub mod segment;
pub mod emit;
#[cfg(test)]
mod tests;

pub use state::{CorkDest, CorkPending, UdpOpts};
pub use table::{SetEffect, get, set};
pub use encap::{EncapConsumed, EncapVerdict, rx_verdict};
pub use segment::{SegmentPlan, plan, plan_v4, plan_v6};

use crate::sock::InetSocket;

/// Level-17 reachability. Linux installs the UDP protocol operations only on
/// a UDP socket, so every other socket answers `ENOPROTOOPT` at this level
/// before the operand is even imported. # C: O(1)
pub fn level_supported(sock: &InetSocket) -> bool { crate::sock_opts::describe(sock).udp }

/// `getsockopt(fd, IPPROTO_UDP, ...)` work function. # C: O(1)
pub fn getsockopt(sock: &InetSocket, optname: u64) -> Result<i32, crate::NetError> {
    get(&sock.opts.udp, optname)
}
