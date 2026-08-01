// RX bottom half — per-CPU input backlog drained by the NET_RX softirq.
//
// Why this exists (and why the drain is NOT inline on the sender's stack):
// receive traversal used to run inline wherever a socket call could have made
// a loopback packet visible (send, poll, recv, shutdown, setsockopt, `Drop`).
// TX and RX therefore shared one call stack, and the deepest aarch64 chain paid
// TX 13 frames + the whole RX subtree on top — 2768 B of receive work charged
// to every sender. The reference model never does that: a device hands a frame
// to a per-CPU backlog and returns; the NET_RX bottom half drains it later, on
// its own stack, through the softirq dispatch table.
//
// The dispatch table is the load-bearing part. A static call-graph walker
// (`tools/stack-depth-gate.py`) follows direct call edges only, so routing the
// drain through `softirq`'s function-pointer table is what actually severs the
// TX→RX edge. A runtime re-entrancy flag does not: the edge is still there in
// the binary. This was measured, not assumed — see the branch's ledger rows.
//
// Module manifest:
// - limits: backlog length cap, NAPI weight, per-drain budget.
// - queue:  per-CPU `SoftnetData` — input/process queues + softnet counters.
// - napi:   device poll list (driver bottom halves) reached from one softirq.
// - action: the NET_RX softirq handler and the process-context schedule call.
// - bh:     the one kernel/hosted difference — how a raise reaches the drain.
// - softnet: `/proc/net/softnet_stat` row rendering.

pub mod limits;
pub mod queue;
pub mod napi;
pub mod action;
mod bh;
pub mod softnet;

#[cfg(test)]
#[path = "backlog/tests.rs"]
mod tests;

pub use action::{install, net_rx_action, net_rx_schedule};
pub use limits::{DEV_RX_WEIGHT, NETDEV_BUDGET, NETDEV_MAX_BACKLOG};
pub use napi::{poll_all, register_poll, unregister_poll};
pub use queue::{BacklogItem, RxVerdict, SoftnetData, SoftnetRow};
pub use softnet::render_softnet_stat;
