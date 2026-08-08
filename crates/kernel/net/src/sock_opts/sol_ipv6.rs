// `IPPROTO_IPV6` option level (slots 54/55) — the ungated owner of every
// decision the shims make here: option numbers, operand widths, value windows,
// capability ladders, errno ordering.
//
// Module manifest:
// - `uapi`: option numbers, value windows, structure sizes.
// - `state`: per-socket storage (`Ipv6Opts`).
// - `set`: Linux-ordered admission for every write.
// - `get`: Linux value/length table for every read.
// - `hdr`: sticky extension-header shape screen.
// - `pktoptions`: `IPV6_2292PKTOPTIONS` — the written ancillary stream's
//   admission, and the messages a read publishes back.
// - `pathmtu`: `IPV6_RECVPATHMTU` — when the single-slot notification cell is
//   filled, when an ordinary receive drains it, and its wire shape.
// - `flowlabel`: the per-namespace flow-label table `IPV6_FLOWLABEL_MGR` leases from.
// - `sndflow`: `IPV6_FLOWINFO_SEND` — the gate on a `sockaddr_in6`'s
//   `sin6_flowinfo`, on connect, per message and in a reported peer name.
// - `autolabel`: the one flow-label generation policy, read back by
//   `IPV6_AUTOFLOWLABEL` and consulted by every transmit path.
// - `tests`: hosted coverage for the ordering, capability and length rules.
//
// No target gate: the decision logic must run under hosted `cargo test`.

pub mod uapi;
pub mod state;
pub mod set;
pub mod get;
pub mod hdr;
pub mod pktoptions;
pub mod pathmtu;
pub mod autolabel;
pub mod sndflow;
pub mod flowlabel;
#[cfg(test)]
mod tests;

pub use state::{Ipv6Opts, Ipv6RouterAlert, Sticky, flag};
