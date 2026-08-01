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
// - `flowlabel`: the per-namespace flow-label table `IPV6_FLOWLABEL_MGR` leases from.
// - `tests`: hosted coverage for the ordering, capability and length rules.
//
// No target gate: the decision logic must run under hosted `cargo test`.

pub mod uapi;
pub mod state;
pub mod set;
pub mod get;
pub mod hdr;
pub mod flowlabel;
#[cfg(test)]
mod tests;

pub use state::{Ipv6Opts, Sticky, flag};
