// `IPPROTO_IP` option level (slots 54/55) — the ungated owner of every
// decision the shims make here: option numbers, operand widths, value windows,
// capability ladders, errno ordering.
//
// Module manifest:
// - `uapi`: option numbers, value windows, header-option kinds.
// - `state`: per-socket storage (`IpOpts`) and the port-range resolution.
// - `set`: Linux-ordered admission for every write.
// - `get`: Linux value/length table for every read.
// - `apply`: installing an admitted result, including the transport state it
//   invalidates.
// - the header option area itself is owned by `crate::ipv4_options`, which
//   is ungated: its compile pass and its emitter are hosted-testable.
// - `tests`: hosted coverage for the ordering, capability and length rules.
//
// No target gate: the decision logic must run under hosted `cargo test`.

pub mod uapi;
pub mod state;
pub mod set;
pub mod get;
pub mod apply;
#[cfg(test)]
mod tests;

pub use state::{IpOpts, effective_port_range, flag};
