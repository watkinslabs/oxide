// IPv4 header option area on transmit. Manifest only.
//
// Module manifest:
// - `compile`: the namespace-aware entry every caller-supplied area enters by.
// - `emit`: the post-route fill pass, the per-fragment copy rule, and the
//   variable-length header writer every IPv4 transmit path uses.
// - `tests`: byte-exact coverage for the emitted header and its fragments.
//
// The area's structural compile pass and its inverse are owned by
// `sock_opts::sol_ip::options`, the level that admits them; this module is
// their namespace-aware and transmit halves. No target gate: every decision
// here must run under hosted `cargo test`.

pub mod compile;
pub mod emit;
#[cfg(test)]
mod tests;

pub use compile::{RemoteUnicast, build_control, build_in};
pub use emit::{Header, fill, fragment, fragmented, header_len, is_strict_route, timestamp,
    wire_dst, write_header};
